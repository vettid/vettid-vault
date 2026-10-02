package parent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"regexp"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// Sizes the parent checks without looking inside (§11.5): a sealed
// result in a response slot is exactly 5,252 bytes.
const resultEnvelopeSize = 5252

var ulidRE = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

// routing is what the parent reads of a queue message: enough to take the
// lease and answer the response slot. The envelope stays opaque and is
// forwarded with the rest of the message, byte for byte.
type routing struct {
	V         int    `json:"v"`
	Op        string `json:"op"`
	VaultID   string `json:"vault_id"`
	RequestID string `json:"request_id"`
}

func parseRouting(b []byte) (routing, bool) {
	var r routing
	if len(b) == 0 || len(b) > 32*1024 || json.Unmarshal(b, &r) != nil {
		return routing{}, false
	}
	switch r.Op {
	case "enroll", "unlock", "lock", "delete":
	default:
		return routing{}, false
	}
	return r, r.V == 1 && vaultIDOK(r.VaultID) && ulidRE.MatchString(r.RequestID)
}

// enclaveResponse is the enclave's answer (§11.5).
type enclaveResponse struct {
	V         int    `json:"v"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Envelope  string `json:"envelope"`
}

// maxConcurrent bounds queue messages in flight to the enclave.
const maxConcurrent = 8

// consume receives queue messages while an enclave with a descriptor is
// connected and forwards them.
func (p *Parent) consume(ctx context.Context) {
	sem := make(chan struct{}, maxConcurrent)
	for ctx.Err() == nil {
		p.mu.Lock()
		ready := p.sess != nil && p.desc != nil
		p.mu.Unlock()
		if !ready {
			select {
			case <-ctx.Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
			continue
		}
		msgs, err := p.cfg.Queues.Receive(ctx, p.queueURL)
		if err != nil {
			if ctx.Err() == nil {
				p.log.Warn("queue receive failed", "error", err.Error())
				time.Sleep(time.Second)
			}
			continue
		}
		for _, m := range msgs {
			sem <- struct{}{}
			go func(m QueueMessage) {
				defer func() { <-sem }()
				p.handleMessage(ctx, m)
			}(m)
		}
	}
}

func (p *Parent) handleMessage(ctx context.Context, m QueueMessage) {
	r, ok := parseRouting(m.Body)
	if !ok {
		p.log.Warn("unreadable queue message dropped", "message_id", m.ID)
		p.deleteMsg(ctx, m)
		return
	}
	log := p.log.With("request_id", r.RequestID, "op", r.Op, "vault_id", r.VaultID)
	takes := r.Op == "enroll" || r.Op == "unlock"
	if takes {
		// §11.1: the lease is taken when the enclave takes the vault. A
		// lease held elsewhere means the request reached the wrong
		// instance: the slot expires and the app refetches (§11.9).
		if err := p.acquire(ctx, r.VaultID); err != nil {
			if errors.Is(err, ErrLeaseHeld) {
				log.Info("vault leased elsewhere; request expired")
				p.writeSlot(ctx, r.RequestID, Slot{Status: "expired"})
				p.deleteMsg(ctx, m)
			} else {
				log.Warn("lease acquisition failed; message left for redelivery", "error", err.Error())
			}
			return
		}
	}
	s := p.session()
	if s == nil {
		log.Warn("enclave gone; message left for redelivery")
		return
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.RequestTimeout)
	rep, err := s.conn.Call(cctx, hostproto.KindQueue, m.Body)
	cancel()
	if err != nil || len(rep) != 2 || string(rep[0]) != hostproto.StatusOK {
		// Not processed (or the enclave failed mid-way): redelivery hits
		// the replay set or, after an enclave restart, etk_unknown.
		log.Warn("enclave did not answer; message left for redelivery")
		if takes && !p.isRunning(r.VaultID) {
			p.enqueueRelease(r.VaultID)
		}
		return
	}
	slot := Slot{Status: "expired"}
	if len(rep[1]) > 0 {
		var er enclaveResponse
		if json.Unmarshal(rep[1], &er) == nil && er.V == 1 && er.RequestID == r.RequestID {
			switch er.Status {
			case "done":
				slot = Slot{Status: "done"}
				if er.Envelope != "" {
					env, err := base64.StdEncoding.DecodeString(er.Envelope)
					if err != nil || len(env) != resultEnvelopeSize {
						slot = Slot{Status: "expired"}
					} else {
						slot.Envelope = env
					}
				}
			case "etk_unknown":
				slot = Slot{Status: "done", Code: "etk_unknown"}
			}
		}
	}
	// Lifecycle events for this request arrived before its answer (one
	// ordered connection); write them first, then the slot (§11.5).
	p.flushEvents(ctx)
	p.writeSlot(ctx, r.RequestID, slot)
	if takes && !p.isRunning(r.VaultID) {
		// The vault did not open here (bad PIN, refused, moved): the
		// lease goes back.
		p.enqueueRelease(r.VaultID)
	}
	p.mu.Lock()
	p.stats.processed++
	p.mu.Unlock()
	log.Info("request answered", "slot", slot.Status, "code", slot.Code)
	p.deleteMsg(ctx, m)
}

func (p *Parent) writeSlot(ctx context.Context, requestID string, s Slot) {
	if err := p.cfg.Tables.WriteSlot(ctx, requestID, s); err != nil {
		p.log.Warn("response slot write failed", "request_id", requestID, "error", err.Error())
	}
}

func (p *Parent) deleteMsg(ctx context.Context, m QueueMessage) {
	if err := p.cfg.Queues.DeleteMessage(ctx, p.queueURL, m.Receipt); err != nil {
		p.log.Warn("queue delete failed", "message_id", m.ID, "error", err.Error())
	}
}
