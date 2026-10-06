package parent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	// ManifestSHA256 names the manifest an enroll or unlock was built
	// with (0.10.0): the parent supplies that document to the enclave.
	ManifestSHA256 string `json:"manifest_sha256"`
}

func parseRouting(b []byte) (routing, bool) {
	var r routing
	if len(b) == 0 || len(b) > 32*1024 || json.Unmarshal(b, &r) != nil {
		return routing{}, false
	}
	switch r.Op {
	case "enroll", "unlock", "lock", "delete", "recovery", "recovery_cancel", "recovery_register", "account":
	default:
		return routing{}, false
	}
	if (r.Op == "enroll" || r.Op == "unlock") != (r.ManifestSHA256 != "") || r.ManifestSHA256 != "" && !sha256RE.MatchString(r.ManifestSHA256) {
		return routing{}, false
	}
	return r, r.V == 1 && vaultIDOK(r.VaultID) && ulidRE.MatchString(r.RequestID)
}

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// enclaveResponse is the enclave's answer (§11.5).
type enclaveResponse struct {
	V         int    `json:"v"`
	RequestID string `json:"request_id"`
	Status    string `json:"status"`
	Envelope  string `json:"envelope"`
	// Code is the enclave's clear marker of a successful recovery
	// register (0.10.6), the only code a "done" answer carries.
	Code string `json:"code"`
}

// codeRecoveryRegistered is copied from a register's answer into its slot
// (§11.5, §11.11.3, 0.10.6): the member API then records the recovery as
// registered and stops releasing the spent code (§11.11.7).
const codeRecoveryRegistered = "recovery_registered"

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
	// §11.5 (0.10.0): an enroll or unlock names its manifest by hash; the
	// enclave gets that document with the message (none if the bucket
	// has no such object: the enclave then answers "manifest").
	var doc []byte
	if r.ManifestSHA256 != "" {
		doc = p.manifestDoc(ctx, r.ManifestSHA256)
		if doc == nil {
			log.Warn("no manifest document for the request's hash", "manifest_sha256", r.ManifestSHA256)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, p.cfg.RequestTimeout)
	rep, err := s.conn.Call(cctx, hostproto.KindQueue, m.Body, doc)
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
						if er.Code == codeRecoveryRegistered && r.Op == "recovery_register" {
							slot.Code = codeRecoveryRegistered
						}
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

// Manifest documents (0.10.0): the vault data bucket holds every served
// manifest as manifests/<sha256>.json, written by the publish step before
// the site serves it, never changed. The parent reads them on demand and
// keeps a few by hash. It checks only the size and that the document's
// manifest bytes hash to the name (so a corrupt object is not cached);
// the enclave verifies everything else.
const (
	maxManifestDoc    = 90112
	manifestCacheSize = 16
)

func (p *Parent) manifestDoc(ctx context.Context, sha string) []byte {
	p.mu.Lock()
	if d, ok := p.manifests[sha]; ok {
		p.mu.Unlock()
		return d
	}
	p.mu.Unlock()
	b, _, err := p.cfg.Objects.Get(ctx, "manifests/"+sha+".json")
	if err != nil || len(b) == 0 || len(b) > maxManifestDoc || !docHashes(b, sha) {
		return nil
	}
	p.mu.Lock()
	if p.manifests == nil || len(p.manifests) >= manifestCacheSize {
		p.manifests = map[string][]byte{}
	}
	p.manifests[sha] = b
	p.mu.Unlock()
	return b
}

// docHashes reports whether a served document's manifest bytes hash to
// sha (hex).
func docHashes(doc []byte, sha string) bool {
	var d struct {
		Manifest string `json:"manifest"`
	}
	if json.Unmarshal(doc, &d) != nil {
		return false
	}
	mb, err := base64.StdEncoding.DecodeString(d.Manifest)
	if err != nil {
		return false
	}
	h := sha256.Sum256(mb)
	return hex.EncodeToString(h[:]) == sha
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
