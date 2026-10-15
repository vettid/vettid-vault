package vault

import (
	"context"
	"crypto/ed25519"
	"errors"
	"math/rand/v2"
	"runtime/debug"
	"sort"
	"strings"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The attachment runner (§10.5.1 "Transfers and memory"): one goroutine
// per unlocked vault that moves blobs and writes and deletes attachment
// objects in the background. It holds the vault's lock only to decide and
// to apply; every relay and store request runs without it. A vault runs at
// most attwire.VaultTransfers blob transfers at once; each also waits for
// the instance's admission (Options.Transfers). Its owner's fetches go
// first, reuploads after missing last.

// Transfer priorities for the instance's admission (lower first).
const (
	PrioOwnerFetch = 0
	PrioTransfer   = 1
	PrioReupload   = 2
)

// TransferGate admits a blob transfer for the instance (the supervisor's
// admission by memory, §10.5.1): Admit blocks until the transfer may
// start or ctx ends, and returns the function that ends it.
type TransferGate interface {
	Admit(ctx context.Context, prio int) (release func(), err error)
}

// OwnerFetchStart is how long an owner's message.attachment.get may wait
// for its transfer to start before it is answered busy (§10.5.1).
const OwnerFetchStart = 30 * time.Second

// AttachTick is the runner's period when nothing wakes it.
const AttachTick = 30 * time.Second

// attMinGap is the least time between two transfers of one attachment.
const attMinGap = time.Second

// attWriteWait bounds how long a deletion waits for the runner's store
// writes in flight (a store request is given 60 s, VAULT-HOST-PROTOCOL §9).
const attWriteWait = 75 * time.Second

// attFetchBound is how long an owner's fetch may take from its request to
// its answer (§10.5.1: within 120 s).
const attFetchBound = 120 * time.Second

type attFetch struct {
	device string
	req    envelope.Inner // id and type of the request
	att    string
	at     time.Time
}

type attDiscard struct {
	blob   string
	sender string // the device's relay key, base64
}

type attRunner struct {
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	slots    int
	running  map[string]bool // entry ids with a transfer or a maintenance job in flight
	fetchQ   []*attFetch
	fetching map[string]int // device id -> content fetches in progress
	discards []attDiscard
	drops    []string // blob ids of the own mailbox to delete
	// lastRun is when each entry's last transfer ended: none starts again
	// within attMinGap, whatever path left it due (no hot loop).
	lastRun map[string]time.Time
	// drained: the collect loop drained the mailbox once since the
	// unlock; purged: the orphan purge ran since then.
	drained, purged bool
}

func (r *attRunner) fetchesOf(device string) int {
	n := r.fetching[device]
	for _, f := range r.fetchQ {
		if f.device == device {
			n++
		}
	}
	return n
}

func (r *attRunner) queueFetch(f *attFetch) {
	r.fetchQ = append(r.fetchQ, f)
	r.poke()
}

func (r *attRunner) queueDiscard(blob string, pk ed25519.PublicKey) {
	r.discards = append(r.discards, attDiscard{blob: blob, sender: relayauth.EncodeKey(pk)})
	r.poke()
}

func (r *attRunner) poke() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// attWake wakes the runner (no-op before it runs).
func (m *Manager) attWake() {
	if m.att != nil {
		m.att.poke()
	}
}

// attDropBlob deletes a blob of the own mailbox, best effort, from the
// runner (an orphan purge catches one lost to a lock).
func (m *Manager) attDropBlob(id string) {
	if m.att != nil && id != "" {
		m.att.drops = append(m.att.drops, id)
		m.att.poke()
	}
}

// attStart starts the runner (Start, with the vault's lock held). It
// lives as long as ctx, the run loop's: a vault whose loop ended (a lock,
// a shutdown) moves no blob.
func (m *Manager) attStart(parent context.Context) {
	if m.att != nil {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	m.att = &attRunner{ctx: ctx, cancel: cancel, wake: make(chan struct{}, 1), running: map[string]bool{}, fetching: map[string]int{}, lastRun: map[string]time.Time{}}
	go m.attLoop(m.att)
}

// attStop ends the runner (zeroize): transfers in flight are abandoned,
// their buffers wiped as they return.
func (m *Manager) attStop() {
	if m.att != nil {
		m.att.cancel()
		m.att = nil
	}
}

func (m *Manager) attTick() time.Duration {
	if m.opt.AttachTick > 0 {
		return m.opt.AttachTick
	}
	return AttachTick
}

func (m *Manager) attLoop(r *attRunner) {
	t := time.NewTimer(0)
	defer t.Stop()
	defer func() {
		m.mu.Lock()
		if m.att == r {
			m.att = nil // the run loop ended; a new one starts another runner
		}
		m.mu.Unlock()
	}()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-r.wake:
		case <-t.C:
		}
		if !m.attPass(r) {
			return
		}
		if !t.Stop() {
			select {
			case <-t.C:
			default:
			}
		}
		t.Reset(m.attTick())
	}
}

// attPass is one pass of the runner; false once the vault is locked.
func (m *Manager) attPass(r *attRunner) bool {
	m.mu.Lock()
	if m.locked || m.st == nil || m.att != r {
		m.mu.Unlock()
		return false
	}
	now := m.attNow()
	for id, t := range r.lastRun {
		if time.Since(t) > time.Minute {
			delete(r.lastRun, id)
		}
	}
	m.attHousekeeping(now)
	m.attBusyFetches(m.now())
	starts := m.attSchedule(now)
	mt := m.attMaintenanceWork(now)
	_ = m.flushIfDirty(context.Background())
	m.drainOutbox(r.ctx)
	_ = m.flushIfDirty(context.Background())
	m.mu.Unlock()
	for _, j := range starts {
		go j()
	}
	m.attMaintain(r, mt)
	return true
}

// --- scheduling ---

type attJob func()

// attBusyFetches answers busy to owner fetches that could not start
// within OwnerFetchStart (§10.5.1).
func (m *Manager) attBusyFetches(now time.Time) {
	r := m.att
	kept := r.fetchQ[:0]
	for _, f := range r.fetchQ {
		if now.Sub(f.at) >= OwnerFetchStart {
			m.attAnswerError(f, "busy")
			continue
		}
		kept = append(kept, f)
	}
	r.fetchQ = kept
}

func (m *Manager) attAnswerError(f *attFetch, code string) {
	p := m.st.Devices[f.device]
	if p == nil {
		return
	}
	req := f.req
	m.sendResponse(p, &req, volatileKey, &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusError,
		Error: &envelope.Error{Code: code}}, m.now())
}

// attPeerReady returns a connection that uploads can reach: active, with
// a standing token it issued the vault.
func (m *Manager) attPeerReady(conn string) *Peer {
	p := m.st.Connections[conn]
	if p == nil || p.State != PeerActive || p.Standing.Token == "" {
		return nil
	}
	return p
}

// attSchedule picks the transfers to start now, by priority, within the
// vault's free slots: owner fetches, then preparing, first deliveries and
// receiving fetches oldest first, then reuploads within peer_reuploads.
func (m *Manager) attSchedule(now time.Time) []attJob {
	r := m.att
	var out []attJob
	free := attwire.VaultTransfers - r.slots
	for free > 0 && len(r.fetchQ) > 0 {
		f := r.fetchQ[0]
		r.fetchQ = r.fetchQ[1:]
		r.slots++
		r.fetching[f.device]++
		free--
		out = append(out, m.ownerFetchJob(r, f))
	}
	a := m.st.Attach
	if a == nil || free <= 0 {
		return out
	}
	var later []*AttEntry
	for _, e := range sortedEntries(a) {
		if free <= 0 {
			break
		}
		if e.Erasing || r.running[e.ID] || now.Before(e.NotBefore) && !m.attTokenArrived(e) || time.Since(r.lastRun[e.ID]) < attMinGap {
			continue
		}
		var j attJob
		switch {
		case e.Dir == DirOut && e.State == AttPreparing && e.Blob != nil:
			j = m.outPrepareJob(r, e)
		case e.Dir == DirOut && e.State == AttSending && e.CW && e.DeliverID == "" && !e.Stopped:
			if p := m.attPeerReady(e.Conn); p != nil {
				j = m.outDeliverJob(r, e, false, m.attNoUpload(e))
			}
		case e.Dir == DirOut && e.LatePending && e.DeliverID != "":
			e.LatePending = false // the deliver went out before: the window decides now
			m.dirty = true
		case e.Dir == DirIn && e.State == AttFetching && e.Blob != nil:
			if !m.attFits(e) {
				m.attRefuseFull(e, now) // its reservation starts with the fetch: checked now
				continue
			}
			j = m.inFetchJob(r, e)
		case e.Dir == DirOut && e.Owed && e.State == AttSending && e.CW && !e.Stopped:
			later = append(later, e)
		}
		if j != nil {
			r.slots++
			r.running[e.ID] = true
			free--
			out = append(out, j)
		}
	}
	for _, e := range later {
		if free <= 0 {
			break
		}
		if m.attPeerReady(e.Conn) == nil {
			continue
		}
		noUpload := m.attNoUpload(e)
		if !noUpload && !m.attReuploadBudget(e, now) {
			continue // kept, served when the rolling budget allows (§10.5.1)
		}
		r.slots++
		r.running[e.ID] = true
		free--
		out = append(out, m.outDeliverJob(r, e, true, noUpload))
	}
	return out
}

// attTokenArrived: a fresh standing token arrived after the vault asked
// for one on a token quota.
func (m *Manager) attTokenArrived(e *AttEntry) bool {
	if e.TokenAsked.IsZero() {
		return false
	}
	p := m.st.Connections[e.Conn]
	return p != nil && p.Standing.Exp.After(e.TokenExp)
}

// attNoUpload: the next delivery goes without a blob (the recipient's
// blob storage is full; or a token quota that no fresh token cured).
func (m *Manager) attNoUpload(e *AttEntry) bool {
	return e.TokenTried && !m.attTokenArrived(e)
}

func (m *Manager) attReuploadBudget(e *AttEntry, now time.Time) bool {
	a := m.st.attach()
	var n int
	var b int64
	a.Reuploads[e.Conn], n, b = pruneStamps(a.Reuploads[e.Conn], now)
	lim := m.attLim()
	return n < lim.PeerReuploads && b+int64(e.Size) <= lim.PeerReuploadBytes
}

// --- transfers ---

// transfer runs fn as one transfer: the instance's admission first (with
// the deadline of ctx), then fn, then the slot is freed and memory
// returned to the system after a transfer of more than 1 MiB.
func (m *Manager) transfer(r *attRunner, prio int, id string, deadline time.Time, fn func(ctx context.Context) int) {
	defer func() {
		m.mu.Lock()
		if m.att == r {
			r.slots--
			delete(r.running, id)
			if !strings.HasPrefix(id, "fetch:") {
				r.lastRun[id] = time.Now()
			}
		}
		m.mu.Unlock()
		r.poke()
	}()
	ctx := r.ctx
	if g := m.opt.Transfers; g != nil {
		actx, cancel := ctx, context.CancelFunc(func() {})
		if !deadline.IsZero() {
			actx, cancel = context.WithDeadline(ctx, deadline)
		}
		release, err := g.Admit(actx, prio)
		cancel()
		if err != nil {
			fn(nil) // not admitted: fn answers what it must (busy)
			return
		}
		defer release()
	}
	if n := fn(ctx); n > 1<<20 {
		debug.FreeOSMemory() // §10.5.1: memory back after each transfer
	}
}

// attRetry schedules the retry of a transient failure (§8.6: full jitter
// from 0.25 s doubling to 30 s; after the first hour at most once every
// 10 minutes).
func attRetry(e *AttEntry, now time.Time, retryAfter int) {
	e.Attempts++
	d := time.Duration(250*(1<<min(e.Attempts, 7))) * time.Millisecond
	d = min(d, outboxMaxBackoff)
	d = time.Duration(rand.Int64N(int64(d)) + 1)
	if now.Sub(e.SentAt) > time.Hour {
		d = 10 * time.Minute
	}
	if ra := time.Duration(retryAfter) * time.Second; ra > d {
		d = ra
	}
	e.NotBefore = now.Add(d)
}

// relayRetryAfter is a relay error's retry_after in seconds (0 if none).
func relayRetryAfter(err error) int {
	var e *relayclient.Error
	if errors.As(err, &e) {
		return e.RetryAfter
	}
	return 0
}

// transient reports a failure worth retrying: a transport error, a 5xx,
// a 429 rate limit.
func transient(err error) bool {
	if err == nil {
		return false
	}
	if RelayCode(err) == "" {
		return true
	}
	st, ok := statusOf(err)
	return ok && (st >= 500 || st == 429 && RelayCode(err) != CodeQuotaExceeded)
}

// fetchBlob fetches and checks a blob of the own mailbox (sending step 5,
// receiving step 2): at most max_blob_bytes, sha256 in constant time,
// decryption, framing and padding, the declared size, and a photo type by
// sniffing. It returns the content and its sniffed type, or a reason:
// "unknown" (blob_unknown), "transient", ReasonBad or ReasonType.
func (m *Manager) fetchBlob(ctx context.Context, b AttBlob, maxBlob int) ([]byte, string, string, error) {
	data, err := m.relay.GetBlob(ctx, b.ID)
	if err != nil {
		switch {
		case RelayCode(err) == CodeBlobUnknown:
			return nil, "", "unknown", err
		case transient(err) || ctx.Err() != nil:
			return nil, "", "transient", err
		}
		return nil, "", ReasonBad, err
	}
	defer suite.Wipe(data)
	if maxBlob > 0 && len(data) > maxBlob {
		return nil, "", ReasonBad, errors.New("blob too large")
	}
	var sum [32]byte
	copy(sum[:], b.SHA256)
	content, err := envelope.OpenBlob(data, b.Key, sum, b.Size)
	if err != nil {
		return nil, "", ReasonBad, err
	}
	mime := attwire.Sniff(content)
	if mime == "" {
		suite.Wipe(content)
		return nil, "", ReasonType, errors.New("not a photo type")
	}
	return content, mime, "", nil
}

// putObject writes an attachment object: create-only, or, when an
// earlier attempt whose flush never happened left one, over it at its
// version (§10.5.1 write order). It writes nothing once the vault is
// locked, and a deletion waits for a write under way (attWaitWrites).
func (m *Manager) putObject(r *attRunner, key string, data []byte) (store.Version, error) {
	m.mu.Lock()
	if m.locked || m.att != r {
		m.mu.Unlock()
		return "", ErrLocked
	}
	m.attWrites.Add(1)
	m.mu.Unlock()
	defer m.attWrites.Done()
	ctx := r.ctx
	v, err := m.opt.Store.Put(ctx, key, data, "")
	if errors.Is(err, store.ErrConflict) {
		_, old, gerr := m.opt.Store.Get(ctx, key)
		if gerr != nil {
			return "", gerr
		}
		return m.opt.Store.Put(ctx, key, data, old)
	}
	return v, err
}

// attWaitWrites waits, at most d, for the runner's store writes in flight.
func (m *Manager) attWaitWrites(d time.Duration) {
	done := make(chan struct{})
	go func() { m.attWrites.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(d):
	}
}

// attRetryApply schedules the retry of an entry after an error of the
// runner's own (a store request, sealing): every error path does, so that
// none reschedules at once.
func (m *Manager) attRetryApply(r *attRunner, id string) {
	m.attApply(r, id, func(e *AttEntry, now time.Time) {
		if e != nil {
			attRetry(e, now, 0)
			m.dirty = true
		}
	})
}

// attCorruptApply counts an object that did not open: retried with the
// backoff, and after attCorruptMax the attachment fails (bad, audited).
func (m *Manager) attCorruptApply(r *attRunner, id string) {
	m.attApply(r, id, func(e *AttEntry, now time.Time) {
		if e == nil || e.Erasing {
			return
		}
		e.Corrupt++
		m.dirty = true
		if e.Corrupt >= attCorruptMax {
			e.Owed = false
			m.attFail(e, ReasonBad, now)
			return
		}
		attRetry(e, now, 0)
	})
}

// deleteObject deletes an attachment object at its recorded version (a
// missing object counts as deleted; a conflict is read and deleted); ver
// "" reads it first.
func (m *Manager) deleteObject(key string, ver store.Version) error {
	return deleteStored(context.Background(), m.opt.Store, key, ver)
}

func deleteStored(ctx context.Context, st store.Store, key string, ver store.Version) error {
	if !store.ValidKey(key) {
		return nil
	}
	if ver == "" {
		_, v, err := st.Get(ctx, key)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		ver = v
	}
	err := st.Delete(ctx, key, ver)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if errors.Is(err, store.ErrConflict) {
		_, v, gerr := st.Get(ctx, key)
		if errors.Is(gerr, store.ErrNotFound) {
			return nil
		}
		if gerr != nil {
			return gerr
		}
		err = st.Delete(ctx, key, v)
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
	}
	return err
}

// attApply runs fn with the vault's lock held on the entry id, if the
// vault is still unlocked and the runner the same; fn gets nil for an
// entry that is gone. Then it flushes and delivers the outbox.
func (m *Manager) attApply(r *attRunner, id string, fn func(e *AttEntry, now time.Time)) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked || m.st == nil || m.att != r {
		return false
	}
	var e *AttEntry
	if m.st.Attach != nil {
		e = m.st.Attach.Entries[id]
	}
	fn(e, m.attNow())
	if err := m.flushIfDirty(context.Background()); err != nil {
		return false
	}
	return true
}

func (m *Manager) attDrain(r *attRunner) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked || m.st == nil || m.att != r {
		return
	}
	m.drainOutbox(r.ctx)
	_ = m.flushIfDirty(context.Background())
}

// outPrepareJob: sending steps 5 and 6, then 7 with the content in hand.
func (m *Manager) outPrepareJob(r *attRunner, e *AttEntry) attJob {
	id, blob, key, vid, maxBlob := e.ID, *e.Blob, append([]byte(nil), e.Key...), m.st.VaultID, m.attMaxBlob()
	blob.Key = append([]byte(nil), blob.Key...)
	return func() {
		defer suite.Wipe(key)
		defer suite.Wipe(blob.Key)
		m.transfer(r, PrioTransfer, id, time.Time{}, func(ctx context.Context) int {
			if ctx == nil {
				return 0
			}
			content, mime, why, err := m.fetchBlob(ctx, blob, maxBlob)
			if err != nil {
				m.attApply(r, id, func(e *AttEntry, now time.Time) {
					if e == nil || e.Erasing || e.State != AttPreparing {
						return
					}
					switch why {
					case "transient":
						attRetry(e, now, relayRetryAfter(err))
						m.dirty = true
					case "unknown":
						m.attFail(e, ReasonBad, now) // blob_unknown is bad (§10.5.1 step 5)
					default:
						m.attFail(e, why, now)
					}
				})
				m.attDrain(r)
				return 0
			}
			defer suite.Wipe(content)
			n := len(content)
			obj, err := attwire.SealObject(key, vid, id, attwire.PartContent, content)
			if err != nil {
				m.attRetryApply(r, id)
				return n
			}
			ver, err := m.putObject(r, attwire.ContentKey(vid, id), obj)
			if err != nil {
				m.attRetryApply(r, id)
				return n
			}
			var deliver bool
			ok := m.attApply(r, id, func(e *AttEntry, now time.Time) {
				if e == nil {
					_ = m.deleteObject(attwire.ContentKey(vid, id), ver) // erased meanwhile
					return
				}
				e.CW, e.CVer = true, ver
				if e.Erasing || e.State != AttPreparing {
					return
				}
				if e.Blob != nil {
					suite.Wipe(e.Blob.Key)
				}
				e.Mime, e.Blob, e.Attempts, e.NotBefore = mime, nil, 0, time.Time{}
				m.attSet(e, AttSending, "", now)
				m.record(Activity{Kind: "message.attachment_sent", ConnectionID: e.Conn, Ref: e.Msg, Direction: DirOut, Audit: true}, m.now())
				deliver = m.attPeerReady(e.Conn) != nil && e.DeliverID == ""
			})
			if !ok {
				return n
			}
			// Only after that flush: the device's blob goes (a crash before it
			// leaves the blob for the next unlock).
			if m.attCrashAt("prepared") {
				return n
			}
			_ = m.relay.DeleteBlob(ctx, blob.ID)
			if deliver {
				m.deliver(ctx, r, id, content, false, false)
			}
			m.attDrain(r)
			return n
		})
	}
}

// outDeliverJob: sending step 7, or a fresh upload on missing (reupload).
// noUpload sends the deliver without a blob.
func (m *Manager) outDeliverJob(r *attRunner, e *AttEntry, reupload, noUpload bool) attJob {
	id, key, vid := e.ID, append([]byte(nil), e.Key...), m.st.VaultID
	prio := PrioTransfer
	if reupload {
		prio = PrioReupload
	}
	return func() {
		defer suite.Wipe(key)
		m.transfer(r, prio, id, time.Time{}, func(ctx context.Context) int {
			if ctx == nil {
				return 0
			}
			var content []byte
			if !noUpload {
				obj, _, err := m.opt.Store.Get(ctx, attwire.ContentKey(vid, id))
				if err != nil {
					m.attRetryApply(r, id)
					return 0
				}
				if content, err = attwire.OpenObject(key, vid, id, attwire.PartContent, obj); err != nil {
					m.attCorruptApply(r, id) // a damaged object: retried, then failed
					return len(obj)
				}
				defer suite.Wipe(content)
			}
			m.deliver(ctx, r, id, content, reupload, noUpload)
			m.attDrain(r)
			return len(content)
		})
	}
}

// deliver uploads a fresh blob of content to the peer and queues
// message.attachment.deliver (§10.5.1 step 7, "Delivery to the peer"); a
// refusal for the recipient's blob storage queues it without a blob.
func (m *Manager) deliver(ctx context.Context, r *attRunner, id string, content []byte, reupload, noUpload bool) {
	var relayURL, mailbox, token string
	var thumb []byte
	var thumbKey []byte
	var tw bool
	vid := ""
	ok := m.attApply(r, id, func(e *AttEntry, _ time.Time) {
		if e == nil || e.Erasing {
			return
		}
		p := m.attPeerReady(e.Conn)
		if p == nil {
			return
		}
		relayURL, mailbox, token = p.Relay.URL, p.Relay.Mailbox, p.Standing.Token
		vid, tw, thumbKey = m.st.VaultID, e.TW, append([]byte(nil), e.Key...)
		thumb = append([]byte(nil), e.Thumb...)
	})
	defer suite.Wipe(thumbKey)
	if !ok {
		return // locked
	}
	if token == "" {
		m.attRetryApply(r, id) // not reachable now: retried later
		return
	}
	if tw {
		obj, _, err := m.opt.Store.Get(ctx, attwire.ThumbKey(vid, id))
		if err != nil {
			m.attRetryApply(r, id)
			return
		}
		if thumb, err = attwire.OpenObject(thumbKey, vid, id, attwire.PartThumb, obj); err != nil {
			m.attCorruptApply(r, id)
			return
		}
	}
	var blob *attwire.Blob
	var expires time.Time
	var upErr error
	if !noUpload {
		data, bkey, sum, err := envelope.SealBlob(content)
		if err != nil {
			suite.Wipe(thumb)
			m.attRetryApply(r, id)
			return
		}
		bid, exp, err := m.relay.PutBlob(ctx, relayURL, mailbox, token, data)
		suite.Wipe(data)
		if err == nil {
			blob = &attwire.Blob{ID: bid, Key: bkey, SHA256: sum, Size: len(content)}
			expires = exp
		} else {
			suite.Wipe(bkey)
			upErr = err
		}
	}
	m.attApply(r, id, func(e *AttEntry, now time.Time) {
		if e == nil || e.Erasing || !(e.State == AttSending || e.State == AttFailed && e.Reason == ReasonUnconfirmed) {
			return
		}
		p := m.attPeerReady(e.Conn)
		if p == nil {
			return
		}
		e.LatePending = false // the one attempt after an unlock past the window (§10.5.1)
		m.dirty = true
		if upErr != nil {
			switch {
			case RelayCode(upErr) == CodeQuotaExceeded && (RelayQuota(upErr) == "token" || RelayQuota(upErr) == "" && !e.TokenTried):
				if !e.TokenTried && m.attAskToken(p, e, now) {
					return // tried once more with the fresh token, or without a blob after an hour
				}
				noUpload = true
			case RelayCode(upErr) == CodeQuotaExceeded:
				noUpload = true // the recipient's blob storage: no retry; it asks with missing
			case RelayCode(upErr) == CodeTokenExpired:
				m.startReconnect(p, m.now())
				e.TokenAsked, e.TokenExp = now, p.Standing.Exp
				e.NotBefore = now.Add(time.Hour)
				m.dirty = true
				return
			case transient(upErr):
				attRetry(e, now, relayRetryAfter(upErr))
				m.dirty = true
				return
			default:
				e.Stopped = true // token_revoked, mailbox_unknown, a refusal: the window decides
				m.dirty = true
				return
			}
		}
		if blob != nil {
			if e.Mime != "" {
				blob.Mime = e.Mime
			} else {
				blob.Mime = attwire.MimeJPEG
			}
			blob.Name, blob.HasName = e.Name, e.HasName
		}
		body := strictjson.NewBuilder().String("message_id", e.Msg)
		if e.DeliverID == "" && e.HasCaption && e.Caption != "" {
			body.String("text", e.Caption)
		}
		body.String("sent_at", envelope.FormatTS(e.SentAt))
		var view []byte
		if blob != nil {
			view = attwire.PeerViewJSON(blob, expires, e.Kind, e.Size, e.Width, e.Height, thumb)
		} else {
			view = attwire.PeerViewJSON(nil, time.Time{}, e.Kind, e.Size, e.Width, e.Height, thumb)
		}
		inner := m.sendTo(p, TypeAttDeliver, body.Raw("attachment", view).Bytes(), m.now())
		if inner == "" {
			attRetry(e, now, 0)
			m.dirty = true
			return
		}
		if e.DeliverAt.IsZero() {
			e.DeliverAt = now
		}
		e.DeliverID = inner
		e.Caption, e.HasCaption = "", false
		e.Attempts, e.NotBefore, e.TokenAsked, e.TokenTried, e.LatePending = 0, time.Time{}, time.Time{}, false, false
		e.Owed = false
		if reupload && blob != nil {
			e.Reoffers++
			a := m.st.attach()
			a.Reuploads[e.Conn] = append(a.Reuploads[e.Conn], AttStamp{At: now, Bytes: int64(e.Size), Att: e.ID})
		}
		m.dirty = true
	})
	suite.Wipe(thumb)
	if blob != nil {
		suite.Wipe(blob.Key) // sealed into the deliver by now
	}
}

// attAskToken asks the peer for a fresh standing token after a token
// quota (§7.2, §8.6) and schedules the one retry: as soon as the token
// arrives, or after an hour without it, the delivery goes without a blob.
func (m *Manager) attAskToken(p *Peer, e *AttEntry, now time.Time) bool {
	e.TokenTried, e.TokenAsked, e.TokenExp = true, now, p.Standing.Exp
	e.NotBefore = now.Add(time.Hour)
	m.dirty = true
	if !m.requestPending(p.ID, tokenRefreshType) {
		if id := m.sendTo(p, tokenRefreshType, []byte(`{}`), m.now()); id != "" {
			m.requests[id] = p.ID
			m.requestTypes[id] = tokenRefreshType
		}
	}
	return true
}

// inFetchJob: receiving step 2.
func (m *Manager) inFetchJob(r *attRunner, e *AttEntry) attJob {
	id, blob, key, vid, maxBlob := e.ID, *e.Blob, append([]byte(nil), e.Key...), m.st.VaultID, m.attMaxBlob()
	blob.Key = append([]byte(nil), blob.Key...)
	return func() {
		defer suite.Wipe(key)
		defer suite.Wipe(blob.Key)
		m.transfer(r, PrioTransfer, id, time.Time{}, func(ctx context.Context) int {
			if ctx == nil {
				return 0
			}
			content, mime, why, err := m.fetchBlob(ctx, blob, maxBlob)
			if err != nil {
				m.attApply(r, id, func(e *AttEntry, now time.Time) {
					if e == nil || e.Erasing || e.State != AttFetching || e.Blob == nil || e.Blob.ID != blob.ID {
						return
					}
					switch why {
					case "transient":
						attRetry(e, now, relayRetryAfter(err))
					case "unknown":
						suite.Wipe(e.Blob.Key)
						e.Blob = nil // expired or deleted: asked for with missing
					case ReasonType:
						m.attUncount(e)               // type refusals do not count against peer_attachments
						m.attFail(e, ReasonType, now) // drops the blob
						m.attSendStatus(e.Conn, strictjson.NewBuilder().String("message_id", e.Msg).String("status", StatusRefused).String("reason", ReasonType), now)
						m.record(Activity{Kind: "message.attachment_refused", ConnectionID: e.Conn, Ref: e.Msg + ":" + ReasonType, Direction: DirIn, Audit: true}, m.now())
					default:
						e.Fetches++
						m.dropBlob(e)
						if e.Fetches >= m.attLim().Reoffers+1 {
							m.attFail(e, ReasonBad, now)
						}
					}
					m.dirty = true
				})
				m.attDrain(r)
				return 0
			}
			defer suite.Wipe(content)
			n := len(content)
			obj, err := attwire.SealObject(key, vid, id, attwire.PartContent, content)
			if err != nil {
				m.attRetryApply(r, id)
				return n
			}
			ver, err := m.putObject(r, attwire.ContentKey(vid, id), obj)
			if err != nil {
				m.attRetryApply(r, id)
				return n
			}
			ok := m.attApply(r, id, func(e *AttEntry, now time.Time) {
				if e == nil {
					_ = m.deleteObject(attwire.ContentKey(vid, id), ver)
					return
				}
				e.CW, e.CVer = true, ver
				if e.Erasing || e.State != AttFetching {
					return
				}
				if e.Blob != nil {
					suite.Wipe(e.Blob.Key)
				}
				e.Mime, e.Size, e.Blob, e.Attempts, e.NotBefore = mime, n, nil, 0, time.Time{}
				m.attSet(e, AttStored, "", now)
				m.record(Activity{Kind: "message.attachment_received", ConnectionID: e.Conn, Ref: e.Msg, Direction: DirIn, Audit: true}, m.now())
				// Queued in this flush, deposited after the blob is deleted.
				m.attSendStatus(e.Conn, strictjson.NewBuilder().String("message_id", e.Msg).String("status", StatusStored), now)
			})
			if ok {
				if m.attCrashAt("stored") {
					return n
				}
				_ = m.relay.DeleteBlob(ctx, blob.ID) // only then (§10.5.1 step 2)
			}
			m.attDrain(r)
			return n
		})
	}
}

// ownerFetchJob: message.attachment.get{content} (§10.5.1 "Fetching"): a
// fresh blob of the stored content in the device's mailbox, answered as a
// volatile response.
func (m *Manager) ownerFetchJob(r *attRunner, f *attFetch) attJob {
	return func() {
		defer func() {
			m.mu.Lock()
			if m.att == r {
				if r.fetching[f.device]--; r.fetching[f.device] <= 0 {
					delete(r.fetching, f.device)
				}
			}
			m.mu.Unlock()
		}()
		m.transfer(r, PrioOwnerFetch, "fetch:"+f.req.ID, f.at.Add(OwnerFetchStart), func(ctx context.Context) int {
			answer := func(body []byte, code string) {
				m.mu.Lock()
				defer m.mu.Unlock()
				if m.locked || m.st == nil || m.att != r {
					return
				}
				p := m.st.Devices[f.device]
				if p == nil {
					return
				}
				req := f.req
				out := &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusOK, Body: body}
				if code != "" {
					out = &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusError, Error: &envelope.Error{Code: code}}
				}
				m.sendResponse(p, &req, volatileKey, out, m.now())
				m.drainOutbox(r.ctx)
			}
			if ctx == nil {
				answer(nil, "busy")
				return 0
			}
			var vid, mime, name, url, mailbox, token string
			var hasName bool
			var key []byte
			found := m.attApply(r, f.att, func(e *AttEntry, _ time.Time) {
				p := m.st.Devices[f.device]
				if e == nil || e.Erasing || !e.CW || p == nil || p.Standing.Token == "" {
					return
				}
				vid, key, mime, name, hasName = m.st.VaultID, append([]byte(nil), e.Key...), e.Mime, e.Name, e.HasName
				url, mailbox, token = p.Relay.URL, p.Relay.Mailbox, p.Standing.Token
			})
			if !found {
				return 0
			}
			if key == nil {
				answer(nil, "unavailable")
				return 0
			}
			defer suite.Wipe(key)
			// §10.5.1: answered within 120 s of the request; what is left of
			// them bounds the read and the upload (relay_error after).
			ctx, cancel := context.WithDeadline(ctx, f.at.Add(attFetchBound))
			defer cancel()
			obj, _, err := m.opt.Store.Get(ctx, attwire.ContentKey(vid, f.att))
			if err != nil {
				if ctx.Err() != nil {
					answer(nil, "relay_error")
				} else {
					answer(nil, "unavailable")
				}
				return 0
			}
			content, err := attwire.OpenObject(key, vid, f.att, attwire.PartContent, obj)
			if err != nil {
				answer(nil, "unavailable")
				return 0
			}
			defer suite.Wipe(content)
			data, bkey, sum, err := envelope.SealBlob(content)
			if err != nil {
				answer(nil, "internal")
				return len(content)
			}
			bid, exp, err := m.relay.PutBlob(ctx, url, mailbox, token, data)
			suite.Wipe(data)
			if err != nil {
				suite.Wipe(bkey)
				answer(nil, "relay_error")
				return len(content)
			}
			b := attwire.Blob{ID: bid, Key: bkey, SHA256: sum, Size: len(content), Mime: mime, Name: name, HasName: hasName}
			if exp.IsZero() {
				exp = time.Now().Add(7 * 24 * time.Hour)
			}
			body := strictjson.NewBuilder().Raw("blob", b.JSON()).String("expires_at", envelope.FormatTS(exp)).Bytes()
			suite.Wipe(bkey)
			answer(body, "")
			return len(content)
		})
	}
}

// --- maintenance (no transfer slot) ---

type attWork struct {
	thumbs   []attThumbWork
	erase    []attEraseWork
	drops    []string
	discards []attDiscard
	missing  []string // entry ids that are due a missing (room checked)
	purge    bool
	needList bool
}

type attThumbWork struct {
	id, vid string
	key     []byte
	thumb   []byte
}

type attEraseWork struct {
	id, vid string
	cw, tw  bool
	cv, tv  store.Version
}

// attMaintenanceWork collects the pass's work that moves no blob.
func (m *Manager) attMaintenanceWork(now time.Time) *attWork {
	r := m.att
	w := &attWork{drops: r.drops, discards: r.discards}
	r.drops, r.discards = nil, nil
	if a := m.st.Attach; a != nil {
		for _, e := range sortedEntries(a) {
			if r.running[e.ID] {
				continue
			}
			switch {
			case e.Erasing:
				r.running[e.ID] = true
				w.erase = append(w.erase, attEraseWork{id: e.ID, vid: m.st.VaultID, cw: e.CW, tw: e.TW, cv: e.CVer, tv: e.TVer})
			case !e.TW && len(e.Thumb) > 0:
				r.running[e.ID] = true
				w.thumbs = append(w.thumbs, attThumbWork{id: e.ID, vid: m.st.VaultID, key: append([]byte(nil), e.Key...), thumb: append([]byte(nil), e.Thumb...)})
			}
		}
		w.missing = m.attMissingDue(now)
	}
	if r.drained && m.attMaxContent() > 0 && (!r.purged || now.Sub(m.st.attach().PurgedAt) >= 24*time.Hour) {
		w.purge = true
	}
	w.needList = len(w.discards) > 0 || len(w.missing) > 0 || w.purge
	return w
}

// attMissingDue picks, per connection, the attachment to ask for now
// (receiving step 3): one at a time, none while a fetch of that
// connection runs, at most once per missing_backoff, in turn.
func (m *Manager) attMissingDue(now time.Time) []string {
	a := m.st.Attach
	byConn := map[string][]*AttEntry{}
	busy := map[string]bool{}
	for _, e := range sortedEntries(a) {
		if e.Dir != DirIn || e.Erasing || e.State != AttFetching {
			continue
		}
		if e.Blob != nil || m.att.running[e.ID] {
			busy[e.Conn] = true
			continue
		}
		byConn[e.Conn] = append(byConn[e.Conn], e)
	}
	var out []string
	conns := make([]string, 0, len(byConn))
	for c := range byConn {
		conns = append(conns, c)
	}
	sort.Strings(conns)
	for c := range a.Turns {
		if _, ok := byConn[c]; !ok {
			delete(a.Turns, c)
		}
	}
	for _, c := range conns {
		if busy[c] || m.attPeerReady(c) == nil {
			continue
		}
		waiting := byConn[c]
		t := a.Turns[c]
		idx := -1
		if t != nil {
			for i, e := range waiting {
				if e.ID == t.Att {
					idx = i
				}
			}
		}
		switch {
		case idx < 0:
			// The turn's attachment is no longer waiting: the next one after
			// it (oldest first), or the oldest.
			next := 0
			if t != nil {
				for i, e := range waiting {
					if e.ID > t.Att {
						next = i
						break
					}
				}
			}
			t = &AttTurn{Att: waiting[next].ID, Since: now}
			a.Turns[c] = t
			idx = next
			m.dirty = true
		case now.Sub(t.Since) >= attwire.MissingTurn && len(waiting) > 1:
			idx = (idx + 1) % len(waiting)
			t = &AttTurn{Att: waiting[idx].ID, Since: now}
			a.Turns[c] = t
			m.dirty = true
		}
		e := waiting[idx]
		if !e.AskedAt.IsZero() && now.Before(e.AskedAt.Add(e.Backoff)) {
			continue
		}
		out = append(out, e.ID)
	}
	return out
}

// attMaintain does the pass's maintenance outside the lock and applies
// its results.
func (m *Manager) attMaintain(r *attRunner, w *attWork) {
	ctx := r.ctx
	for _, id := range w.drops {
		if ctx.Err() != nil {
			return
		}
		_ = m.relay.DeleteBlob(ctx, id)
	}
	for _, t := range w.thumbs {
		obj, err := attwire.SealObject(t.key, t.vid, t.id, attwire.PartThumb, t.thumb)
		suite.Wipe(t.thumb)
		suite.Wipe(t.key)
		var ver store.Version
		if err == nil {
			ver, err = m.putObject(r, attwire.ThumbKey(t.vid, t.id), obj)
		}
		if err == nil && m.attCrashAt("thumb") {
			return
		}
		m.attApply(r, t.id, func(e *AttEntry, _ time.Time) {
			delete(r.running, t.id)
			if err != nil {
				return
			}
			if e == nil {
				_ = m.deleteObject(attwire.ThumbKey(t.vid, t.id), ver)
				return
			}
			e.TW, e.TVer = true, ver
			suite.Wipe(e.Thumb)
			e.Thumb = nil
			m.dirty = true
		})
	}
	for _, x := range w.erase {
		err := m.deleteObject(attwire.ContentKey(x.vid, x.id), x.cv)
		if err == nil {
			err = m.deleteObject(attwire.ThumbKey(x.vid, x.id), x.tv)
		}
		m.attApply(r, x.id, func(e *AttEntry, now time.Time) {
			delete(r.running, x.id)
			if err != nil || e == nil {
				return
			}
			if e.CW != x.cw || e.TW != x.tw {
				return // an object was written meanwhile: deleted on the next pass
			}
			suite.Wipe(e.Key)
			delete(m.st.Attach.Entries, x.id)
			m.dirty = true
		})
	}
	if !w.needList || ctx.Err() != nil {
		return
	}
	list, err := m.relay.ListBlobs(ctx)
	listed := err == nil
	if err != nil && w.purge {
		m.mu.Lock()
		if m.att == r {
			r.purged = true // a relay without the list: nothing to purge from
		}
		m.mu.Unlock()
	}
	// Discards: only a blob this device uploaded that nothing names
	// (without the list nothing is deleted).
	for _, d := range w.discards {
		if !listed {
			break
		}
		for _, b := range list.Blobs {
			if b.BlobID == d.blob && b.Sender != "" && b.Sender == d.sender {
				m.mu.Lock()
				named := m.st != nil && m.attBlobNamed(d.blob)
				m.mu.Unlock()
				if !named {
					_ = m.relay.DeleteBlob(ctx, d.blob)
				}
			}
		}
	}
	if len(w.missing) > 0 {
		m.mu.Lock()
		if !m.locked && m.st != nil && m.att == r {
			now := m.attNow()
			for _, id := range w.missing {
				e := m.st.Attach.Entries[id]
				if e == nil || e.Erasing || e.State != AttFetching || e.Blob != nil {
					continue
				}
				if listed && list.MaxBytes > 0 && list.MaxBytes-list.UsedBytes < int64(envelope.BlobLen(e.Size)) {
					continue // no room for it yet (§10.5.1 step 3)
				}
				m.attSendStatus(e.Conn, strictjson.NewBuilder().String("message_id", e.Msg).String("status", StatusMissing), now)
				e.Asked, e.AskedAt = true, now
				if e.Backoff == 0 {
					e.Backoff = attwire.MissingFirst
				} else {
					e.Backoff = min(2*e.Backoff, attwire.MissingMax)
				}
				m.dirty = true
			}
			m.drainOutbox(ctx)
			_ = m.flushIfDirty(context.Background())
		}
		m.mu.Unlock()
	}
	if w.purge && listed {
		m.attPurge(r, list)
	}
}

// attPurge deletes every blob of the own mailbox older than 24 hours that
// no entry names (§10.5.1 "Orphan blobs").
func (m *Manager) attPurge(r *attRunner, list BlobList) {
	m.mu.Lock()
	if m.locked || m.st == nil || m.att != r {
		m.mu.Unlock()
		return
	}
	now := m.attNow()
	var del []string
	for _, b := range list.Blobs {
		t, err := time.Parse(time.RFC3339, b.CreatedAt)
		if err != nil || now.Sub(t) < 24*time.Hour || m.attBlobNamed(b.BlobID) {
			continue
		}
		del = append(del, b.BlobID)
	}
	r.purged = true
	m.st.attach().PurgedAt = now
	m.dirty = true
	_ = m.flushIfDirty(context.Background())
	m.mu.Unlock()
	for _, id := range del {
		_ = m.relay.DeleteBlob(r.ctx, id)
	}
}

// attDrained notes that a collect returned less than a full batch: the
// mailbox was drained (the orphan purge waits for that, §10.5.1).
func (m *Manager) attDrained() {
	if m.att != nil && !m.att.drained {
		m.att.drained = true
		m.att.poke()
	}
}

// attCrashAt runs the AttachStep hook (tests): an error there is a crash at
// that step, the vault zeroized without a flush.
func (m *Manager) attCrashAt(step string) bool {
	h := m.opt.Hooks.AttachStep
	if h == nil || h(step) == nil {
		return false
	}
	m.Crash()
	return true
}
