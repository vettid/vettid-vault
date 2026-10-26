package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Vault deletion (VAULT-MESSAGING §12.5, 0.9.0). A deletion is authorized
// by the credential feature (vault.delete: the holder with the PIN and the
// password, or a recovering app, §11.11.5) or by the host (account
// cancellation, the queue operation `delete`). It runs in this order, so
// that a crash at any point converges to "deleted" and never back to a
// running vault:
//
//  1. mark: in the request's flush, state and header record Deleting; the
//     credential and every feature's secrets are destroyed (VaultDeleting);
//     every connection is sent connection.removed and every owner device
//     device.unlinked{reason: "vault_deleted"}; every token the vault
//     issued is revoked by jti and every peer's relay key by sub; open
//     claims are deleted. A vault whose header says Deleting never runs
//     again: any later unlock or recovery finishes the deletion instead.
//     (0.51.0) Once the flush is stored the parent records the deletion on
//     the vault row (MarkDeleting, "Mark at the host"); nothing of step 2
//     leaves before its ok, and without one within 2 minutes the vault
//     ends locked, still marked, with its outbox undelivered.
//  2. relay and drain: the vault's own mailbox is deleted at the relay
//     (RELAY-PROTOCOL 0.5.0 §6.10) with its messages, denylist, blobs and
//     claims; the queued revocations and claim deletions concerned that
//     mailbox and are dropped. If the deletion fails (a relay before 0.5.0
//     answers not_found) they stay queued as the fallback. Then the outbox
//     is delivered once, best effort (the notices go to the connections'
//     and devices' mailboxes, not this one).
//  3. zeroize: every key in memory is wiped and the vault is locked.
//  4. erase: every written attachment object (0.32.0, by its recorded
//     version), the state object, then the headers of every release the vault
//     knew (its own last: it is the deletion marker), then the enclave's
//     member index, each by a conditional delete; a missing object is
//     already deleted. (0.51.0) A store error is retried for 60 s; then
//     the process ends without reporting, and the member API's resume
//     (the queue op delete_resume) finishes the erase.
//  5. report: the lifecycle event `deleted`, which the parent records and
//     the member API turns into the member's email and the removal of the
//     vault rows.

// Deletion is the deletion in progress.
type Deletion struct {
	At  time.Time `json:"at"`
	Via string    `json:"via"` // app, recovery or host
}

// DeleteConfirmation is the phrase vault.delete must carry (§12.5).
const DeleteConfirmation = "delete my vault"

// VaultDeleting is implemented by features that hold secrets: they are
// destroyed in the deletion's first flush.
type VaultDeleting interface {
	VaultDeleting(s *Session)
}

// DeleteHost is how the credential feature starts a deletion it has
// authorized.
type DeleteHost interface {
	DeleteVault(via string, now time.Time) error
}

// DeleteVault starts the deletion of the vault (§12.5); the runtime
// finishes it after the batch's flush.
func (s *Session) DeleteVault(via string) error {
	h, ok := s.host.(DeleteHost)
	if !ok {
		return errUnavailable
	}
	return h.DeleteVault(via, s.now)
}

func (h managerHost) DeleteVault(via string, now time.Time) error {
	// Marked right after the handler returns (outside the feature's lock),
	// in the same batch and flush (afterHandle).
	h.m.deleteRequest = via
	return nil
}

// Deleting reports whether a deletion has started (tests, hosts).
func (m *Manager) Deleting() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.st != nil && m.st.Deleting != nil
}

// beginDelete is step 1. It is idempotent.
func (m *Manager) beginDelete(via string, now time.Time) {
	if m.st == nil {
		return
	}
	if m.st.Deleting != nil {
		// Already marked in the state (0.51.0, §12.5): a marking flush
		// that stored the state and perhaps not the header. Step 1 is
		// completed from here (the header, then the host's mark) and
		// steps 2 to 5 follow; what the first run destroyed and queued is
		// in the stored state.
		m.hdr.Deleting = true
		m.deletePending = true
		return
	}
	// Release R (§11.14.3, §12.5): the recovery generation is closed at
	// the counter before anything is erased; the deletion goes ahead
	// whether or not the close was confirmed, and the audit says which.
	if g := m.hdr.Rec.Generation; g > 0 {
		ref := strconv.FormatUint(g, 10) + "/delete"
		if c := m.counter(); c != nil && c.Close(context.Background(), g) == nil {
			m.record(Activity{Kind: "recovery.generation_closed", Ref: ref, Audit: true}, now)
		} else {
			m.record(Activity{Kind: "recovery.generation_closed", Ref: ref + "/unconfirmed", Audit: true}, now)
		}
	}
	m.st.Deleting = &Deletion{At: now.UTC(), Via: via}
	m.hdr.Deleting = true
	m.deletePending = true
	sess := m.session(now)
	for _, f := range m.features {
		if d, ok := f.(VaultDeleting); ok {
			d.VaultDeleting(sess)
		}
	}
	if m.st.Transfer != nil {
		m.st.Transfer = nil
	}
	for _, p := range m.st.Connections {
		if p.State == PeerActive {
			m.sendTo(p, peerwire.TypeConnectionRemoved, peerwire.ConnectionRemovedBody(), now)
		}
	}
	notice := strictjson.NewBuilder().String("reason", "vault_deleted").Bytes()
	for _, p := range m.st.Devices {
		if p.State == PeerActive {
			m.sendTo(p, "device.unlinked", notice, now)
		}
	}
	for i := range m.st.Issued {
		t := &m.st.Issued[i]
		if !t.Denied {
			t.Denied = true
			m.queueRevoke("jti", t.JTI, now)
		}
	}
	for _, p := range m.allPeers() {
		if p.Relay.PK != nil {
			m.denySubOnly(p, now)
		}
	}
	for id, inv := range m.st.Invites {
		if !inv.Used && inv.ClaimID != "" {
			m.queueDeleteClaim(inv.ClaimID, now)
		}
		delete(m.st.Invites, id)
	}
	m.dirty = true
}

// denySubOnly queues a sub revocation without touching the records.
func (m *Manager) denySubOnly(p *Peer, now time.Time) {
	m.queueRevoke("sub", relayauth.EncodeKey(p.Relay.PK), now)
}

// Retry schedules of a deletion (0.51.0, §12.5; VAULT-HOST-PROTOCOL §5.6,
// §9): from 1 s, doubling to 15 s, for 2 minutes in all for the host's
// mark and 60 s for a store error of step 4.
const (
	deleteRetryFirst = time.Second
	deleteRetryCap   = 15 * time.Second
	markDeletingFor  = 2 * time.Minute
	eraseRetryFor    = 60 * time.Second
)

// DeleteRetry overrides a deletion's retry schedules (tests); a zero field
// keeps its default.
type DeleteRetry struct {
	First, Cap  time.Duration
	Mark, Erase time.Duration
}

func (m *Manager) deleteRetry() DeleteRetry {
	r := DeleteRetry{First: deleteRetryFirst, Cap: deleteRetryCap, Mark: markDeletingFor, Erase: eraseRetryFor}
	if o := m.opt.DeleteRetry; o != nil {
		for _, f := range []struct{ to, from *time.Duration }{{&r.First, &o.First}, {&r.Cap, &o.Cap}, {&r.Mark, &o.Mark}, {&r.Erase, &o.Erase}} {
			if *f.from != 0 {
				*f.to = *f.from
			}
		}
	}
	return r
}

// retryFor calls fn until it succeeds or budget has passed since the first
// call, waiting first, then twice as long each time up to most, between
// calls. Every call's context ends with the budget. It returns the last
// error.
func retryFor(ctx context.Context, budget, first, most time.Duration, fn func(ctx context.Context) error) error {
	deadline := time.Now().Add(budget)
	wait := first
	for {
		cctx, cancel := context.WithDeadline(ctx, deadline)
		err := fn(cctx)
		cancel()
		if err == nil {
			return nil
		}
		left := time.Until(deadline)
		if left <= 0 || ctx.Err() != nil {
			return err
		}
		if !sleep(ctx, min(wait, left)) || time.Until(deadline) <= 0 {
			return err
		}
		wait = min(2*wait, most)
	}
}

// holdForMark reports whether the outbox and the relay mailbox are held
// (0.51.0, P19): a deletion is marked in the state and its step 1 has not
// been completed (the header's mark and the host's ok, completeMark).
// Every path that delivers checks it, not only the deletion's own: a
// marking flush that failed leaves the notices and the requester's answer
// queued in a vault that may still run (the queue op account, the
// attachment runner, a push wake, a rotation).
func (m *Manager) holdForMark() bool {
	return m.st != nil && m.st.Deleting != nil && !m.markOK
}

// NoHostMark is Options.MarkDeleting for a vault that has no host to
// record its deletion (development, tests): it answers ok at once. Without
// any MarkDeleting a deletion is never recorded and the vault ends locked
// (fail closed).
func NoHostMark(context.Context, string) error { return nil }

// errNoMarkDeleting: Options.MarkDeleting is not set.
var errNoMarkDeleting = errors.New("vault: no MarkDeleting")

// ErrNotMarked reports a deletion whose step 1 could not be completed: the
// header's mark was not written, or the parent gave no ok to MarkDeleting
// within its 2 minutes (0.51.0, §12.5). The vault is locked with the mark
// stored where it was, and nothing of step 2 has left.
var ErrNotMarked = errors.New("vault: deletion not recorded at the host; locked")

// completeMark completes step 1 after the marking flush (0.51.0, §12.5):
// the header records Deleting (the flush may have stored the state alone,
// §13.2), then the parent records the deletion on the vault row
// (MarkDeleting, VAULT-HOST-PROTOCOL §5.6), retried for 2 minutes. Only
// then may step 2 begin: no device hears vault_deleted before the member
// API can finish the deletion without it (P19).
func (m *Manager) completeMark(ctx context.Context) error {
	if !m.markStored {
		if m.hdr.StateSeq < m.st.StateSeq {
			m.hdr.StateSeq = m.st.StateSeq
		}
		if err := m.writeHeader(ctx); err != nil {
			if errors.Is(err, ErrSplitBrain) {
				return err
			}
			return ErrNotMarked
		}
		if !m.markStored {
			return ErrNotMarked
		}
	}
	mark := m.opt.MarkDeleting
	if mark == nil {
		mark = func(context.Context, string) error { return errNoMarkDeleting } // fail closed
	}
	r := m.deleteRetry()
	vid := m.st.VaultID
	if err := retryFor(ctx, r.Mark, r.First, r.Cap, func(ctx context.Context) error { return mark(ctx, vid) }); err != nil {
		return ErrNotMarked
	}
	m.markOK = true
	return nil
}

// Step 2's bounds (0.51.0): it gets at most step2For, and inside a caller's
// deadline (a vault process's open or lock, which its supervisor bounds)
// it runs only with step2Least left, so that the bound cannot end the
// process in the middle of the notices. A step 2 that does not run is the
// crash between steps 1 and 2 of §12.5: the deletion still converges.
const (
	step2For   = 60 * time.Second
	step2Least = 10 * time.Second
)

// step2Context is step 2's context, or nil when step 2 is skipped.
func step2Context(ctx context.Context) (context.Context, context.CancelFunc) {
	end := time.Now().Add(step2For)
	if d, ok := ctx.Deadline(); ok {
		if time.Until(d) < step2Least {
			return nil, nil
		}
		if d.Before(end) {
			end = d
		}
	}
	return context.WithDeadline(ctx, end)
}

// finishDelete completes step 1 (completeMark) and runs steps 2–5 after the
// marking flush. It returns nil once the vault is gone (or another writer
// took it, ErrSplitBrain). Without the host's mark it locks the vault,
// reports `locked` and returns ErrNotMarked; after a step 4 that failed
// for 60 s it returns that error without reporting.
func (m *Manager) finishDelete(ctx context.Context) error {
	if err := m.completeMark(ctx); err != nil {
		if errors.Is(err, ErrSplitBrain) {
			return err // zeroized by the conflicting write
		}
		vid := m.st.VaultID
		m.zeroize()
		m.report("locked", vid, m.opt.Release.PCR0)
		return err
	}
	if m.relay != nil {
		if sctx, cancel := step2Context(ctx); sctx != nil {
			m.deleteMailbox(sctx)
			m.drainOutbox(sctx)
			cancel()
		}
	}
	vid, guid := m.st.VaultID, m.st.UserGUID
	releases := []string{}
	if mv := m.st.ReleaseMove; mv != nil {
		releases = append(releases, mv.To, mv.From)
	}
	if m.st.SealedRelease != "" {
		releases = append(releases, m.st.SealedRelease)
	}
	own := m.hdr.SealedRelease
	stateVer, headerVer := m.stateVer, m.headerVer
	// §12.5 step 3 (0.32.0): the store key and recorded version of every
	// attachment object, taken before the keys go (no key material).
	atts := m.attObjects()
	m.zeroize()
	// A write of the runner already under way lands before the erase (it
	// cannot land after it, nor after the parent's sweep saw the prefix
	// empty); none starts once the vault is locked.
	m.attWaitWrites(attWriteWait)
	// Step 4: the attachment objects first, each at its recorded version,
	// then the state and the headers. What an erase without the index
	// misses, the parent sweeps after `deleted` (P15). Every delete is
	// idempotent, so a store error repeats the whole step (0.51.0: for up
	// to 60 s; then the member API's resume finishes it).
	r := m.deleteRetry()
	err := retryFor(ctx, r.Erase, r.First, r.Cap, func(ctx context.Context) error {
		for _, o := range atts {
			if err := deleteStored(ctx, m.opt.Store, o.Key, o.Ver); err != nil {
				return err
			}
		}
		return EraseStored(ctx, m.opt.Store, vid, guid, releases, own, stateVer, headerVer)
	})
	if err != nil {
		return err
	}
	m.report("deleted", vid, m.opt.Release.PCR0)
	return nil
}

// finishMarked handles a stored state that records Deleting, found by an
// unlock or a recovery's open (0.51.0, §12.5 "A state that records
// deleting never runs"): the vault is not started. Step 1 is completed
// (the header records Deleting, then the host's mark) and steps 2 to 5 run
// with the keys the state holds, so the notices and the mailbox deletion
// still happen. Nothing reports `unlocked`; the caller answers as for a
// missing vault. The manager is locked afterwards.
func (m *Manager) finishMarked(ctx context.Context) {
	m.beginDelete("", m.now())
	m.deletePending = false
	if err := m.loadKeys(); err == nil && m.opt.Relay != nil {
		m.relay = m.opt.Relay(m.st.Relay.URL, m.keys.relay)
	}
	_ = m.finishDelete(ctx)
	if !m.locked {
		m.zeroize()
	}
}

// deleteMailbox deletes the vault's relay mailbox (step 2), once: the relay
// key exists only until step 3, and after a crash the convergence path
// (an unlock or recovery that finds the marker) has no key to sign with,
// so the mailbox then stays, as on a relay before 0.5.0. The request is
// idempotent at the relay. On success every queued revocation and claim
// deletion is done: they concerned this mailbox, which no longer exists.
func (m *Manager) deleteMailbox(ctx context.Context) {
	if m.holdForMark() {
		return
	}
	if err := m.relay.DeleteMailbox(ctx); err != nil {
		return // the revocations and claim deletions remain the fallback
	}
	for _, e := range m.st.Outbox {
		if e.Op == OpRevoke || e.Op == OpDeleteClaim {
			e.Done = true
		}
	}
	m.dirty = true
}

// UserIndexHash is the store key component of a member's index object
// (§11.5): hex SHA-256("vettid/vms/2/user" || 0x00 || user_guid).
func UserIndexHash(userGUID string) string {
	h := sha256.Sum256([]byte("vettid/vms/2/user\x00" + userGUID))
	return hex.EncodeToString(h[:])
}

// EraseStored is step 4: it deletes the vault's state, the headers of the
// given releases (own last) and the member index if it still names this
// vault. Versions from a running vault make the deletes conditional on
// them; a missing object counts as deleted. It is idempotent.
func EraseStored(ctx context.Context, st store.Store, vaultID, userGUID string, releases []string, own string,
	stateVer, headerVer store.Version) error {
	del := func(key string, ver store.Version) error {
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
			// Written since: delete what is there now (a deletion wins).
			_, v, gerr := st.Get(ctx, key)
			if errors.Is(gerr, store.ErrNotFound) {
				return nil
			}
			if gerr != nil {
				return gerr
			}
			return st.Delete(ctx, key, v)
		}
		return err
	}
	if err := del(store.StateKey(vaultID), stateVer); err != nil {
		return err
	}
	seen := map[string]bool{own: true}
	for _, r := range releases {
		if r == "" || seen[r] {
			continue
		}
		seen[r] = true
		if err := del(store.HeaderKey(vaultID, r), ""); err != nil {
			return err
		}
	}
	if own != "" {
		if err := del(store.HeaderKey(vaultID, own), headerVer); err != nil {
			return err
		}
	}
	if userGUID != "" {
		k := store.UserKey(UserIndexHash(userGUID))
		if b, v, err := st.Get(ctx, k); err == nil && string(b) == vaultID {
			if err := del(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrDeleted reports a vault whose header records a deletion: it was
// finished instead of opened.
var ErrDeleted = errors.New("vault: deleted")

// Outcomes of ResumeDelete (0.51.0, §12.5 "Without the app: the resume"),
// for the enclave's log. Only ResumeFinished and ResumeErased are
// reported `deleted`.
const (
	// ResumeFinished: the release's own header records Deleting; step 4
	// ran as for a header that records it.
	ResumeFinished = "finished"
	// ResumeErased: neither that header nor the state exists; the member
	// index was erased if it still named the vault (an erase that ran and
	// was not reported).
	ResumeErased = "erased"
	// ResumeLive: the header records no deletion. Nothing is touched.
	ResumeLive = "live"
	// ResumeState: no header for this release but a state object (the
	// vault may live under another release). Nothing is touched.
	ResumeState = "state"
	// ResumeUnreadable: the header (or whether one exists) could not be
	// read. Nothing is touched.
	ResumeUnreadable = "unreadable"
	// ResumeFailed: an erase that a resume may do failed; the next resume
	// tries again. Not reported.
	ResumeFailed = "erase_failed"
)

// ResumeDelete is the enclave's side of the queue operation delete_resume
// (0.51.0, §12.5, VAULT-HOST-PROTOCOL §6.1) for a vault that does not run
// on the instance (the caller checks that first). It decides from what it
// can read alone: the message is not an authority to delete (P20). It
// erases only a vault whose header sealed to release, unsealed here,
// records Deleting (a deletion the vault itself authorised and began), or
// whose header and state are both gone. userGUID is the queue message's,
// used only where there is no header to name the member, and then only
// for an index object that names this vault. The caller reports `deleted`
// for ResumeFinished and ResumeErased.
func ResumeDelete(ctx context.Context, st store.Store, s Sealer, release, vaultID, userGUID string) string {
	hkey, skey := store.HeaderKey(vaultID, release), store.StateKey(vaultID)
	if !store.ValidKey(hkey) || !store.ValidKey(skey) {
		return ResumeUnreadable
	}
	blob, _, err := st.Get(ctx, hkey)
	if errors.Is(err, store.ErrNotFound) {
		switch _, _, serr := st.Get(ctx, skey); {
		case serr == nil:
			return ResumeState
		case !errors.Is(serr, store.ErrNotFound):
			return ResumeUnreadable
		}
		if eraseIndex(ctx, st, vaultID, userGUID) != nil {
			return ResumeFailed
		}
		return ResumeErased
	}
	if err != nil {
		return ResumeUnreadable
	}
	h, err := PeekHeader(ctx, s, blob, vaultID, release)
	if err != nil {
		return ResumeUnreadable
	}
	if !h.Deleting {
		return ResumeLive
	}
	// As an unlock that finds the marker does (DEK-less: its own release's
	// header, last; the parent sweeps the attachment objects after
	// `deleted`, P15).
	if EraseStored(ctx, st, vaultID, h.UserGUID, nil, release, "", "") != nil {
		return ResumeFailed
	}
	return ResumeFinished
}

// eraseIndex deletes the member index object of userGUID if it names
// vaultID; a missing object counts as deleted.
func eraseIndex(ctx context.Context, st store.Store, vaultID, userGUID string) error {
	if userGUID == "" {
		return nil
	}
	k := store.UserKey(UserIndexHash(userGUID))
	if !store.ValidKey(k) {
		return nil
	}
	b, v, err := st.Get(ctx, k)
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if string(b) != vaultID {
		return nil
	}
	if err := st.Delete(ctx, k, v); err != nil && !errors.Is(err, store.ErrNotFound) {
		return err // a conflict: written since; the next resume reads it again
	}
	return nil
}
