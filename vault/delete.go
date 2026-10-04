package vault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault/store"
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
//  2. relay and drain: the vault's own mailbox is deleted at the relay
//     (RELAY-PROTOCOL 0.5.0 §6.10) with its messages, denylist, blobs and
//     claims; the queued revocations and claim deletions concerned that
//     mailbox and are dropped. If the deletion fails (a relay before 0.5.0
//     answers not_found) they stay queued as the fallback. Then the outbox
//     is delivered once, best effort (the notices go to the connections'
//     and devices' mailboxes, not this one).
//  3. zeroize: every key in memory is wiped and the vault is locked.
//  4. erase: the state object, then the headers of every release the vault
//     knew (its own last: it is the deletion marker), then the enclave's
//     member index, each by a conditional delete; a missing object is
//     already deleted.
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
	if m.st == nil || m.st.Deleting != nil {
		return
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
			m.sendTo(p, "connection.removed", json.RawMessage(`{}`), now)
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

// finishDelete runs steps 2–5 after the marking flush. It returns nil
// once the vault is gone (or another writer took it, ErrSplitBrain).
func (m *Manager) finishDelete(ctx context.Context) error {
	m.deleteMailbox(ctx)
	m.drainOutbox(ctx)
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
	m.zeroize()
	err := EraseStored(ctx, m.opt.Store, vid, guid, releases, own, stateVer, headerVer)
	if err != nil {
		return err
	}
	m.report("deleted", vid, m.opt.Release.PCR0)
	return nil
}

// deleteMailbox deletes the vault's relay mailbox (step 2), once: the relay
// key exists only until step 3, and after a crash the convergence path
// (an unlock or recovery that finds the marker) has no key to sign with,
// so the mailbox then stays, as on a relay before 0.5.0. The request is
// idempotent at the relay. On success every queued revocation and claim
// deletion is done: they concerned this mailbox, which no longer exists.
func (m *Manager) deleteMailbox(ctx context.Context) {
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
