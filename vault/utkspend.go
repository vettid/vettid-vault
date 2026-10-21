package vault

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// Spend first and the one live holder (VAULT-MESSAGING 0.52.0; owner
// decisions of 2026-10-20): a request spends the UTK it presents before
// anything else is checked, a refusal included (§3.5.4 "Using a UTK");
// the credential's holder is none or exactly one live app, and a vault
// with a credential but no holder answers credential_required with body
// {"reason": "no_holder"} (§3.5.7, §3.5.9, §10.1).

// UTKSpender is implemented by the credential feature (§3.5.4, 0.52.0).
// The runtime calls SpendPresentedUTK for every request it will answer,
// before its checks of the request (the shape, credential_required,
// owner_check_required, forbidden, session_required, LEASH), and
// EndPresentedUTK when the request is done.
type UTKSpender interface {
	// SpendPresentedUTK removes from the pool of deviceID the UTK that
	// body's top-level utk_id names, when body parses as a JSON object
	// and the id reads as a UTK id; otherwise it removes nothing. The
	// removed key stays with the request (deviceID and the inner id
	// msgID), in memory only, for the handler to open the payload with.
	// It reports whether a UTK was removed (the pool changed).
	SpendPresentedUTK(deviceID, msgID string, body json.RawMessage, now time.Time) bool
	// EndPresentedUTK wipes the key of a UTK spent for the request that
	// its handler did not use.
	EndPresentedUTK()
}

// CredentialHolder is implemented by the credential feature: the device id
// its state records as the holder ("" for none, §3.5.9).
type CredentialHolder interface {
	CredentialHolder() string
}

// HolderPruner is implemented by the credential feature: ClearDeadHolder
// clears a holder for which live reports false (§3.5.9, 0.52.0) and
// returns the device id it cleared ("" when it cleared none).
type HolderPruner interface {
	ClearDeadHolder(live func(deviceID string) bool) string
}

// NoHolderBody is the body of credential_required from a vault with a
// credential but no holder (§3.5.7, §3.5.9, §10.1; 0.52.0). A vault
// without a credential sends no body.
var NoHolderBody = json.RawMessage(`{"reason":"no_holder"}`)

// NoHolderError is credential_required{reason: "no_holder"}.
func NoHolderError() error {
	return &HandlerError{Code: "credential_required", Body: NoHolderBody}
}

// spendPresented spends the UTK a request presents (§3.5.4, 0.52.0).
func (m *Manager) spendPresented(p *Peer, in *envelope.Inner, now time.Time) {
	for _, f := range m.features {
		if sp, ok := f.(UTKSpender); ok && sp.SpendPresentedUTK(p.ID, in.ID, in.Body, now) {
			m.dirty = true // the spend is part of the batch's flush
		}
	}
}

// endPresented wipes a spent UTK's key that no handler used.
func (m *Manager) endPresented() {
	for _, f := range m.features {
		if sp, ok := f.(UTKSpender); ok {
			sp.EndPresentedUTK()
		}
	}
}

// liveApp reports whether id names a live app (§3.5.9, 0.52.0): a device
// record of role app that has completed its pairing.
func (m *Manager) liveApp(id string) bool {
	p, ok := m.st.Devices[id]
	return ok && p.Kind == KindApp && p.State != PeerPending
}

// holderLive reports whether the credential's holder, if the feature
// reports one, names a live app; true without such a feature.
func (m *Manager) holderLive() bool {
	for _, f := range m.features {
		if h, ok := f.(CredentialHolder); ok {
			return m.liveApp(h.CredentialHolder())
		}
	}
	return true
}

// clearDeadHolder runs when the state is loaded (an unlock, a resume, a
// move to another release, a recovery's open): a holder that names no
// live app is cleared, so that a vault an earlier release left with a
// holder naming a removed device is a vault without a holder (§3.5.9,
// 0.52.0). Since a removal clears the holder with its device, a hit
// points to a fault or to tampering: it is audited
// credential.holder_cleared (device_id = the cleared holder, no ref;
// History only, no feed item; 0.54.0), in the same flush.
func (m *Manager) clearDeadHolder() {
	for _, f := range m.features {
		hp, ok := f.(HolderPruner)
		if !ok {
			continue
		}
		if id := hp.ClearDeadHolder(m.liveApp); id != "" {
			m.dirty = true
			m.record(Activity{Kind: AuditHolderCleared, DeviceID: id, Audit: true}, m.now())
		}
	}
}

// AuditHolderCleared is the audit kind of a holder cleared at load
// (§3.5.9, §10.9; 0.54.0).
const AuditHolderCleared = "credential.holder_cleared"

// TimeScaleHost is implemented by hosts that run under the staging time
// scale (§11.10.8). The Manager implements it.
type TimeScaleHost interface {
	TimeScale() uint64
}

// TimeScale returns the running release's time scale: 1 on a host
// without one. Features scale with it only the waits the spec scales
// (the UTK resync, §3.5.4, 0.52.0).
func (s *Session) TimeScale() uint64 {
	if h, ok := s.host.(TimeScaleHost); ok {
		if n := h.TimeScale(); n > 1 {
			return n
		}
	}
	return 1
}

func (h managerHost) TimeScale() uint64 { return h.m.opt.timeScale() }
