package vault

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Signer binding (VAULT-MESSAGING 0.27.0 §11.7.1, Android). The enclave
// records the signing-certificate digest of an app's attestation in the
// device binding, beside the attested key, in the sealed header. The
// vault has one app, and the vault's signer binding is the signer
// recorded for that app's key. This file is the runtime's side: reading
// the signer out of a binding (which is otherwise opaque here), the
// refusal at unlock, the transfer's confirmation, the audit entries and
// what device.list reports. Verifying attestations and deciding whether a
// signer is pinned are the enclave's (package devattest).

// CodeSignerRefused is the unlock result of a key whose recorded signer
// the running release does not pin, or that has no recorded signer and
// brought no valid chain (§11.4, §11.7.1). It is sealed like every
// result, decided before the PIN is tried, and is not a PIN failure.
const CodeSignerRefused = "signer_refused"

// Signer refusal reasons: the `ref` of device.signer_refused.
const (
	SignerUnpinned = "unpinned"
	SignerUnbound  = "unbound"
)

// SignerRefused is returned by AltUnlockParams.VerifyDevice (and by an
// update's VerifyApproval) when the unlock signature and the device
// assertion verified but the key's signer does not pass §11.7.1.
type SignerRefused struct {
	Reason string // SignerUnpinned or SignerUnbound
}

func (e *SignerRefused) Error() string { return "vault: signer refused (" + e.Reason + ")" }

// SignerPin is an Android signer the running release pins: the SHA-256 of
// its certificate (64 lowercase hex digits) and its class (§11.10.8).
type SignerPin struct {
	Digest string
	Class  string
}

// Audit and feed kinds of the signer binding (§10.9, §11.7.1). None
// carries a digest.
const (
	kindSignerBound   = "device.signer_bound"   // ref: the class
	kindSignerChanged = "device.signer_changed" // device_id: the new app; ref: <old class>:<new class>
	kindSignerRefused = "device.signer_refused" // ref: unpinned or unbound; no device_id
)

// signerRefusedEvery bounds the header-log entries of refusals.
const signerRefusedEvery = 24 * time.Hour

// classUnknown names a signer whose class neither the running release
// nor the binding knows (a binding can only lack a class if it was
// written by code that did not record one).
const classUnknown = "unknown"

// bindingSigner is the part of a device binding (devattest.Binding) the
// runtime reads.
type bindingSigner struct {
	Platform    string `json:"platform"`
	Signer      string `json:"signer"`
	SignerClass string `json:"signer_class"`
}

// signerOf returns the signer recorded in an Android binding: its digest
// (64 lowercase hex digits) and the class recorded with it. Both are ""
// for an iOS binding, a binding made before 0.27.0, and no binding.
func signerOf(binding json.RawMessage) (digest, class string) {
	var b bindingSigner
	if len(binding) == 0 || json.Unmarshal(binding, &b) != nil || b.Platform != altchan.PlatformAndroid || !validDigest(b.Signer) {
		return "", ""
	}
	return b.Signer, b.SignerClass
}

func validDigest(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

func validSignerClass(c string) bool {
	return c == "vettid" || c == "google_play" || c == "development"
}

// signerClass names a signer's class: the running release's for a pinned
// signer; otherwise the class recorded with the digest (a signer a later
// release stopped pinning); otherwise "unknown".
func (o *Options) signerClass(digest, recorded string) (class string, pinned bool) {
	for _, p := range o.AndroidSigners {
		if p.Digest == digest {
			return p.Class, true
		}
	}
	if validSignerClass(recorded) {
		return recorded, false
	}
	return classUnknown, false
}

// bindingOf returns an app's device binding: the sealed header's copy,
// which is authoritative once written, or the one its handshake brought
// (a transfer's or recovery's new app before the flush that adds its
// unlock key).
func (m *Manager) bindingOf(p *Peer) json.RawMessage {
	if p == nil {
		return nil
	}
	for i := range m.hdr.UnlockKeys {
		if k := &m.hdr.UnlockKeys[i]; suite.EqualPublic(k.IK, p.IK) && len(k.Attestation) > 0 {
			return k.Attestation
		}
	}
	return p.Attestation
}

// vaultSigner is the vault's signer binding (§11.7.1): the signer
// recorded for its app's key. A recovering app is not the vault's app
// until credential.recover succeeds, so its signer does not count; `not`
// excludes a device (the new app of a completing transfer).
func (m *Manager) vaultSigner(not string) (digest, class string) {
	for _, p := range m.sortedDevices() {
		if p.Kind != KindApp || p.State != PeerActive || p.Recovering || p.ID == not {
			continue
		}
		if d, c := signerOf(m.bindingOf(p)); d != "" {
			return d, c
		}
	}
	return "", ""
}

// signerMoved audits the binding's move to a new app's signer in the
// flush that makes it the vault's app (a completed transfer or recovery):
// device.signer_bound when the vault had no recorded signer,
// device.signer_changed (audit and a feed item of priority high) when the
// digest changed, nothing when it is the same or the new app has none.
func (m *Manager) signerMoved(oldDigest, oldClass string, newApp *Peer, now time.Time) {
	nd, nc := signerOf(m.bindingOf(newApp))
	if nd == "" || nd == oldDigest {
		return
	}
	newClass, _ := m.opt.signerClass(nd, nc)
	if oldDigest == "" {
		m.record(Activity{Kind: kindSignerBound, DeviceID: newApp.ID, Ref: newClass, Audit: true}, now)
		return
	}
	was, _ := m.opt.signerClass(oldDigest, oldClass)
	m.record(Activity{Kind: kindSignerChanged, DeviceID: newApp.ID, Ref: was + ":" + newClass, Audit: true, Feed: true, Priority: "high"}, now)
}

// transferSigner describes a transfer's new app for the holder
// (device.transfer.pending, §6.7.1): the class of its signer, and whether
// its digest differs from the vault's binding. ok is false when the new
// app has no signer (iOS): the members are then absent. changed is false
// when the vault has no recorded signer; the transfer then simply binds.
func (m *Manager) transferSigner(r *Request) (class string, changed, ok bool) {
	if r == nil || r.Peer == nil {
		return "", false, false
	}
	nd, nc := signerOf(r.Peer.Attestation)
	if nd == "" {
		return "", false, false
	}
	class, _ = m.opt.signerClass(nd, nc)
	old, _ := m.vaultSigner(r.Peer.ID)
	return class, old != "" && old != nd, true
}

var errSignerUnconfirmed = &HandlerError{Code: "signer_unconfirmed"}

// confirmTransferSigner is the approval's check of §6.7.1 step 3
// (0.27.0), made before the PIN is tried: when the new app's signer
// differs from the vault's binding, the approval must name the new app's
// class. A `signer` that names anything else than the new app's class is
// refused too, changed or not: the holder confirmed something the vault
// is not about to do. Nothing is counted and the transfer stays open;
// (0.52.0) the approval's UTK is already spent (§3.5.4). An unknown transfer is left to the approval
// itself (not_found).
func (m *Manager) confirmTransferSigner(id, signer string, present bool) error {
	t := m.st.Transfer
	if t == nil || t.ID != id || t.Inbound == "" {
		return nil
	}
	class, changed, ok := m.transferSigner(m.st.Requests[t.Inbound])
	if present && (!ok || signer != class) {
		return errSignerUnconfirmed
	}
	if changed && !present {
		return errSignerUnconfirmed
	}
	return nil
}

// TransferSignerHost is the runtime's side of the approval's signer
// confirmation; the Manager implements it.
type TransferSignerHost interface {
	ConfirmTransferSigner(id, signer string, present bool) error
}

func (h managerHost) ConfirmTransferSigner(id, signer string, present bool) error {
	return h.m.confirmTransferSigner(id, signer, present)
}

// ConfirmTransferSigner checks a device.transfer.approve's `signer`
// against the transfer's new app before anything is spent (§6.7.1 step 3,
// §11.7.1): signer_unconfirmed, or nil.
func (s *Session) ConfirmTransferSigner(id, signer string, present bool) error {
	if h, ok := s.host.(TransferSignerHost); ok {
		return h.ConfirmTransferSigner(id, signer, present)
	}
	return nil
}

// signerJSON is the `signer` member of the app's device.list entry
// (§10.3): the vault's signer binding, for an Android app with a recorded
// signer. Nil otherwise (iOS, a vault not yet bound, a recovering app).
func (m *Manager) signerJSON(p *Peer) []byte {
	if p.Kind != KindApp || p.Recovering {
		return nil
	}
	d, c := signerOf(m.bindingOf(p))
	if d == "" {
		return nil
	}
	class, _ := m.opt.signerClass(d, c)
	if !validSignerClass(class) {
		return nil
	}
	return strictjson.NewBuilder().String("class", class).String("digest", d).Bytes()
}

// logSignerRefused records a refusal in the sealed header's log, at most
// once per 24 hours; it moves into the audit log at the next unlock that
// succeeds (applyRecovery). It reports whether an entry was added.
func (h *Header) logSignerRefused(now time.Time, reason string) bool {
	for _, e := range h.RecoveryLog {
		if e.Kind == kindSignerRefused && now.Sub(e.At) < signerRefusedEvery {
			return false
		}
	}
	h.logRecovery(now, kindSignerRefused, reason)
	return true
}
