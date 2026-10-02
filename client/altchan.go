package client

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/nitro"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Alternate-channel errors (§11.2, §11.10.6).
var (
	ErrEnclave       = errors.New("client: enclave attestation not acceptable")
	ErrRollbackRel   = errors.New("client: refusing to send a PIN to an older release")
	ErrManifestOlder = errors.New("client: manifest older than one already seen")
	ErrNoPending     = errors.New("client: no pending request")
	ErrResult        = errors.New("client: result unreadable")
)

// Attester is the app's hardware attestation key (§11.7): Android
// Keystore or App Attest. Tests use internal/enclavetest.
type Attester interface {
	Platform() string
	Attest(challenge [32]byte) (*altchan.DeviceAttest, error)
	Assert(s devattest.Signed) (*altchan.DeviceAssertion, error)
}

// Trust is what an app pins (§11.2, §11.10.1): the AWS Nitro root and the
// manifest public keys.
type Trust struct {
	NitroRoots   *x509.CertPool
	ManifestKeys []*ecdsa.PublicKey
}

// Attestation freshness (§11.2 step 3).
const (
	MaxAttestationAge = 26 * time.Hour
	attestationSkew   = 5 * time.Minute
)

// Enclave is a verified enclave instance (§11.2).
type Enclave struct {
	Descriptor   *altchan.Descriptor
	Measurements nitro.Measurements
	Release      manifest.Release
}

// VerifyManifest verifies a served manifest (§11.10.1) and the serial rule
// against the highest serial this device has seen for its vault.
func (d *Device) VerifyManifest(served []byte, t Trust) (*manifest.Served, *manifest.Manifest, error) {
	s, err := manifest.ParseServed(served)
	if err != nil {
		return nil, nil, err
	}
	m, err := manifest.Verify(s, t.ManifestKeys)
	if err != nil {
		return nil, nil, err
	}
	d.mu.Lock()
	seen := uint64(0)
	if d.st.Alt != nil {
		seen = d.st.Alt.ManifestSerial
	}
	d.mu.Unlock()
	if m.Serial < seen {
		return nil, nil, ErrManifestOlder
	}
	return s, m, nil
}

// VerifyEnclave checks an ETK descriptor and its attestation document
// (§11.2): the chain to the pinned Nitro root, PCR0-2 equal to a manifest
// entry (an active one to enroll), no debug PCRs, user_data over the exact
// descriptor bytes, release = PCR0, not_after in the future and at most
// 24 h after the attestation, and an attestation less than 26 h old.
func VerifyEnclave(desc, att []byte, m *manifest.Manifest, enroll bool, t Trust, now time.Time) (*Enclave, error) {
	ds, err := altchan.ParseDescriptor(desc)
	if err != nil {
		return nil, ErrEnclave
	}
	doc, err := nitro.Verify(att, t.NitroRoots)
	if err != nil {
		return nil, ErrEnclave
	}
	ud := altchan.ETKUserData(desc)
	if doc.CheckUserData(ud[:]) != nil || doc.CheckFresh(now, MaxAttestationAge, attestationSkew) != nil {
		return nil, ErrEnclave
	}
	ms := doc.Measurements()
	if ms.IsDebug() || ms.PCR0 != ds.Release {
		return nil, ErrEnclave
	}
	if !now.Before(ds.NotAfter) || ds.NotAfter.After(doc.Timestamp.Add(24*time.Hour+time.Second)) {
		return nil, ErrEnclave
	}
	e, ok := m.ByPCR0(ms.PCR0)
	if !ok || !(nitro.Measurements{PCR0: e.PCR0, PCR1: e.PCR1, PCR2: e.PCR2}).Equal(ms) {
		return nil, ErrEnclave
	}
	if enroll && e.Status != manifest.StatusActive {
		return nil, ErrEnclave
	}
	return &Enclave{Descriptor: ds, Measurements: ms, Release: *e}, nil
}

// AltState is what the app stores per vault for the alternate channel
// (§11.3 "App state", §11.10.6, §13.2).
type AltState struct {
	// Release the vault last unlocked into (PCR0, number).
	Release       string `json:"release,omitempty"`
	ReleaseNumber uint64 `json:"release_number,omitempty"`
	// PreviousRelease is the release before an unconfirmed move, kept
	// so the app can abandon the move (§11.10.4).
	PreviousRelease       string `json:"previous_release,omitempty"`
	PreviousReleaseNumber uint64 `json:"previous_release_number,omitempty"`
	ManifestSerial        uint64 `json:"manifest_serial"`
	StateSeq              uint64 `json:"state_seq"`
	// HeaderSeq is the highest header_seq seen per release: each release
	// has its own header object (§11.10.2).
	HeaderSeq map[string]uint64 `json:"header_seq"`
	// Pending enrollment: the nonce and measurements vault.enrolled must
	// carry.
	EnrollNonce  []byte `json:"enroll_nonce,omitempty"`
	EnrollPCRs   string `json:"enroll_pcrs,omitempty"`
	EnrollNumber uint64 `json:"enroll_number,omitempty"`
}

func (d *Device) alt() *AltState {
	if d.st.Alt == nil {
		d.st.Alt = &AltState{}
	}
	if d.st.Alt.HeaderSeq == nil {
		d.st.Alt.HeaderSeq = map[string]uint64{}
	}
	return d.st.Alt
}

// Alt returns a copy of the alternate-channel state.
func (d *Device) Alt() AltState {
	d.mu.Lock()
	defer d.mu.Unlock()
	a := *d.alt()
	a.HeaderSeq = map[string]uint64{}
	for k, v := range d.st.Alt.HeaderSeq {
		a.HeaderSeq[k] = v
	}
	return a
}

// Request is a sealed request ready to post (§11.3, §11.4).
type Request struct {
	RequestID string
	ETKKid    string
	Envelope  []byte
	// ReleaseChanged is set when the routed release differs from the one
	// the app last unlocked into: the app tells the user before it sends
	// the PIN (§11.2 step 4).
	ReleaseChanged bool
}

// BuildEnroll builds a vault.enroll request sealed to the enclave's ETK
// (§11.3), attesting a fresh device key with the request's challenge.
func (d *Device) BuildEnroll(userGUID, pin string, e *Enclave, served *manifest.Served, att Attester) (*Request, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.cfg.Now()
	rid, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	ts := now.UTC().Truncate(time.Millisecond)
	ch, err := altchan.DevattChallenge(rid, "", envelope.FormatTS(ts))
	if err != nil {
		return nil, err
	}
	da, err := att.Attest(ch)
	if err != nil {
		return nil, err
	}
	open, err := d.own.MintOpenToken(d.st.RelayURL, 10*time.Minute, "")
	if err != nil {
		return nil, err
	}
	nonce, err := suite.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	ra := d.RelayAddr()
	body, err := (&altchan.EnrollRequest{UserGUID: userGUID, RequestID: rid, Nonce: nonce, PIN: pin,
		IK: d.IdentityKey(), KEM: d.kem.Public(), Relay: altchan.RelayAddr{URL: ra.URL, Mailbox: ra.Mailbox, PK: ra.PK},
		OpenToken: open, Name: d.st.Name, Attest: da, Manifest: served}).Marshal()
	if err != nil {
		return nil, err
	}
	env, err := altchan.SealRequest(e.Descriptor.ETK, altchan.TypeEnroll, rid, ts, body)
	if err != nil {
		return nil, err
	}
	a := d.alt()
	a.EnrollNonce = nonce
	a.EnrollPCRs = e.Measurements.PCR0 + e.Measurements.PCR1 + e.Measurements.PCR2
	a.EnrollNumber = e.Release.Number
	return &Request{RequestID: rid, ETKKid: e.Descriptor.Kid.String(), Envelope: env}, nil
}

// OpenEnrollResult reads vault.enroll.result from the response slot.
func (d *Device) OpenEnrollResult(raw []byte, requestID string) (*altchan.EnrollResult, error) {
	body, err := altchan.OpenResult(raw, d.kem, altchan.TypeEnrollResult, requestID)
	if err != nil {
		return nil, ErrResult
	}
	return altchan.ParseEnrollResult(body)
}

// Approval is a member-approved release update (§11.10.3).
type Approval struct {
	To        string // target PCR0
	ToRelease uint64
}

// UnlockOptions select the less common unlock paths.
type UnlockOptions struct {
	Approve *Approval
	// Abandon returns to the previous release before the newer one has
	// run the vault (§11.10.4): the request goes to the previous release
	// and approves it as its own target.
	Abandon bool
}

// pendingUnlock is kept between BuildUnlock and OpenUnlockResult.
type pendingUnlock struct {
	requestID string
	release   string
	number    uint64
	serial    uint64
	toNumber  uint64 // the approved target's release number
}

// BuildUnlock builds a vault.unlock request (§11.4) for the enclave e:
// rollback minimums, a fresh token for this device's mailbox, the device
// assertion over the challenge, the manifest, an optional release
// approval, and the Ed25519 signature by this app's identity key.
func (d *Device) BuildUnlock(userGUID, pin string, e *Enclave, served *manifest.Served, m *manifest.Manifest, att Attester, o UnlockOptions) (*Request, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Vault == nil || d.st.VaultID == "" {
		return nil, ErrNotPaired
	}
	a := d.alt()
	if m.Serial < a.ManifestSerial {
		return nil, ErrManifestOlder
	}
	changed := a.Release != "" && a.Release != e.Release.PCR0
	if a.ReleaseNumber != 0 && e.Release.Number < a.ReleaseNumber {
		// Never send a PIN to an older release than the last one unlocked
		// into (§11.10.6), except to abandon an unconfirmed move to it.
		if !o.Abandon || e.Release.PCR0 != a.PreviousRelease {
			return nil, ErrRollbackRel
		}
	}
	now := d.cfg.Now()
	rid, err := envelope.NewULID(now)
	if err != nil {
		return nil, err
	}
	ts := now.UTC().Truncate(time.Millisecond)
	tss := envelope.FormatTS(ts)
	ch, err := altchan.DevattChallenge(rid, d.st.VaultID, tss)
	if err != nil {
		return nil, err
	}
	tok, err := d.mintForVault()
	if err != nil {
		return nil, err
	}
	as, err := att.Assert(devattest.ForChallenge(ch))
	if err != nil {
		return nil, err
	}
	var upd *altchan.ReleaseUpdate
	switch {
	case o.Abandon:
		upd = &altchan.ReleaseUpdate{To: e.Release.PCR0, ToRelease: e.Release.Number}
	case o.Approve != nil:
		upd = &altchan.ReleaseUpdate{To: o.Approve.To, ToRelease: o.Approve.ToRelease}
	}
	toPCR0 := ""
	if upd != nil {
		s, err := altchan.ApprovalSigningString(d.st.VaultID, rid, e.Release.PCR0, upd.To, upd.ToRelease, m.Serial)
		if err != nil {
			return nil, err
		}
		if upd.Approval, err = att.Assert(devattest.ForString(s)); err != nil {
			return nil, err
		}
		toPCR0 = upd.To
	}
	req := &altchan.UnlockRequest{UserGUID: userGUID, VaultID: d.st.VaultID, RequestID: rid, DeviceIK: d.IdentityKey(),
		PIN: pin, MinStateSeq: a.StateSeq, MinHeaderSeq: a.HeaderSeq[e.Release.PCR0], Token: tok, Assertion: as,
		Manifest: served, Update: upd}
	ss, err := altchan.UnlockSigningString(altchan.UnlockFields{UserGUID: userGUID, VaultID: d.st.VaultID, RequestID: rid,
		TS: tss, ETKKid: e.Descriptor.Kid, MinStateSeq: req.MinStateSeq, MinHeaderSeq: req.MinHeaderSeq, PIN: pin,
		Token: tok, Manifest: served.Manifest, ToPCR0: toPCR0})
	if err != nil {
		return nil, err
	}
	req.Sig = ed25519.Sign(d.ik, []byte(ss))
	body, err := req.Marshal()
	if err != nil {
		return nil, err
	}
	env, err := altchan.SealRequest(e.Descriptor.ETK, altchan.TypeUnlock, rid, ts, body)
	if err != nil {
		return nil, err
	}
	d.pending = &pendingUnlock{requestID: rid, release: e.Release.PCR0, number: e.Release.Number, serial: m.Serial}
	if upd != nil {
		d.pending.toNumber = upd.ToRelease
	}
	return &Request{RequestID: rid, ETKKid: e.Descriptor.Kid.String(), Envelope: env, ReleaseChanged: changed}, nil
}

// OpenUnlockResult reads vault.unlock.result (§11.4) and records the
// sequence numbers, release and token it carries. On state_rollback the
// app MUST warn the user (§13.2).
func (d *Device) OpenUnlockResult(raw []byte) (*altchan.UnlockResult, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.pending
	if p == nil {
		return nil, ErrNoPending
	}
	body, err := altchan.OpenResult(raw, d.kem, altchan.TypeUnlockResult, p.requestID)
	if err != nil {
		return nil, ErrResult
	}
	r, err := altchan.ParseUnlockResult(body)
	if err != nil {
		return nil, err
	}
	d.pending = nil
	a := d.alt()
	if !r.OK {
		if r.HeaderSeq > a.HeaderSeq[p.release] {
			a.HeaderSeq[p.release] = r.HeaderSeq
		}
		return r, nil
	}
	if r.Release != p.release || r.ReleaseNumber != p.number {
		return nil, ErrResult // a result from another release than the attested one
	}
	if r.StateSeq > a.StateSeq {
		a.StateSeq = r.StateSeq
	}
	if r.ManifestSerial > a.ManifestSerial {
		a.ManifestSerial = r.ManifestSerial
	}
	release, number := r.Release, r.ReleaseNumber
	if u := r.Update; u != nil {
		switch u.Result {
		case "moved":
			// header_seq is the new release's header (§11.4); keep this
			// release's for an abandonment.
			a.PreviousRelease, a.PreviousReleaseNumber = r.Release, r.ReleaseNumber
			release, number = u.To, p.toNumber
		case "abandoned":
			a.PreviousRelease, a.PreviousReleaseNumber = "", 0
		}
	}
	if r.HeaderSeq > a.HeaderSeq[release] {
		a.HeaderSeq[release] = r.HeaderSeq
	}
	a.Release = release
	if number != 0 {
		a.ReleaseNumber = number
	}
	if r.Token != "" && d.st.Vault != nil {
		if exp, err := d.heldFromVault(r.Token); err == nil && exp.After(d.st.Vault.TokenExp) {
			d.st.Vault.Token, d.st.Vault.TokenExp = r.Token, exp
		}
	}
	return r, nil
}
