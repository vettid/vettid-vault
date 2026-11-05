package handshake

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// roundTrip passes v through JSON, as the runtime's state store does.
func roundTrip[T any](t *testing.T, v T) T {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Every in-flight handshake state survives export, JSON and restore, and
// the restored halves complete the handshake.
func TestSnapshotsCompleteHandshake(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	is, err := ini.Export()
	if err != nil {
		t.Fatal(err)
	}
	ini2, err := RestoreInitiator(roundTrip(t, is), i.ik)
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := p.Export()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := RestorePending(roundTrip(t, ps))
	if err != nil {
		t.Fatal(err)
	}
	if p2.Init().Ctx != testInviteID {
		t.Fatal("restored pending differs")
	}
	resp, respEnv, err := p2.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := resp.Export()
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := RestoreResponder(roundTrip(t, rs))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ini2.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	fr, err := resp2.HandleFin(res.Fin, i.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	// Epochs and keyrings survive too.
	var k Keyring
	k.Activate(res.Epoch, t0)
	k2, err := ImportKeyring(roundTrip(t, k.Export()))
	if err != nil {
		t.Fatal(err)
	}
	if fr.SAS == "" || fr.SAS != res.SAS {
		t.Fatal("SAS after a restored responder differs")
	}
	er2, err := ImportEpoch(roundTrip(t, fr.Epoch.Export()))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := er2.Seal(&envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "test.ping", TS: t0})
	if err != nil {
		t.Fatal(err)
	}
	env, _ := envelope.Parse(raw)
	if _, _, err := k2.Open(env, t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptRekey(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ea, eb := runHandshake(t, a, b, PurposeConnection)
	cfg := initCfg(a, b, PurposeRekey)
	cfg.Current, cfg.Ctx, cfg.ResponderEK, cfg.Token, cfg.ReconnectToken = ea, "", nil, "", ""
	ini, _ := NewInitiator(cfg)
	var kb Keyring
	kb.Activate(eb, t0)
	env, _ := envelope.Parse(ini.Envelope())
	in, e, err := kb.Open(env, t0)
	if err != nil {
		t.Fatal(err)
	}
	p, err := AcceptRekey(ini.Envelope(), in, e, t0)
	if err != nil || p.Th1() != ini.Th1() {
		t.Fatalf("AcceptRekey: %v", err)
	}
}

// An initiator is restored only with the identity key its hs.init named:
// after the initiator's ik rotated, hs.fin signed with the new key would
// not verify at the responder (§3.4).
func TestRestoreInitiatorOtherIdentity(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	is, err := ini.Export()
	if err != nil {
		t.Fatal(err)
	}
	other := newParty(t, 0x30)
	if _, err := RestoreInitiator(roundTrip(t, is), other.ik); !errors.Is(err, ErrIdentity) {
		t.Fatalf("restored under another identity: %v", err)
	}
	if _, err := RestoreInitiator(roundTrip(t, is), i.ik); err != nil {
		t.Fatal(err)
	}
}

// A verify-only initiator holds no identity key: it verifies the hs.resp
// (a bad sig_R aborts it as any other) and returns the responder's inner
// message, but signs nothing: no hs.fin (§6.6, the evidence of a replaced
// line's rekey kept across a rotation).
func TestRestoreInitiatorVerifyOnly(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	is, err := ini.Export()
	if err != nil {
		t.Fatal(err)
	}
	vo, err := RestoreInitiatorVerifyOnly(roundTrip(t, is))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vo.Export(); err != nil {
		t.Fatalf("a verify-only initiator is stored again: %v", err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	_, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	res, err := vo.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Epoch.Destroy()
	if res.Fin != nil || res.Inner == nil || res.Inner.Type != TypeResp {
		t.Fatalf("fin %d bytes, inner %+v", len(res.Fin), res.Inner)
	}
	// A responder under another identity: sig_R does not verify.
	other := newParty(t, 0x30)
	vo2, err := RestoreInitiatorVerifyOnly(roundTrip(t, is))
	if err != nil {
		t.Fatal(err)
	}
	p2, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	rc := respCfg(i, r, PurposeConnection)
	rc.Identity = other.ik
	_, bad, err := p2.Respond(rc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := vo2.HandleResp(bad, r.relayPK(), t0); !errors.Is(err, ErrSigResp) {
		t.Fatalf("a bad sig_R: %v", err)
	}
}
