package handshake

import (
	"encoding/json"
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
	if p2.SAS() != ini2.SAS() || p2.Init().Ctx != testInviteID {
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
	er, _, err := resp2.HandleFin(res.Fin, i.relayPK(), t0)
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
	er2, err := ImportEpoch(roundTrip(t, er.Export()))
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
	if err != nil || p.SAS() != ini.SAS() {
		t.Fatalf("AcceptRekey: %v", err)
	}
}
