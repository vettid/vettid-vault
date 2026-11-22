package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// bodies records each handshake body as wipeBody leaves it, by type.
func bodies(t *testing.T) map[string][][]byte {
	t.Helper()
	got := map[string][][]byte{}
	testBodyWipedHook = func(typ string, b []byte) { got[typ] = append(got[typ], append([]byte(nil), b...)) }
	t.Cleanup(func() { testBodyWipedHook = nil })
	return got
}

func allZero(b []byte) bool { return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b) }

func testAPIKeyDER(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// An app's hs.init carries the app key, the unlock secret and the token:
// its body is wiped once sealed, and what was sealed still opens to them;
// the hs.resp body, which carries the tokens, is wiped too, and the
// initiator still reads them.
func TestHandshakeBodiesWipedOnceSealed(t *testing.T) {
	got := bodies(t)
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	cfg := initCfg(i, r, PurposeApp)
	cfg.APIKey = testAPIKeyDER(t)
	cfg.UnlockSecret = bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
	apiKey, unlock := append([]byte(nil), cfg.APIKey...), append([]byte(nil), cfg.UnlockSecret...)
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[TypeInit]) != 1 || !allZero(got[TypeInit][0]) {
		t.Fatalf("hs.init body not wiped: %q", got[TypeInit])
	}
	// The caller's own secrets are the caller's: untouched.
	if !bytes.Equal(cfg.APIKey, apiKey) || !bytes.Equal(cfg.UnlockSecret, unlock) {
		t.Fatal("the caller's app key or unlock secret was wiped")
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if in := p.Init(); !bytes.Equal(in.APIKey, apiKey) || !bytes.Equal(in.UnlockSecret, unlock) || in.Token != tokA {
		t.Fatalf("sealed hs.init opens to %+v", in)
	}
	rc := respCfg(i, r, PurposeApp)
	_, respEnv, err := p.Respond(rc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got[TypeResp]) != 1 || !allZero(got[TypeResp][0]) {
		t.Fatalf("hs.resp body not wiped: %q", got[TypeResp])
	}
	res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil || res.Resp == nil || res.Resp.Token != tokC {
		t.Fatalf("sealed hs.resp: %v %+v", err, res)
	}
}

// A reconnect carries both tokens each way, and a rekey travels in session
// mode: their bodies are wiped too.
func TestHandshakeBodiesWipedEveryPath(t *testing.T) {
	for _, purpose := range []Purpose{PurposeConnection, PurposeDesktop, PurposeAgent} {
		got := bodies(t)
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		runHandshake(t, i, r, purpose)
		if len(got[TypeInit]) != 1 || !allZero(got[TypeInit][0]) || len(got[TypeResp]) != 1 || !allZero(got[TypeResp][0]) {
			t.Fatalf("%s: %d hs.init, %d hs.resp wiped", purpose, len(got[TypeInit]), len(got[TypeResp]))
		}
	}
	// A reconnect: both tokens each way.
	{
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		ei, _ := runHandshake(t, i, r, PurposeConnection)
		got := bodies(t)
		rc := reconnectCase{storedIKofI: i.pub(), storedIKofR: r.pub(), storedEKofR: r.kem.Public(), lastEpoch: ei.ID()}
		res, _, err := reconnect(t, i, r, rc, nil, nil)
		if err != nil || res.Resp.ReconnectToken != tokD || res.Resp.Token != tokC {
			t.Fatalf("reconnect: %v %+v", err, res)
		}
		if len(got[TypeInit]) != 1 || !allZero(got[TypeInit][0]) || len(got[TypeResp]) != 1 || !allZero(got[TypeResp][0]) {
			t.Fatalf("reconnect: %d hs.init, %d hs.resp wiped", len(got[TypeInit]), len(got[TypeResp]))
		}
	}
	got := bodies(t)
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ei, er := runHandshake(t, i, r, PurposeConnection)
	before := len(got[TypeInit])
	ini, err := NewInitiator(InitiatorConfig{Purpose: PurposeRekey, Identity: i.ik, StaticKEM: i.kem.Public(), Relay: i.addr,
		ResponderIK: r.pub(), ResponderRelayKey: r.relayPK(), Current: ei, Policy: PolicyVaultToVault, Now: t0})
	if err != nil {
		t.Fatal(err)
	}
	if len(got[TypeInit]) != before+1 || !allZero(got[TypeInit][len(got[TypeInit])-1]) {
		t.Fatalf("rekey hs.init not wiped: %d", len(got[TypeInit])-before)
	}
	env, _ := envelope.Parse(ini.Envelope())
	if in, err := er.Open(env); err != nil || in.Type != TypeInit {
		t.Fatalf("the sealed rekey hs.init does not open: %v", err)
	}
}

// The hs.init and hs.resp builders never outgrow the room reserved for
// them, whatever members a body holds.
func TestHandshakeBodiesNeverOutgrown(t *testing.T) {
	grew := 0
	built := 0
	testMarshalHook = func(g bool) {
		built++
		if g {
			grew++
		}
	}
	defer func() { testMarshalHook = nil }()
	for _, purpose := range []Purpose{PurposeConnection, PurposeApp, PurposeDesktop, PurposeAgent} {
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		cfg := initCfg(i, r, purpose)
		if purpose == PurposeApp {
			cfg.APIKey = testAPIKeyDER(t)
			cfg.UnlockSecret = bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
		}
		ini, err := NewInitiator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		p, err := OpenInit(ini.Envelope(), r.lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := p.Respond(respCfg(i, r, purpose)); err != nil {
			t.Fatal(err)
		}
	}
	// A long profile beside the keys.
	in := sampleInit(t, PurposeApp)
	in.Profile = []byte(`{"name":"` + string(bytes.Repeat([]byte{'x'}, 2000)) + `"}`)
	in.APIKey = testAPIKeyDER(t)
	in.UnlockSecret = bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
	if _, err := in.Marshal(); err != nil {
		t.Fatal(err)
	}
	// A reconnect, both tokens each way.
	{
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		ei, _ := runHandshake(t, i, r, PurposeConnection)
		rc := reconnectCase{storedIKofI: i.pub(), storedIKofR: r.pub(), storedEKofR: r.kem.Public(), lastEpoch: ei.ID()}
		if _, _, err := reconnect(t, i, r, rc, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if built < 13 || grew != 0 {
		t.Fatalf("%d of %d bodies outgrew their buffer", grew, built)
	}
}

// The Initiator keeps copies of its own of the app key and the unlock
// secret, and wipes them when the handshake ends (aborted or completed);
// Done says it ended without marshalling the hs.init again.
func TestInitiatorWipesItsSecretsWhenDone(t *testing.T) {
	for _, complete := range []bool{false, true} {
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		cfg := initCfg(i, r, PurposeApp)
		cfg.APIKey = testAPIKeyDER(t)
		cfg.UnlockSecret = bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
		ini, err := NewInitiator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		held, unlock := ini.Body().APIKey, ini.Body().UnlockSecret
		if &held[0] == &cfg.APIKey[0] || &unlock[0] == &cfg.UnlockSecret[0] {
			t.Fatal("the Initiator shares the caller's slices")
		}
		built := 0
		testMarshalHook = func(bool) { built++ }
		// A garbage answer from the wrong sender: not done, and asking costs
		// no marshal.
		if _, err := ini.HandleResp([]byte("junk"), r.relayPK(), t0); err == nil || ini.Done() || built != 0 {
			t.Fatalf("junk: %v done=%v marshals=%d", err, ini.Done(), built)
		}
		testMarshalHook = nil
		if complete {
			p, err := OpenInit(ini.Envelope(), r.lookup, t0)
			if err != nil {
				t.Fatal(err)
			}
			_, env, err := p.Respond(respCfg(i, r, PurposeApp))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ini.HandleResp(env, r.relayPK(), t0); err != nil {
				t.Fatal(err)
			}
		} else {
			ini.Abort()
		}
		if !ini.Done() || !allZero(held) || !allZero(unlock) || ini.Body().APIKey != nil {
			t.Fatalf("complete=%v: secrets kept after the end", complete)
		}
		if allZero(cfg.APIKey) || allZero(cfg.UnlockSecret) {
			t.Fatal("the caller's slices were wiped")
		}
	}
}

// hs.fin's body carries n_I: wiped once sealed.
func TestFinBodyWiped(t *testing.T) {
	got := bodies(t)
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	runHandshake(t, i, r, PurposeApp)
	if len(got[TypeFin]) != 1 || !allZero(got[TypeFin][0]) {
		t.Fatalf("hs.fin body not wiped: %q", got[TypeFin])
	}
}

// InitiatorState.Wipe wipes its secrets, and a state restored before the
// wipe still works (RestoreInitiator copies what it keeps).
func TestInitiatorStateWipe(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	st, err := ini.Export()
	if err != nil {
		t.Fatal(err)
	}
	seed, ks, nI, body := st.EphSeed, st.Ks, st.NI, st.Body
	c, err := RestoreInitiator(st, i.ik)
	if err != nil {
		t.Fatal(err)
	}
	st.Wipe()
	for _, b := range [][]byte{seed, ks, nI, body} {
		if !allZero(b) {
			t.Fatal("a secret of the state kept")
		}
	}
	if st.EphSeed != nil || st.Body != nil {
		t.Fatal("the state still names its secrets")
	}
	p, err := OpenInit(c.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	_, env, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.HandleResp(env, r.relayPK(), t0); err != nil {
		t.Fatalf("the restored copy after the wipe: %v", err)
	}
}
