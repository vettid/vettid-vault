package handshake

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
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

// Each body's builder reserves room for every member it writes, at least
// that member's encoded length (so it never outgrows its buffer, which
// would leave a copy behind), for every member of hs.init, hs.resp and
// hs.fin that the handshakes below write.
func TestHandshakeBodiesNeverOutgrown(t *testing.T) {
	type built struct {
		terms []sizeTerm
		body  []byte
		grew  bool
	}
	got := map[string][]built{}
	testMarshalHook = func(typ string, terms []sizeTerm, body []byte, grew bool) {
		got[typ] = append(got[typ], built{terms, append([]byte(nil), body...), grew})
	}
	t.Cleanup(func() { testMarshalHook = nil })
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
		_, env, err := p.Respond(respCfg(i, r, purpose))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ini.HandleResp(env, r.relayPK(), t0); err != nil {
			t.Fatal(err)
		}
	}
	// Every member hs.init may carry, beside the keys.
	in := sampleInit(t, PurposeApp)
	in.Profile = []byte(`{"name":"` + string(bytes.Repeat([]byte{'x'}, 2000)) + `"}`)
	in.APIKey = testAPIKeyDER(t)
	in.UnlockSecret = bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
	in.DeviceAttest = &altchan.DeviceAttest{Platform: "android", Chain: [][]byte{{0x30, 0x82}, {0x30, 0x81}}}
	if _, err := in.Marshal(); err != nil {
		t.Fatal(err)
	}
	// A reconnect's hs.init with relay links, and its hs.resp with the
	// relay and relay links.
	links := sampleInit(t, PurposeReconnect)
	links.RelayLinks = relayChain(t, relayKey(0x71), ed25519.NewKeyFromSeed(seed(0x10+2)))
	if _, err := links.Marshal(); err != nil {
		t.Fatal(err)
	}
	k1, k2 := relayKey(0x71), relayKey(0x72)
	addr := RelayAddr{URL: "https://relay.example.org", Mailbox: MailboxID(pubOf(k2)), PK: pubOf(k2)}
	resp := &Resp{Token: tokC, ReconnectToken: tokD, Suite: 2, Sig: make([]byte, 64), Relay: &addr, RelayLinks: relayChain(t, k1, k2)}
	if _, err := resp.Marshal(PurposeReconnect); err != nil {
		t.Fatal(err)
	}
	// A reconnect, both tokens and rotations each way.
	{
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		ei, _ := runHandshake(t, i, r, PurposeConnection)
		rc := reconnectCase{storedIKofI: i.pub(), storedIKofR: r.pub(), storedEKofR: r.kem.Public(), lastEpoch: ei.ID()}
		rotI := []*Rotation{rotateParty(t, i, 0x40)}
		oldKEM := r.kem
		rotR := []*Rotation{rotateParty(t, r, 0x60)}
		r.retired = oldKEM
		if _, _, err := reconnect(t, i, r, rc, rotI, rotR); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]map[string]bool{}
	for typ, bs := range got {
		seen[typ] = map[string]bool{}
		for _, b := range bs {
			if b.grew {
				t.Fatalf("an %s body outgrew its buffer", typ)
			}
			o, err := strictjson.ParseObject(b.body)
			if err != nil {
				t.Fatal(err)
			}
			for name, raw := range o {
				// "name":value and its comma.
				need := len(name) + 3 + len(raw) + 1
				ok := false
				for _, tm := range b.terms {
					if tm.name == name && tm.bound >= need {
						ok = true
					}
				}
				if !ok {
					t.Errorf("%s: no room reserved for %q (%d bytes)", typ, name, need)
				}
				seen[typ][name] = true
			}
		}
	}
	want := map[string][]string{
		TypeInit: {"purpose", "ctx", "from", "eph", "token", "reconnect_token", "suites", "profile", "rotations", "relay_links",
			"device_attest", "api_key", "unlock_secret", "sas_commit"},
		TypeResp: {"token", "reconnect_token", "suite", "rotations", "sas_nonce", "sig", "relay", "relay_links"},
		TypeFin:  {"sig", "sas_nonce"},
	}
	for typ, names := range want {
		for _, n := range names {
			if !seen[typ][n] {
				t.Errorf("%s: no body written with %q: its room is not checked", typ, n)
			}
		}
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
		testMarshalHook = func(string, []sizeTerm, []byte, bool) { built++ }
		t.Cleanup(func() { testMarshalHook = nil })
		// An answer that does not open: not done, and asking costs no
		// marshal.
		if _, err := ini.HandleResp([]byte("junk"), r.relayPK(), t0); err == nil || ini.Done() || built != 0 {
			t.Fatalf("junk: %v done=%v marshals=%d", err, ini.Done(), built)
		}
		testMarshalHook = nil
		if ini.cfg.APIKey != nil || ini.cfg.UnlockSecret != nil {
			t.Fatal("the Initiator still names the caller's app key or unlock secret")
		}
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

// A NewInitiator that fails after it made its eph, n_I, K_s or its copies
// of the app key and unlock secret ends them all; an hs.init body built
// before the failure is wiped too.
func TestNewInitiatorFailuresWipeEverything(t *testing.T) {
	bad := []string{"B"} // not a feature name: the seal refuses it
	cases := []struct {
		name string
		cfg  func(i, r *party) InitiatorConfig
		// body: whether an hs.init body was built (and must be wiped);
		// secrets: how many of the app key, unlock secret, n_I and K_s it
		// held when it failed.
		body    bool
		secrets int
	}{
		{"the body does not marshal (a short unlock secret)", func(i, r *party) InitiatorConfig {
			c := initCfg(i, r, PurposeApp)
			c.APIKey, c.UnlockSecret = testAPIKeyDER(t), []byte{1, 2, 3}
			return c
		}, false, 3},
		{"the seal fails (a bad feature name)", func(i, r *party) InitiatorConfig {
			c := initCfg(i, r, PurposeApp)
			c.APIKey, c.UnlockSecret = testAPIKeyDER(t), bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
			c.Features = bad
			return c
		}, true, 3},
		{"a rekey under a retired epoch", func(i, r *party) InitiatorConfig {
			ei, _ := runHandshake(t, i, r, PurposeConnection)
			ei.Destroy()
			return InitiatorConfig{Purpose: PurposeRekey, Identity: i.ik, StaticKEM: i.kem.Public(), Relay: i.addr,
				ResponderIK: r.pub(), ResponderRelayKey: r.relayPK(), Current: ei, Policy: PolicyVaultToVault, Now: t0}
		}, true, 0},
		{"a rekey's seal fails (a bad feature name)", func(i, r *party) InitiatorConfig {
			ei, _ := runHandshake(t, i, r, PurposeConnection)
			return InitiatorConfig{Purpose: PurposeRekey, Identity: i.ik, StaticKEM: i.kem.Public(), Relay: i.addr,
				ResponderIK: r.pub(), ResponderRelayKey: r.relayPK(), Current: ei, Policy: PolicyVaultToVault, Now: t0, Features: bad}
		}, true, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			i, r := newParty(t, 0x10), newParty(t, 0x20)
			cfg := c.cfg(i, r)
			got := bodies(t)
			var half *Initiator
			var held [][]byte
			testNewInitiatorFailHook = func(ini *Initiator) {
				half = ini
				held = [][]byte{ini.body.APIKey, ini.body.UnlockSecret, ini.nI, ini.ks}
			}
			t.Cleanup(func() { testNewInitiatorFailHook = nil })
			if ini, err := NewInitiator(cfg); err == nil || ini != nil {
				t.Fatalf("NewInitiator did not fail: %v", err)
			}
			if half == nil {
				t.Fatal("failed before the Initiator was built")
			}
			n := 0
			for _, b := range held {
				if b == nil {
					continue
				}
				n++
				if !allZero(b) {
					t.Fatal("a secret of the failed Initiator kept")
				}
			}
			if n != c.secrets || half.eph != nil || !half.done || half.body.APIKey != nil {
				t.Fatalf("not ended: %d secrets held, eph %v, done %v", n, half.eph != nil, half.done)
			}
			if c.body != (len(got[TypeInit]) == 1) || c.body && !allZero(got[TypeInit][0]) {
				t.Fatalf("hs.init bodies wiped: %d", len(got[TypeInit]))
			}
		})
	}
}

// An hs.resp or hs.fin body whose seal fails is wiped too.
func TestBodiesWipedWhenTheSealFails(t *testing.T) {
	bad := []string{"B"}
	t.Run("hs.resp", func(t *testing.T) {
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
		if err != nil {
			t.Fatal(err)
		}
		p, err := OpenInit(ini.Envelope(), r.lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		got := bodies(t)
		rc := respCfg(i, r, PurposeConnection)
		rc.Features = bad
		if _, _, err := p.Respond(rc); err == nil {
			t.Fatal("the hs.resp sealed")
		}
		if len(got[TypeResp]) != 1 || !allZero(got[TypeResp][0]) {
			t.Fatalf("hs.resp bodies wiped: %d", len(got[TypeResp]))
		}
	})
	t.Run("hs.fin", func(t *testing.T) {
		i, r := newParty(t, 0x10), newParty(t, 0x20)
		ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
		if err != nil {
			t.Fatal(err)
		}
		p, err := OpenInit(ini.Envelope(), r.lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		_, env, err := p.Respond(respCfg(i, r, PurposeConnection))
		if err != nil {
			t.Fatal(err)
		}
		got := bodies(t)
		ini.cfg.Features = bad // the hs.fin's seal refuses it
		if _, err := ini.HandleResp(env, r.relayPK(), t0); err == nil {
			t.Fatal("the hs.fin sealed")
		}
		if len(got[TypeFin]) != 1 || !allZero(got[TypeFin][0]) {
			t.Fatalf("hs.fin bodies wiped: %d", len(got[TypeFin]))
		}
	})
}
