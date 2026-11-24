package handshake

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// The older copies of a handshake's secrets are wiped: what ParseInit
// decodes, an hs.init dropped on an error, a PendingInit discarded, the
// replaced snapshots and an hs.resp's plaintext once read.

// transferInit is an app hs.init that carries an app key and an unlock
// secret (a transfer's), sealed from i to r.
func transferInit(t *testing.T, i, r *party) *Initiator {
	t.Helper()
	cfg := initCfg(i, r, PurposeApp)
	cfg.APIKey = testAPIKeyDER(t)
	cfg.UnlockSecret = bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return ini
}

// dropped records what dropInit is handed, before it wipes it.
type dropped struct {
	inners [][]byte // inner bodies
	keys   [][]byte // app keys and unlock secrets
	bodies int      // parsed bodies handed
}

func watchDrops(t *testing.T) *dropped {
	t.Helper()
	d := &dropped{}
	testDropInitHook = func(in *envelope.Inner, body *Init) {
		if in != nil {
			d.inners = append(d.inners, in.Body)
		}
		if body != nil {
			d.bodies++
			for _, b := range [][]byte{body.APIKey, body.UnlockSecret} {
				if b != nil {
					d.keys = append(d.keys, b)
				}
			}
		}
	}
	t.Cleanup(func() { testDropInitHook = nil })
	return d
}

func (d *dropped) wiped(t *testing.T, wantInner bool, wantKeys int) {
	t.Helper()
	if wantInner && len(d.inners) == 0 {
		t.Fatal("no inner dropped")
	}
	for _, b := range d.inners {
		if !allZero(b) {
			t.Fatal("a dropped inner was not wiped")
		}
	}
	if len(d.keys) != wantKeys {
		t.Fatalf("%d secrets dropped, want %d", len(d.keys), wantKeys)
	}
	for _, b := range d.keys {
		if !allZero(b) {
			t.Fatal("a dropped app key or unlock secret was not wiped")
		}
	}
}

// ParseInit decodes api_key and unlock_secret straight to bytes and wipes
// their members in the object it parsed; the other members are left.
func TestParseInitWipesItsSecretMembers(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	cfg := transferInitCfg(t, i, r)
	cfg.Profile = json.RawMessage(`{"name":"Al"}`)
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var seen []strictjson.Object
	testParsedHook = func(o strictjson.Object) { seen = append(seen, o) }
	defer func() { testParsedHook = nil }()
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 {
		t.Fatalf("%d bodies parsed", len(seen))
	}
	o := seen[0]
	for _, name := range []string{"api_key", "unlock_secret", "token"} {
		if !allZero(o[name]) {
			t.Fatalf("%s was left in the parsed object", name)
		}
	}
	if allZero(o["purpose"]) || allZero(o["profile"]) {
		t.Fatal("another member was wiped")
	}
	if prof := p.Init().Profile; string(prof) != `{"name":"Al"}` {
		t.Fatalf("Init.Profile, which aliases the parsed member, reads %q", prof)
	}
	if in := p.Init(); in.Token != tokA {
		t.Fatal("the token was not decoded")
	}
	if in := p.Init(); len(in.APIKey) == 0 || !bytes.Equal(in.UnlockSecret, bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)) {
		t.Fatal("the secrets were not decoded")
	}
}

// A reconnect's hs.init carries reconnect_token: ParseInit wipes its
// parsed member too, and the Init keeps the decoded token.
func TestParseInitWipesTheReconnectToken(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeReconnect))
	if err != nil {
		t.Fatal(err)
	}
	var seen []strictjson.Object
	testParsedHook = func(o strictjson.Object) { seen = append(seen, o) }
	defer func() { testParsedHook = nil }()
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 {
		t.Fatalf("%d bodies parsed", len(seen))
	}
	o := seen[0]
	for _, name := range []string{"token", "reconnect_token"} {
		if len(o[name]) == 0 || !allZero(o[name]) {
			t.Fatalf("%s was left in the parsed object (or is missing): %q", name, o[name])
		}
	}
	if allZero(o["purpose"]) {
		t.Fatal("another member was wiped")
	}
	if in := p.Init(); in.Token != tokA || in.ReconnectToken != tokB {
		t.Fatal("the tokens were not decoded")
	}
}

// bodyOf is ini's hs.init body as the responder opened it, with members
// replaced.
func bodyOf(t *testing.T, ini *Initiator, r *party, set map[string]string) []byte {
	t.Helper()
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Init().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range set {
		m[k] = json.RawMessage(v)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// A body ParseInit refuses after it decoded the secrets (a malformed
// sas_commit, read after them) keeps nothing: they are wiped.
func TestParseInitRefusedWipesWhatItDecoded(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	body := bodyOf(t, transferInit(t, i, r), r, map[string]string{"sas_commit": `"AAAA"`})
	d := watchDrops(t)
	if _, err := ParseInit(body); err == nil {
		t.Fatal("the body was accepted")
	}
	d.wiped(t, false, 2)
}

// A body refused before its secrets are read (an early malformed member)
// has the secrets' text wiped in the object it parsed too.
func TestParseInitRefusedEarlyWipesTheSecretMembers(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	body := bodyOf(t, transferInit(t, i, r), r, map[string]string{"suites": `[]`})
	var seen []strictjson.Object
	testParsedHook = func(o strictjson.Object) { seen = append(seen, o) }
	defer func() { testParsedHook = nil }()
	if _, err := ParseInit(body); err == nil {
		t.Fatal("the body was accepted")
	}
	if len(seen) != 1 || !allZero(seen[0]["api_key"]) || !allZero(seen[0]["unlock_secret"]) {
		t.Fatal("the secrets' text was left in the parsed object")
	}
}

// api_key is bounded as altchan.ParseAppKey bounds it, on the key itself,
// not on how it is spelled: a key with every character escaped (over 256
// characters written) is read. (A key over the bound is no P-256 SPKI, so
// the DER check refuses it too: the bound itself is not observable here.)
func TestParseInitAPIKeyBound(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini := transferInit(t, i, r)
	plain := bodyOf(t, ini, r, nil)
	var m map[string]json.RawMessage
	if err := json.Unmarshal(plain, &m); err != nil {
		t.Fatal(err)
	}
	key := string(m["api_key"][1 : len(m["api_key"])-1])
	esc := "\\" + "u00"
	spelled := ""
	for _, c := range key {
		spelled += esc + fmt.Sprintf("%02x", c) // every character escaped: over 256 written
	}
	in, err := ParseInit(bodyOf(t, ini, r, map[string]string{"api_key": `"` + spelled + `"`}))
	if err != nil {
		t.Fatalf("an escaped key: %v", err)
	}
	want, _ := ParseInit(plain)
	if !bytes.Equal(in.APIKey, want.APIKey) {
		t.Fatal("the escaped key reads as other bytes")
	}
}

// The secrets decode from an escaped string too (a \u escape, \/), as
// from a plain one; an escaped control character is not base64.
func TestParseInitEscapedSecrets(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini := transferInit(t, i, r)
	// 32 bytes of 0x5a encode as "Wlpa...Wlo=": spelled with escapes.
	want := bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
	plain := `"` + strings.Repeat("Wlpa", 10) + `Wlo="`
	in, err := ParseInit(bodyOf(t, ini, r, map[string]string{"unlock_secret": plain}))
	if err != nil || !bytes.Equal(in.UnlockSecret, want) {
		t.Fatalf("plain: %v", err)
	}
	escaped := `"\u0057` + plain[2:]
	in, err = ParseInit(bodyOf(t, ini, r, map[string]string{"unlock_secret": escaped}))
	if err != nil || !bytes.Equal(in.UnlockSecret, want) {
		t.Fatalf("escaped: %v", err)
	}
	for _, bad := range []string{`"\n` + plain[1:], `"\u00e9` + plain[2:], `"` + plain[1:len(plain)-2] + `\/="`} {
		if _, err := ParseInit(bodyOf(t, ini, r, map[string]string{"unlock_secret": bad})); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

// An hs.init OpenInit opened and then refused (its ts an hour ahead) is
// dropped: its inner plaintext, with the secrets, is wiped.
func TestOpenInitRefusedWipesTheInner(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini := transferInit(t, i, r)
	d := watchDrops(t)
	if _, err := OpenInit(ini.Envelope(), r.lookup, t0.Add(-time.Hour)); err == nil {
		t.Fatal("an hs.init from an hour ahead was accepted")
	}
	d.wiped(t, true, 0)
}

// OpenRekeyInit drops a refused one as OpenInit does.
func TestOpenRekeyInitRefusedWipesTheInner(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ea, eb := runHandshake(t, a, b, PurposeConnection)
	cfg := initCfg(a, b, PurposeRekey)
	cfg.Current, cfg.Ctx, cfg.ResponderEK, cfg.Token, cfg.ReconnectToken = ea, "", nil, "", ""
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d := watchDrops(t)
	if _, err := OpenRekeyInit(ini.Envelope(), eb, t0.Add(-time.Hour)); err == nil {
		t.Fatal("a rekey from an hour ahead was accepted")
	}
	d.wiped(t, true, 0)
}

// AcceptRekey drops the body it parsed when it refuses the rekey (another
// epoch's ctx); the inner is its caller's.
func TestAcceptRekeyRefusedDropsTheBody(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ea, eb := runHandshake(t, a, b, PurposeConnection)
	_, other := runHandshake(t, newParty(t, 0x30), b, PurposeConnection)
	cfg := initCfg(a, b, PurposeRekey)
	cfg.Current, cfg.Ctx, cfg.ResponderEK, cfg.Token, cfg.ReconnectToken = ea, "", nil, "", ""
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var kb Keyring
	kb.Activate(eb, t0)
	env, _ := envelope.Parse(ini.Envelope())
	in, _, err := kb.Open(env, t0)
	if err != nil {
		t.Fatal(err)
	}
	d := watchDrops(t)
	if _, err := AcceptRekey(ini.Envelope(), in, other, t0); !errors.Is(err, ErrCtx) {
		t.Fatalf("AcceptRekey: %v, want ErrCtx", err)
	}
	if d.bodies != 1 || len(d.inners) != 0 {
		t.Fatalf("dropped %d bodies, %d inners; want the body alone", d.bodies, len(d.inners))
	}
}

// RestorePending drops an inner whose body does not parse.
func TestRestorePendingRefusedWipesTheInner(t *testing.T) {
	inner, err := (&envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: TypeInit, TS: t0,
		Body: []byte(`{"purpose":"app","secret":"c2VjcmV0"}`)}).Marshal(envelope.ModeSealed)
	if err != nil {
		t.Fatal(err)
	}
	d := watchDrops(t)
	if _, err := RestorePending(PendingState{Env: []byte("env"), Inner: inner, Ks: make([]byte, 32)}); err == nil {
		t.Fatal("a body that does not parse was restored")
	}
	d.wiped(t, true, 0)
}

// restoreInitiator drops the body it parsed on each refusal after it.
func TestRestoreInitiatorRefusedDropsTheBody(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	for _, c := range []struct {
		name   string
		break_ func(s *InitiatorState) // the state to restore
		other  bool                    // restore with another identity
	}{
		{"another ephemeral key", func(s *InitiatorState) { s.EphSeed = bytes.Repeat([]byte{7}, len(s.EphSeed)) }, false},
		{"another identity", func(*InitiatorState) {}, true},
		{"a chain entry that does not parse", func(s *InitiatorState) { s.KnownResponderChain = []json.RawMessage{json.RawMessage(`{}`)} }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			st, err := transferInit(t, i, r).Export()
			if err != nil {
				t.Fatal(err)
			}
			c.break_(&st)
			id := i.ik
			if c.other {
				id = newParty(t, 0x30).ik
			}
			d := watchDrops(t)
			if _, err := RestoreInitiator(st, id); err == nil {
				t.Fatal("restored")
			}
			d.wiped(t, false, 2)
		})
	}
}

// Discard wipes the hs.init's inner plaintext and its parsed secrets, also
// once it was answered.
func TestDiscardWipesTheInit(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	p, err := OpenInit(transferInit(t, i, r).Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Respond(respCfg(i, r, PurposeApp)); err != nil {
		t.Fatal(err)
	}
	inner, ak, us := p.Inner().Body, p.Init().APIKey, p.Init().UnlockSecret
	p.Discard()
	for name, b := range map[string][]byte{"inner": inner, "app key": ak, "unlock secret": us} {
		if !allZero(b) {
			t.Fatalf("the %s was not wiped", name)
		}
	}
	if p.Init().UnlockSecret != nil || p.Init().APIKey != nil {
		t.Fatal("the wiped secrets are still referenced")
	}
}

// The snapshot types wipe their secrets, and a result its hs.resp
// plaintext.
func TestSnapshotAndResultWipes(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	resp, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	rs, err := resp.Export()
	if err != nil {
		t.Fatal(err)
	}
	secrets := [][]byte{rs.Ks, rs.Ke, rs.PRK, rs.KI2R, rs.KR2I, rs.RK}
	rs.Wipe()
	for n, b := range secrets {
		if !allZero(b) {
			t.Fatalf("responder state secret %d not wiped", n)
		}
	}
	res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	body := res.Inner.Body
	res.Wipe()
	if !allZero(body) {
		t.Fatal("the hs.resp plaintext was not wiped")
	}
	var kr Keyring
	kr.Activate(res.Epoch, t0)
	ks := kr.Export()
	es := ks.Current
	keys := [][]byte{es.SendKey, es.RecvKey, es.RK}
	ks.Wipe()
	for n, b := range keys {
		if !allZero(b) {
			t.Fatalf("epoch key %d not wiped", n)
		}
	}
	if es.SendKey != nil || es.RecvKey != nil || es.RK != nil {
		t.Fatal("the wiped keys are still referenced")
	}
}

// A restore copies every byte of its snapshot: once restored, the
// snapshot can be wiped and the handshake still finishes. (A restore that
// shared a slice with the snapshot would have its keys zeroed by a write's
// replacement of the snapshot.)
func TestRestoreThenWipeTheSnapshot(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(transferInitCfg(t, i, r))
	if err != nil {
		t.Fatal(err)
	}
	is, err := ini.Export()
	if err != nil {
		t.Fatal(err)
	}
	ini2, err := RestoreInitiator(is, i.ik)
	if err != nil {
		t.Fatal(err)
	}
	is.Wipe()
	p, err := OpenInit(ini2.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := p.Export()
	if err != nil {
		t.Fatal(err)
	}
	p2, err := RestorePending(ps)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{ps.Ks, ps.Inner, ps.Env} {
		clear(b)
	}
	resp, respEnv, err := p2.Respond(respCfg(i, r, PurposeApp))
	if err != nil {
		t.Fatalf("Respond after the pending snapshot was wiped: %v", err)
	}
	rs, err := resp.Export()
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := RestoreResponder(rs)
	if err != nil {
		t.Fatal(err)
	}
	rs.Wipe()
	clear(rs.Th)
	res, err := ini2.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatalf("HandleResp after the initiator snapshot was wiped: %v", err)
	}
	fr, err := resp2.HandleFin(res.Fin, i.relayPK(), t0)
	if err != nil {
		t.Fatalf("HandleFin after the responder snapshot was wiped: %v", err)
	}
	if fr.SAS == "" || fr.SAS != res.SAS {
		t.Fatal("the restored responder's SAS differs: its schedule was not its own copy")
	}
	var kI, kR Keyring
	kI.Activate(res.Epoch, t0)
	kR.Activate(fr.Epoch, t0)
	ks := kI.Export()
	kI2, err := ImportKeyring(ks)
	if err != nil {
		t.Fatal(err)
	}
	es := fr.Epoch.Export()
	eR2, err := ImportEpoch(es)
	if err != nil {
		t.Fatal(err)
	}
	ks.Wipe()
	es.Wipe()
	clear(es.ID)
	var kR2 Keyring
	kR2.Activate(eR2, t0)
	if err := sealOpen(t, kI2.Current(), &kR2, t0); err != nil {
		t.Fatalf("an epoch restored before its snapshot was wiped: %v", err)
	}
}

func transferInitCfg(t *testing.T, i, r *party) InitiatorConfig {
	cfg := initCfg(i, r, PurposeApp)
	cfg.APIKey = testAPIKeyDER(t)
	cfg.UnlockSecret = bytes.Repeat([]byte{0x5a}, altchan.UnlockSecretSize)
	return cfg
}

// A message of the new epoch that arrives before hs.fin is opened, refused
// (ErrType) and dropped by HandleFin: its plaintext is wiped. The real
// hs.fin still finishes the handshake afterwards.
func TestHandleFinWipesARefusedMessage(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, err := NewInitiator(initCfg(i, r, PurposeApp))
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	resp, respEnv, err := p.Respond(respCfg(i, r, PurposeApp))
	if err != nil {
		t.Fatal(err)
	}
	res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := envelope.NewULID(t0)
	early, err := res.Epoch.Seal(&envelope.Inner{ID: id, Type: "test.early", TS: t0, Body: []byte(`{"secret":"before the fin"}`)})
	if err != nil {
		t.Fatal(err)
	}
	var refused []*envelope.Inner
	testFinFailHook = func(in *envelope.Inner) { refused = append(refused, in) }
	t.Cleanup(func() { testFinFailHook = nil })
	if _, err := resp.HandleFin(early, i.relayPK(), t0); !errors.Is(err, ErrType) {
		t.Fatalf("HandleFin of a message before hs.fin: %v, want ErrType", err)
	}
	if len(refused) != 1 || refused[0].ID != id || len(refused[0].Body) == 0 || !allZero(refused[0].Body) {
		t.Fatalf("the refused message's plaintext was not wiped: %+v", refused)
	}
	fr, err := resp.HandleFin(res.Fin, i.relayPK(), t0)
	if err != nil || fr.SAS != res.SAS {
		t.Fatalf("the hs.fin after it: %v", err)
	}
}
