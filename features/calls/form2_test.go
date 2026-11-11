package calls

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/vettid/vettid-vault/vms/envelope"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// testIK is the identity key of a test vault that set none (NewHost's).
var testIK = featuretest.NewHost().IK

// outP and inP are the parties (0.88.16) of an unlinked test vault's call
// to conn, and of conn's call to it.
func outP(conn string) callwire.Parties {
	return callwire.Parties{Caller: testIK, Callee: peerVault(conn).Public().(ed25519.PublicKey)}
}

func inP(conn string) callwire.Parties {
	return callwire.Parties{Caller: peerVault(conn).Public().(ed25519.PublicKey), Callee: testIK}
}

// startBody2 is a form 2 call.start from dev-app (both forms signed) on an
// unlinked test vault.
func startBody2(conn, id string, ek []byte, suites []int) string {
	return startBody2P(conn, id, ek, suites, outP(conn))
}

func startBody2P(conn, id string, ek []byte, suites []int, p callwire.Parties) string {
	dev := featuretest.DeviceKey("dev-app")
	sig, _ := callwire.SignShare(dev, callwire.ShareMessage(callwire.RoleOffer, id, "video", ek))
	sig2, _ := callwire.SignShare(dev, callwire.OfferMessage2(id, "video", suites, p, ek))
	return `{"connection_id":"` + conn + `","call_id":"` + id + `","media":"video","sdp":"` + strings.ReplaceAll(sdpOffer, "\r\n", `\r\n`) +
		`","ek":"` + b64(ek) + `","ek_sig":"` + b64(sig) + `","suites":` + string(suitesJSON(suites)) + `,"ek_sig2":"` + b64(sig2) + `"}`
}

// answerBody2 is a form 2 call.answer from dev, enc_sig over m2, to an
// offer from cA on an unlinked test vault.
func answerBody2(dev, id string, enc []byte, chosen int, offered []int, confirm []byte) string {
	return answerBody2P(dev, id, enc, chosen, offered, confirm, inP("cA"))
}

func answerBody2P(dev, id string, enc []byte, chosen int, offered []int, confirm []byte, p callwire.Parties) string {
	sig, _ := callwire.SignShare(featuretest.DeviceKey(dev), callwire.AnswerMessage2(id, chosen, offered, p, enc))
	return `{"call_id":"` + id + `","sdp":"v=0","enc":"` + b64(enc) + `","enc_sig":"` + b64(sig) +
		`","suite":` + itoa(chosen) + `,"offered":` + string(suitesJSON(offered)) + `,"confirm":"` + b64(confirm) + `"}`
}

func itoa(n int) string { return string(suitesJSON([]int{n})[1 : len(suitesJSON([]int{n}))-1]) }

// A form 2 call between two C2 vaults (§10.10 "Call forms"): the offer
// carries both forms, each vouched; the callee's devices get both; a form
// 2 answer (suite, offered, confirm, enc_sig over m2) is vouched over m2
// and reaches the calling device with its members; the vaults don't judge
// the choice or confirm.
func TestForm2Call(t *testing.T) {
	a, b := newSide("cB"), newSide("cA")
	link(a, b)
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	id := newCallID("f2")
	suites := []int{1}
	p := callwire.Parties{Caller: a.h.IK, Callee: b.h.IK} // each vault names the other by its pinned key
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2P("cB", id, ek, suites, p)); !r.OK() {
		t.Fatalf("start: %q", r.Code)
	}
	off := a.sent(t, "cB", "call.offer")
	o := obj(t, off.Body)
	devIK, _ := o.Base64("device_ik", ed25519.PublicKeySize)
	d1, _ := o.Base64("device_sig", 64)
	v1, _ := o.Base64("vault_sig", 64)
	d2, _ := o.Base64("device_sig2", 64)
	v2, _ := o.Base64("vault_sig2", 64)
	if callwire.VerifyShare(a.h.IK, devIK, callwire.ShareMessage(callwire.RoleOffer, id, "video", ek), d1, v1) != nil ||
		callwire.VerifyShare(a.h.IK, devIK, callwire.OfferMessage2(id, "video", suites, p, ek), d2, v2) != nil {
		t.Fatal("the offer's forms aren't both vouched")
	}
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
	ring := b.sent(t, "devices", "call.offer")
	// What rings is exactly what was verified.
	r := obj(t, ring.Body)
	for k, want := range map[string]string{"device_sig": b64(d1), "vault_sig": b64(v1), "device_sig2": b64(d2), "vault_sig2": b64(v2)} {
		if got, _ := r.String(k); got != want {
			t.Errorf("the devices' offer %s = %q", k, got)
		}
	}
	if raw, _, _ := r.OptArray("suites"); len(raw) != 1 || string(raw[0]) != "1" {
		t.Fatalf("the devices' offer suites: %s", ring.Body)
	}
	enc, kCall, err := callwire.Answer(ek, id)
	if err != nil {
		t.Fatal(err)
	}
	kc, _ := callwire.ConfirmKey(kCall, id)
	confirm := callwire.Confirm(kc, 1, suites, id, p)
	b.h.Reset()
	if r := featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", answerBody2P("dev-app", id, enc, 1, suites, confirm, p)); !r.OK() {
		t.Fatalf("answer: %q", r.Code)
	}
	fwd := b.sent(t, "cA", "call.answer")
	fo := obj(t, fwd.Body)
	fd, _ := fo.Base64("device_sig", 64)
	fv, _ := fo.Base64("vault_sig", 64)
	fdev, _ := fo.Base64("device_ik", ed25519.PublicKeySize)
	if callwire.VerifyShare(b.h.IK, fdev, callwire.AnswerMessage2(id, 1, suites, p, enc), fd, fv) != nil {
		t.Fatal("the answer isn't vouched over m2")
	}
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0.Add(time.Second), "connection:cB", "call.answer", string(fwd.Body))
	got := obj(t, a.sent(t, "dev-app", "call.answer").Body)
	gc, _ := got.Base64("confirm", 32)
	if s, _ := got.Uint("suite", 1, 65535); s != 1 || !callwire.VerifyConfirm(kc, 1, suites, id, p, gc) {
		t.Fatal("the calling device didn't get the form 2 members")
	}
	for k, want := range map[string]string{"device_sig": b64(fd), "vault_sig": b64(fv), "device_ik": b64(fdev)} {
		if g, _ := got.String(k); g != want {
			t.Errorf("the calling device's answer %s = %q", k, g)
		}
	}
	if raw, _, _ := got.OptArray("offered"); len(raw) != 1 || string(raw[0]) != "1" {
		t.Fatalf("the calling device's offered: %v", got)
	}
}

// What a vault refuses in form 2.
func TestForm2Refusals(t *testing.T) {
	a := newSide("cB")
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	start := func(body string) string {
		return featuretest.Call(a.f, a.h, t0, "app", "call.start", body).Code
	}
	id := newCallID("f2r")
	good := startBody2("cB", id, ek, []int{1})
	for name, body := range map[string]string{
		"suites without ek_sig2": strings.Replace(good, `,"ek_sig2":"`, `,"x":"`, 1),
		"ek_sig2 without suites": strings.Replace(good, `"suites":[1],`, ``, 1),
		"a suite of 0":           startBody2("cB", id, ek, []int{0}),
		"a suite over 65535":     startBody2("cB", id, ek, []int{65536}),
		"a repeated suite":       startBody2("cB", id, ek, []int{1, 1}),
		"nine suites":            startBody2("cB", id, ek, []int{1, 2, 3, 4, 5, 6, 7, 8, 9}),
		"no suites":              strings.Replace(startBody2("cB", id, ek, []int{1}), `"suites":[1]`, `"suites":[]`, 1),
	} {
		if c := start(body); c != "bad_request" {
			t.Errorf("%s: %q", name, c)
		}
	}
	// ek_sig2 over other suites than sent: the device's form 2 doesn't verify.
	dev := featuretest.DeviceKey("dev-app")
	wrong, _ := callwire.SignShare(dev, callwire.OfferMessage2(id, "video", []int{2}, outP("cB"), ek))
	o, _ := strictjson.ParseObject([]byte(good))
	body := strings.Replace(good, mustStr(t, o, "ek_sig2"), b64(wrong), 1)
	if c := start(body); c != "bad_request" {
		t.Fatalf("a bad ek_sig2: %q", c)
	}
	if c := start(good); c != "" {
		t.Fatalf("the good form 2 start: %q", c)
	}
}

func mustStr(t *testing.T, o strictjson.Object, k string) string {
	t.Helper()
	v, err := o.String(k)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// peerOffer2 is a peer's offer with both forms, or with form 2 changed.
func peerOffer2(conn, id, media string, ek []byte, suites []int, vaultSig2 bool, badDev2 bool) string {
	dev := featuretest.DeviceKey("peer-device")
	devPub := dev.Public().(ed25519.PublicKey)
	m1 := callwire.ShareMessage(callwire.RoleOffer, id, media, ek)
	d1, _ := callwire.SignShare(dev, m1)
	v1, _ := suite.Sign(peerVault(conn), callwire.LabelVouch, callwire.VouchMessage(devPub, m1))
	m2 := callwire.OfferMessage2(id, media, suites, inP(conn), ek)
	if badDev2 {
		m2 = callwire.OfferMessage2(id, media, []int{2}, inP(conn), ek)
	}
	d2, _ := callwire.SignShare(dev, m2)
	v2, _ := suite.Sign(peerVault(conn), callwire.LabelVouch, callwire.VouchMessage(devPub, callwire.OfferMessage2(id, media, suites, inP(conn), ek)))
	s := `{"call_id":"` + id + `","media":"` + media + `","sdp":"v=0","ek":"` + b64(ek) + `","device_ik":"` + b64(devPub) +
		`","device_sig":"` + b64(d1) + `","vault_sig":"` + b64(v1) + `","suites":` + string(suitesJSON(suites)) + `,"device_sig2":"` + b64(d2) + `"`
	if vaultSig2 {
		s += `,"vault_sig2":"` + b64(v2) + `"`
	}
	return s + `}`
}

// An offer with suites but not both form 2 signatures, or a form 2 that
// doesn't verify, rings nobody (drop.call_share).
func TestForm2OfferChecked(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	for name, c := range map[string]struct{ vs2, bad bool }{"no vault_sig2": {false, false}, "a bad device_sig2": {true, true}} {
		b := newSide("cA")
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", newCallID("cA"), "audio", ek, []int{1}, c.vs2, c.bad))
		if len(b.h.SentOfType("call.offer")) != 0 || !b.h.HasActivity("drop.call_share") {
			t.Errorf("%s: rang, or not audited", name)
		}
	}
	b := newSide("cA")
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", newCallID("cA"), "audio", ek, []int{1}, true, false))
	b.sent(t, "devices", "call.offer")
}

// A form 2 answer: all of suite, offered and confirm, or none; enc_sig
// over m2; a form 1 signature on a form 2 answer is refused.
func TestForm2AnswerChecked(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	for name, mk := range map[string]func(id string, enc []byte) string{
		"no confirm": func(id string, enc []byte) string {
			return strings.Replace(answerBody2("dev-app", id, enc, 1, []int{1}, make([]byte, 32)), `,"confirm":"`+b64(make([]byte, 32))+`"`, ``, 1)
		},
		"no offered, signed so": func(id string, enc []byte) string {
			sig, _ := callwire.SignShare(featuretest.DeviceKey("dev-app"), callwire.AnswerMessage2(id, 1, nil, inP("cA"), enc))
			return `{"call_id":"` + id + `","sdp":"v=0","enc":"` + b64(enc) + `","enc_sig":"` + b64(sig) + `","suite":1,"confirm":"` + b64(make([]byte, 32)) + `"}`
		},
		"form 1 signature": func(id string, enc []byte) string {
			sig, _ := callwire.SignShare(featuretest.DeviceKey("dev-app"), callwire.ShareMessage(callwire.RoleAnswer, id, "", enc))
			return `{"call_id":"` + id + `","sdp":"v=0","enc":"` + b64(enc) + `","enc_sig":"` + b64(sig) + `","suite":1,"offered":[1],"confirm":"` + b64(make([]byte, 32)) + `"}`
		},
	} {
		b := newSide("cA")
		id := newCallID("cA")
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", id, "audio", ek, []int{1}, true, false))
		enc, _, _ := callwire.Answer(ek, id)
		b.h.Reset()
		r := featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", mk(id, enc))
		if len(b.h.SentOfType("call.answer")) != 0 {
			t.Errorf("%s: passed on (%q)", name, r.Code)
		}
		if c, _ := b.f.Get(id); c.State == StateActive {
			t.Errorf("%s: made active", name)
		}
	}
}

// call.list (C2): v: 2, now (the vault's clock), and per call exp (the
// offer's) and device_id (the call's device; absent while an incoming
// call rings).
func TestCallListV2(t *testing.T) {
	a := newSide("cB")
	a.addConn("cC")
	sk, _ := callwire.NewOfferKey()
	out := newCallID("lv2")
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", out, sk.Public().Bytes(), []int{1})); !r.OK() {
		t.Fatal(r.Code)
	}
	in := newCallID("cC")
	inExp := t0.Add(30 * time.Second)
	featuretest.CallExp(a.f, a.h, t0, inExp, "connection:cC", "call.offer", peerOffer("cC", in, "audio", sk.Public().Bytes()))
	now := t0.Add(1234 * time.Millisecond)
	r := featuretest.Call(a.f, a.h, now, "app", "call.list", `{}`)
	var got struct {
		V     int                          `json:"v"`
		Now   string                       `json:"now"`
		Calls []map[string]json.RawMessage `json:"calls"`
	}
	if err := json.Unmarshal(r.Body, &got); err != nil {
		t.Fatal(err)
	}
	if got.V != 2 || got.Now != envelope.FormatTS(now) || len(got.Calls) != 2 {
		t.Fatalf("%s", r.Body)
	}
	str := func(c map[string]json.RawMessage, k string) string {
		var v string
		_ = json.Unmarshal(c[k], &v)
		return v
	}
	seen := 0
	for _, c := range got.Calls {
		switch str(c, "call_id") {
		case out:
			seen++
			if str(c, "exp") != envelope.FormatTS(t0.Add(OfferTTL).UTC().Truncate(time.Millisecond)) || str(c, "device_id") != "dev-app" {
				t.Errorf("outgoing: %v", c)
			}
		case in:
			seen++
			if _, has := c["device_id"]; has || str(c, "exp") != envelope.FormatTS(inExp) {
				t.Errorf("incoming ringing: exp %s, device_id present %v", str(c, "exp"), has)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("%s", r.Body)
	}
}

// peerAnswerSigned is a call.answer from conn's vault: its share signed
// and vouched over sigM (form 1 or form 2 bytes), carrying the extra
// members given (form 2's, or none).
func peerAnswerSigned(conn, id string, enc, sigM []byte, extra string) string {
	dev := featuretest.DeviceKey("peer-device")
	devPub := dev.Public().(ed25519.PublicKey)
	ds, _ := callwire.SignShare(dev, sigM)
	vs, _ := suite.Sign(peerVault(conn), callwire.LabelVouch, callwire.VouchMessage(devPub, sigM))
	return `{"call_id":"` + id + `","sdp":"v=0","enc":"` + b64(enc) + `","device_ik":"` + b64(devPub) +
		`","device_sig":"` + b64(ds) + `","vault_sig":"` + b64(vs) + `"` + extra + `}`
}

// A peer's answer in the form its signatures don't cover, or with part of
// form 2, reaches no device: the call keeps ringing (drop.call_share). A
// vault that adds form 2's members to a form 1 answer, or strips them from
// a form 2 one, gains nothing.
func TestForm2PeerAnswerChecked(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	conf := `"` + b64(make([]byte, 32)) + `"`
	f2 := `,"suite":1,"offered":[1],"confirm":` + conf
	for name, mk := range map[string]func(id string, enc []byte) string{
		"form 2 members on a form 1 answer": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.ShareMessage(callwire.RoleAnswer, id, "", enc), f2)
		},
		"form 2 stripped": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.AnswerMessage2(id, 1, []int{1}, outP("cB"), enc), "")
		},
		"another choice than signed": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.AnswerMessage2(id, 1, []int{1, 2}, outP("cB"), enc), `,"suite":2,"offered":[1,2],"confirm":`+conf)
		},
		"no confirm": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.AnswerMessage2(id, 1, []int{1}, outP("cB"), enc), `,"suite":1,"offered":[1]`)
		},
		"no suite": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.AnswerMessage2(id, 1, []int{1}, outP("cB"), enc), `,"offered":[1],"confirm":`+conf)
		},
		"a short confirm": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.AnswerMessage2(id, 1, []int{1}, outP("cB"), enc), `,"suite":1,"offered":[1],"confirm":"`+b64(make([]byte, 31))+`"`)
		},
		"form 1 signed, a stray suite": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.ShareMessage(callwire.RoleAnswer, id, "", enc), `,"suite":1`)
		},
		"form 1 signed, a stray confirm": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.ShareMessage(callwire.RoleAnswer, id, "", enc), `,"confirm":`+conf)
		},
		"a bad offered": func(id string, enc []byte) string {
			return peerAnswerSigned("cB", id, enc, callwire.AnswerMessage2(id, 1, []int{1}, outP("cB"), enc), `,"suite":1,"offered":[1,1],"confirm":`+conf)
		},
	} {
		a := newSide("cB")
		id := newCallID("f2pa")
		if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", id, ek, []int{1})); !r.OK() {
			t.Fatalf("start: %q", r.Code)
		}
		enc, _, _ := callwire.Answer(ek, id)
		a.h.Reset()
		featuretest.Call(a.f, a.h, t0.Add(time.Second), "connection:cB", "call.answer", mk(id, enc))
		c, _ := a.f.Get(id)
		if len(a.h.SentOfType("call.answer")) != 0 || c.State != StateRinging || !a.h.HasActivity("drop.call_share") {
			t.Errorf("%s: passed on, ended or not audited (%s)", name, c.State)
		}
	}
	// The same answer in its own form goes through.
	a := newSide("cB")
	id := newCallID("f2pa")
	featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", id, ek, []int{1}))
	enc, _, _ := callwire.Answer(ek, id)
	featuretest.Call(a.f, a.h, t0.Add(time.Second), "connection:cB", "call.answer",
		peerAnswerSigned("cB", id, enc, callwire.AnswerMessage2(id, 1, []int{1}, outP("cB"), enc), f2))
	got := obj(t, a.sent(t, "dev-app", "call.answer").Body)
	if !got.Has("suite") || !got.Has("offered") || !got.Has("confirm") {
		t.Fatalf("form 2 members not passed on: %v", got)
	}
}

// A device's answer with part of form 2 is treated as a share that
// doesn't verify: audited, the device told unavailable, the call still
// rings.
func TestForm2PartialDeviceAnswer(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	for name, edit := range map[string]func(string) string{
		"no confirm": func(s string) string { return s[:strings.Index(s, `,"confirm":`)] + `}` },
		"no suite":   func(s string) string { return strings.Replace(s, `,"suite":1`, ``, 1) },
		"no offered": func(s string) string { return strings.Replace(s, `,"offered":[1]`, ``, 1) },
		"suite as a string": func(s string) string {
			return strings.Replace(s, `"suite":1`, `"suite":"1"`, 1)
		},
		// Signed in form 1, with one of form 2's members: not a form 1
		// answer either.
		"form 1 signed, a stray offered": func(string) string { return "form1:" + `,"offered":[1]` },
		"form 1 signed, a stray suite":   func(string) string { return "form1:" + `,"suite":1` },
	} {
		b := newSide("cA")
		id := newCallID("cA")
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", id, "audio", ek, []int{1}, true, false))
		enc, _, _ := callwire.Answer(ek, id)
		b.h.Reset()
		body := edit(answerBody2("dev-app", id, enc, 1, []int{1}, make([]byte, 32)))
		if extra, ok := strings.CutPrefix(body, "form1:"); ok {
			body = strings.TrimSuffix(answerBody("dev-app", id, enc), "}") + extra + "}"
		}
		featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", body)
		assertBadShareFromDevice(t, b, id, name)
	}
}

// The members' types: suites, suite and confirm in exactly their form.
func TestForm2MemberTypes(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	a := newSide("cB")
	id := newCallID("f2t")
	good := startBody2("cB", id, ek, []int{1})
	for _, v := range []string{`[-1]`, `[1e0]`, `[1.0]`, `["1"]`, `[01]`, `null`, `1`, `[[1]]`, `[true]`} {
		if c := featuretest.Call(a.f, a.h, t0, "app", "call.start", strings.Replace(good, `"suites":[1]`, `"suites":`+v, 1)).Code; c != "bad_request" {
			t.Errorf("start suites %s: %q", v, c)
		}
	}
	// A device's answer: suite and confirm malformed are refused as a bad
	// share (a device told unavailable, nothing passed on).
	cf := bytes.Repeat([]byte{0xff}, 32) // "//8…", so the URL alphabet differs
	conf := b64(cf)
	for name, edit := range map[string]func(string) string{
		"suite -1":                 func(s string) string { return strings.Replace(s, `"suite":1`, `"suite":-1`, 1) },
		"suite 1e0":                func(s string) string { return strings.Replace(s, `"suite":1`, `"suite":1e0`, 1) },
		"suite 1.0":                func(s string) string { return strings.Replace(s, `"suite":1`, `"suite":1.0`, 1) },
		"suite 0":                  func(s string) string { return strings.Replace(s, `"suite":1`, `"suite":0`, 1) },
		"suite 65536":              func(s string) string { return strings.Replace(s, `"suite":1`, `"suite":65536`, 1) },
		"confirm 31 bytes":         func(s string) string { return strings.Replace(s, conf, b64(make([]byte, 31)), 1) },
		"confirm 33 bytes":         func(s string) string { return strings.Replace(s, conf, b64(make([]byte, 33)), 1) },
		"confirm unpadded":         func(s string) string { return strings.Replace(s, conf, strings.TrimRight(conf, "="), 1) },
		"confirm url-safe":         func(s string) string { return strings.Replace(s, conf, b64url(cf), 1) },
		"confirm non-zero padding": func(s string) string { return strings.Replace(s, conf, conf[:len(conf)-2]+"9=", 1) },
		"offered null":             func(s string) string { return strings.Replace(s, `"offered":[1]`, `"offered":null`, 1) },
	} {
		b := newSide("cA")
		cid := newCallID("cA")
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", cid, "audio", ek, []int{1}, true, false))
		enc, _, _ := callwire.Answer(ek, cid)
		b.h.Reset()
		body := edit(answerBody2("dev-app", cid, enc, 1, []int{1}, cf))
		if body == answerBody2("dev-app", cid, enc, 1, []int{1}, cf) {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", body)
		assertBadShareFromDevice(t, b, cid, name)
	}
}

// Malformed form 2 in a peer's offer: dropped, audited.
func TestForm2PeerOfferMalformed(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	for name, edit := range map[string]func(s string) string{
		"a bad vault_sig2": func(s string) string {
			i := strings.Index(s, `"vault_sig2":"`) + len(`"vault_sig2":"`)
			return s[:i] + b64(make([]byte, 64)) + s[i+88:]
		},
		"sigs without suites": func(s string) string { return strings.Replace(s, `"suites":[1],`, ``, 1) },
		"suites [0]":          func(s string) string { return strings.Replace(s, `"suites":[1]`, `"suites":[0]`, 1) },
		"suites [1,1]":        func(s string) string { return strings.Replace(s, `"suites":[1]`, `"suites":[1,1]`, 1) },
		`suites ["1"]`:        func(s string) string { return strings.Replace(s, `"suites":[1]`, `"suites":["1"]`, 1) },
		"suites [1.0]":        func(s string) string { return strings.Replace(s, `"suites":[1]`, `"suites":[1.0]`, 1) },
		"suites null":         func(s string) string { return strings.Replace(s, `"suites":[1]`, `"suites":null`, 1) },
		"suites []":           func(s string) string { return strings.Replace(s, `"suites":[1]`, `"suites":[]`, 1) },
	} {
		b := newSide("cA")
		body := peerOffer2("cA", newCallID("cA"), "audio", ek, []int{1}, true, false)
		if edit(body) == body {
			t.Fatalf("%s: the edit changed nothing", name)
		}
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", edit(body))
		if len(b.h.SentOfType("call.offer")) != 0 || len(b.h.SentOfType("call.end")) != 0 || !b.h.HasActivity("drop.call_share") {
			t.Errorf("%s: rang, answered, or not audited", name)
		}
	}
}

func b64url(b []byte) string { return base64.URLEncoding.EncodeToString(b) }

// assertBadShareFromDevice: a device's answer was refused as a share that
// doesn't verify: audited, nothing passed on, the device told unavailable,
// the call still ringing.
func assertBadShareFromDevice(t *testing.T, b *side, id, name string) {
	t.Helper()
	c, _ := b.f.Get(id)
	end := b.h.SentOfType("call.end")
	if len(b.h.SentOfType("call.answer")) != 0 || c.State != StateRinging || !b.h.HasActivity("drop.call_share") ||
		len(end) != 1 || end[0].To != "dev-app" || string(end[0].Body) != string(endJSON(id, "unavailable")) {
		t.Errorf("%s: state %s, %d sent", name, c.State, len(b.h.Sent))
	}
}

// Values outside their limits, signed as sent, so only the parsing can
// refuse them: a device's answer, a peer's offer and a peer's answer.
func TestForm2OutOfRangeSigned(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	cf := make([]byte, 32)
	for name, c := range map[string]struct {
		suite   int
		offered []int
	}{
		"suite 0": {0, []int{1}}, "suite -1": {-1, []int{1}}, "suite 65536": {65536, []int{1}},
		"offered [1,1]": {1, []int{1, 1}}, "offered [0]": {1, []int{0}}, "offered nine": {1, []int{1, 2, 3, 4, 5, 6, 7, 8, 9}},
	} {
		// From a device.
		b := newSide("cA")
		id := newCallID("cA")
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", id, "audio", ek, []int{1}, true, false))
		enc, _, _ := callwire.Answer(ek, id)
		b.h.Reset()
		featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", answerBody2("dev-app", id, enc, c.suite, c.offered, cf))
		assertBadShareFromDevice(t, b, id, "device "+name)
		// From the peer.
		a := newSide("cB")
		oid := newCallID("f2or")
		featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", oid, ek, []int{1}))
		enc, _, _ = callwire.Answer(ek, oid)
		a.h.Reset()
		featuretest.Call(a.f, a.h, t0.Add(time.Second), "connection:cB", "call.answer", peerAnswerSigned("cB", oid, enc,
			callwire.AnswerMessage2(oid, c.suite, c.offered, outP("cB"), enc),
			`,"suite":`+itoa(c.suite)+`,"offered":`+string(suitesJSON(c.offered))+`,"confirm":"`+b64(cf)+`"`))
		if got, _ := a.f.Get(oid); len(a.h.SentOfType("call.answer")) != 0 || got.State != StateRinging || !a.h.HasActivity("drop.call_share") {
			t.Errorf("peer answer %s: passed on, ended or not audited", name)
		}
	}
	for name, suites := range map[string][]int{"[0]": {0}, "[1,1]": {1, 1}, "[65536]": {65536}, "nine": {1, 2, 3, 4, 5, 6, 7, 8, 9}} {
		b := newSide("cA")
		featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cA", "call.offer", peerOffer2("cA", newCallID("cA"), "audio", ek, suites, true, false))
		if len(b.h.SentOfType("call.offer")) != 0 || !b.h.HasActivity("drop.call_share") {
			t.Errorf("peer offer suites %s: rang, or not audited", name)
		}
	}
}

// Part of form 2 in an answer for a call that isn't there, isn't ringing
// or isn't the sender's: as any such answer, no drop.call_share (a
// connection can't have one audited against another's call); a device
// is told unavailable.
func TestForm2PartialForNoCall(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	b := newSide("cA")
	id := newCallID("cA")
	enc, _, _ := callwire.Answer(ek, id)
	partial := strings.Replace(answerBody2("dev-app", id, enc, 1, []int{1}, make([]byte, 32)), `,"suite":1`, ``, 1)
	featuretest.Call(b.f, b.h, t0, "app", "call.answer", partial)
	if end := b.h.SentOfType("call.end"); b.h.HasActivity("drop.call_share") || len(end) != 1 || end[0].To != "dev-app" {
		t.Fatalf("device, no call: %+v", b.h.Activities)
	}
	// Our call to cB, answered by cC with part of form 2.
	a := newSide("cB")
	a.addConn("cC")
	oid := newCallID("f2nc")
	featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", oid, ek, []int{1}))
	enc, _, _ = callwire.Answer(ek, oid)
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0.Add(time.Second), "connection:cC", "call.answer", peerAnswerSigned("cC", oid, enc,
		callwire.AnswerMessage2(oid, 1, []int{1}, outP("cC"), enc), `,"offered":[1]`))
	if a.h.HasActivity("drop.call_share") {
		t.Fatal("another connection's partial answer audited against our call")
	}
}

// (0.88.16) A call passed on by a shared connection fails on both sides.
// A's device calls C; C re-vouches A's device share for its own vault and
// offers it to B as its own call: B's vault checks "C calls B" and drops
// it. B's answer to such a call, passed back to A as C's, fails at A's
// vault, which checks "A calls C". A device that names another callee
// than the connection's key is refused at the start.
func TestForm2RelayedCall(t *testing.T) {
	sk, _ := callwire.NewOfferKey()
	ek := sk.Public().Bytes()
	aIK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xa1}, 32)).Public().(ed25519.PublicKey)
	cIK := peerVault("cC").Public().(ed25519.PublicKey)
	id := newCallID("relay")
	devA := featuretest.DeviceKey("peer-device")
	devPub := devA.Public().(ed25519.PublicKey)

	// B, whose connection C relays: A's device signed "A calls C".
	b := newSide("cC")
	m1 := callwire.ShareMessage(callwire.RoleOffer, id, "audio", ek)
	d1, _ := callwire.SignShare(devA, m1)
	signed := callwire.OfferMessage2(id, "audio", []int{1}, callwire.Parties{Caller: aIK, Callee: cIK}, ek)
	d2, _ := callwire.SignShare(devA, signed)
	v1, _ := suite.Sign(peerVault("cC"), callwire.LabelVouch, callwire.VouchMessage(devPub, m1))
	v2, _ := suite.Sign(peerVault("cC"), callwire.LabelVouch, callwire.VouchMessage(devPub, signed)) // C re-vouches what A signed
	offer := `{"call_id":"` + id + `","media":"audio","sdp":"v=0","ek":"` + b64(ek) + `","device_ik":"` + b64(devPub) +
		`","device_sig":"` + b64(d1) + `","vault_sig":"` + b64(v1) + `","suites":[1],"device_sig2":"` + b64(d2) + `","vault_sig2":"` + b64(v2) + `"}`
	featuretest.CallExp(b.f, b.h, t0, t0.Add(OfferTTL), "connection:cC", "call.offer", offer)
	if len(b.h.SentOfType("call.offer")) != 0 || !b.h.HasActivity("drop.call_share") {
		t.Fatal("B rang for a call passed on by C")
	}
	// Signed "C calls B", as C's own call would be, it rings.
	b2 := newSide("cC")
	featuretest.CallExp(b2.f, b2.h, t0, t0.Add(OfferTTL), "connection:cC", "call.offer", peerOffer2("cC", newCallID("relay"), "audio", ek, []int{1}, true, false))
	b2.sent(t, "devices", "call.offer")

	// A, whose call to cB is answered with B's answer passed on: B's
	// device signed "cB calls B" (B's own view), not "A calls cB".
	a := newSide("cB")
	oid := newCallID("relay")
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", oid, ek, []int{1})); !r.OK() {
		t.Fatal(r.Code)
	}
	enc, _, _ := callwire.Answer(ek, oid)
	bIK := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0xb2}, 32)).Public().(ed25519.PublicKey)
	cbIK := peerVault("cB").Public().(ed25519.PublicKey)
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0.Add(time.Second), "connection:cB", "call.answer", peerAnswerSigned("cB", oid, enc,
		callwire.AnswerMessage2(oid, 1, []int{1}, callwire.Parties{Caller: cbIK, Callee: bIK}, enc), `,"suite":1,"offered":[1],"confirm":"`+b64(make([]byte, 32))+`"`))
	if c, _ := a.f.Get(oid); len(a.h.SentOfType("call.answer")) != 0 || c.State != StateRinging || !a.h.HasActivity("drop.call_share") {
		t.Fatal("A used an answer passed on")
	}

	// A device that names another callee than the connection's key.
	a3 := newSide("cB")
	wrong := startBody2P("cB", newCallID("relay"), ek, []int{1}, callwire.Parties{Caller: testIK, Callee: cIK})
	if r := featuretest.Call(a3.f, a3.h, t0, "app", "call.start", wrong); r.Code != "bad_request" {
		t.Fatalf("a start naming another callee: %q", r.Code)
	}
	wrong = startBody2P("cB", newCallID("relay"), ek, []int{1}, callwire.Parties{Caller: aIK, Callee: cbIK})
	if r := featuretest.Call(a3.f, a3.h, t0, "app", "call.start", wrong); r.Code != "bad_request" {
		t.Fatalf("a start naming another caller: %q", r.Code)
	}
}
