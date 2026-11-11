package calls

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/suite"
)

// startBody2 is a form 2 call.start from dev-app (both forms signed).
func startBody2(conn, id string, ek []byte, suites []int) string {
	dev := featuretest.DeviceKey("dev-app")
	sig, _ := callwire.SignShare(dev, callwire.ShareMessage(callwire.RoleOffer, id, "video", ek))
	sig2, _ := callwire.SignShare(dev, callwire.OfferMessage2(id, "video", suites, ek))
	return `{"connection_id":"` + conn + `","call_id":"` + id + `","media":"video","sdp":"` + strings.ReplaceAll(sdpOffer, "\r\n", `\r\n`) +
		`","ek":"` + b64(ek) + `","ek_sig":"` + b64(sig) + `","suites":` + string(suitesJSON(suites)) + `,"ek_sig2":"` + b64(sig2) + `"}`
}

// answerBody2 is a form 2 call.answer from dev, enc_sig over m2.
func answerBody2(dev, id string, enc []byte, chosen int, offered []int, confirm []byte) string {
	sig, _ := callwire.SignShare(featuretest.DeviceKey(dev), callwire.AnswerMessage2(id, chosen, offered, enc))
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
	if r := featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", id, ek, suites)); !r.OK() {
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
		callwire.VerifyShare(a.h.IK, devIK, callwire.OfferMessage2(id, "video", suites, ek), d2, v2) != nil {
		t.Fatal("the offer's forms aren't both vouched")
	}
	featuretest.CallExp(b.f, b.h, t0, off.Opt.Exp, "connection:cA", "call.offer", string(off.Body))
	ring := b.sent(t, "devices", "call.offer")
	if r := obj(t, ring.Body); !r.Has("suites") || !r.Has("device_sig2") || !r.Has("vault_sig2") {
		t.Fatalf("the devices' offer lacks form 2: %s", ring.Body)
	}
	enc, kCall, err := callwire.Answer(ek, id)
	if err != nil {
		t.Fatal(err)
	}
	kc, _ := callwire.ConfirmKey(kCall, id)
	confirm := callwire.Confirm(kc, 1, suites, id)
	b.h.Reset()
	if r := featuretest.Call(b.f, b.h, t0.Add(time.Second), "app", "call.answer", answerBody2("dev-app", id, enc, 1, suites, confirm)); !r.OK() {
		t.Fatalf("answer: %q", r.Code)
	}
	fwd := b.sent(t, "cA", "call.answer")
	fo := obj(t, fwd.Body)
	fd, _ := fo.Base64("device_sig", 64)
	fv, _ := fo.Base64("vault_sig", 64)
	fdev, _ := fo.Base64("device_ik", ed25519.PublicKeySize)
	if callwire.VerifyShare(b.h.IK, fdev, callwire.AnswerMessage2(id, 1, suites, enc), fd, fv) != nil {
		t.Fatal("the answer isn't vouched over m2")
	}
	a.h.Reset()
	featuretest.Call(a.f, a.h, t0.Add(time.Second), "connection:cB", "call.answer", string(fwd.Body))
	got := obj(t, a.sent(t, "dev-app", "call.answer").Body)
	gc, _ := got.Base64("confirm", 32)
	if s, _ := got.Uint("suite", 1, 65535); s != 1 || !callwire.VerifyConfirm(kc, 1, suites, id, gc) {
		t.Fatal("the calling device didn't get the form 2 members")
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
	wrong, _ := callwire.SignShare(dev, callwire.OfferMessage2(id, "video", []int{2}, ek))
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
	m2 := callwire.OfferMessage2(id, media, suites, ek)
	if badDev2 {
		m2 = callwire.OfferMessage2(id, media, []int{2}, ek)
	}
	d2, _ := callwire.SignShare(dev, m2)
	v2, _ := suite.Sign(peerVault(conn), callwire.LabelVouch, callwire.VouchMessage(devPub, callwire.OfferMessage2(id, media, suites, ek)))
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
			sig, _ := callwire.SignShare(featuretest.DeviceKey("dev-app"), callwire.AnswerMessage2(id, 1, nil, enc))
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

// call.list (C2): v: 2, now, and per call exp and device_id.
func TestCallListV2(t *testing.T) {
	a := newSide("cB")
	sk, _ := callwire.NewOfferKey()
	id := newCallID("lv2")
	featuretest.Call(a.f, a.h, t0, "app", "call.start", startBody2("cB", id, sk.Public().Bytes(), []int{1}))
	r := featuretest.Call(a.f, a.h, t0.Add(time.Second), "app", "call.list", `{}`)
	o := obj(t, r.Body)
	if v, _ := o.Uint("v", 0, 10); v != 2 || mustStr(t, o, "now") == "" {
		t.Fatalf("%s", r.Body)
	}
	if !strings.Contains(string(r.Body), `"exp":"`) || !strings.Contains(string(r.Body), `"device_id":"dev-app"`) {
		t.Fatalf("per call: %s", r.Body)
	}
}
