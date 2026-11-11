package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hpkederand"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

func TestCallVectors(t *testing.T) { checkCallVectors(t, Dir) }

// checkCallVectors re-derives calls.json (§10.10) independently of
// callwire where it can (the HPKE values with the derandomized key
// schedule, the HKDF, the signed bytes and the Ed25519 signatures by
// hand), and through callwire's own receiving functions.
func checkCallVectors(t *testing.T, dir string) {
	d := load(t, dir, "calls.json")
	checkGlareVectors(t, d)
	for k, want := range map[string]string{"label_call": "vettid/vms/2/call", "label_call_key": "vettid/vms/2/call-key",
		"media_salt": "vettid-call-v1", "label_share": "vettid/vms/2/call-share", "label_vouch": "vettid/vms/2/call-vouch",
		"label_ice": "vettid/vms/2/ice"} {
		if d.str(k) != want {
			t.Errorf("%s = %q", k, d.str(k))
		}
	}
	id := d.str("call_id")
	type party struct {
		dev, vault       ed25519.PrivateKey
		devPub, vaultPub ed25519.PublicKey
	}
	load := func(name string) party {
		p := d.sub(name)
		dev, vault := ed25519.NewKeyFromSeed(p.hex("device_ik_seed_hex")), ed25519.NewKeyFromSeed(p.hex("vault_ik_seed_hex"))
		out := party{dev, vault, dev.Public().(ed25519.PublicKey), vault.Public().(ed25519.PublicKey)}
		eq(t, name+" device ik", out.devPub, p.b64("device_ik_b64"))
		eq(t, name+" vault ik", out.vaultPub, p.b64("vault_ik_b64"))
		return out
	}
	caller, callee := load("caller"), load("callee")

	// Key agreement.
	sk, err := suite.NewPrivateKey(d.hex("offer_kem_seed_hex"))
	if err != nil {
		t.Fatal(err)
	}
	ek, enc := d.b64("ek_b64"), d.b64("enc_b64")
	eq(t, "ek", sk.Public().Bytes(), ek)
	if len(ek) != callwire.EKSize || len(enc) != callwire.EncSize {
		t.Fatalf("sizes: ek %d, enc %d", len(ek), len(enc))
	}
	if d.str("info") != "vettid/vms/2/call"+id {
		t.Error("info")
	}
	s, err := hpkederand.NewSender(ek, []byte(d.str("info")), d.hex("answer_randomness_hex"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "enc", s.Enc(), enc)
	k, err := s.Export("vettid/vms/2/call-key", 32)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "exporter", k, d.hex("exporter_hex"))
	kCall, err := hkdf.Key(sha256.New, k, []byte("vettid-call-v1"), id, 32)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "k_call", kCall, d.hex("k_call_hex"))
	got, err := callwire.Accept(sk, enc, id)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "k_call (callwire.Accept)", got, kCall)
	if other, err := callwire.Accept(sk, enc, id[:len(id)-1]+"1"); err == nil && bytes.Equal(other, kCall) {
		t.Error("k_call is not bound to call_id")
	}

	// Shares.
	check := func(name, role, media string, share []byte, by party, wrongVault ed25519.PublicKey) {
		sh := d.sub(name)
		if sh.str("role") != role || sh.str("media") != media {
			t.Errorf("%s: role or media", name)
		}
		m := bytes.Join([][]byte{[]byte(role), []byte(id), []byte(media), share}, []byte{0})
		eq(t, name+" message", m, sh.b64("message_b64"))
		ds := ed25519.Sign(by.dev, append([]byte("vettid/vms/2/call-share"), m...))
		eq(t, name+" device_sig", ds, sh.b64("device_sig_b64"))
		vm := append(append([]byte(nil), by.devPub...), m...)
		eq(t, name+" vouch message", vm, sh.b64("vouch_message_b64"))
		vs := ed25519.Sign(by.vault, append([]byte("vettid/vms/2/call-vouch"), vm...))
		eq(t, name+" vault_sig", vs, sh.b64("vault_sig_b64"))
		if err := callwire.VerifyShare(by.vaultPub, by.devPub, m, ds, vs); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if callwire.VerifyShare(wrongVault, by.devPub, m, ds, vs) == nil {
			t.Errorf("%s: verifies under another vault's ik", name)
		}
	}
	check("offer_share", "offer", "audio", ek, caller, callee.vaultPub)
	check("answer_share", "answer", "", enc, callee, caller.vaultPub)

	// (C2) Form 2 and key confirmation, by hand: m2 with the suites, and
	// k_confirm and confirm by HKDF and HMAC. A frozen calls.json from
	// before C2 has none.
	if _, ok := d.m["offer_share2"]; ok {
		// ints reads a vector's suite list; list(x) is written by hand.
		ints := func(sh doc, k string) []int {
			var v []int
			if err := json.Unmarshal(sh.m[k], &v); err != nil || len(v) == 0 {
				t.Fatalf("%s: %v", k, err)
			}
			return v
		}
		list := func(v []int) string {
			parts := make([]string, len(v))
			for i, n := range v {
				parts[i] = strconv.Itoa(n)
			}
			return strings.Join(parts, " ")
		}
		check2 := func(name, role, media, lists string, share []byte, by party, wrongVault ed25519.PublicKey) {
			sh := d.sub(name)
			if sh.str("role") != role || sh.str("media") != media {
				t.Errorf("%s: role or media", name)
			}
			m := bytes.Join([][]byte{[]byte(role), []byte(id), []byte(media), []byte(lists), share}, []byte{0})
			eq(t, name+" message", m, sh.b64("message_b64"))
			if !callwire.ValidShareMessage(m) {
				t.Errorf("%s: a vault wouldn't vouch for it", name)
			}
			ds := ed25519.Sign(by.dev, append([]byte("vettid/vms/2/call-share"), m...))
			eq(t, name+" device_sig", ds, sh.b64("device_sig_b64"))
			vm := append(append([]byte(nil), by.devPub...), m...)
			eq(t, name+" vouch message", vm, sh.b64("vouch_message_b64"))
			vs := ed25519.Sign(by.vault, append([]byte("vettid/vms/2/call-vouch"), vm...))
			eq(t, name+" vault_sig", vs, sh.b64("vault_sig_b64"))
			if err := callwire.VerifyShare(by.vaultPub, by.devPub, m, ds, vs); err != nil {
				t.Errorf("%s: %v", name, err)
			}
			if callwire.VerifyShare(wrongVault, by.devPub, m, ds, vs) == nil {
				t.Errorf("%s: verifies under another vault's ik", name)
			}
			// A form 2 signature never verifies as form 1, nor the reverse.
			m1 := bytes.Join([][]byte{[]byte(strings.TrimSuffix(role, "2")), []byte(id), []byte(media), share}, []byte{0})
			if callwire.VerifyDeviceShare(by.devPub, m1, ds) == nil {
				t.Errorf("%s: a form 2 signature verifies over form 1", name)
			}
			ds1 := ed25519.Sign(by.dev, append([]byte("vettid/vms/2/call-share"), m1...))
			if callwire.VerifyDeviceShare(by.devPub, m, ds1) == nil {
				t.Errorf("%s: a form 1 signature verifies over form 2", name)
			}
		}
		offered := ints(d.sub("offer_share2"), "suites")
		a2 := d.sub("answer_share2")
		chosen := a2.num("suite")
		if got := ints(a2, "offered"); list(got) != list(offered) {
			t.Errorf("answer_share2 offered %v, the offer's suites %v", got, offered)
		}
		if callwire.ValidSuites(offered) != nil || !slices.Contains(offered, chosen) {
			t.Errorf("suites %v, suite %d", offered, chosen)
		}
		check2("offer_share2", "offer2", "audio", list(offered), ek, caller, callee.vaultPub)
		check2("answer_share2", "answer2", "", strconv.Itoa(chosen)+"\x00"+list(offered), enc, callee, caller.vaultPub)
		eq(t, "offer_share2 message (callwire)", callwire.OfferMessage2(id, "audio", offered, ek), d.sub("offer_share2").b64("message_b64"))
		eq(t, "answer_share2 message (callwire)", callwire.AnswerMessage2(id, chosen, offered, enc), a2.b64("message_b64"))
		if d.str("label_confirm") != "vettid/vms/2/call-confirm" {
			t.Error("label_confirm")
		}
		kc, err := hkdf.Key(sha256.New, kCall, []byte("vettid/vms/2/call-confirm"), id, 32)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, "k_confirm", kc, d.hex("k_confirm_hex"))
		mac := hmac.New(sha256.New, kc)
		mac.Write([]byte(strconv.Itoa(chosen) + "\x00" + list(offered) + "\x00" + id))
		eq(t, "confirm", mac.Sum(nil), d.b64("confirm_b64"))
		if !callwire.VerifyConfirm(kc, chosen, offered, id, d.b64("confirm_b64")) || callwire.VerifyConfirm(kc, chosen+1, offered, id, d.b64("confirm_b64")) {
			t.Error("confirm through callwire, or bound to the choice")
		}
	}

	// ICE configurations.
	exp := int64(d.num("ice_exp"))
	for name, want := range map[string]string{
		"ice": `{"v":1,"call_id":"` + id + `","exp":1800000000,"ice_servers":[{"urls":["stun:turn.example.org:3478"]},` +
			`{"urls":["turn:turn.example.org:3478?transport=udp","turns:turn.example.org:443?transport=tcp"],` +
			`"username":"1800000000:` + id + `","credential":"c2VjcmV0"}]}`,
		"ice_no_servers": `{"v":1,"call_id":"` + id + `","exp":1800000000,"ice_servers":[]}`,
	} {
		c := d.sub(name)
		cfg := c.b64("ice_config_b64")
		if c.str("config") != want || string(cfg) != want {
			t.Errorf("%s: config %s", name, cfg)
		}
		sig := ed25519.Sign(caller.vault, append([]byte("vettid/vms/2/ice"), cfg...))
		eq(t, name+" ice_sig", sig, c.b64("ice_sig_b64"))
		if _, err := callwire.VerifyICE(caller.vaultPub, cfg, sig, id, time.Unix(exp-1, 0)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := callwire.VerifyICE(caller.vaultPub, cfg, sig, id, time.Unix(exp, 0)); err != callwire.ErrICEStale {
			t.Errorf("%s: accepted at exp", name)
		}
		if _, err := callwire.VerifyICE(callee.vaultPub, cfg, sig, id, time.Unix(exp-1, 0)); err != callwire.ErrICESig {
			t.Errorf("%s: accepted under another vault's ik", name)
		}
	}
}

// checkGlareVectors re-derives the §10.10 "Glare" cases byte by byte (the
// lower call_id, as its 26 ASCII bytes, wins) and through callwire. A
// frozen calls.json from before C2's glare has none.
func checkGlareVectors(t *testing.T, d doc) {
	raw, ok := d.m["glare"]
	if !ok {
		return
	}
	var cases []struct {
		Own     string `json:"own"`
		Offer   string `json:"offer"`
		OwnWins bool   `json:"own_wins"`
	}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("glare: %v", err)
	}
	wins, losses := 0, 0
	for i, c := range cases {
		if !envelope.ValidULID(c.Own) || !envelope.ValidULID(c.Offer) {
			t.Errorf("glare %d: not call ids", i)
		}
		if got := bytes.Compare([]byte(c.Own), []byte(c.Offer)) < 0; got != c.OwnWins || callwire.LowerWins(c.Own, c.Offer) != c.OwnWins {
			t.Errorf("glare %d: own_wins %v", i, c.OwnWins)
		}
		if c.OwnWins {
			wins++
		} else {
			losses++
		}
	}
	if wins == 0 || losses == 0 {
		t.Error("glare: the cases don't show both outcomes")
	}
}
