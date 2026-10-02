package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hpkederand"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// doc is one parsed vector file with typed getters that fail the test.
type doc struct {
	t testing.TB
	m map[string]json.RawMessage
}

func load(t testing.TB, name string) doc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(Dir, name))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return doc{t, m}
}

func (d doc) sub(k string) doc {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(d.m[k], &m); err != nil {
		d.t.Fatalf("%s: %v", k, err)
	}
	return doc{d.t, m}
}

func (d doc) str(k string) string {
	var s string
	if err := json.Unmarshal(d.m[k], &s); err != nil {
		d.t.Fatalf("%s: %v", k, err)
	}
	return s
}

func (d doc) num(k string) int {
	var n int
	if err := json.Unmarshal(d.m[k], &n); err != nil {
		d.t.Fatalf("%s: %v", k, err)
	}
	return n
}

func (d doc) hex(k string) []byte {
	b, err := hex.DecodeString(d.str(k))
	if err != nil {
		d.t.Fatalf("%s: %v", k, err)
	}
	return b
}

func (d doc) b64(k string) []byte {
	b, err := base64.StdEncoding.DecodeString(d.str(k))
	if err != nil {
		d.t.Fatalf("%s: %v", k, err)
	}
	return b
}

func eq(t testing.TB, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got  %x\n want %x", what, got, want)
	}
}

type keyset struct {
	ik    ed25519.PrivateKey
	kem   *suite.PrivateKey
	relay ed25519.PrivateKey
}

func checkPrincipal(t *testing.T, d doc) keyset {
	t.Helper()
	ik := ed25519.NewKeyFromSeed(d.hex("ik_seed_hex"))
	eq(t, "ik_pk", ik.Public().(ed25519.PublicKey), d.b64("ik_pk_b64"))
	kem, err := suite.NewPrivateKey(d.hex("kem_seed_hex"))
	if err != nil {
		t.Fatal(err)
	}
	ek := kem.Public().Bytes()
	if len(ek) != suite.EKSize {
		t.Fatalf("ek %d bytes", len(ek))
	}
	eq(t, "ek", ek, d.b64("ek_b64"))
	kid := suite.KidOf(ek)
	eq(t, "kid", kid[:], d.hex("kid_hex"))
	h := sha256.Sum256(append([]byte("vettid/vms/2/kid"), ek...))
	eq(t, "kid (direct)", h[:8], d.hex("kid_hex"))
	ks := keyset{ik: ik, kem: kem}
	if _, ok := d.m["relay_seed_hex"]; ok {
		ks.relay = ed25519.NewKeyFromSeed(d.hex("relay_seed_hex"))
		pk := ks.relay.Public().(ed25519.PublicKey)
		eq(t, "relay_pk", pk, d.b64("relay_pk_b64"))
		if handshake.MailboxID(pk) != d.str("mailbox") {
			t.Error("mailbox")
		}
	}
	return ks
}

func kemFrom(t *testing.T, d doc) *suite.PrivateKey {
	t.Helper()
	k, err := suite.NewPrivateKey(d.hex("kem_seed_hex"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "ek", k.Public().Bytes(), d.b64("ek_b64"))
	kid := k.Public().Kid()
	eq(t, "kid", kid[:], d.hex("kid_hex"))
	return k
}

// TestVectors checks every vector file from the receiving side, deriving
// each value independently of the generator.
func TestVectors(t *testing.T) {
	keys := load(t, "keys.json")
	vault := checkPrincipal(t, keys.sub("vault"))
	ini := checkPrincipal(t, keys.sub("initiator"))
	eph := kemFrom(t, keys.sub("initiator_ephemeral"))
	etk := kemFrom(t, keys.sub("etk"))

	t.Run("hpke", func(t *testing.T) {
		d := load(t, "hpke.json")
		eq(t, "recipient ek", d.b64("recipient_ek_b64"), vault.kem.Public().Bytes())
		s, err := hpkederand.NewSender(d.b64("recipient_ek_b64"), []byte(d.str("info")), d.hex("encapsulation_randomness_hex"))
		if err != nil {
			t.Fatal(err)
		}
		v := s.Values()
		if d.num("enc_len") != suite.EncSize {
			t.Error("enc_len")
		}
		eq(t, "enc", v.Enc, d.b64("enc_b64"))
		eq(t, "shared_secret", v.SharedSecret, d.hex("shared_secret_hex"))
		eq(t, "key", v.Key, d.hex("key_hex"))
		eq(t, "base_nonce", v.BaseNonce, d.hex("base_nonce_hex"))
		eq(t, "exporter_secret", v.ExporterSecret, d.hex("exporter_secret_hex"))
	})

	t.Run("envelope_sealed", func(t *testing.T) {
		d := load(t, "envelope_sealed.json")
		h := load(t, "hpke.json")
		raw := d.b64("envelope_b64")
		if len(raw) != d.num("envelope_len") || len(raw) != 1668 || d.num("padded_len") != 512 {
			t.Fatalf("lengths %d", len(raw))
		}
		if d.str("inner") != SpecInner {
			t.Fatal("inner is not the §16 inner")
		}
		e, err := envelope.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		sk, rk := e.SenderKid(), e.RecipientKid()
		eq(t, "sender_kid", sk[:], d.hex("sender_kid_hex"))
		eq(t, "recipient_kid", rk[:], d.hex("recipient_kid_hex"))
		eq(t, "enc in header", raw[20:1140], h.b64("enc_b64"))
		padded, _, err := envelope.OpenSealed(e, vault.kem)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, "padded", padded, d.hex("padded_hex"))
		j, err := envelope.Unpad(padded)
		if err != nil || string(j) != SpecInner {
			t.Fatalf("inner: %v", err)
		}
		// Sender side, byte for byte, from the HPKE values.
		s, _ := hpkederand.NewSender(vault.kem.Public().Bytes(), []byte(suite.InfoSealed), h.hex("encapsulation_randomness_hex"))
		ct, _ := s.Seal(raw[:1140], padded)
		eq(t, "envelope", append(bytes.Clone(raw[:1140]), ct...), raw)
		if _, err := envelope.DecodeInner(padded, envelope.ModeSealed); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("envelope_session", func(t *testing.T) {
		d := load(t, "envelope_session.json")
		raw := d.b64("envelope_b64")
		if len(raw) != d.num("envelope_len") || len(raw) != 572 {
			t.Fatalf("length %d", len(raw))
		}
		hdr := append([]byte{2, 2, 1, 0}, d.hex("sender_kid_hex")...)
		hdr = append(hdr, d.hex("recipient_kid_hex")...)
		hdr = append(hdr, d.hex("nonce_hex")...)
		padded, err := envelope.Pad([]byte(d.str("inner")))
		if err != nil {
			t.Fatal(err)
		}
		ct, err := suite.SealX(d.hex("k_i2r_hex"), d.hex("nonce_hex"), hdr, padded)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, "envelope", append(hdr, ct...), raw)
		e, err := envelope.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := envelope.OpenSession(e, d.hex("k_i2r_hex"))
		if err != nil {
			t.Fatal(err)
		}
		in, err := envelope.DecodeInner(pt, envelope.ModeSession)
		if err != nil || in.Seq != 1 {
			t.Fatalf("inner: %v", err)
		}
	})

	t.Run("handshake", func(t *testing.T) {
		d := load(t, "handshake.json")
		in := d.sub("inputs")
		eq(t, "eph seed", in.hex("initiator_eph_seed_hex"), mustSeed(t, eph))
		envInit := d.b64("hs_init_envelope_b64")
		envResp := d.b64("hs_resp_envelope_b64")
		envFin := d.b64("hs_fin_envelope_b64")
		t0, _ := time.Parse(time.RFC3339, "2026-10-01T12:00:00Z")

		// hs.init as the vault receives it.
		lookup := func(k suite.Kid) *suite.PrivateKey {
			if k.Equal(vault.kem.Public().Kid()) {
				return vault.kem
			}
			return nil
		}
		p, err := handshake.OpenInit(envInit, lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		ib, _ := p.Init().Marshal()
		if string(ib) != d.str("hs_init_body") {
			t.Error("hs.init body")
		}
		if !p.Init().Eph.Equal(eph.Public()) {
			t.Error("eph")
		}
		ie, _ := envelope.Parse(envInit)
		sk := ie.SenderKid()
		ik := ini.kem.Public().Kid()
		eq(t, "hs.init sender_kid", sk[:], ik[:])
		_, iexp, err := envelope.OpenSealed(ie, vault.kem)
		if err != nil {
			t.Fatal(err)
		}
		ks, _ := iexp.Export("vettid/vms/2/hs-ks", 32)
		eq(t, "K_s", ks, d.hex("K_s_hex"))
		// Sender side of hs.init, byte for byte.
		s, _ := hpkederand.NewSender(vault.kem.Public().Bytes(), []byte(suite.InfoSealed), in.hex("init_encapsulation_randomness_hex"))
		eq(t, "hs.init enc", envInit[20:1140], s.Enc())

		// hs.resp as the initiator receives it.
		re, err := envelope.Parse(envResp)
		if err != nil {
			t.Fatal(err)
		}
		if !re.RecipientKid().Equal(eph.Public().Kid()) || !re.SenderKid().IsAnonymous() {
			t.Error("hs.resp kids")
		}
		rpad, rexp, err := envelope.OpenSealed(re, eph)
		if err != nil {
			t.Fatal(err)
		}
		ke, _ := rexp.Export("vettid/vms/2/hs-ke", 32)
		eq(t, "K_e", ke, d.hex("K_e_hex"))
		rin, err := envelope.DecodeInner(rpad, envelope.ModeSealed)
		if err != nil {
			t.Fatal(err)
		}
		rj, _ := rin.Marshal(envelope.ModeSealed)
		if string(rj) != d.str("hs_resp_inner") {
			t.Error("hs.resp inner")
		}
		s2, _ := hpkederand.NewSender(eph.Public().Bytes(), []byte(suite.InfoSealed), in.hex("resp_encapsulation_randomness_hex"))
		eq(t, "hs.resp enc", envResp[20:1140], s2.Enc())

		// Transcript and key schedule, from the formulas of §6.3.
		th1 := sha256.Sum256(append([]byte("vettid/vms/2/th1"), envInit...))
		eq(t, "th1", th1[:], d.hex("th1_hex"))
		th := sha256.Sum256(append(append([]byte("vettid/vms/2/th"), envInit...), envResp[:1140]...))
		eq(t, "th", th[:], d.hex("th_hex"))
		sc, err := handshake.DeriveSchedule(ks, ke, th1, th)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, "prk", sc.PRK, d.hex("prk_hex"))
		eq(t, "k_i2r", sc.KI2R, d.hex("k_i2r_hex"))
		eq(t, "k_r2i", sc.KR2I, d.hex("k_r2i_hex"))
		eq(t, "kid_i2r", sc.KidI2R[:], d.hex("kid_i2r_hex"))
		eq(t, "kid_r2i", sc.KidR2I[:], d.hex("kid_r2i_hex"))
		eq(t, "rk", sc.RK, d.hex("rk_hex"))
		eq(t, "epoch_id", sc.EpochID[:], d.hex("epoch_id_hex"))
		sas, _ := handshake.SAS(ks, th1)
		if sas != d.str("sas") {
			t.Errorf("sas %s", sas)
		}

		// Signatures.
		sigR := d.b64("sig_R_b64")
		if handshake.VerifyResp(vault.ik.Public().(ed25519.PublicKey), th, sigR) != nil {
			t.Error("sig_R")
		}
		if !strings.Contains(string(rpad), d.str("sig_R_b64")) {
			t.Error("sig_R not in hs.resp")
		}
		sigI := d.b64("sig_I_b64")
		if handshake.VerifyFin(ini.ik.Public().(ed25519.PublicKey), th, sigI) != nil {
			t.Error("sig_I")
		}
		myR, _ := handshake.SignResp(vault.ik, th)
		eq(t, "sig_R (Ed25519 is deterministic)", myR, sigR)

		// hs.fin: session mode, direction i2r, opened with k_i2r.
		fe, err := envelope.Parse(envFin)
		if err != nil {
			t.Fatal(err)
		}
		if fe.Mode() != envelope.ModeSession || !fe.RecipientKid().Equal(sc.KidI2R) || !fe.SenderKid().Equal(sc.KidR2I) {
			t.Error("hs.fin header")
		}
		eq(t, "hs.fin nonce", envFin[20:44], in.hex("fin_nonce_hex"))
		fpad, err := envelope.OpenSession(fe, sc.KI2R)
		if err != nil {
			t.Fatal(err)
		}
		fin, err := envelope.DecodeInner(fpad, envelope.ModeSession)
		if err != nil || fin.Type != "hs.fin" || fin.Seq != 1 || fin.ID != in.str("fin_id") {
			t.Fatalf("hs.fin inner: %v", err)
		}
		got, err := handshake.ParseFin(fin.Body)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, "hs.fin sig", got, sigI)
	})

	t.Run("invite", func(t *testing.T) {
		d := load(t, "invite.json")
		blob := d.b64("blob_b64")
		nonce := d.hex("nonce_hex")
		ct, _ := suite.SealX(d.hex("k_b_hex"), nonce, []byte("vettid/vms/2/bundle"), []byte(d.str("bundle_json")))
		eq(t, "blob", append(bytes.Clone(nonce), ct...), blob)
		h := sha256.Sum256(blob)
		eq(t, "h", h[:], d.hex("h_hex"))
		q, err := invite.ParseLink(d.str("link"))
		if err != nil {
			t.Fatal(err)
		}
		qj, _ := q.Marshal()
		if string(qj) != d.str("qr_json") {
			t.Error("qr json")
		}
		now, _ := time.Parse(time.RFC3339, d.str("now"))
		b, err := invite.OpenBundle(blob, q, now)
		if err != nil {
			t.Fatal(err)
		}
		if !b.Vault.KEM.Equal(vault.kem.Public()) {
			t.Error("bundle vault kem")
		}
	})

	t.Run("altchan", func(t *testing.T) {
		d := load(t, "altchan.json")
		desc := []byte(d.str("descriptor"))
		ud := sha256.Sum256(append([]byte("vettid/vms/2/etk"), desc...))
		eq(t, "descriptor user_data", ud[:], d.hex("descriptor_user_data_hex"))
		if !strings.Contains(string(desc), base64.StdEncoding.EncodeToString(etk.Public().Bytes())) {
			t.Error("descriptor etk")
		}
		for _, k := range []string{"devatt_enroll", "devatt_unlock"} {
			c := d.sub(k)
			want := sha256.Sum256([]byte("vettid/vms/2/devatt" + c.str("request_id") + c.str("vault_id") + c.str("ts")))
			eq(t, k, want[:], c.hex("challenge_hex"))
			got, err := altchan.DevattChallenge(c.str("request_id"), c.str("vault_id"), c.str("ts"))
			if err != nil {
				t.Fatal(err)
			}
			eq(t, k+" (lib)", got[:], want[:])
		}
		f := d.sub("unlock_fields")
		kid, _ := suite.ParseKidHex(f.str("etk_kid_hex"))
		if !kid.Equal(etk.Public().Kid()) {
			t.Error("etk kid")
		}
		pin := sha256.Sum256([]byte(f.str("pin")))
		tok := sha256.Sum256([]byte(f.str("token")))
		want := strings.Join([]string{"vettid/vms/2/unlock", f.str("user_guid"), f.str("vault_id"), f.str("request_id"),
			f.str("ts"), f.str("etk_kid_hex"), "1234", "1301", hex.EncodeToString(pin[:]), hex.EncodeToString(tok[:])}, "\n")
		if d.str("unlock_signing_string") != want {
			t.Error("unlock signing string")
		}
		if !ed25519.Verify(ini.ik.Public().(ed25519.PublicKey), []byte(want), d.b64("unlock_sig_b64")) {
			t.Error("unlock sig")
		}
		raw := d.b64("unlock_envelope_b64")
		if len(raw) != 5252 || d.num("unlock_envelope_len") != 5252 {
			t.Fatalf("unlock envelope %d", len(raw))
		}
		e, err := envelope.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		pt, _, err := envelope.OpenSealed(e, etk)
		if err != nil {
			t.Fatal(err)
		}
		j, err := envelope.UnpadFixed(pt, 4096)
		if err != nil || string(j) != d.str("unlock_inner") {
			t.Fatalf("unlock inner: %v", err)
		}
		ui, err := envelope.ParseInner(j, envelope.ModeSealed)
		if err != nil {
			t.Fatal(err)
		}
		var ub map[string]json.RawMessage
		if err := json.Unmarshal(ui.Body, &ub); err != nil {
			t.Fatal(err)
		}
		if _, err := altchan.ParseDeviceAssertion(ub["device_assertion"]); err != nil {
			t.Fatalf("device_assertion: %v", err)
		}
		s, _ := hpkederand.NewSender(etk.Public().Bytes(), []byte(suite.InfoSealed), d.hex("unlock_encapsulation_randomness_hex"))
		ct, _ := s.Seal(raw[:1140], pt)
		eq(t, "unlock envelope", append(bytes.Clone(raw[:1140]), ct...), raw)
	})
}

func mustSeed(t *testing.T, k *suite.PrivateKey) []byte {
	s, err := k.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
