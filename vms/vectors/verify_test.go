package vectors

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
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
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

// doc is one parsed vector file with typed getters that fail the test.
type doc struct {
	t testing.TB
	m map[string]json.RawMessage
}

func load(t testing.TB, dir, name string) doc {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
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
func TestVectors(t *testing.T) { checkVectors(t, Dir) }

// checkVectors checks the vector files in dir: HEAD's code must derive
// every value of them, whether they are HEAD's own vectors or a published
// release's frozen ones (TestFrozenReleaseVectors).
func checkVectors(t *testing.T, dir string) {
	keys := load(t, dir, "keys.json")
	vault := checkPrincipal(t, keys.sub("vault"))
	ini := checkPrincipal(t, keys.sub("initiator"))
	eph := kemFrom(t, keys.sub("initiator_ephemeral"))
	etk := kemFrom(t, keys.sub("etk"))
	if _, ok := keys.m["ik_fingerprint"]; ok { // 0.18.0; absent in older frozen vectors
		t.Run("ik_fingerprint", func(t *testing.T) {
			d := keys.sub("ik_fingerprint")
			ik := vault.ik.Public().(ed25519.PublicKey)
			eq(t, "ik", d.b64("ik_b64"), ik)
			h := sha256.Sum256(append([]byte("vettid/vms/2/ik-fp"), ik...))
			eq(t, "sha256", h[:], d.hex("sha256_hex"))
			fp := suite.IKFingerprint(ik)
			eq(t, "sha256 (suite)", fp[:], h[:])
			hx := hex.EncodeToString(h[:16])
			var g []string
			for i := 0; i < 32; i += 4 {
				g = append(g, hx[i:i+4])
			}
			if s := strings.Join(g, " "); d.str("shown") != s || suite.FormatIKFingerprint(ik) != s {
				t.Fatalf("shown %q, want %q", d.str("shown"), s)
			}
			// §16 (0.18.0): the vector the spec prints.
			if d.str("shown") != "9a1f bb7d 873e eafb 494b ef94 f072 7b25" ||
				d.str("sha256_hex") != "9a1fbb7d873eeafb494bef94f0727b2539c2faf27783d46d4e6862673f6216c3" {
				t.Fatal("not the §16 vector")
			}
		})
	}

	t.Run("hpke", func(t *testing.T) {
		d := load(t, dir, "hpke.json")
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
		d := load(t, dir, "envelope_sealed.json")
		h := load(t, dir, "hpke.json")
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
		d := load(t, dir, "envelope_session.json")
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
		d := load(t, dir, "handshake.json")
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
		// The SAS commitment and the SAS (0.10.3).
		nI, nR := in.hex("n_I_hex"), in.hex("n_R_hex")
		commit := sha256.Sum256(append([]byte("vettid/vms/2/sas-commit"), nI...))
		eq(t, "sas_commit", commit[:], d.hex("sas_commit_hex"))
		eq(t, "hs.init sas_commit", p.Init().SASCommit, commit[:])
		sas, _ := handshake.SAS(sc.PRK, th, nI, nR)
		if sas != d.str("sas") {
			t.Errorf("sas %s", sas)
		}
		if !strings.Contains(d.str("hs_resp_inner"), `"sas_nonce":"`+base64.StdEncoding.EncodeToString(nR)+`"`) {
			t.Error("n_R not in hs.resp")
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
		got, err := handshake.ParseFin(fin.Body, handshake.PurposeConnection)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, "hs.fin sig", got.Sig, sigI)
		eq(t, "hs.fin n_I", got.SASNonce, nI)
	})

	t.Run("invite", func(t *testing.T) {
		d := load(t, dir, "invite.json")
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
		d := load(t, dir, "altchan.json")
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
		rel := load(t, dir, "release.json")
		man := sha256.Sum256([]byte(rel.str("manifest")))
		eq(t, "unlock manifest hash", man[:], f.hex("manifest_sha256_hex"))
		want := strings.Join([]string{"vettid/vms/2/unlock", f.str("user_guid"), f.str("vault_id"), f.str("request_id"),
			f.str("ts"), f.str("etk_kid_hex"), "1234", "1301", hex.EncodeToString(pin[:]), hex.EncodeToString(tok[:]),
			hex.EncodeToString(man[:]), f.str("to_pcr0_hex")}, "\n")
		if d.str("unlock_signing_string") != want {
			t.Error("unlock signing string")
		}
		if !ed25519.Verify(ini.ik.Public().(ed25519.PublicKey), []byte(want), d.b64("unlock_sig_b64")) {
			t.Error("unlock sig")
		}
		raw := d.b64("unlock_envelope_b64")
		if len(raw) != 13444 || d.num("unlock_envelope_len") != 13444 {
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
		j, err := envelope.UnpadFixed(pt, 12288)
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
		// 0.10.0: the request names the manifest by hash and serial; the
		// document itself is not in the request.
		var mh string
		var ms int
		if json.Unmarshal(ub["manifest_sha256"], &mh) != nil || mh != rel.str("manifest_sha256_hex") ||
			json.Unmarshal(ub["manifest_serial"], &ms) != nil || ms != 7 {
			t.Fatal("unlock manifest_sha256 / manifest_serial")
		}
		if _, ok := ub["manifest"]; ok {
			t.Fatal("unlock still carries the manifest document")
		}
		s, _ := hpkederand.NewSender(etk.Public().Bytes(), []byte(suite.InfoSealed), d.hex("unlock_encapsulation_randomness_hex"))
		ct, _ := s.Seal(raw[:1140], pt)
		eq(t, "unlock envelope", append(bytes.Clone(raw[:1140]), ct...), raw)
	})
}

// §11.10 release vectors, checked from the receiving side.
func TestReleaseVectors(t *testing.T) { checkReleaseVectors(t, Dir) }

func checkReleaseVectors(t *testing.T, dir string) {
	d := load(t, dir, "release.json")
	mb := []byte(d.str("manifest"))
	if len(mb) != 1060 || d.num("manifest_len") != 1060 {
		t.Fatalf("manifest length %d", len(mb))
	}
	h := sha256.Sum256(mb)
	eq(t, "manifest sha256", h[:], d.hex("manifest_sha256_hex"))
	dg := sha256.Sum256(append([]byte("vettid/pcr-manifest/1\x00"), mb...))
	eq(t, "manifest signed digest", dg[:], d.hex("manifest_signed_digest_hex"))
	spki := d.b64("manifest_key_spki_b64")
	ks := sha256.Sum256(spki)
	if hex.EncodeToString(ks[:8]) != d.str("manifest_key_id") {
		t.Error("key_id")
	}
	pk, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		t.Fatal(err)
	}
	pub := pk.(*ecdsa.PublicKey)
	sig := d.b64("manifest_sig_b64")
	if len(sig) != 64 || !ecdsa.Verify(pub, dg[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Error("manifest signature")
	}
	priv, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d.hex("manifest_key_scalar_hex"))
	if err != nil || !priv.PublicKey.Equal(pub) {
		t.Error("manifest key scalar")
	}
	s, err := manifest.ParseServed([]byte(d.str("served")))
	if err != nil {
		t.Fatal(err)
	}
	if m, err := manifest.Verify(s, []*ecdsa.PublicKey{pub}); err != nil || m.Serial != 7 || len(m.Releases) != 2 {
		t.Fatalf("library verify: %v", err)
	}
	a := d.sub("approval")
	want := strings.Join([]string{"vettid/vms/2/release-approval", a.str("vault_id"), a.str("request_id"), a.str("from_pcr0_hex"),
		a.str("to_pcr0_hex"), "4", "7"}, "\n")
	if a.str("signing_string") != want {
		t.Error("approval string")
	}
	if got, _ := altchan.ApprovalSigningString(a.str("vault_id"), a.str("request_id"), a.str("from_pcr0_hex"), a.str("to_pcr0_hex"), 4, 7); got != want {
		t.Error("approval string (lib)")
	}
	ah := sha256.Sum256([]byte(want))
	eq(t, "approval sha256", ah[:], a.hex("signing_string_sha256_hex"))
	dk, err := x509.ParsePKIXPublicKey(a.b64("device_key_spki_b64"))
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(dk.(*ecdsa.PublicKey), ah[:], a.b64("sig_der_b64")) {
		t.Error("approval signature")
	}
	u := d.sub("unlock_with_update")
	if !strings.HasSuffix(u.str("signing_string"), "\n"+hex.EncodeToString(h[:])+"\n"+a.str("to_pcr0_hex")) {
		t.Error("unlock signing string with update")
	}
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{SeedInitIK}, 32))
	if !ed25519.Verify(ik.Public().(ed25519.PublicKey), []byte(u.str("signing_string")), u.b64("sig_b64")) {
		t.Error("unlock sig with update")
	}
	// 0.10.0: removed and ends_at.
	n := d.sub("manifest_0_10_0")
	nb := []byte(n.str("manifest"))
	if len(nb) != n.num("manifest_len") {
		t.Error("0.10.0 manifest length")
	}
	nh := sha256.Sum256(nb)
	eq(t, "0.10.0 manifest sha256", nh[:], n.hex("manifest_sha256_hex"))
	if n.str("object_key") != "manifests/"+hex.EncodeToString(nh[:])+".json" {
		t.Error("object key")
	}
	ndg := sha256.Sum256(append([]byte("vettid/pcr-manifest/1\x00"), nb...))
	eq(t, "0.10.0 manifest signed digest", ndg[:], n.hex("manifest_signed_digest_hex"))
	nsig := n.b64("manifest_sig_b64")
	if len(nsig) != 64 || !ecdsa.Verify(pub, ndg[:], new(big.Int).SetBytes(nsig[:32]), new(big.Int).SetBytes(nsig[32:])) {
		t.Error("0.10.0 manifest signature")
	}
	nm, err := manifest.VerifyByHash([]byte(n.str("served")), n.str("manifest_sha256_hex"), 8, []*ecdsa.PublicKey{pub})
	if err != nil || len(nm.Releases) != 3 || nm.Releases[0].Status != manifest.StatusRemoved || nm.Releases[0].EndsAt.IsZero() ||
		nm.Releases[1].Status != manifest.StatusRetired || !nm.Releases[2].EndsAt.IsZero() {
		t.Fatalf("0.10.0 library verify: %v", err)
	}
	if !bytes.Contains(nb, []byte(`"status":"removed","published_at":"2025-09-01T00:00:00Z","ends_at":"2026-09-01T00:00:00Z","notes"`)) {
		t.Error("0.10.0 member order")
	}
}

// §11.11.2 recovery vectors, checked from the portal's side: the browser
// key opens both seals with an independent key schedule, and the library
// opens them and builds the QR.
func TestRecoveryVectors(t *testing.T) { checkRecoveryVectors(t, Dir) }

func checkRecoveryVectors(t *testing.T, dir string) {
	d := load(t, dir, "recovery.json")
	bk, err := ecdh.P256().NewPrivateKey(d.hex("browser_key_scalar_hex"))
	if err != nil {
		t.Fatal(err)
	}
	bpub := bk.PublicKey().Bytes()
	eq(t, "browser key", bpub, d.hex("browser_key_pub_hex"))
	vid, rid, code := d.str("vault_id"), d.str("recovery_id"), d.str("code")
	cb, err := base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding).DecodeString(code)
	if err != nil || len(code) != 32 {
		t.Fatalf("code form: %v", err)
	}
	eq(t, "code bytes", cb, d.hex("code_bytes_hex"))
	ch := sha256.Sum256([]byte("vettid/vms/2/recovery-code\x00" + vid + "\x00" + rid + "\x00" + code))
	eq(t, "code hash", ch[:], d.hex("code_hash_hex"))
	info := "vettid/vms/2/recovery-code-seal\x00" + vid + "\x00" + rid
	open := func(name string) map[string]any {
		s := d.sub(name)
		out := s.b64("out_b64")
		if len(out) != 5252 || s.num("out_len") != 5252 || out[0] != 0x01 {
			t.Fatalf("%s: out length %d", name, len(out))
		}
		oh := sha256.Sum256(out)
		eq(t, name+" out sha256", oh[:], s.hex("out_sha256_hex"))
		eph, err := ecdh.P256().NewPrivateKey(s.hex("eph_scalar_hex"))
		if err != nil {
			t.Fatal(err)
		}
		eq(t, name+" eph", out[1:66], eph.PublicKey().Bytes())
		eq(t, name+" eph pub", out[1:66], s.hex("eph_pub_hex"))
		eq(t, name+" nonce", out[66:78], s.hex("nonce_hex"))
		eq(t, name+" aad", out[:78], s.hex("aad_hex"))
		// The portal's side: ECDH with the browser key.
		ephPub, err := ecdh.P256().NewPublicKey(out[1:66])
		if err != nil {
			t.Fatal(err)
		}
		shared, err := bk.ECDH(ephPub)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, name+" ecdh", shared, s.hex("ecdh_shared_hex"))
		salt := append(append([]byte(nil), out[1:66]...), bpub...)
		eq(t, name+" salt", salt, s.hex("hkdf_salt_hex"))
		k, err := hkdf.Key(sha256.New, shared, salt, info, 32)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, name+" k", k, s.hex("k_hex"))
		blk, _ := aes.NewCipher(k)
		g, _ := cipher.NewGCM(blk)
		pt, err := g.Open(nil, out[66:78], out[78:], out[:78])
		if err != nil {
			t.Fatalf("%s: AES-GCM open: %v", name, err)
		}
		js := []byte(s.str("pt_json"))
		if len(pt) != s.num("pt_len") || len(pt) != 5252-78-16 {
			t.Fatalf("%s: pt length %d", name, len(pt))
		}
		eq(t, name+" pt", pt, append(bytes.Clone(js), make([]byte, len(pt)-len(js))...))
		var m map[string]any
		if err := json.Unmarshal(js, &m); err != nil {
			t.Fatal(err)
		}
		if m["v"] != float64(1) || m["vault_id"] != vid || m["recovery_id"] != rid {
			t.Fatalf("%s: pt %s", name, js)
		}
		return m
	}
	m := open("sealed")
	if len(m) != 6 || m["code"] != code || m["not_before"] != d.str("not_before") || m["expires_at"] != d.str("expires_at") {
		t.Fatalf("sealed pt: %v", m)
	}
	if nb, _ := envelope.ParseTS(d.str("not_before")); !nb.Add(24 * time.Hour).Equal(mustTS(t, d.str("expires_at"))) {
		t.Error("expires_at = not_before + 24 h")
	}
	if m := open("no_credential"); len(m) != 4 || m["error"] != "no_credential" {
		t.Fatalf("no_credential pt: %v", m)
	}
	// 0.16.0 (§16): the no_backup refusal, eph 32 x 0x28, nonce 12 x 0x29;
	// absent from frozen vectors of earlier releases.
	if _, ok := d.m["no_backup"]; ok {
		nb := d.sub("no_backup")
		eq(t, "no_backup eph scalar", nb.hex("eph_scalar_hex"), bytes.Repeat([]byte{0x28}, 32))
		eq(t, "no_backup nonce", nb.hex("nonce_hex"), bytes.Repeat([]byte{0x29}, 12))
		if m := open("no_backup"); len(m) != 4 || m["error"] != "no_backup" {
			t.Fatalf("no_backup pt: %v", m)
		}
		if r, err := altchan.OpenRecoveryCode(bk, nb.b64("out_b64"), vid, rid); err != nil || r.Error != "no_backup" || r.Code != "" {
			t.Fatalf("library open (no_backup): %v", err)
		}
	} else if dir == Dir {
		t.Error("recovery.json lacks no_backup (0.16.0)")
	}
	// The library opens both.
	c, err := altchan.OpenRecoveryCode(bk, d.sub("sealed").b64("out_b64"), vid, rid)
	if err != nil || c.Code != code || envelope.FormatTS(c.NotBefore) != d.str("not_before") || envelope.FormatTS(c.Expires) != d.str("expires_at") {
		t.Fatalf("library open: %v", err)
	}
	if r, err := altchan.OpenRecoveryCode(bk, d.sub("no_credential").b64("out_b64"), vid, rid); err != nil || r.Error != "no_credential" || r.Code != "" {
		t.Fatalf("library open (no_credential): %v", err)
	}
	// The QR payload.
	want := `{"v":1,"t":"r","vault_id":"` + vid + `","recovery_id":"` + rid + `","code":"` + code + `"}`
	if d.str("qr") != want || string(altchan.RecoveryQR(c)) != want {
		t.Errorf("qr: %s", d.str("qr"))
	}
	if q, err := altchan.ParseRecoveryQR([]byte(d.str("qr"))); err != nil || q.Code != code || q.VaultID != vid || q.RecoveryID != rid {
		t.Errorf("parse qr: %v", err)
	}
}

func mustTS(t *testing.T, s string) time.Time {
	ts, err := envelope.ParseTS(s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

func mustSeed(t *testing.T, k *suite.PrivateKey) []byte {
	s, err := k.Seed()
	if err != nil {
		t.Fatal(err)
	}
	return s
}
