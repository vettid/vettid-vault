package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hpkederand"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// checkDesktopVectors re-derives handshake_desktop.json (§6.3, §6.4, §6.7)
// from the receiving side: the pairing bundle and QR as the desktop reads
// them, hs.init (purpose desktop) as the vault opens it, hs.resp and hs.fin
// with the key schedule, SAS and signatures, and the hs.init bodies a vault
// must refuse.
func checkDesktopVectors(t *testing.T, dir string) {
	keys := load(t, dir, "keys.json")
	vault := checkPrincipal(t, keys.sub("vault"))
	d := load(t, dir, "handshake_desktop.json")
	dev := checkPrincipal(t, d.sub("desktop"))
	in := d.sub("inputs")
	t0, _ := time.Parse(time.RFC3339, "2026-10-01T12:00:00Z")
	if in.str("ts") != TS {
		t.Fatal("ts")
	}
	eph, err := suite.NewPrivateKey(in.hex("desktop_eph_seed_hex"))
	if err != nil {
		t.Fatal(err)
	}

	// The pairing bundle and QR (kind desktop, t = "d").
	pr := d.sub("pairing")
	blob := pr.b64("blob_b64")
	nonce := pr.hex("nonce_hex")
	bct, _ := suite.SealX(pr.hex("k_b_hex"), nonce, []byte("vettid/vms/2/bundle"), []byte(pr.str("bundle_json")))
	eq(t, "blob", append(bytes.Clone(nonce), bct...), blob)
	h := sha256.Sum256(blob)
	eq(t, "h", h[:], pr.hex("h_hex"))
	q, err := invite.ParseLink(pr.str("link"))
	if err != nil {
		t.Fatal(err)
	}
	qj, _ := q.Marshal()
	if string(qj) != pr.str("qr_json") || q.Kind != invite.KindDesktop || !strings.Contains(string(qj), `"t":"d"`) {
		t.Error("qr")
	}
	b, err := invite.OpenBundle(blob, q, t0)
	if err != nil {
		t.Fatal(err)
	}
	if b.Kind != "desktop" || b.InviteID != DesktopPairingID || b.Remote || b.Token != pr.str("open_token") ||
		!b.Vault.KEM.Equal(vault.kem.Public()) || b.Exp.Sub(t0) != invite.PairingTTL {
		t.Errorf("bundle %s", pr.str("bundle_json"))
	}
	if b.Vault.Relay.PK == nil || !bytes.Equal(b.Vault.Relay.PK, vault.relay.Public().(ed25519.PublicKey)) {
		t.Error("bundle relay")
	}
	if _, err := invite.OpenBundle(blob, q, b.Exp.Add(time.Second)); err == nil {
		t.Error("an expired pairing opens")
	}

	// hs.init as the vault receives it.
	envInit := d.b64("hs_init_envelope_b64")
	envResp := d.b64("hs_resp_envelope_b64")
	envFin := d.b64("hs_fin_envelope_b64")
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
	body := p.Init()
	ib, _ := body.Marshal()
	if string(ib) != d.str("hs_init_body") {
		t.Error("hs.init body")
	}
	if body.Purpose != "desktop" || body.Ctx != b.InviteID ||
		body.Token != DesktopTokenStanding || body.ReconnectToken != "" || body.DeviceAttest != nil || body.APIKey != nil ||
		body.UnlockSecret != nil || body.Rotations != nil || string(body.Profile) != `{"name":"`+DesktopName+`"}` {
		t.Error("hs.init members")
	}
	if !body.Eph.Equal(eph.Public()) || !body.From.KEM.Equal(dev.kem.Public()) {
		t.Error("eph or from.kem")
	}
	ie, _ := envelope.Parse(envInit)
	if ik := dev.kem.Public().Kid(); !ie.SenderKid().Equal(ik) || !ie.RecipientKid().Equal(vault.kem.Public().Kid()) {
		t.Error("hs.init kids")
	}
	_, iexp, err := envelope.OpenSealed(ie, vault.kem)
	if err != nil {
		t.Fatal(err)
	}
	ks, _ := iexp.Export("vettid/vms/2/hs-ks", 32)
	eq(t, "K_s", ks, d.hex("K_s_hex"))
	s, _ := hpkederand.NewSender(vault.kem.Public().Bytes(), []byte(suite.InfoSealed), in.hex("init_encapsulation_randomness_hex"))
	eq(t, "hs.init enc", envInit[20:1140], s.Enc())

	// hs.resp as the desktop receives it.
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
	if string(rj) != d.str("hs_resp_inner") || rin.Type != "hs.resp" || rin.ID != in.str("resp_id") {
		t.Error("hs.resp inner")
	}
	resp, err := handshake.ParseResp(rin.Body, handshake.PurposeDesktop)
	if err != nil || resp.Token != DesktopTokenResp || resp.ReconnectToken != "" || resp.Suite != 2 {
		t.Fatalf("hs.resp body: %v", err)
	}
	nI, nR := in.hex("n_I_hex"), in.hex("n_R_hex")
	eq(t, "hs.resp n_R", resp.SASNonce, nR)
	s2, _ := hpkederand.NewSender(eph.Public().Bytes(), []byte(suite.InfoSealed), in.hex("resp_encapsulation_randomness_hex"))
	eq(t, "hs.resp enc", envResp[20:1140], s2.Enc())

	// Transcript, key schedule, SAS, signatures.
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
	commit := sha256.Sum256(append([]byte("vettid/vms/2/sas-commit"), nI...))
	eq(t, "sas_commit", commit[:], d.hex("sas_commit_hex"))
	eq(t, "hs.init sas_commit", body.SASCommit, commit[:])
	if sas, _ := handshake.SAS(sc.PRK, th, nI, nR); sas != d.str("sas") {
		t.Errorf("sas %s", sas)
	}
	if handshake.VerifyResp(vault.ik.Public().(ed25519.PublicKey), th, d.b64("sig_R_b64")) != nil || !bytes.Equal(resp.Sig, d.b64("sig_R_b64")) {
		t.Error("sig_R")
	}
	if handshake.VerifyFin(dev.ik.Public().(ed25519.PublicKey), th, d.b64("sig_I_b64")) != nil {
		t.Error("sig_I")
	}

	// hs.fin: session mode, direction i2r, reveals n_I.
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
	got, err := handshake.ParseFin(fin.Body, handshake.PurposeDesktop)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "hs.fin sig", got.Sig, d.b64("sig_I_b64"))
	eq(t, "hs.fin n_I", got.SASNonce, nI)

	// The epoch policy of a device: 7 days, no message bound.
	var pol struct {
		MaxAge int `json:"max_age_seconds"`
	}
	if err := json.Unmarshal(d.m["epoch_policy"], &pol); err != nil {
		t.Fatal(err)
	}
	if time.Duration(pol.MaxAge)*time.Second != handshake.PolicyVaultToDevice.MaxAge || pol.MaxAge != 7*24*3600 ||
		handshake.PolicyVaultToDevice.MaxMessages != 0 {
		t.Error("epoch policy")
	}

	// A desktop's hs.init that a vault MUST refuse.
	var rejects []map[string]string
	if err := json.Unmarshal(d.m["hs_init_rejects"], &rejects); err != nil || len(rejects) == 0 {
		t.Fatal("hs_init_rejects")
	}
	if _, err := handshake.ParseInit([]byte(d.str("hs_init_body"))); err != nil {
		t.Fatal(err)
	}
	for _, r := range rejects {
		if r["body"] == d.str("hs_init_body") {
			t.Errorf("%s: unchanged", r["case"])
		}
		if _, err := handshake.ParseInit([]byte(r["body"])); err == nil {
			t.Errorf("%s: hs.init accepted", r["case"])
		}
	}
}
