package vectors

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hpkederand"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// epochFrom imports one side's epoch from the values of a vector file's
// epoch object (k_i2r, k_r2i, kids, rk, epoch id): initiator is the side
// that was I in the handshake that made the epoch.
func epochFrom(t *testing.T, d doc, initiator bool, policy handshake.Policy, now time.Time) *handshake.Epoch {
	t.Helper()
	i2r, r2i := d.hex("k_i2r_hex"), d.hex("k_r2i_hex")
	kI2R, kR2I := d.hex("kid_i2r_hex"), d.hex("kid_r2i_hex")
	s := handshake.EpochState{
		ID: d.hex("epoch_id_hex"), Role: handshake.RoleResponder, Suite: 2, Policy: policy, Created: now,
		SendKey: r2i, SendRecipientKid: kR2I, SendSenderKid: kI2R,
		RecvKey: i2r, RecvKid: kI2R, RecvSenderKid: kR2I, RK: d.hex("rk_hex"),
	}
	if initiator {
		s.Role = handshake.RoleInitiator
		s.SendKey, s.SendRecipientKid, s.SendSenderKid = i2r, kI2R, kR2I
		s.RecvKey, s.RecvKid, s.RecvSenderKid = r2i, kR2I, kI2R
	}
	e, err := handshake.ImportEpoch(s)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// hkdfExpand is HKDF-Expand(prk, label || th, n) of §6.3.
func hkdfExpand(t *testing.T, prk []byte, label string, th []byte, n int) []byte {
	t.Helper()
	b, err := hkdf.Expand(sha256.New, prk, label+string(th), n)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkRekeyVectors re-derives rekey.json (§6.5) from the receiving side:
// hs.init as the peer opens it under the old epoch, hs.resp as the
// initiator opens it with its ephemeral key, hs.fin and the first message
// of each direction in the new epoch, and every value of the key schedule
// by hand from K_s = the old epoch's rk.
func checkRekeyVectors(t *testing.T, dir string) {
	keys := load(t, dir, "keys.json")
	vault := checkPrincipal(t, keys.sub("vault"))
	peer := checkPrincipal(t, keys.sub("initiator"))
	hs := load(t, dir, "handshake.json")
	d := load(t, dir, "rekey.json")
	in := d.sub("inputs")
	t1, err := time.Parse(time.RFC3339, in.str("ts"))
	if err != nil {
		t.Fatal(err)
	}

	// The old epoch is the one of handshake.json.
	old := d.sub("old_epoch")
	for _, k := range []string{"epoch_id_hex", "k_i2r_hex", "k_r2i_hex", "kid_i2r_hex", "kid_r2i_hex", "rk_hex"} {
		eq(t, "old "+k, old.hex(k), hs.hex(k))
	}
	peerOld := epochFrom(t, old, true, handshake.PolicyVaultToVault, time.Time{})

	eph, err := suite.NewPrivateKey(in.hex("initiator_eph_seed_hex"))
	if err != nil {
		t.Fatal(err)
	}

	// hs.init: a session envelope of the old epoch, vault to peer (r2i).
	envInit := d.b64("hs_init_envelope_b64")
	hdr := append([]byte{2, 2, 1, 0}, old.hex("kid_i2r_hex")...) // sender_kid = kid_i2r on r2i
	hdr = append(hdr, old.hex("kid_r2i_hex")...)
	hdr = append(hdr, in.hex("init_nonce_hex")...)
	padded, err := envelope.Pad([]byte(d.str("hs_init_inner")))
	if err != nil {
		t.Fatal(err)
	}
	ct, err := suite.SealX(old.hex("k_r2i_hex"), in.hex("init_nonce_hex"), hdr, padded)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "hs.init", append(bytes.Clone(hdr), ct...), envInit)

	pend, err := handshake.OpenRekeyInit(envInit, peerOld, t1)
	if err != nil {
		t.Fatal(err)
	}
	ij, _ := pend.Inner().Marshal(envelope.ModeSession)
	if string(ij) != d.str("hs_init_inner") || pend.Inner().Seq != 1 || pend.Inner().ID != in.str("init_id") {
		t.Errorf("hs.init inner %s", ij)
	}
	body := pend.Init()
	bj, _ := body.Marshal()
	if string(bj) != d.str("hs_init_body") {
		t.Error("hs.init body")
	}
	if body.Purpose != handshake.PurposeRekey || body.Ctx != base64.StdEncoding.EncodeToString(old.hex("epoch_id_hex")) ||
		body.Token != "" || body.ReconnectToken != "" || body.SASCommit != nil || body.Profile != nil {
		t.Error("hs.init members")
	}
	if !body.Eph.Equal(eph.Public()) || body.Eph.Equal(body.From.KEM) {
		t.Error("eph")
	}
	if !body.From.KEM.Equal(vault.kem.Public()) || !bytes.Equal(body.From.IK, vault.ik.Public().(ed25519.PublicKey)) {
		t.Error("from")
	}
	// A rekey is accepted only under the current epoch.
	newPeer := epochFrom(t, d.sub("new_epoch"), false, handshake.PolicyVaultToVault, t1) // peer was R in the rekey
	if _, err := handshake.AcceptRekey(envInit, pend.Inner(), newPeer, t1); !errors.Is(err, handshake.ErrCtx) {
		t.Errorf("AcceptRekey under another epoch: %v", err)
	}
	ks := old.hex("rk_hex")
	eq(t, "K_s", ks, d.hex("K_s_hex"))

	// hs.resp: sealed to eph, as the initiator receives it.
	envResp := d.b64("hs_resp_envelope_b64")
	re, err := envelope.Parse(envResp)
	if err != nil {
		t.Fatal(err)
	}
	if re.Mode() != envelope.ModeSealed || !re.SenderKid().IsAnonymous() || !re.RecipientKid().Equal(eph.Public().Kid()) {
		t.Error("hs.resp header")
	}
	rpad, rexp, err := envelope.OpenSealed(re, eph)
	if err != nil {
		t.Fatal(err)
	}
	ke, _ := rexp.Export("vettid/vms/2/hs-ke", 32)
	eq(t, "K_e", ke, d.hex("K_e_hex"))
	rin, err := envelope.DecodeInner(rpad, envelope.ModeSealed)
	if err != nil || rin.Type != "hs.resp" || rin.ID != in.str("resp_id") {
		t.Fatalf("hs.resp inner: %v", err)
	}
	rj, _ := rin.Marshal(envelope.ModeSealed)
	if string(rj) != d.str("hs_resp_inner") {
		t.Error("hs.resp inner")
	}
	resp, err := handshake.ParseResp(rin.Body, handshake.PurposeRekey)
	if err != nil || resp.Suite != 2 || resp.SASNonce != nil || resp.Token != "" {
		t.Fatalf("hs.resp body: %v", err)
	}
	s, _ := hpkederand.NewSender(eph.Public().Bytes(), []byte(suite.InfoSealed), in.hex("resp_encapsulation_randomness_hex"))
	eq(t, "hs.resp enc", envResp[20:1140], s.Enc())
	sct, _ := s.Seal(envResp[:1140], rpad)
	eq(t, "hs.resp", append(bytes.Clone(envResp[:1140]), sct...), envResp)

	// The key schedule, by hand (§6.3).
	th1 := sha256.Sum256(append([]byte("vettid/vms/2/th1"), envInit...))
	eq(t, "th1", th1[:], d.hex("th1_hex"))
	if pth1 := pend.Th1(); !bytes.Equal(pth1[:], th1[:]) {
		t.Error("pending th1")
	}
	th := sha256.Sum256(append(append([]byte("vettid/vms/2/th"), envInit...), envResp[:1140]...))
	eq(t, "th", th[:], d.hex("th_hex"))
	prk, err := hkdf.Extract(sha256.New, append(bytes.Clone(ke), ks...), []byte("vettid/vms/2/session"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "prk", prk, d.hex("prk_hex"))
	ne := d.sub("new_epoch")
	eq(t, "k_i2r", hkdfExpand(t, prk, "vettid/vms/2/i2r", th[:], 32), ne.hex("k_i2r_hex"))
	eq(t, "k_r2i", hkdfExpand(t, prk, "vettid/vms/2/r2i", th[:], 32), ne.hex("k_r2i_hex"))
	eq(t, "kid_i2r", hkdfExpand(t, prk, "vettid/vms/2/kid-i2r", th[:], 8), ne.hex("kid_i2r_hex"))
	eq(t, "kid_r2i", hkdfExpand(t, prk, "vettid/vms/2/kid-r2i", th[:], 8), ne.hex("kid_r2i_hex"))
	eq(t, "rk", hkdfExpand(t, prk, "vettid/vms/2/rk", th[:], 32), ne.hex("rk_hex"))
	eq(t, "epoch_id", hkdfExpand(t, prk, "vettid/vms/2/epoch", th[:], 16), ne.hex("epoch_id_hex"))
	var th1a, tha [32]byte
	copy(th1a[:], th1[:])
	copy(tha[:], th[:])
	sc, err := handshake.DeriveSchedule(ks, ke, th1a, tha)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "schedule k_i2r", sc.KI2R, ne.hex("k_i2r_hex"))
	eq(t, "schedule epoch_id", sc.EpochID[:], ne.hex("epoch_id_hex"))
	if bytes.Equal(ne.hex("epoch_id_hex"), old.hex("epoch_id_hex")) || bytes.Equal(ne.hex("rk_hex"), old.hex("rk_hex")) {
		t.Error("the new epoch repeats the old one")
	}

	// Signatures: sig_R by the peer (R), sig_I by the vault (I).
	if handshake.VerifyResp(peer.ik.Public().(ed25519.PublicKey), tha, d.b64("sig_R_b64")) != nil ||
		!bytes.Contains(rpad, []byte(d.str("sig_R_b64"))) {
		t.Error("sig_R")
	}
	if handshake.VerifyFin(vault.ik.Public().(ed25519.PublicKey), tha, d.b64("sig_I_b64")) != nil {
		t.Error("sig_I")
	}

	// hs.fin: session mode, direction i2r (vault to peer), seq 1.
	envFin := d.b64("hs_fin_envelope_b64")
	fe, err := envelope.Parse(envFin)
	if err != nil {
		t.Fatal(err)
	}
	frk, fsk := fe.RecipientKid(), fe.SenderKid()
	if fe.Mode() != envelope.ModeSession || !bytes.Equal(frk[:], ne.hex("kid_i2r_hex")) || !bytes.Equal(fsk[:], ne.hex("kid_r2i_hex")) {
		t.Error("hs.fin header")
	}
	eq(t, "hs.fin nonce", envFin[20:44], in.hex("fin_nonce_hex"))
	fpad, err := envelope.OpenSession(fe, ne.hex("k_i2r_hex"))
	if err != nil {
		t.Fatal(err)
	}
	fin, err := envelope.DecodeInner(fpad, envelope.ModeSession)
	if err != nil || fin.Type != "hs.fin" || fin.Seq != 1 || fin.ID != in.str("fin_id") {
		t.Fatalf("hs.fin inner: %v", err)
	}
	fb, err := handshake.ParseFin(fin.Body, handshake.PurposeRekey)
	if err != nil || fb.SASNonce != nil {
		t.Fatalf("hs.fin body: %v", err)
	}
	eq(t, "hs.fin sig", fb.Sig, d.b64("sig_I_b64"))

	// One message in each direction of the new epoch: the vault is I, so
	// its messages go i2r (seq 2 after hs.fin) and the peer's r2i (seq 1).
	vaultNew := epochFrom(t, ne, true, handshake.PolicyVaultToVault, t1)
	peerNew := epochFrom(t, ne, false, handshake.PolicyVaultToVault, t1)
	for _, c := range []struct {
		name string
		to   *handshake.Epoch
		seq  uint64
		id   string
		n    string
	}{{"message_i2r", peerNew, 2, in.str("msg_i2r_id"), "msg_i2r_nonce_hex"}, {"message_r2i", vaultNew, 1, in.str("msg_r2i_id"), "msg_r2i_nonce_hex"}} {
		m := d.sub(c.name)
		raw := m.b64("envelope_b64")
		e, err := envelope.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, c.name+" nonce", raw[20:44], in.hex(c.n))
		got, err := c.to.Open(e)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		j, _ := got.Marshal(envelope.ModeSession)
		if string(j) != m.str("inner") || got.Seq != c.seq || got.ID != c.id || got.Type != "test.ping" {
			t.Errorf("%s inner %s", c.name, j)
		}
		// Not under the old epoch's keys.
		if _, err := envelope.OpenSession(e, old.hex("k_i2r_hex")); err == nil {
			t.Errorf("%s opens under the old epoch", c.name)
		}
	}
}
