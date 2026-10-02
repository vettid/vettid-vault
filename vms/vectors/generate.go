//go:build vmsvectors

package vectors

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

func rep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func hx(b []byte) string  { return hex.EncodeToString(b) }
func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// script is a randomness source that yields exactly the given bytes, in
// order, and fails on any other draw, so an unexpected random draw in the
// library cannot go unnoticed.
type script struct{ buf []byte }

func newScript(parts ...[]byte) *script { return &script{buf: bytes.Join(parts, nil)} }

func (s *script) Read(p []byte) (int, error) {
	if len(s.buf) < len(p) {
		return 0, errors.New("vectors: unexpected randomness draw")
	}
	n := copy(p, s.buf)
	s.buf = s.buf[n:]
	return n, nil
}

// with runs f with s as the only randomness source and requires that f
// consumed all of it.
func with(s *script, f func() error) error {
	restore := suite.SetVectorRandomness(s)
	defer restore()
	if err := f(); err != nil {
		return err
	}
	if len(s.buf) != 0 {
		return fmt.Errorf("vectors: %d scripted random bytes unused", len(s.buf))
	}
	return nil
}

type principal struct {
	ikSeed, kemSeed, relaySeed byte
	ik                         ed25519.PrivateKey
	kem                        *suite.PrivateKey
	relay                      ed25519.PrivateKey
	addr                       handshake.RelayAddr
}

func newPrincipal(ik, kem, relay byte) (*principal, error) {
	k, err := suite.NewPrivateKey(rep(kem, 32))
	if err != nil {
		return nil, err
	}
	r := ed25519.NewKeyFromSeed(rep(relay, 32))
	pk := r.Public().(ed25519.PublicKey)
	return &principal{ikSeed: ik, kemSeed: kem, relaySeed: relay, ik: ed25519.NewKeyFromSeed(rep(ik, 32)), kem: k, relay: r,
		addr: handshake.RelayAddr{URL: RelayURL, Mailbox: handshake.MailboxID(pk), PK: pk}}, nil
}

func (p *principal) ikPub() ed25519.PublicKey    { return p.ik.Public().(ed25519.PublicKey) }
func (p *principal) relayPub() ed25519.PublicKey { return p.relay.Public().(ed25519.PublicKey) }

func (p *principal) keysObj() obj {
	kid := p.kem.Public().Kid()
	return obj{
		{"ik_seed_hex", hx(rep(p.ikSeed, 32))},
		{"ik_pk_b64", b64(p.ikPub())},
		{"kem_seed_hex", hx(rep(p.kemSeed, 32))},
		{"ek_b64", b64(p.kem.Public().Bytes())},
		{"kid_hex", hx(kid[:])},
		{"relay_seed_hex", hx(rep(p.relaySeed, 32))},
		{"relay_pk_b64", b64(p.relayPub())},
		{"mailbox", p.addr.Mailbox},
		{"relay_url", RelayURL},
	}
}

// Generate builds every vector file through the library's sending code.
func Generate() (map[string][]byte, error) {
	t0, _ := time.Parse(time.RFC3339, "2026-10-01T12:00:00Z")
	vault, err := newPrincipal(SeedVaultIK, SeedVaultKEM, SeedVaultRelay)
	if err != nil {
		return nil, err
	}
	ini, err := newPrincipal(SeedInitIK, SeedInitKEM, SeedInitRelay)
	if err != nil {
		return nil, err
	}
	eph, err := suite.NewPrivateKey(rep(SeedInitEph, 32))
	if err != nil {
		return nil, err
	}
	etk, err := suite.NewPrivateKey(rep(SeedETK, 32))
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	put := func(name string, o obj) error {
		b, err := render(o)
		if err != nil {
			return err
		}
		out[name] = b
		return nil
	}

	// keys.json (§3.2)
	ephKid := eph.Public().Kid()
	etkKid := etk.Public().Kid()
	if err := put("keys.json", obj{
		{"description", "VAULT-MESSAGING §3.2/§4.4 test keys. All seeds are fixed, public and TEST-ONLY. ek = MLKEM768X25519 encapsulation key (1216 bytes) from the 32-byte seed (the seed is the RFC 9180 serialized private key; it is expanded with SHAKE256 as in draft-ietf-hpke-pq / X-Wing). kid = SHA-256(\"vettid/vms/2/kid\" || ek)[0:8]. mailbox per RELAY-PROTOCOL §3.2."},
		{"vault", vault.keysObj()},
		{"initiator", ini.keysObj()},
		{"initiator_ephemeral", obj{{"kem_seed_hex", hx(rep(SeedInitEph, 32))}, {"ek_b64", b64(eph.Public().Bytes())}, {"kid_hex", hx(ephKid[:])}}},
		{"etk", obj{{"kem_seed_hex", hx(rep(SeedETK, 32))}, {"ek_b64", b64(etk.Public().Bytes())}, {"kid_hex", hx(etkKid[:])}}},
	}); err != nil {
		return nil, err
	}

	// hpke.json (§4.3) and envelope_sealed.json (§5.2): one sealing.
	var sealedEnv []byte
	padded, err := envelope.Pad([]byte(SpecInner))
	if err != nil {
		return nil, err
	}
	if err := with(newScript(rep(RandSealed, 64)), func() error {
		var err error
		sealedEnv, _, err = envelope.SealSealed(vault.kem.Public(), suite.Anonymous, padded)
		return err
	}); err != nil {
		return nil, err
	}
	hv, ok := suite.LastSenderValues()
	if !ok {
		return nil, errors.New("vectors: no sender values")
	}
	vaultKid := vault.kem.Public().Kid()
	if err := put("hpke.json", obj{
		{"description", "VAULT-MESSAGING §4.3: HPKE base mode, suite 2 = KEM MLKEM768X25519 (0x647a), KDF HKDF-SHA256 (0x0001), AEAD ChaCha20-Poly1305 (0x0003). Encapsulation randomness is 64 bytes: [0:32] is the ML-KEM-768 message m, [32:64] the X25519 ephemeral secret (X-Wing EncapsulateDerand). This is the context of envelope_sealed.json."},
		{"kem_id", "0x647a"}, {"kdf_id", "0x0001"}, {"aead_id", "0x0003"},
		{"recipient_ek_b64", b64(vault.kem.Public().Bytes())},
		{"info", suite.InfoSealed},
		{"encapsulation_randomness_hex", hx(rep(RandSealed, 64))},
		{"enc_b64", b64(hv.Enc)},
		{"enc_len", len(hv.Enc)},
		{"shared_secret_hex", hx(hv.SharedSecret)},
		{"key_hex", hx(hv.Key)},
		{"base_nonce_hex", hx(hv.BaseNonce)},
		{"exporter_secret_hex", hx(hv.ExporterSecret)},
	}); err != nil {
		return nil, err
	}
	if err := put("envelope_sealed.json", obj{
		{"description", "VAULT-MESSAGING §5.2 sealed-mode envelope of the §16 inner plaintext, sealed to the vault ek (keys.json) with the HPKE context of hpke.json. sender_kid is anonymous (all zero); recipient_kid is the vault kid. AAD = envelope bytes[0:1140]."},
		{"inner", SpecInner},
		{"padded_len", len(padded)},
		{"padded_hex", hx(padded)},
		{"sender_kid_hex", hx(suite.Anonymous[:])},
		{"recipient_kid_hex", hx(vaultKid[:])},
		{"envelope_len", len(sealedEnv)},
		{"envelope_b64", b64(sealedEnv)},
	}); err != nil {
		return nil, err
	}

	// envelope_session.json (§5.2)
	sessInner := (&envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Type: "test.ping", TS: t0, Seq: 1})
	sj, err := sessInner.Marshal(envelope.ModeSession)
	if err != nil {
		return nil, err
	}
	sp, err := envelope.Pad(sj)
	if err != nil {
		return nil, err
	}
	var sessEnv []byte
	if err := with(newScript(rep(NonceSession, 24)), func() error {
		var err error
		sessEnv, err = envelope.SealSession(rep(KeySession, 32), suite.Kid(rep(SessionSenderKid, 8)), suite.Kid(rep(SessionRecipientKid, 8)), sp)
		return err
	}); err != nil {
		return nil, err
	}
	if err := put("envelope_session.json", obj{
		{"description", "VAULT-MESSAGING §5.2 session-mode envelope: XChaCha20-Poly1305(k_i2r, nonce, aad = bytes[0:44], padded_inner). The kids are arbitrary test values."},
		{"k_i2r_hex", hx(rep(KeySession, 32))},
		{"nonce_hex", hx(rep(NonceSession, 24))},
		{"sender_kid_hex", hx(rep(SessionSenderKid, 8))},
		{"recipient_kid_hex", hx(rep(SessionRecipientKid, 8))},
		{"inner", string(sj)},
		{"padded_len", len(sp)},
		{"envelope_len", len(sessEnv)},
		{"envelope_b64", b64(sessEnv)},
	}); err != nil {
		return nil, err
	}

	// handshake.json (§6)
	hs, err := genHandshake(t0, vault, ini, eph)
	if err != nil {
		return nil, err
	}
	if err := put("handshake.json", hs); err != nil {
		return nil, err
	}

	// invite.json (§6.4)
	iv, err := genInvite(t0, vault)
	if err != nil {
		return nil, err
	}
	if err := put("invite.json", iv); err != nil {
		return nil, err
	}

	// altchan.json (§11)
	ac, err := genAltchan(t0, ini, etk)
	if err != nil {
		return nil, err
	}
	if err := put("altchan.json", ac); err != nil {
		return nil, err
	}

	// release.json (§11.10)
	rv, err := genRelease(ini, etk)
	if err != nil {
		return nil, err
	}
	if err := put("release.json", rv); err != nil {
		return nil, err
	}
	return out, nil
}

func genHandshake(t0 time.Time, vault, ini *principal, eph *suite.PrivateKey) (obj, error) {
	lookup := func(kid suite.Kid) *suite.PrivateKey {
		if kid.Equal(vault.kem.Public().Kid()) {
			return vault.kem
		}
		return nil
	}
	var (
		in   *handshake.Initiator
		pend *handshake.PendingInit
		resp *handshake.Responder
		renv []byte
		res  *handshake.Result
	)
	icfg := handshake.InitiatorConfig{
		Purpose: handshake.PurposeConnection, Ctx: HSInviteID,
		Identity: ini.ik, StaticKEM: ini.kem.Public(), Relay: ini.addr,
		Token: HSTokenInit, ReconnectToken: HSReconnectInit, Suites: []int{2},
		ResponderIK: vault.ikPub(), ResponderEK: vault.kem.Public(), ResponderRelayKey: vault.relayPub(),
		Policy: handshake.PolicyVaultToVault, ID: HSInitID, FinID: HSFinID, Now: t0,
	}
	if err := with(newScript(rep(SeedInitEph, 32), rep(RandInit, 64)), func() error {
		var err error
		in, err = handshake.NewInitiator(icfg)
		return err
	}); err != nil {
		return nil, err
	}
	var err error
	if pend, err = handshake.OpenInit(in.Envelope(), lookup, t0); err != nil {
		return nil, err
	}
	if err := with(newScript(rep(RandResp, 64)), func() error {
		var err error
		resp, renv, err = pend.Respond(handshake.ResponderConfig{
			Identity: vault.ik, Token: HSTokenResp, ReconnectToken: HSReconnectResp,
			Policy: handshake.PolicyVaultToVault, CollectSender: ini.relayPub(), ID: HSRespID, Now: t0,
		})
		return err
	}); err != nil {
		return nil, err
	}
	if err := with(newScript(rep(NonceFin, 24)), func() error {
		var err error
		res, err = in.HandleResp(renv, vault.relayPub(), t0)
		return err
	}); err != nil {
		return nil, err
	}
	ep, _, err := resp.HandleFin(res.Fin, ini.relayPub(), t0)
	if err != nil {
		return nil, err
	}
	if ep.ID() != res.Epoch.ID() {
		return nil, errors.New("vectors: epoch mismatch")
	}

	// Intermediate values, recomputed from the receiving side.
	envInit := in.Envelope()
	ie, _ := envelope.Parse(envInit)
	_, iexp, err := envelope.OpenSealed(ie, vault.kem)
	if err != nil {
		return nil, err
	}
	ks, _ := iexp.Export(suite.LabelHsKs, 32)
	re, _ := envelope.Parse(renv)
	rpad, rexp, err := envelope.OpenSealed(re, eph)
	if err != nil {
		return nil, err
	}
	ke, _ := rexp.Export(suite.LabelHsKe, 32)
	th1 := handshake.Th1(envInit)
	th := handshake.Th(envInit, renv[:envelope.HeaderSealed])
	s, err := handshake.DeriveSchedule(ks, ke, th1, th)
	if err != nil {
		return nil, err
	}
	sas, _ := handshake.SAS(ks, th1)
	sigR, _ := handshake.SignResp(vault.ik, th)
	sigI, _ := handshake.SignFin(ini.ik, th)
	rin, err := envelope.DecodeInner(rpad, envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	initBody := in.Body()
	ib, _ := initBody.Marshal()
	return obj{
		{"description", "VAULT-MESSAGING §6.1-§6.3 handshake, purpose connection: the initiator (keys.json initiator, ephemeral seed 32 x 0x0c) to the vault (keys.json vault). hs.init is sealed to the vault ek with encapsulation randomness 64 x 0x0d and sender_kid = kid(initiator ek); hs.resp is sealed to eph with randomness 64 x 0x0e and sender_kid all zero; hs.fin is a session-mode envelope in the new epoch (direction i2r) with nonce 24 x 0x0f. Tokens are dummy strings, not real PASETO tokens."},
		{"inputs", obj{
			{"initiator_eph_seed_hex", hx(rep(SeedInitEph, 32))},
			{"init_encapsulation_randomness_hex", hx(rep(RandInit, 64))},
			{"resp_encapsulation_randomness_hex", hx(rep(RandResp, 64))},
			{"fin_nonce_hex", hx(rep(NonceFin, 24))},
			{"ts", TS},
			{"init_id", HSInitID}, {"resp_id", HSRespID}, {"fin_id", HSFinID},
		}},
		{"hs_init_body", string(ib)},
		{"hs_init_envelope_b64", b64(envInit)},
		{"hs_resp_inner", mustInner(rin)},
		{"hs_resp_envelope_b64", b64(renv)},
		{"hs_fin_envelope_b64", b64(res.Fin)},
		{"K_s_hex", hx(ks)},
		{"K_e_hex", hx(ke)},
		{"th1_hex", hx(th1[:])},
		{"th_hex", hx(th[:])},
		{"prk_hex", hx(s.PRK)},
		{"k_i2r_hex", hx(s.KI2R)},
		{"k_r2i_hex", hx(s.KR2I)},
		{"kid_i2r_hex", hx(s.KidI2R[:])},
		{"kid_r2i_hex", hx(s.KidR2I[:])},
		{"rk_hex", hx(s.RK)},
		{"epoch_id_hex", hx(s.EpochID[:])},
		{"sas", sas},
		{"sig_R_b64", b64(sigR)},
		{"sig_I_b64", b64(sigI)},
	}, nil
}

func mustInner(in *envelope.Inner) string {
	b, err := in.Marshal(envelope.ModeSealed)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func genInvite(t0 time.Time, vault *principal) (obj, error) {
	b := &invite.Bundle{
		Kind: "connection", InviteID: HSInviteID, Remote: false,
		Vault: handshake.Principal{IK: vault.ikPub(), KEM: vault.kem.Public(), Relay: vault.addr},
		Token: InviteOpenToken, Exp: t0.Add(invite.TTLInPerson), HintName: "Test Vault",
	}
	bj, err := b.Marshal()
	if err != nil {
		return nil, err
	}
	var blob, kb []byte
	var h [32]byte
	if err := with(newScript(rep(KeyBundle, 32), rep(NonceBundle, 24)), func() error {
		var err error
		blob, kb, h, err = invite.SealBundle(bj)
		return err
	}); err != nil {
		return nil, err
	}
	q := &invite.QR{Kind: invite.KindConnection, Relay: RelayURL, ClaimID: InviteClaimID, Hash: h, Key: kb, Exp: b.Exp.Unix()}
	qj, err := q.Marshal()
	if err != nil {
		return nil, err
	}
	link, _ := q.Link()
	return obj{
		{"description", "VAULT-MESSAGING §6.4 claim bundle: blob = nonce(24) || XChaCha20-Poly1305(k_b, nonce, aad = \"vettid/vms/2/bundle\", bundle_json); h = SHA-256(blob). QR b64url values are unpadded; the link is the unpadded base64url of the QR JSON. The claim id and token are dummy values."},
		{"bundle_json", string(bj)},
		{"k_b_hex", hx(kb)},
		{"nonce_hex", hx(rep(NonceBundle, 24))},
		{"blob_b64", b64(blob)},
		{"h_hex", hx(h[:])},
		{"qr_json", string(qj)},
		{"link", link},
		{"now", "2026-10-01T12:00:00Z"},
	}, nil
}

// specManifest is the §16 release manifest (1,060 bytes).
func specManifest() []byte {
	rs := []manifest.Release{
		{Number: 3, PCR0: strings.Repeat("ab", 48), PCR1: strings.Repeat("11", 48), PCR2: strings.Repeat("22", 48),
			SealKey: "arn:aws:kms:us-east-1:000000000000:key/test-release-3", Status: manifest.StatusDeprecated,
			PublishedAt: time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), Notes: "https://vettid.org/releases/3"},
		{Number: 4, PCR0: strings.Repeat("cd", 48), PCR1: strings.Repeat("33", 48), PCR2: strings.Repeat("44", 48),
			SealKey: "arn:aws:kms:us-east-1:000000000000:key/test-release-4", Status: manifest.StatusActive,
			PublishedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC), Notes: "https://vettid.org/releases/4"},
	}
	return manifest.Build(7, time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), rs)
}

func p256(seed byte) (*ecdsa.PrivateKey, error) {
	return ecdsa.ParseRawPrivateKey(elliptic.P256(), rep(seed, 32))
}

func spkiB64(k *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		return "", err
	}
	return b64(der), nil
}

func genRelease(app *principal, etk *suite.PrivateKey) (obj, error) {
	mk, err := p256(SeedManifestKey)
	if err != nil {
		return nil, err
	}
	mb := specManifest()
	served, err := manifest.Sign(mk, mb)
	if err != nil {
		return nil, err
	}
	mspki, err := spkiB64(mk)
	if err != nil {
		return nil, err
	}
	mh := sha256.Sum256(mb)
	md := manifest.Digest(mb)
	from, to := strings.Repeat("ab", 48), strings.Repeat("cd", 48)
	as, err := altchan.ApprovalSigningString(ACVaultID, ACApprovalRequestID, from, to, 4, 7)
	if err != nil {
		return nil, err
	}
	ah := sha256.Sum256([]byte(as))
	dk, err := p256(SeedDeviceKey)
	if err != nil {
		return nil, err
	}
	dspki, err := spkiB64(dk)
	if err != nil {
		return nil, err
	}
	asig, err := dk.Sign(nil, ah[:], crypto.SHA256) // RFC 6979
	if err != nil {
		return nil, err
	}
	// The unlock that carries this approval: its signing string covers the
	// manifest and to_pcr0 (§11.4).
	us, err := altchan.UnlockSigningString(altchan.UnlockFields{UserGUID: ACUserGUID, VaultID: ACVaultID,
		RequestID: ACApprovalRequestID, TS: TS, ETKKid: etk.Public().Kid(), MinStateSeq: 1234, MinHeaderSeq: 1301,
		PIN: ACPIN, Token: ACToken, Manifest: mb, ToPCR0: to})
	if err != nil {
		return nil, err
	}
	usig := ed25519.Sign(app.ik, []byte(us))
	return obj{
		{"description", "VAULT-MESSAGING §11.10 release updates. Manifest signature: ECDSA P-256 (RFC 6979 deterministic nonce) over SHA-256(\"vettid/pcr-manifest/1\" || 0x00 || manifest), encoded r || s (IEEE P1363); key_id = hex(SHA-256(SPKI DER)[0:8]). Approval: the §11.10.3 signing string signed by the Android device attestation key (ECDSA P-256 with SHA-256, DER). The unlock signing string is the §11.4 string of the unlock that carries the approval (to_pcr0 = the target). All keys are TEST ONLY."},
		{"manifest_key_scalar_hex", hx(rep(SeedManifestKey, 32))},
		{"manifest_key_spki_b64", mspki},
		{"manifest_key_id", served.KeyID},
		{"manifest", string(mb)},
		{"manifest_len", len(mb)},
		{"manifest_sha256_hex", hx(mh[:])},
		{"manifest_signed_digest_hex", hx(md[:])},
		{"manifest_sig_b64", b64(served.Sig)},
		{"served", string(served.Marshal())},
		{"approval", obj{
			{"vault_id", ACVaultID}, {"request_id", ACApprovalRequestID}, {"from_pcr0_hex", from}, {"to_pcr0_hex", to},
			{"to_release", 4}, {"manifest_serial", 7},
			{"signing_string", as},
			{"signing_string_sha256_hex", hx(ah[:])},
			{"device_key_scalar_hex", hx(rep(SeedDeviceKey, 32))},
			{"device_key_spki_b64", dspki},
			{"sig_der_b64", b64(asig)},
		}},
		{"unlock_with_update", obj{
			{"ts", TS}, {"etk_kid_hex", etk.Public().Kid().String()},
			{"signing_string", us},
			{"sig_b64", b64(usig)},
		}},
	}, nil
}

func genAltchan(t0 time.Time, app *principal, etk *suite.PrivateKey) (obj, error) {
	etkKid := etk.Public().Kid()
	desc := strictjson.NewBuilder().
		Uint("v", 1).Uint("suite", 2).
		String("instance_id", ACInstanceID).
		String("kid", etkKid.String()).
		String("etk", b64(etk.Public().Bytes())).
		String("release", ACRelease).
		String("not_after", ACNotAfter).
		Bytes()
	ud := altchan.ETKUserData(desc)
	enrollChal, err := altchan.DevattChallenge(ACEnrollRequestID, "", TS)
	if err != nil {
		return nil, err
	}
	unlockChal, err := altchan.DevattChallenge(ACUnlockRequestID, ACVaultID, TS)
	if err != nil {
		return nil, err
	}
	mk, err := p256(SeedManifestKey)
	if err != nil {
		return nil, err
	}
	served, err := manifest.Sign(mk, specManifest())
	if err != nil {
		return nil, err
	}
	fields := altchan.UnlockFields{UserGUID: ACUserGUID, VaultID: ACVaultID, RequestID: ACUnlockRequestID, TS: TS,
		ETKKid: etkKid, MinStateSeq: 1234, MinHeaderSeq: 1301, PIN: ACPIN, Token: ACToken, Manifest: served.Manifest}
	ss, err := altchan.UnlockSigningString(fields)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(app.ik, []byte(ss))
	// A dummy Android assertion: the enclave verifies it in phase V3.
	assertion, err := (&altchan.DeviceAssertion{Platform: altchan.PlatformAndroid, Sig: rep(0x2a, 72)}).Marshal()
	if err != nil {
		return nil, err
	}
	body := strictjson.NewBuilder().
		String("user_guid", ACUserGUID).
		String("vault_id", ACVaultID).
		String("request_id", ACUnlockRequestID).
		String("device_ik", b64(app.ikPub())).
		String("pin", ACPIN).
		Uint("min_state_seq", 1234).
		Uint("min_header_seq", 1301).
		String("token", ACToken).
		Raw("device_assertion", assertion).
		Raw("manifest", served.Marshal()).
		String("sig", b64(sig)).
		Bytes()
	t1, _ := envelope.ParseTS(TS)
	inner, err := (&envelope.Inner{ID: ACUnlockRequestID, Type: "vault.unlock", TS: t1, Body: body}).Marshal(envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	padded, err := envelope.PadFixed(inner, altchan.RequestPaddedSize)
	if err != nil {
		return nil, err
	}
	var env []byte
	if err := with(newScript(rep(RandUnlock, 64)), func() error {
		var err error
		env, _, err = envelope.SealSealed(etk.Public(), suite.Anonymous, padded)
		return err
	}); err != nil {
		return nil, err
	}
	_ = t0
	return obj{
		{"description", "VAULT-MESSAGING 0.3.0 §11 alternate channel. The descriptor is compact JSON in the member order of §11.2; user_data = SHA-256(\"vettid/vms/2/etk\" || descriptor). devatt challenge = SHA-256(\"vettid/vms/2/devatt\" || request_id || vault_id_or_empty || ts), the same for Android and iOS. The unlock signing string joins its 12 fields with \\n (no trailing newline): it ends with hex(SHA-256(manifest_bytes)) and to_pcr0 (empty here: no release update); sig is Ed25519 by the device ik (keys.json initiator ik). The manifest is release.json's served document. The vault.unlock inner is padded to exactly 12,288 bytes and sealed to the ETK (encapsulation randomness 64 x 0x13, sender_kid all zero). PIN, token, ids and the device_assertion signature (72 x 0x2a) are dummy test values."},
		{"descriptor", string(desc)},
		{"descriptor_user_data_hex", hx(ud[:])},
		{"devatt_enroll", obj{{"request_id", ACEnrollRequestID}, {"vault_id", ""}, {"ts", TS}, {"challenge_hex", hx(enrollChal[:])}}},
		{"devatt_unlock", obj{{"request_id", ACUnlockRequestID}, {"vault_id", ACVaultID}, {"ts", TS}, {"challenge_hex", hx(unlockChal[:])}}},
		{"unlock_fields", obj{
			{"user_guid", ACUserGUID}, {"vault_id", ACVaultID}, {"request_id", ACUnlockRequestID}, {"ts", TS},
			{"etk_kid_hex", etkKid.String()}, {"min_state_seq", 1234}, {"min_header_seq", 1301},
			{"pin", ACPIN}, {"token", ACToken}, {"manifest_sha256_hex", hx(sha256Of(served.Manifest))}, {"to_pcr0_hex", ""},
		}},
		{"unlock_signing_string", ss},
		{"unlock_sig_b64", b64(sig)},
		{"unlock_inner", string(inner)},
		{"unlock_encapsulation_randomness_hex", hx(rep(RandUnlock, 64))},
		{"unlock_envelope_len", len(env)},
		{"unlock_envelope_b64", b64(env)},
	}, nil
}

func sha256Of(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
