//go:build vmsvectors

package vectors

import (
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// DesktopOpenToken is the pairing bundle's open token (a dummy string).
const DesktopOpenToken = "v4.public.VEVTVC1ERVNLVE9QLW9wZW4"

// genDesktop builds handshake_desktop.json (§6.3, §6.7): a desktop pairs
// with the vault of keys.json. What differs from a connection handshake
// (handshake.json): the purpose is "desktop"; ctx is the pairing id of
// the claim bundle (kind "desktop", QR t "d"); hs.init is deposited on the
// bundle's open token and carries the desktop's standing token and a
// self-asserted profile; there is no device attestation (that is for the
// app) and no api_key or unlock_secret; the epoch policy is the
// vault-to-device one (7 days); and hs.init's token is the desktop's
// standing token (the one device.pair.rejected is deposited on, §6.7), not
// a request token, which only a connection's hs.init carries.
func genDesktop(t0 time.Time, vault *principal) (obj, error) {
	dev, err := newPrincipal(SeedDesktopIK, SeedDesktopKEM, SeedDesktopRelay)
	if err != nil {
		return nil, err
	}
	eph, err := suite.NewPrivateKey(rep(SeedDesktopEph, 32))
	if err != nil {
		return nil, err
	}

	// The pairing: bundle, QR and link (§6.4, §6.7).
	b := &invite.Bundle{
		Kind: "desktop", InviteID: DesktopPairingID, Remote: false,
		Vault: handshake.Principal{IK: vault.ikPub(), KEM: vault.kem.Public(), Relay: vault.addr},
		Token: DesktopOpenToken, Exp: t0.Add(invite.PairingTTL),
	}
	bj, err := b.Marshal()
	if err != nil {
		return nil, err
	}
	var blob, kb []byte
	var h [32]byte
	if err := with(newScript(rep(KeyDesktopBundle, 32), rep(NonceDesktopBundle, 24)), func() error {
		var err error
		blob, kb, h, err = invite.SealBundle(bj)
		return err
	}); err != nil {
		return nil, err
	}
	q := &invite.QR{Kind: invite.KindDesktop, Relay: RelayURL, ClaimID: DesktopClaimID, Hash: h, Key: kb, Exp: b.Exp.Unix()}
	qj, err := q.Marshal()
	if err != nil {
		return nil, err
	}
	link, err := q.Link()
	if err != nil {
		return nil, err
	}

	// The handshake.
	lookup := func(kid suite.Kid) *suite.PrivateKey {
		if kid.Equal(vault.kem.Public().Kid()) {
			return vault.kem
		}
		return nil
	}
	profile := strictjson.NewBuilder().String("name", DesktopName).Bytes()
	var (
		in   *handshake.Initiator
		resp *handshake.Responder
		renv []byte
		res  *handshake.Result
	)
	if err := with(newScript(rep(SeedDesktopEph, 32), rep(NonceDesktopSASI, 32), rep(RandDesktopInit, 64)), func() error {
		var err error
		in, err = handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeDesktop, Ctx: DesktopPairingID,
			Identity: dev.ik, StaticKEM: dev.kem.Public(), Relay: dev.addr,
			Token: DesktopTokenStanding, Suites: []int{2}, Profile: profile,
			ResponderIK: vault.ikPub(), ResponderEK: vault.kem.Public(), ResponderRelayKey: vault.relayPub(),
			Policy: handshake.PolicyVaultToDevice, ID: DesktopInitID, FinID: DesktopFinID, Now: t0,
		})
		return err
	}); err != nil {
		return nil, err
	}
	pend, err := handshake.OpenInit(in.Envelope(), lookup, t0)
	if err != nil {
		return nil, err
	}
	if err := with(newScript(rep(NonceDesktopSASR, 32), rep(RandDesktopResp, 64)), func() error {
		var err error
		resp, renv, err = pend.Respond(handshake.ResponderConfig{
			Identity: vault.ik, Token: DesktopTokenResp,
			Policy: handshake.PolicyVaultToDevice, CollectSender: dev.relayPub(), ID: DesktopRespID, Now: t0,
		})
		return err
	}); err != nil {
		return nil, err
	}
	if err := with(newScript(rep(NonceDesktopFin, 24)), func() error {
		var err error
		res, err = in.HandleResp(renv, vault.relayPub(), t0)
		return err
	}); err != nil {
		return nil, err
	}
	fr, err := resp.HandleFin(res.Fin, dev.relayPub(), t0)
	if err != nil {
		return nil, err
	}
	if fr.Epoch.ID() != res.Epoch.ID() || fr.SAS != res.SAS {
		return nil, errors.New("vectors: epoch or SAS mismatch")
	}
	if fr.Epoch.NeedsRekey(t0.Add(7*24*time.Hour-time.Second)) || !fr.Epoch.NeedsRekey(t0.Add(7*24*time.Hour)) {
		return nil, errors.New("vectors: epoch policy is not 7 days")
	}

	// Intermediate values, from the receiving side.
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
	sc, err := handshake.DeriveSchedule(ks, ke, th1, th)
	if err != nil {
		return nil, err
	}
	nI, nR := rep(NonceDesktopSASI, 32), rep(NonceDesktopSASR, 32)
	commit := handshake.SASCommit(nI)
	sas, err := handshake.SAS(sc.PRK, th, nI, nR)
	if err != nil || sas != res.SAS {
		return nil, errors.New("vectors: SAS mismatch")
	}
	sigR, _ := handshake.SignResp(vault.ik, th)
	sigI, _ := handshake.SignFin(dev.ik, th)
	rin, err := envelope.DecodeInner(rpad, envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	hi := in.Body()
	ib, err := hi.Marshal()
	if err != nil {
		return nil, err
	}
	body := string(ib)

	// hs.init bodies a vault MUST refuse for a desktop: each is the body
	// above with one change.
	tokenMember := `"token":"` + DesktopTokenStanding + `",`
	commitMember := `,"sas_commit":"` + base64.StdEncoding.EncodeToString(commit[:]) + `"`
	if !strings.Contains(body, tokenMember) || !strings.HasSuffix(body, commitMember+"}") {
		return nil, errors.New("vectors: unexpected hs.init body layout")
	}
	rejects := []obj{
		{{"case", "token_missing"}, {"reason", "a desktop's hs.init requires a token (§6.2)"},
			{"body", strings.Replace(body, tokenMember, "", 1)}},
		{{"case", "sas_commit_missing"}, {"reason", "hs.init of purpose desktop requires sas_commit (§6.2, 0.10.3)"},
			{"body", strings.Replace(body, commitMember, "", 1)}},
		{{"case", "reconnect_token_present"}, {"reason", "reconnect_token MUST be absent for desktop (§6.2)"},
			{"body", strings.Replace(body, tokenMember, tokenMember+`"reconnect_token":"`+DesktopTokenStanding+`",`, 1)}},
		{{"case", "unlock_secret_present"}, {"reason", "unlock_secret is for a transfer's app only (§6.2): MUST be absent for desktop"},
			{"body", strings.Replace(body, commitMember, `,"unlock_secret":"`+base64.StdEncoding.EncodeToString(rep(0x00, 32))+`"`+commitMember, 1)}},
	}
	rj := make([]any, len(rejects))
	for i, r := range rejects {
		rj[i] = r
	}

	return obj{
		{"description", "VAULT-MESSAGING 0.10.3 §6.1-§6.3, §6.4, §6.7 handshake, purpose desktop: a desktop (keys below) pairs with the vault of keys.json. The vault shows a pairing QR (kind desktop, QR t = \"d\", TTL 10 min, remote false) whose bundle's invite_id is the pairing id and whose token is the open token; the desktop sends hs.init (purpose desktop, ctx = the pairing id) sealed to the vault ek with sender_kid = kid(desktop ek), deposited on the open token. It carries its standing token (the one device.pair.rejected is deposited on, §6.7; only a connection's hs.init carries a request token), a self-asserted profile {name}, suites [2] and sas_commit; it has no device_attest (an app's only), api_key or unlock_secret, and no reconnect_token. hs.resp (sealed to eph, sender_kid all zero) carries the vault's request token and n_R; hs.fin (session, direction i2r) reveals n_I. The vault does not activate the epoch until its owner approves the SAS (§6.7); the epoch policy is the vault-to-device one: 7 days, no message bound (so no max_messages member). The mechanics are those of handshake.json: encapsulation randomness, th and every key follow §6.3. Tokens are dummy strings, not real PASETO tokens. Fixed test-only inputs."},
		{"desktop", dev.keysObj()},
		{"pairing", obj{
			{"bundle_json", string(bj)},
			{"k_b_hex", hx(kb)},
			{"nonce_hex", hx(rep(NonceDesktopBundle, 24))},
			{"blob_b64", b64(blob)},
			{"h_hex", hx(h[:])},
			{"qr_json", string(qj)},
			{"link", link},
			{"open_token", DesktopOpenToken},
		}},
		{"inputs", obj{
			{"desktop_eph_seed_hex", hx(rep(SeedDesktopEph, 32))},
			{"init_encapsulation_randomness_hex", hx(rep(RandDesktopInit, 64))},
			{"resp_encapsulation_randomness_hex", hx(rep(RandDesktopResp, 64))},
			{"fin_nonce_hex", hx(rep(NonceDesktopFin, 24))},
			{"n_I_hex", hx(nI)},
			{"n_R_hex", hx(nR)},
			{"ts", TS},
			{"init_id", DesktopInitID}, {"resp_id", DesktopRespID}, {"fin_id", DesktopFinID},
		}},
		{"epoch_policy", obj{{"max_age_seconds", int(handshake.PolicyVaultToDevice.MaxAge / time.Second)}}},
		{"hs_init_body", body},
		{"hs_init_envelope_b64", b64(envInit)},
		{"hs_resp_inner", mustInner(rin)},
		{"hs_resp_envelope_b64", b64(renv)},
		{"hs_fin_envelope_b64", b64(res.Fin)},
		{"K_s_hex", hx(ks)},
		{"K_e_hex", hx(ke)},
		{"th1_hex", hx(th1[:])},
		{"th_hex", hx(th[:])},
		{"prk_hex", hx(sc.PRK)},
		{"k_i2r_hex", hx(sc.KI2R)},
		{"k_r2i_hex", hx(sc.KR2I)},
		{"kid_i2r_hex", hx(sc.KidI2R[:])},
		{"kid_r2i_hex", hx(sc.KidR2I[:])},
		{"rk_hex", hx(sc.RK)},
		{"epoch_id_hex", hx(sc.EpochID[:])},
		{"sas_commit_hex", hx(commit[:])},
		{"sas", sas},
		{"sig_R_b64", b64(sigR)},
		{"sig_I_b64", b64(sigI)},
		{"hs_init_rejects", rj},
	}, nil
}
