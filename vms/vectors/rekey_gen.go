//go:build vmsvectors

package vectors

import (
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// epochObj lists an epoch's keys as the initiator of its handshake holds
// them: k_i2r is the send key, k_r2i the receive key.
func epochObj(e *handshake.Epoch) obj {
	s := e.Export()
	return obj{
		{"epoch_id_hex", hx(s.ID)},
		{"k_i2r_hex", hx(s.SendKey)},
		{"k_r2i_hex", hx(s.RecvKey)},
		{"kid_i2r_hex", hx(s.SendRecipientKid)},
		{"kid_r2i_hex", hx(s.SendSenderKid)},
		{"rk_hex", hx(s.RK)},
	}
}

// genRekey builds rekey.json (§6.5): the vault rekeys the session that
// handshake.json established, 24 h after it (the vault-to-vault limit).
// hs.init travels as a session envelope of the old epoch, in direction
// r2i (the vault answered the first handshake), and K_s is the old
// epoch's rk. The peer answers with hs.resp sealed to the vault's fresh
// ephemeral key; hs.fin is a session envelope of the new epoch.
func genRekey(t0 time.Time, vault, peer *principal, peerEpoch, vaultEpoch *handshake.Epoch) (obj, error) {
	t1 := t0.Add(24 * time.Hour)
	if !vaultEpoch.NeedsRekey(t1) {
		return nil, errors.New("vectors: the epoch is not due for rekey")
	}
	old := epochObj(peerEpoch)
	eph, err := suite.NewPrivateKey(rep(SeedRekeyEph, 32))
	if err != nil {
		return nil, err
	}
	var (
		in   *handshake.Initiator
		resp *handshake.Responder
		renv []byte
		res  *handshake.Result
	)
	// The rekey initiator is the vault. Draw order: the ephemeral seed, then
	// the nonce of hs.init (no n_I: a rekey has no SAS).
	if err := with(newScript(rep(SeedRekeyEph, 32), rep(NonceRekeyInit, 24)), func() error {
		var err error
		in, err = handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeRekey, Current: vaultEpoch,
			Identity: vault.ik, StaticKEM: vault.kem.Public(), Relay: vault.addr,
			Suites:      []int{2},
			ResponderIK: peer.ikPub(), ResponderRelayKey: peer.relayPub(),
			Policy: handshake.PolicyVaultToVault, ID: RekeyInitID, FinID: RekeyFinID, Now: t1,
		})
		return err
	}); err != nil {
		return nil, err
	}
	envInit := in.Envelope()
	// The peer opens it under its copy of the old epoch (AcceptRekey and
	// OpenRekeyInit apply the same checks).
	pend, err := handshake.OpenRekeyInit(envInit, peerEpoch, t1)
	if err != nil {
		return nil, err
	}
	initInner, err := pend.Inner().Marshal(envelope.ModeSession)
	if err != nil {
		return nil, err
	}
	initBody, err := pend.Init().Marshal()
	if err != nil {
		return nil, err
	}
	if err := with(newScript(rep(RandRekeyResp, 64)), func() error {
		var err error
		resp, renv, err = pend.Respond(handshake.ResponderConfig{
			Identity: peer.ik, Policy: handshake.PolicyVaultToVault,
			CollectSender: vault.relayPub(), RecordRelayKey: vault.relayPub(), KnownInitiatorIK: vault.ikPub(),
			ID: RekeyRespID, Now: t1,
		})
		return err
	}); err != nil {
		return nil, err
	}
	if err := with(newScript(rep(NonceRekeyFin, 24)), func() error {
		var err error
		res, err = in.HandleResp(renv, peer.relayPub(), t1)
		return err
	}); err != nil {
		return nil, err
	}
	fr, err := resp.HandleFin(res.Fin, vault.relayPub(), t1)
	if err != nil {
		return nil, err
	}
	if fr.Epoch.ID() != res.Epoch.ID() || fr.Epoch.ID() == vaultEpoch.ID() {
		return nil, errors.New("vectors: rekey epoch mismatch")
	}

	// Intermediate values, recomputed from the receiving side.
	re, _ := envelope.Parse(renv)
	rpad, rexp, err := envelope.OpenSealed(re, eph)
	if err != nil {
		return nil, err
	}
	ke, _ := rexp.Export(suite.LabelHsKe, 32)
	ks := vaultEpoch.Export().RK
	th1 := handshake.Th1(envInit)
	th := handshake.Th(envInit, renv[:envelope.HeaderSealed])
	sc, err := handshake.DeriveSchedule(ks, ke, th1, th)
	if err != nil {
		return nil, err
	}
	rin, err := envelope.DecodeInner(rpad, envelope.ModeSealed)
	if err != nil {
		return nil, err
	}
	sigR, _ := handshake.SignResp(peer.ik, th)
	sigI, _ := handshake.SignFin(vault.ik, th)

	// One message in each direction of the new epoch. The initiator's hs.fin
	// was its first message (seq 1).
	msg := func(id string, send *handshake.Epoch, nonce byte) (string, []byte, error) {
		m := &envelope.Inner{ID: id, Type: "test.ping", TS: t1}
		var env []byte
		if err := with(newScript(rep(nonce, 24)), func() error {
			var err error
			env, err = send.Seal(m)
			return err
		}); err != nil {
			return "", nil, err
		}
		j, err := m.Marshal(envelope.ModeSession)
		return string(j), env, err
	}
	msgI, envI, err := msg(RekeyMsgIID, res.Epoch, NonceRekeyMsgI)
	if err != nil {
		return nil, err
	}
	msgR, envR, err := msg(RekeyMsgRID, fr.Epoch, NonceRekeyMsgR)
	if err != nil {
		return nil, err
	}
	return obj{
		{"description", "VAULT-MESSAGING §6.2, §6.3, §6.5 rekey of the session of handshake.json, 24 h after it (the vault-to-vault limit): the vault (keys.json vault) initiates and the peer (keys.json initiator) answers. hs.init (purpose rekey) is a session-mode envelope of the old epoch, sent by the vault in direction r2i (the vault answered the first handshake), with ctx = the standard base64 of the old epoch_id, a fresh ephemeral key (seed 32 x 0x70), no token, no sas_commit and no SAS; K_s is the old epoch's rk. hs.resp is sealed to that ephemeral key with encapsulation randomness 64 x 0x72 and sender_kid all zero; hs.fin is a session envelope of the new epoch, direction i2r, seq 1, nonce 24 x 0x73. In the new epoch the vault is the initiator I (its direction is i2r) and the peer is R. th, prk and every key follow §6.3 with K_s = old rk. The last two messages are the first of the new epoch after hs.fin, one per direction. Fixed test-only inputs; the old epoch's values are copied from handshake.json."},
		{"old_epoch", old},
		{"initiator", "keys.json vault"},
		{"responder", "keys.json initiator"},
		{"inputs", obj{
			{"ts", envelope.FormatTS(t1)},
			{"initiator_eph_seed_hex", hx(rep(SeedRekeyEph, 32))},
			{"init_nonce_hex", hx(rep(NonceRekeyInit, 24))},
			{"resp_encapsulation_randomness_hex", hx(rep(RandRekeyResp, 64))},
			{"fin_nonce_hex", hx(rep(NonceRekeyFin, 24))},
			{"msg_i2r_nonce_hex", hx(rep(NonceRekeyMsgI, 24))},
			{"msg_r2i_nonce_hex", hx(rep(NonceRekeyMsgR, 24))},
			{"init_id", RekeyInitID}, {"resp_id", RekeyRespID}, {"fin_id", RekeyFinID},
			{"msg_i2r_id", RekeyMsgIID}, {"msg_r2i_id", RekeyMsgRID},
		}},
		{"hs_init_inner", string(initInner)},
		{"hs_init_body", string(initBody)},
		{"hs_init_envelope_b64", b64(envInit)},
		{"hs_resp_inner", mustInner(rin)},
		{"hs_resp_envelope_b64", b64(renv)},
		{"hs_fin_envelope_b64", b64(res.Fin)},
		{"K_s_hex", hx(ks)},
		{"K_e_hex", hx(ke)},
		{"th1_hex", hx(th1[:])},
		{"th_hex", hx(th[:])},
		{"prk_hex", hx(sc.PRK)},
		{"new_epoch", epochObj(res.Epoch)},
		{"sig_R_b64", b64(sigR)},
		{"sig_I_b64", b64(sigI)},
		{"message_i2r", obj{{"inner", msgI}, {"envelope_b64", b64(envI)}}},
		{"message_r2i", obj{{"inner", msgR}, {"envelope_b64", b64(envR)}}},
	}, nil
}
