package handshake

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

func ping(t testing.TB, id string) *envelope.Inner {
	t.Helper()
	return &envelope.Inner{ID: id, Type: "test.ping", TS: t0, Body: json.RawMessage(`{"n":1}`)}
}

func exchange(t *testing.T, from, to *Epoch) *envelope.Inner {
	t.Helper()
	raw, err := from.Seal(ping(t, "01JB2Z6V9K3M4N5P6Q7R8S9T0W"))
	if err != nil {
		t.Fatal(err)
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	in, err := to.Open(env)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return in
}

func TestHandshakeAllPurposes(t *testing.T) {
	for _, p := range []Purpose{PurposeConnection, PurposeApp, PurposeDesktop, PurposeAgent} {
		t.Run(string(p), func(t *testing.T) {
			i, r := newParty(t, 0x10), newParty(t, 0x20)
			ei, er := runHandshake(t, i, r, p)
			if ei.ID() != er.ID() {
				t.Fatal("epoch ids differ")
			}
			// hs.fin consumed i2r seq 1; next i2r message is seq 2.
			if in := exchange(t, ei, er); in.Seq != 2 {
				t.Fatalf("i2r seq = %d, want 2", in.Seq)
			}
			if in := exchange(t, er, ei); in.Seq != 1 {
				t.Fatalf("r2i seq = %d, want 1", in.Seq)
			}
		})
	}
}

// §6.3: I MUST verify sig_R before using any epoch key, and MUST abort.
func TestMustVerifySigRAndAbort(t *testing.T) {
	i, r, mallory := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	ini, err := NewInitiator(initCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	// Mallory answers with her own identity key: sig_R does not verify
	// under the pinned ik_R.
	rc := respCfg(i, r, PurposeConnection)
	rc.Identity = mallory.ik
	_, respEnv, err := p.Respond(rc)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ini.HandleResp(respEnv, r.relayPK(), t0); !errors.Is(err, ErrSigResp) {
		t.Fatalf("err = %v, want ErrSigResp", err)
	}
	// Aborted: the state is gone, nothing more is accepted.
	if _, err := ini.HandleResp(respEnv, r.relayPK(), t0); !errors.Is(err, ErrDone) {
		t.Fatalf("after abort err = %v, want ErrDone", err)
	}
}

// §6.3: R activates the epoch only after sig_I verifies.
func TestMustActivateOnlyAfterSigI(t *testing.T) {
	i, r, mallory := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	cfg := initCfg(i, r, PurposeConnection)
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	resp, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	// I completes, but signs hs.fin with the wrong key.
	ini.cfg.Identity = mallory.ik
	res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.HandleFin(res.Fin, i.relayPK(), t0); !errors.Is(err, ErrSigFin) {
		t.Fatalf("err = %v, want ErrSigFin", err)
	}
	// Still pending (not activated, not cancelled by the bad message).
	if resp.done {
		t.Fatal("responder activated or aborted on a bad sig_I")
	}
}

// §6.3: the collect sender MUST equal from.relay.pk for hs.init, and the
// relay key on record for later messages.
func TestMustCheckCollectSender(t *testing.T) {
	i, r, mallory := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	rc := respCfg(i, r, PurposeConnection)
	rc.CollectSender = mallory.relayPK()
	if _, _, err := p.Respond(rc); !errors.Is(err, ErrSender) {
		t.Fatalf("hs.init sender: err = %v, want ErrSender", err)
	}
	resp, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ini.HandleResp(respEnv, mallory.relayPK(), t0); !errors.Is(err, ErrSender) {
		t.Fatalf("hs.resp sender: err = %v, want ErrSender", err)
	}
	// The failed HandleResp aborted I; run a fresh one for hs.fin.
	ini2, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	p2, _ := OpenInit(ini2.Envelope(), r.lookup, t0)
	resp2, respEnv2, _ := p2.Respond(respCfg(i, r, PurposeConnection))
	res2, err := ini2.HandleResp(respEnv2, r.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp2.HandleFin(res2.Fin, mallory.relayPK(), t0); !errors.Is(err, ErrSender) {
		t.Fatalf("hs.fin sender: err = %v, want ErrSender", err)
	}
	_ = resp
	if err := CheckSender(mallory.relayPK(), i.relayPK()); !errors.Is(err, ErrSender) {
		t.Fatal("CheckSender accepted a mismatch")
	}
	if err := CheckSender(i.relayPK(), i.relayPK()); err != nil {
		t.Fatal(err)
	}
}

// §6.2 kids: hs.init recipient_kid = kid(ek_R); sender_kid = anonymous or
// kid(from.kem); hs.resp recipient_kid = kid(eph).
func TestHandshakeKids(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	for _, anon := range []bool{false, true} {
		cfg := initCfg(i, r, PurposeConnection)
		cfg.AnonymousSender = anon
		ini, err := NewInitiator(cfg)
		if err != nil {
			t.Fatal(err)
		}
		env, _ := envelope.Parse(ini.Envelope())
		if !env.RecipientKid().Equal(r.kem.Public().Kid()) {
			t.Fatal("hs.init recipient_kid != kid(ek_R)")
		}
		want := i.kem.Public().Kid()
		if anon {
			want = suite.Anonymous
		}
		if !env.SenderKid().Equal(want) {
			t.Fatal("hs.init sender_kid wrong")
		}
		p, err := OpenInit(ini.Envelope(), r.lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		_, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
		if err != nil {
			t.Fatal(err)
		}
		renv, _ := envelope.Parse(respEnv)
		if !renv.RecipientKid().Equal(ini.EphKid()) || !renv.SenderKid().IsAnonymous() {
			t.Fatal("hs.resp kids wrong")
		}
		if renv.Mode() != envelope.ModeSealed {
			t.Fatal("hs.resp not sealed")
		}
	}
}

// A non-anonymous sender_kid that is not kid(from.kem) is rejected.
func TestHandshakeSenderKidMismatch(t *testing.T) {
	i, r, m := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	cfg := initCfg(i, r, PurposeConnection)
	cfg.StaticKEM = i.kem.Public()
	ini, _ := NewInitiator(cfg)
	raw := ini.Envelope()
	// Rewrite sender_kid to Mallory's kid: the AAD changes, so decryption
	// fails before the kid check could even be reached.
	mk := m.kem.Public().Kid()
	copy(raw[4:12], mk[:])
	if _, err := OpenInit(raw, r.lookup, t0); err == nil {
		t.Fatal("accepted tampered sender_kid")
	}
}

// §4.4: a receiver MUST NOT trial-decrypt under other principals' keys:
// with no key for the recipient_kid, nothing is tried.
func TestMustNotTrialDecrypt(t *testing.T) {
	i, r, other := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	tried := 0
	lookup := func(kid suite.Kid) *suite.PrivateKey {
		tried++
		if kid.Equal(other.kem.Public().Kid()) {
			return other.kem
		}
		return nil
	}
	if _, err := OpenInit(ini.Envelope(), lookup, t0); !errors.Is(err, ErrNoKey) {
		t.Fatalf("err = %v, want ErrNoKey", err)
	}
	if tried != 1 {
		t.Fatalf("lookup called %d times", tried)
	}
	// A lookup that returns the wrong key is caught by the kid check.
	wrong := func(suite.Kid) *suite.PrivateKey { return other.kem }
	if _, err := OpenInit(ini.Envelope(), wrong, t0); !errors.Is(err, envelope.ErrKid) {
		t.Fatalf("err = %v, want ErrKid", err)
	}
}

// §6.3 (0.10.3): the SAS exists only after hs.resp (initiator) and hs.fin
// (responder); both compute the same six digits from prk, th and both
// nonces.
func TestSASBothSides(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	for _, purpose := range []Purpose{PurposeApp, PurposeDesktop, PurposeAgent, PurposeConnection} {
		ini, _ := NewInitiator(initCfg(i, r, purpose))
		if ini.Body().SASCommit == nil {
			t.Fatalf("%s: no sas_commit", purpose)
		}
		p, err := OpenInit(ini.Envelope(), r.lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		resp, respEnv, err := p.Respond(respCfg(i, r, purpose))
		if err != nil {
			t.Fatal(err)
		}
		res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
		if err != nil {
			t.Fatal(err)
		}
		fr, err := resp.HandleFin(res.Fin, i.relayPK(), t0)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.SAS) != 6 || res.SAS != fr.SAS {
			t.Fatalf("%s: SAS %q vs %q", purpose, res.SAS, fr.SAS)
		}
		for _, c := range res.SAS {
			if c < '0' || c > '9' {
				t.Fatal("non-digit SAS")
			}
		}
		// One hs.resp per hs.init: n_I is revealed, the state is gone.
		if _, err := ini.HandleResp(respEnv, r.relayPK(), t0); !errors.Is(err, ErrDone) {
			t.Fatalf("second hs.resp: %v", err)
		}
	}
}

// §6.3 (0.10.3): the SAS depends on both nonces.
func TestSASDependsOnBothNonces(t *testing.T) {
	prk := bytes.Repeat([]byte{1}, 32)
	var th [32]byte
	a := bytes.Repeat([]byte{0x16}, 32)
	b := bytes.Repeat([]byte{0x17}, 32)
	s1, _ := SAS(prk, th, a, b)
	s2, _ := SAS(prk, th, b, a)
	s3, _ := SAS(prk, th, a, a)
	if s1 == s2 && s1 == s3 {
		t.Fatal("SAS does not depend on the nonces")
	}
	if _, err := SAS(prk, th, a[:31], b); err == nil {
		t.Fatal("short nonce accepted")
	}
	c := SASCommit(a)
	if !CheckSASCommit(c[:], a) || CheckSASCommit(c[:], b) || CheckSASCommit(c[:], nil) {
		t.Fatal("commitment check")
	}
}

// §6.3 (0.10.3): an hs.fin whose sig_I verifies but whose n_I does not
// open sas_commit aborts the handshake and destroys its state.
func TestSASCommitMismatchAborts(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	resp, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	ini.nI = bytes.Repeat([]byte{0x99}, 32) // a nonce other than the committed one
	res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resp.HandleFin(res.Fin, i.relayPK(), t0); !errors.Is(err, ErrSASCommit) {
		t.Fatalf("err = %v, want ErrSASCommit", err)
	}
	if !resp.done {
		t.Fatal("responder kept the handshake after a commitment mismatch")
	}
	if _, err := resp.HandleFin(res.Fin, i.relayPK(), t0); !errors.Is(err, ErrDone) {
		t.Fatalf("after abort: %v", err)
	}
}

// §6.2 (0.10.3): rekeys and reconnects carry no commitment fields and
// have no SAS.
func TestNoSASForRekeyAndReconnect(t *testing.T) {
	if PurposeRekey.HasSAS() || PurposeReconnect.HasSAS() {
		t.Fatal("rekey or reconnect has a SAS")
	}
	in := sampleInit(t, PurposeReconnect)
	c := SASCommit(make([]byte, 32))
	in.SASCommit = c[:]
	if _, err := in.Marshal(); err == nil {
		t.Fatal("sas_commit accepted for a reconnect")
	}
	in = sampleInit(t, PurposeConnection)
	in.SASCommit = nil
	if _, err := in.Marshal(); err == nil {
		t.Fatal("connection hs.init without sas_commit accepted")
	}
}

// §13.4: sig_R covers th, which covers the whole hs.init including the
// suites offer; any change to the hs.init bytes the initiator holds breaks
// sig_R.
func TestDowngradeSuitesStripDetected(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	cfg := initCfg(i, r, PurposeConnection)
	cfg.Suites = []int{2, 3}
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenInit(ini.Envelope(), r.lookup, t0)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Init().Suites; len(got) != 2 {
		t.Fatalf("suites = %v", got)
	}
	_, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	// The responder saw (and signed) a different hs.init than the one
	// the initiator sent: model it by changing the initiator's copy.
	ini.env[len(ini.env)-1] ^= 1
	if _, err := ini.HandleResp(respEnv, r.relayPK(), t0); !errors.Is(err, ErrSigResp) {
		t.Fatalf("err = %v, want ErrSigResp", err)
	}
}

// §13.4: a responder's choice must be offered and not below the pin.
func TestDowngradeChosenSuite(t *testing.T) {
	if err := suite.CheckChosen(2, []int{2}, 0); err != nil {
		t.Fatal(err)
	}
	if err := suite.CheckChosen(1, []int{2}, 0); !errors.Is(err, suite.ErrSuite1) {
		t.Fatalf("suite 1: %v", err)
	}
	if err := suite.CheckChosen(2, []int{2}, 3); !errors.Is(err, suite.ErrDowngrade) {
		t.Fatalf("below pin: %v", err)
	}
	if err := suite.CheckChosen(3, []int{2}, 0); err == nil {
		t.Fatal("accepted unoffered/unsupported suite")
	}
	// A pinned record refuses a handshake whose offer cannot meet the pin.
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	p, _ := OpenInit(ini.Envelope(), r.lookup, t0)
	rc := respCfg(i, r, PurposeConnection)
	rc.PinnedSuite = 3
	if _, _, err := p.Respond(rc); !errors.Is(err, suite.ErrNoCommonSuite) {
		t.Fatalf("err = %v, want ErrNoCommonSuite", err)
	}
}

func TestHandshakeTamperedResp(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	for _, off := range []int{0, 3, 25, 1139, 1140, -1} {
		ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
		p, _ := OpenInit(ini.Envelope(), r.lookup, t0)
		_, respEnv, _ := p.Respond(respCfg(i, r, PurposeConnection))
		if off < 0 {
			off = len(respEnv) - 1
		}
		respEnv[off] ^= 0x40
		if _, err := ini.HandleResp(respEnv, r.relayPK(), t0); err == nil {
			t.Fatalf("accepted tampered byte %d", off)
		}
	}
}

func TestResponderSingleUse(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	p, _ := OpenInit(ini.Envelope(), r.lookup, t0)
	if _, _, err := p.Respond(respCfg(i, r, PurposeConnection)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := p.Respond(respCfg(i, r, PurposeConnection)); !errors.Is(err, ErrDone) {
		t.Fatalf("second Respond: %v", err)
	}
}

func TestRekeyMustTravelInSessionMode(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ei, _ := runHandshake(t, i, r, PurposeConnection)
	cfg := initCfg(i, r, PurposeRekey)
	cfg.Current = ei
	cfg.Ctx = ""
	cfg.ResponderEK = nil
	cfg.Token = ""
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := envelope.Parse(ini.Envelope())
	if env.Mode() != envelope.ModeSession {
		t.Fatal("rekey hs.init not in session mode")
	}
	// It cannot be opened as a sealed hs.init.
	if _, err := OpenInit(ini.Envelope(), r.lookup, t0); err == nil {
		t.Fatal("rekey accepted through OpenInit")
	}
}

// Messages that never decrypt under eph cannot cancel a pending handshake;
// the genuine hs.resp still completes it.
func TestJunkDoesNotCancelHandshake(t *testing.T) {
	i, r, m := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	p, _ := OpenInit(ini.Envelope(), r.lookup, t0)
	_, respEnv, err := p.Respond(respCfg(i, r, PurposeConnection))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ini.HandleResp(respEnv, m.relayPK(), t0); !errors.Is(err, ErrSender) {
		t.Fatal("wrong sender accepted")
	}
	bad := append([]byte(nil), respEnv...)
	bad[len(bad)-1] ^= 1
	if _, err := ini.HandleResp(bad, r.relayPK(), t0); err == nil {
		t.Fatal("tampered accepted")
	}
	if _, err := ini.HandleResp([]byte("junk"), r.relayPK(), t0); err == nil {
		t.Fatal("junk accepted")
	}
	if _, err := ini.HandleResp(respEnv, r.relayPK(), t0); err != nil {
		t.Fatalf("genuine hs.resp after junk: %v", err)
	}
}
