package handshake

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// rekey runs a rekey initiated by the side holding `from` (with keyrings
// kFrom/kTo) and activates the new epoch on both sides.
func rekey(t *testing.T, ip, rp *party, kI, kR *Keyring, now time.Time) {
	t.Helper()
	cfg := initCfg(ip, rp, PurposeRekey)
	cfg.Current, cfg.Ctx, cfg.ResponderEK, cfg.Token, cfg.ReconnectToken = kI.Current(), "", nil, "", ""
	cfg.Now = now
	ini, err := NewInitiator(cfg)
	if err != nil {
		t.Fatalf("rekey NewInitiator: %v", err)
	}
	p, err := OpenRekeyInit(ini.Envelope(), kR.Current(), now)
	if err != nil {
		t.Fatalf("OpenRekeyInit: %v", err)
	}
	rc := respCfg(ip, rp, PurposeRekey)
	rc.Token, rc.ReconnectToken = "", ""
	rc.RecordRelayKey, rc.KnownInitiatorIK, rc.Now = ip.relayPK(), ip.pub(), now
	resp, respEnv, err := p.Respond(rc)
	if err != nil {
		t.Fatalf("rekey Respond: %v", err)
	}
	res, err := ini.HandleResp(respEnv, rp.relayPK(), now)
	if err != nil {
		t.Fatalf("rekey HandleResp: %v", err)
	}
	kI.Activate(res.Epoch, now)
	er, _, err := resp.HandleFin(res.Fin, ip.relayPK(), now)
	if err != nil {
		t.Fatalf("rekey HandleFin: %v", err)
	}
	kR.Activate(er, now)
}

func sealOpen(t *testing.T, from *Epoch, to *Keyring, now time.Time) error {
	t.Helper()
	raw, err := from.Seal(ping(t, "01JB2Z6V9K3M4N5P6Q7R8S9T0X"))
	if err != nil {
		return err
	}
	env, err := envelope.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = to.Open(env, now)
	return err
}

// §6.2/§6.5: rekey travels in session mode with K_s = rk of the previous
// epoch; on activation the previous send key is deleted and its receive key
// kept for 16 days.
func TestRekeyAndRetention(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ea, eb := runHandshake(t, a, b, PurposeConnection)
	var ka, kb Keyring
	ka.Activate(ea, t0)
	kb.Activate(eb, t0)
	old := ka.Current()

	// A message b sends in the old epoch before learning of the rekey.
	inflight, err := kb.Current().Seal(ping(t, "01JB2Z6V9K3M4N5P6Q7R8S9T0Y"))
	if err != nil {
		t.Fatal(err)
	}

	rekey(t, a, b, &ka, &kb, t0.Add(time.Hour))
	if ka.Current() == old || ka.Current().ID() == old.ID() {
		t.Fatal("no new epoch")
	}
	// Send keys of the previous epoch are gone.
	if old.CanSend() {
		t.Fatal("previous send key retained")
	}
	if _, err := old.Seal(ping(t, "01JB2Z6V9K3M4N5P6Q7R8S9T0Z")); !errors.Is(err, ErrEpochRetired) {
		t.Fatalf("seal in retired epoch: %v", err)
	}
	// New epoch works both ways.
	if err := sealOpen(t, ka.Current(), &kb, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := sealOpen(t, kb.Current(), &ka, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	// The in-flight old-epoch message still opens within retention...
	env, _ := envelope.Parse(inflight)
	if _, _, err := ka.Open(env, t0.Add(15*24*time.Hour)); err != nil {
		t.Fatalf("old epoch within retention: %v", err)
	}
	// ...and not after 16 days.
	ka.Prune(t0.Add(time.Hour + ReceiveKeyRetention + time.Second))
	if _, _, err := ka.Open(env, t0.Add(17*24*time.Hour)); !errors.Is(err, envelope.ErrKid) {
		t.Fatalf("old epoch after retention: %v", err)
	}
}

func TestRekeyCtxMustBeCurrentEpoch(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ea, _ := runHandshake(t, a, b, PurposeConnection)
	cfg := initCfg(a, b, PurposeRekey)
	cfg.Current, cfg.ResponderEK, cfg.Token, cfg.ReconnectToken = ea, nil, "", ""
	cfg.Ctx = EpochCtx([16]byte{1})
	if _, err := NewInitiator(cfg); !errors.Is(err, ErrCtx) {
		t.Fatalf("err = %v, want ErrCtx", err)
	}
}

func TestRekeyRequiresRecordIdentity(t *testing.T) {
	a, b, m := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	ea, eb := runHandshake(t, a, b, PurposeConnection)
	cfg := initCfg(a, b, PurposeRekey)
	cfg.Current, cfg.Ctx, cfg.ResponderEK, cfg.Token, cfg.ReconnectToken = ea, "", nil, "", ""
	ini, _ := NewInitiator(cfg)
	p, err := OpenRekeyInit(ini.Envelope(), eb, t0)
	if err != nil {
		t.Fatal(err)
	}
	rc := respCfg(a, b, PurposeRekey)
	rc.Token, rc.ReconnectToken = "", ""
	rc.RecordRelayKey, rc.KnownInitiatorIK = a.relayPK(), m.pub()
	if _, _, err := p.Respond(rc); !errors.Is(err, ErrIdentity) {
		t.Fatalf("err = %v, want ErrIdentity", err)
	}
	rc.KnownInitiatorIK, rc.RecordRelayKey = a.pub(), m.relayPK()
	if _, _, err := p.Respond(rc); !errors.Is(err, ErrSender) {
		t.Fatalf("err = %v, want ErrSender", err)
	}
}

// §6.5: if both sides initiate at once, the lower th1 wins.
func TestSimultaneousRekeyLowerTh1Wins(t *testing.T) {
	lo, hi := [32]byte{0x01}, [32]byte{0x02}
	if !SimultaneousRekeyWinner(lo, hi) || SimultaneousRekeyWinner(hi, lo) {
		t.Fatal("lower th1 must win")
	}
	// Both sides reach the same decision.
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ea, eb := runHandshake(t, a, b, PurposeConnection)
	ca := initCfg(a, b, PurposeRekey)
	ca.Current, ca.Ctx, ca.ResponderEK, ca.Token, ca.ReconnectToken = ea, "", nil, "", ""
	cb := initCfg(b, a, PurposeRekey)
	cb.Current, cb.Ctx, cb.ResponderEK, cb.Token, cb.ReconnectToken = eb, "", nil, "", ""
	ia, _ := NewInitiator(ca)
	ib, _ := NewInitiator(cb)
	pa, err := OpenRekeyInit(ib.Envelope(), ea, t0) // a receives b's
	if err != nil {
		t.Fatal(err)
	}
	pb, err := OpenRekeyInit(ia.Envelope(), eb, t0)
	if err != nil {
		t.Fatal(err)
	}
	aWins := SimultaneousRekeyWinner(ia.Th1(), pa.Th1())
	bWins := SimultaneousRekeyWinner(ib.Th1(), pb.Th1())
	if aWins == bWins {
		t.Fatal("both or neither side won")
	}
}

// §6.5 epoch lengths.
func TestEpochPolicy(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ea, eb := runHandshake(t, a, b, PurposeConnection)
	if ea.NeedsRekey(t0.Add(23*time.Hour)) || !ea.NeedsRekey(t0.Add(24*time.Hour)) {
		t.Fatal("vault-to-vault 24 h bound")
	}
	// 10,000 messages in either direction.
	ea.mu.Lock()
	ea.sent = 9999
	ea.mu.Unlock()
	if ea.NeedsRekey(t0) {
		t.Fatal("rekey before 10,000")
	}
	ea.mu.Lock()
	ea.sent = 10000
	ea.mu.Unlock()
	if !ea.NeedsRekey(t0) {
		t.Fatal("no rekey at 10,000 sent")
	}
	eb.mu.Lock()
	eb.received = 10000
	eb.mu.Unlock()
	if !eb.NeedsRekey(t0) {
		t.Fatal("no rekey at 10,000 received")
	}
	// Device sessions: 7 days, no message bound.
	d := &Epoch{policy: PolicyVaultToDevice, created: t0, sent: 1 << 40}
	if d.NeedsRekey(t0.Add(6*24*time.Hour)) || !d.NeedsRekey(t0.Add(7*24*time.Hour)) {
		t.Fatal("device 7 d bound")
	}
}

// §5.2/§6.3 session-mode kids: i2r carries recipient_kid = kid_i2r and
// sender_kid = kid_r2i; r2i mirrors it. A message in one direction cannot
// be opened as the other.
func TestSessionDirectionKids(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ei, er := runHandshake(t, a, b, PurposeConnection)
	raw, _ := ei.Seal(ping(t, "01JB2Z6V9K3M4N5P6Q7R8S9T10"))
	env, _ := envelope.Parse(raw)
	if !env.RecipientKid().Equal(er.recvKid) || !env.SenderKid().Equal(er.recvSenderKid) {
		t.Fatal("i2r kids")
	}
	if !env.RecipientKid().Equal(ei.sendRecipientKid) || env.RecipientKid().Equal(ei.recvKid) {
		t.Fatal("direction kids not distinct")
	}
	// Reflecting I's own message back to I fails (kid mismatch).
	if _, err := ei.Open(env); !errors.Is(err, envelope.ErrKid) {
		t.Fatalf("reflection: %v", err)
	}
}

func TestEpochRedacted(t *testing.T) {
	a, b := newParty(t, 0x10), newParty(t, 0x20)
	ei, _ := runHandshake(t, a, b, PurposeConnection)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x"} {
		if got := fmt.Sprintf(verb, ei); got != "[redacted]" {
			t.Fatalf("epoch formats as %q with %s", got, verb)
		}
	}
	if got := fmtV(ei); got != "[redacted]" {
		t.Fatalf("epoch formats as %q", got)
	}
	if got := fmtV(&Schedule{Ks: []byte{1, 2, 3}}); got != "[redacted]" {
		t.Fatalf("schedule formats as %q", got)
	}
	k, _ := suite.NewPrivateKey(seed(9))
	if got := fmtV(k); got != "[redacted]" {
		t.Fatalf("private key formats as %q", got)
	}
}

func fmtV(v any) string { return fmt.Sprintf("%v", v) }
