package handshake

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// rotateParty rotates p's identity and KEM keys and returns the statement.
func rotateParty(t *testing.T, p *party, base byte) *Rotation {
	t.Helper()
	newIK := ed25519.NewKeyFromSeed(seed(base))
	newKEM, err := suite.NewPrivateKey(seed(base + 1))
	if err != nil {
		t.Fatal(err)
	}
	r, err := NewRotation(p.ik, newIK, newKEM.Public())
	if err != nil {
		t.Fatal(err)
	}
	p.ik, p.kem = newIK, newKEM
	return r
}

type reconnectCase struct {
	// Stored state on each side from the last epoch.
	storedIKofI, storedIKofR ed25519.PublicKey
	storedEKofR              *suite.PublicKey
	lastEpoch                [16]byte
}

func reconnect(t *testing.T, i, r *party, rc reconnectCase, rotI, rotR []*Rotation) (*Result, *Epoch, error) {
	t.Helper()
	cfg := initCfg(i, r, PurposeReconnect)
	cfg.Ctx = EpochCtx(rc.lastEpoch)
	cfg.ResponderIK, cfg.ResponderEK = rc.storedIKofR, rc.storedEKofR
	cfg.Rotations = rotI
	ini, err := NewInitiator(cfg)
	if err != nil {
		return nil, nil, err
	}
	// The vault keeps retired KEM keys for reconnects sealed to them.
	lookup := r.lookup
	if r.retired != nil {
		lookup = func(kid suite.Kid) *suite.PrivateKey {
			if k := r.lookup(kid); k != nil {
				return k
			}
			if kid.Equal(r.retired.Public().Kid()) {
				return r.retired
			}
			return nil
		}
	}
	p, err := OpenInit(ini.Envelope(), lookup, t0)
	if err != nil {
		return nil, nil, err
	}
	// Permitted use of a reconnect token (§6.6).
	if err := CheckReconnectTokenUse(envelope.ModeSealed, p); err != nil {
		return nil, nil, err
	}
	rcfg := respCfg(i, r, PurposeReconnect)
	rcfg.RecordRelayKey, rcfg.KnownInitiatorIK = i.relayPK(), rc.storedIKofI
	rcfg.ExpectedCtx = EpochCtx(rc.lastEpoch)
	rcfg.Rotations = rotR
	resp, respEnv, err := p.Respond(rcfg)
	if err != nil {
		return nil, nil, err
	}
	res, err := ini.HandleResp(respEnv, r.relayPK(), t0)
	if err != nil {
		return nil, nil, err
	}
	fr, err := resp.HandleFin(res.Fin, i.relayPK(), t0)
	if err != nil {
		return nil, nil, err
	}
	return res, fr.Epoch, nil
}

// §6.6: a reconnect needs no SAS when identities match; both sides follow
// each other's rotation chains; retired KEM keys still open old hs.inits.
func TestReconnectWithRotations(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ei, _ := runHandshake(t, i, r, PurposeConnection)
	rc := reconnectCase{storedIKofI: i.pub(), storedIKofR: r.pub(), storedEKofR: r.kem.Public(), lastEpoch: ei.ID()}

	// Both rotate while unreachable. R keeps its retired KEM key.
	rotI := []*Rotation{rotateParty(t, i, 0x40), rotateParty(t, i, 0x50)}
	oldKEM := r.kem
	rotR := []*Rotation{rotateParty(t, r, 0x60)}
	r.retired = oldKEM

	res, er, err := reconnect(t, i, r, rc, rotI, rotR)
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	if !suite.EqualPublic(res.ResponderIK, r.pub()) || !res.ResponderKEM.Equal(r.kem.Public()) {
		t.Fatal("initiator did not follow R's rotation chain")
	}
	if res.Epoch.ID() != er.ID() {
		t.Fatal("epochs differ")
	}
}

func TestReconnectRejections(t *testing.T) {
	i, r, m := newParty(t, 0x10), newParty(t, 0x20), newParty(t, 0x30)
	ei, _ := runHandshake(t, i, r, PurposeConnection)
	base := reconnectCase{storedIKofI: i.pub(), storedIKofR: r.pub(), storedEKofR: r.kem.Public(), lastEpoch: ei.ID()}

	t.Run("identity not reached by chain", func(t *testing.T) {
		rc := base
		rc.storedIKofI = m.pub()
		if _, _, err := reconnect(t, i, r, rc, nil, nil); !errors.Is(err, ErrIdentity) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("broken chain", func(t *testing.T) {
		ii := *i
		rot := rotateParty(t, &ii, 0x70)
		rot.SigOld[0] ^= 1
		if _, _, err := reconnect(t, &ii, r, base, []*Rotation{rot}, nil); !errors.Is(err, ErrRotation) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("from.kem not the chain's final new_kem", func(t *testing.T) {
		ii := *i
		rot := rotateParty(t, &ii, 0x90)
		ii.kem = i.kem // presents the old KEM key after rotating
		if _, _, err := reconnect(t, &ii, r, base, []*Rotation{rot}, nil); !errors.Is(err, ErrIdentity) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("wrong ctx", func(t *testing.T) {
		rc := base
		rc.lastEpoch = [16]byte{9}
		cfg := initCfg(i, r, PurposeReconnect)
		cfg.Ctx = EpochCtx(rc.lastEpoch)
		ini, _ := NewInitiator(cfg)
		p, err := OpenInit(ini.Envelope(), r.lookup, t0)
		if err != nil {
			t.Fatal(err)
		}
		rcfg := respCfg(i, r, PurposeReconnect)
		rcfg.RecordRelayKey, rcfg.KnownInitiatorIK = i.relayPK(), i.pub()
		rcfg.ExpectedCtx = EpochCtx(base.lastEpoch)
		if _, _, err := p.Respond(rcfg); !errors.Is(err, ErrCtx) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("sender not the record", func(t *testing.T) {
		cfg := initCfg(i, r, PurposeReconnect)
		cfg.Ctx = EpochCtx(base.lastEpoch)
		ini, _ := NewInitiator(cfg)
		p, _ := OpenInit(ini.Envelope(), r.lookup, t0)
		rcfg := respCfg(i, r, PurposeReconnect)
		rcfg.RecordRelayKey, rcfg.KnownInitiatorIK = m.relayPK(), i.pub()
		rcfg.ExpectedCtx = EpochCtx(base.lastEpoch)
		if _, _, err := p.Respond(rcfg); !errors.Is(err, ErrSender) {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("responder chain wrong", func(t *testing.T) {
		rr := *r
		rot := rotateParty(t, &rr, 0x80)
		rr.ik, rr.kem = r.ik, r.kem // R signs with the old key but announces a rotation
		if _, _, err := reconnect(t, i, &rr, base, nil, []*Rotation{rot}); !errors.Is(err, ErrSigResp) {
			t.Fatalf("err = %v", err)
		}
	})
}

// §6.6 Permitted use: only a sealed hs.init with purpose reconnect.
func TestReconnectTokenPermittedUse(t *testing.T) {
	i, r := newParty(t, 0x10), newParty(t, 0x20)
	ini, _ := NewInitiator(initCfg(i, r, PurposeConnection))
	p, _ := OpenInit(ini.Envelope(), r.lookup, t0)
	if err := CheckReconnectTokenUse(envelope.ModeSealed, p); !errors.Is(err, ErrTokenUse) {
		t.Fatal("connection hs.init accepted on a reconnect token")
	}
	if err := CheckReconnectTokenUse(envelope.ModeSession, nil); !errors.Is(err, ErrTokenUse) {
		t.Fatal("session message accepted on a reconnect token")
	}
	if err := CheckReconnectTokenUse(envelope.ModeSealed, nil); !errors.Is(err, ErrTokenUse) {
		t.Fatal("non-hs.init accepted on a reconnect token")
	}
}

func TestReconnectTokenParameters(t *testing.T) {
	if ReconnectTokenLifetime(0) != 365*24*time.Hour {
		t.Fatal("default lifetime")
	}
	if ReconnectTokenLifetime(400*24*time.Hour) != 365*24*time.Hour {
		t.Fatal("lifetime above 365 d")
	}
	if ReconnectTokenLifetime(100*24*time.Hour) != 100*24*time.Hour {
		t.Fatal("relay cap not applied")
	}
	if !ShouldUseReconnect(true, t0.Add(time.Hour), t0) || !ShouldUseReconnect(false, t0, t0) || ShouldUseReconnect(false, t0.Add(time.Second), t0) {
		t.Fatal("ShouldUseReconnect")
	}
	if !ReconnectRemintDue(t0.Add(59*24*time.Hour), t0) || ReconnectRemintDue(t0.Add(61*24*time.Hour), t0) {
		t.Fatal("ReconnectRemintDue")
	}
}

func TestRotationChain(t *testing.T) {
	p := newParty(t, 0x10)
	start := p.pub()
	r1 := rotateParty(t, p, 0x40)
	r2 := rotateParty(t, p, 0x50)
	final, kem, err := ResolveChain(start, []*Rotation{r1, r2})
	if err != nil || !suite.EqualPublic(final, p.pub()) || !kem.Equal(p.kem.Public()) {
		t.Fatalf("chain: %v", err)
	}
	if _, _, err := ResolveChain(start, []*Rotation{r2, r1}); !errors.Is(err, ErrRotation) {
		t.Fatal("out-of-order chain accepted")
	}
	if f, k, err := ResolveChain(start, nil); err != nil || !suite.EqualPublic(f, start) || k != nil {
		t.Fatal("empty chain")
	}
	// Round trip.
	r1b, err := ParseRotation(r1.Marshal())
	if err != nil || r1b.Verify() != nil {
		t.Fatalf("round trip: %v", err)
	}
	r1b.SigNew[3] ^= 1
	if r1b.Verify() == nil {
		t.Fatal("bad sig_new accepted")
	}
	long := make([]*Rotation, MaxRotations+1)
	if _, _, err := ResolveChain(start, long); !errors.Is(err, ErrRotation) {
		t.Fatal("overlong chain accepted")
	}
}
