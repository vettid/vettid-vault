package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// A5 (VAULT-MESSAGING 0.88.2 §3.4.1 "Liveness between honest vaults"):
// release 29 does not rotate a vault's relay key (its mailbox key and
// address, §3.4 step 1) and does not advertise relay_follow. Every path
// that rotates keys (a transfer, a recovery, credential.rotate) leaves the
// relay key and mailbox as they were and sends no relay.address.update;
// the ik, kem and wake key change.

type a5Keys struct {
	relaySeed []byte
	mailbox   string
	ik        ed25519.PublicKey
	kem       []byte
}

// a5Snapshot records the keys, and gives the vault a push registration
// (its wake key, §14.1) for the rotation to replace.
func a5Snapshot(m *Manager) a5Keys {
	m.st.Push = &PushRegistration{DeviceID: "a5-app", WakeSeed: bytes.Repeat([]byte{0xa5}, 32)}
	return a5Keys{relaySeed: append([]byte(nil), m.st.Relay.Seed...),
		mailbox: m.st.Relay.Mailbox, ik: append(ed25519.PublicKey(nil), m.keys.ik.Public().(ed25519.PublicKey)...),
		kem: m.keys.kem.Public().Bytes()}
}

func a5Check(t *testing.T, path string, before a5Keys, m *Manager) {
	t.Helper()
	after := a5Keys{relaySeed: m.st.Relay.Seed, mailbox: m.st.Relay.Mailbox, ik: m.keys.ik.Public().(ed25519.PublicKey),
		kem: m.keys.kem.Public().Bytes()}
	if !bytes.Equal(before.relaySeed, after.relaySeed) || before.mailbox != after.mailbox ||
		!bytes.Equal(m.keys.relay.Public().(ed25519.PublicKey), ed25519.NewKeyFromSeed(before.relaySeed).Public().(ed25519.PublicKey)) {
		t.Fatalf("%s: the relay key or mailbox changed", path)
	}
	if bytes.Equal(before.ik, after.ik) || bytes.Equal(before.kem, after.kem) {
		t.Fatalf("%s: the ik or kem did not change", path)
	}
	if m.st.Push != nil {
		t.Fatalf("%s: the wake key (push registration) was not replaced", path)
	}
}

// sentTypes opens side from's deposits to side to with to's keyring and
// returns their inner types.
func (f *r29Fx) sentTypes(from, to int) []string {
	fm := f.m(from)
	fm.mu.Lock()
	_ = fm.flushThenDrain(context.Background())
	fm.mu.Unlock()
	kr := f.m(to).sessions[f.id[to]]
	var types []string
	f.d[from].relay.mu.Lock()
	defer f.d[from].relay.mu.Unlock()
	for _, dep := range f.d[from].relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err != nil || dep.mailbox != f.m(to).st.Relay.Mailbox || env.Mode() != envelope.ModeSession {
			continue
		}
		if in, _, err := kr.Open(env, f.clk); err == nil {
			types = append(types, in.Type)
		}
	}
	return types
}

func TestR29A5RelayKeyNotRotated(t *testing.T) {
	paths := map[string]func(f *r29Fx){
		"credential.rotate": func(f *r29Fx) {
			f.do(0, func(m *Manager, _ *Peer) {
				if err := m.session(f.clk).RotateIdentity(); err != nil {
					t.Fatal(err)
				}
			})
		},
		"transfer": func(f *r29Fx) {
			f.do(0, func(m *Manager, _ *Peer) {
				m.st.RotationOwed = &RotationOwed{Transfer: "t1", At: f.clk.Add(-8 * 24 * time.Hour), DEKVersion: m.dekVersion()}
				m.retryOwedRotation(f.clk)
			})
		},
		"recovery (owed)": func(f *r29Fx) {
			f.do(0, func(m *Manager, _ *Peer) {
				m.st.RotationOwed = &RotationOwed{Recovery: "r1"}
				m.retryOwedRotation(f.clk)
			})
		},
	}
	for path, rotate := range paths {
		f := newR29Fx(t)
		f.longTokens()
		f.lose(0, 1, kAny)
		f.m(0).mu.Lock()
		before := a5Snapshot(f.m(0))
		f.m(0).mu.Unlock()
		rounds := len(f.m(0).st.Rotations)
		rotate(f)
		if len(f.m(0).st.Rotations) != rounds+1 {
			t.Fatalf("%s: setup: no rotation", path)
		}
		a5Check(t, path, before, f.m(0))
		types := f.sentTypes(0, 1)
		if !slices.Contains(types, "identity.rotate") || slices.Contains(types, "relay.address.update") {
			t.Fatalf("%s: sent %v", path, types)
		}
	}
	// A recovery's open (§11.14.6 step 6) rotates at once.
	var before a5Keys
	f := newOpenFixtureWith(t, func(f *openFixture) {
		f.m.mu.Lock()
		before = a5Snapshot(f.m)
		f.m.mu.Unlock()
	})
	m, out := f.open(testPIN, rPW)
	if m == nil || !out.OK {
		t.Fatalf("recovery open: %+v", out)
	}
	m.mu.Lock()
	a5Check(t, "recovery open", before, m)
	m.mu.Unlock()
	m.Crash()
}

func TestR29A5NoRelayFollowAdvertised(t *testing.T) {
	const name = "relay_follow"
	if slices.Contains(CoreFeatures(), name) {
		t.Fatal("CoreFeatures advertises relay_follow")
	}
	for _, offered := range []bool{true, false} {
		if slices.Contains(altchan.ReleaseCapabilities(offered), name) {
			t.Fatal("the §11.10.9 release capability list has relay_follow")
		}
	}
	f := newR29Fx(t)
	f.do(0, func(m *Manager, p *Peer) {
		if slices.Contains(m.featuresFor(p), name) {
			t.Fatal("a connection's inner features have relay_follow")
		}
		svc := *p
		svc.PeerKind = "service"
		if slices.Contains(m.featuresFor(&svc), name) {
			t.Fatal("a service's inner features have relay_follow")
		}
		if slices.Contains(m.featuresFor(&Peer{ID: "d", Kind: KindApp}), name) {
			t.Fatal("a device's inner features have relay_follow")
		}
	})
	// The inner features of a deposited message.
	f.note(0, "a5")
	fm := f.m(0)
	fm.mu.Lock()
	_ = fm.flushThenDrain(context.Background())
	fm.mu.Unlock()
	kr := f.m(1).sessions[f.id[1]]
	seen := false
	f.d[0].relay.mu.Lock()
	for _, dep := range f.d[0].relay.deposits {
		env, err := envelope.Parse(dep.payload)
		if err != nil || env.Mode() != envelope.ModeSession {
			continue
		}
		if in, _, err := kr.Open(env, f.clk); err == nil && in.Type == "test.note" {
			seen = true
			if slices.Contains(in.Features, name) || len(in.Features) == 0 {
				f.d[0].relay.mu.Unlock()
				t.Fatalf("deposited features %v", in.Features)
			}
		}
	}
	f.d[0].relay.mu.Unlock()
	if !seen {
		t.Fatal("setup: no deposited message")
	}
}
