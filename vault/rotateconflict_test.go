package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// One successor per key (VAULT-MESSAGING 0.33.0 §3.4): a second valid
// successor of an accepted old_ik suspends the connection until the
// holder resolves it.
func TestRotationConflict(t *testing.T) {
	f := newFixture(t)
	m := f.m
	now := time.Now()
	key := func(b byte) ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, 32)) }
	kem, _ := suite.GeneratePrivateKey()
	old, a, b := key(1), key(2), key(3)
	ra, _ := handshake.NewRotation(old, a, kem.Public())
	rb, _ := handshake.NewRotation(old, b, kem.Public())
	p := &Peer{ID: "c1", Kind: KindConnection, State: PeerActive, IK: a.Public().(ed25519.PublicKey), Chain: []json.RawMessage{ra.Marshal()}}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.st.Connections[p.ID] = p
	if m.rotationConflict(p, ra, now) {
		t.Fatal("the same statement again is no conflict")
	}
	if !m.rotationConflict(p, rb, now) || p.Conflict == nil || len(p.Conflict.Statements) != 2 {
		t.Fatal("no conflict recorded")
	}
	if id := m.sendTo(p, "message.send", []byte(`{}`), now); id != "" {
		t.Fatal("a suspended connection was sent to")
	}
	// The holder keeps b.
	s := m.session(now)
	s.from = PeerInfo{ID: "app1", Kind: KindApp}
	in := testInner(`{"connection_id":"c1","new_ik":"` + b64(b.Public().(ed25519.PublicKey)) + `"}`)
	if _, err := m.hRotationResolve(context.Background(), s, in); err != nil {
		t.Fatal(err)
	}
	if p.Conflict != nil || !suite.EqualPublic(p.IK, b.Public().(ed25519.PublicKey)) {
		t.Fatal("not resolved to b")
	}
	if _, err := m.hRotationResolve(context.Background(), s, in); err == nil {
		t.Fatal("resolved twice")
	}
	s.from = PeerInfo{ID: "d1", Kind: KindDesktop}
	if _, err := m.hRotationResolve(context.Background(), s, in); err == nil {
		t.Fatal("a desktop resolved")
	}
}

func testInner(body string) *envelope.Inner {
	return &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T50", Type: TypeRotationResolve, TS: time.Now(), Body: []byte(body)}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
