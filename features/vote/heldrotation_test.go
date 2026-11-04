package vote

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// §11.14.10: a transfer's approval rotates the credential key but holds
// the statement until the new phone's first unlock from storage. The
// ballots are re-signed under the new key while it is open, but the body
// under the pinned key stays in force (and is the one resent) until the
// statement has gone; then the new body is sent once, after it.
func TestHeldRotationWaitsForTheStatement(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	c.cast(v, "yes")
	oldBody := string(c.rec(v.ID).Ballot.Body)
	leaf := c.leafOf(v)
	oldPub := c.cred.Public().(ed25519.PublicKey)
	_, k1, _ := ed25519.GenerateKey(rand.Reader)
	k1Pub := k1.Public().(ed25519.PublicKey)
	c.h.Reset()
	c.f.CredentialKeysHeld(c.session(), c.cred, k1)
	b := c.rec(v.ID).Ballot
	if len(c.h.SentOfType("vote.cast")) != 0 || string(b.Body) != oldBody || b.Gen != 0 {
		t.Fatal("a body under the held key was sent or put in force")
	}
	if b.Held == nil || !eq(b.Held.Key, k1Pub) || votewire.VerifyCast(k1Pub, v.Hash, leaf, b.Held.CastSig) != nil {
		t.Fatalf("not kept aside under the new key: %+v", b.Held)
	}
	// The schedule resends the body under the pinned key.
	c.tickAt(2 * time.Minute)
	bodies, _ := c.casts()
	if len(bodies) != 1 || string(bodies[0]) != oldBody {
		t.Fatalf("resent %d bodies", len(bodies))
	}
	// A statement for another key changes nothing.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	c.h.Reset()
	c.f.CredentialKeyRotated(c.session(), &credwire.KeyRotation{Old: oldPub, New: other.Public().(ed25519.PublicKey)})
	if c.rec(v.ID).Ballot.Held == nil || len(c.h.SentOfType("vote.cast")) != 0 {
		t.Fatal("another key's statement took the held body")
	}
	// The statement K0→K1 has gone out: the new body, once.
	c.f.CredentialKeyRotated(c.session(), &credwire.KeyRotation{Old: oldPub, New: k1Pub})
	b = c.rec(v.ID).Ballot
	bodies, _ = c.casts()
	if b.Held != nil || len(bodies) != 1 || string(bodies[0]) == oldBody || b.Gen != 1 || b.SentGen != 1 {
		t.Fatalf("after the statement: held %v, %d sent, gen %d/%d", b.Held != nil, len(bodies), b.Gen, b.SentGen)
	}
	if votewire.VerifyCast(k1Pub, v.Hash, leaf, b.CastSig) != nil {
		t.Fatal("the body in force is not under K1")
	}
	// A later rotation (K1→K2) re-signs as usual.
	_, k2, _ := ed25519.GenerateKey(rand.Reader)
	c.h.Reset()
	c.f.CredentialKeysOpen(c.session(), k1, k2)
	if b := c.rec(v.ID).Ballot; votewire.VerifyCast(k2.Public().(ed25519.PublicKey), v.Hash, leaf, b.CastSig) != nil || len(c.h.SentOfType("vote.cast")) != 1 {
		t.Fatal("K1→K2 not re-signed and sent")
	}
}

// A ballot cast while the statement is held, with the new key in the
// unlock window, waits aside and goes after the statement.
func TestCastWhileRotationHeld(t *testing.T) {
	c := newCastEnv(t)
	v := c.open(1)
	oldPub := c.cred.Public().(ed25519.PublicKey)
	_, k1, _ := ed25519.GenerateKey(rand.Reader)
	k1Pub := k1.Public().(ed25519.PublicKey)
	c.keys.key = k1
	c.h.HeldRotations = [][]byte{[]byte(`{}`)}
	c.h.Reset()
	if r, err := c.cast(v, "yes"); err != nil || r.State != BallotSending {
		t.Fatalf("cast: %v %+v", err, r)
	}
	b := c.rec(v.ID).Ballot
	if len(c.h.SentOfType("vote.cast")) != 0 || b.Held == nil || b.Body != nil {
		t.Fatal("cast under the held key sent")
	}
	c.tickAt(2 * time.Minute)
	if len(c.h.SentOfType("vote.cast")) != 0 {
		t.Fatal("sent by the schedule while held")
	}
	c.h.HeldRotations = nil
	c.f.CredentialKeyRotated(c.session(), &credwire.KeyRotation{Old: oldPub, New: k1Pub})
	bodies, _ := c.casts()
	b = c.rec(v.ID).Ballot
	if len(bodies) != 1 || b.Held != nil || votewire.VerifyCast(k1Pub, v.Hash, c.leafOf(v), b.CastSig) != nil {
		t.Fatalf("after the statement: %d sent", len(bodies))
	}
}
