package vault

import (
	"context"
	"crypto/ed25519"
	"testing"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// §10.15: an introduction's invitation is accepted only from the identity
// key the introducer named; another identity is dropped and audited
// (drop.intro_mismatch) and the invitation stays usable; the pending
// request carries introduced_by.
func TestIntroInvite(t *testing.T) {
	d := newDevFixture(t)
	right, wrong := newNewcomer(t, 0x60), newNewcomer(t, 0x64)
	d.m.mu.Lock()
	h := managerHost{d.m}
	id, link, err := h.CreateIntroInvite(context.Background(), right.ik.Public().(ed25519.PublicKey), "conn-B", d.m.now())
	if err == nil {
		inv := d.m.st.Invites[id]
		if inv == nil || !inv.Remote || inv.IntroBy != "conn-B" || link == "" {
			err = errBadRequest
		}
	}
	d.m.mu.Unlock()
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	d.responses(t)
	wrong.hsInit(t, d.m, handshake.PurposeConnection, id, "w1")
	if len(d.m.st.Inbound) != 0 || !d.audited("intro_mismatch") || d.m.st.Invites[id].Used {
		t.Fatal("another identity was accepted or used up the invitation")
	}
	right.hsInit(t, d.m, handshake.PurposeConnection, id, "r1")
	if len(d.m.st.Inbound) != 1 {
		t.Fatal("the named identity was refused")
	}
	var found bool
	for _, ev := range d.responses(t) {
		if ev.Type == "connection.request.pending" && bodyStr(t, ev, "introduced_by") == "conn-B" {
			found = true
		}
	}
	if !found {
		t.Fatal("pending request without introduced_by")
	}
	for _, ib := range d.m.st.Inbound {
		if ib.IntroBy != "conn-B" || !ib.Remote {
			t.Fatalf("inbound: %+v", ib)
		}
	}
	// Cancelling an introduction's invitation denylists it.
	d.m.mu.Lock()
	id2, _, err := h.CreateIntroInvite(context.Background(), right.ik.Public().(ed25519.PublicKey), "conn-B", d.m.now())
	if err == nil {
		h.CancelInvite(id2, d.m.now())
	}
	_, still := d.m.st.Invites[id2]
	d.m.mu.Unlock()
	if err != nil || still {
		t.Fatalf("cancel: %v %v", err, still)
	}
	d.m.mu.Lock()
	_, _, err = h.CreateIntroInvite(context.Background(), []byte{1}, "x", d.m.now())
	d.m.mu.Unlock()
	if err == nil {
		t.Fatal("bad key accepted")
	}
}
