//go:build devenclave && e2e

package e2e

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
)

// VAULT-MESSAGING 0.49.0 §11.5, §11.11.4, §11.14.8 through the enclave:
// an owner app's unlock with cancel_recovery answers the clear marker
// recovery_cancelled with the id of the recovery it ended, and its
// unlocked event carries the id; a cancel that names another recovery
// cancels nothing and answers recovery_not_current (no envelope); a
// seven-line cancel keeps the old rule.

// unlockResp is acWorld.unlock that also returns the answer's clear part.
func (aw *acWorld) unlockResp(a *acApp, pin string, o client.UnlockOptions) (*altchan.UnlockResult, *enclave.Response) {
	aw.t.Helper()
	e, in := aw.enclave(a, "", false)
	_, m, err := a.dev.VerifyManifest(aw.w.Served(), aw.trust)
	if err != nil {
		aw.t.Fatal(err)
	}
	req, err := a.dev.BuildUnlock(a.guid, pin, e, m, a.att, o)
	if err != nil {
		aw.t.Fatal(err)
	}
	resp, err := aw.w.Post(ctxT(aw.t, 60*time.Second), in, enclave.OpUnlock, a.vid, a.guid, req)
	if err != nil {
		aw.t.Fatal(err)
	}
	r, err := a.dev.OpenUnlockResult(resp.Envelope)
	if err != nil {
		aw.t.Fatal(err)
	}
	return r, resp
}

func TestRecoveryCancelledMarkerAndNamedCancel(t *testing.T) {
	rr := newRecR(t)
	a := rr.newApp("member-rc", enclavetest.NewAndroidAttester(0x71, enclavetest.AndroidOptions{}))
	if r := rr.enroll(a, acPIN); !r.OK {
		t.Fatal(r.Code)
	}
	rr.advance(73 * time.Hour)
	ctx := ctxT(t, 120*time.Second)
	in := rr.w.Instance(3)

	// R1, cancelled by a cancel that names another recovery: nothing is
	// cancelled; the answer has no envelope and the code
	// recovery_not_current.
	q1, _ := rr.request(a)
	resp := rr.w.RecoveryCancelNamed(ctx, in, a.vid, a.guid, "01JB2Z6V9K3M4N5P6Q7R8S9T99")
	if resp == nil || resp.Status != enclave.StatusDone || resp.Code != enclave.CodeRecoveryNotCurrent || resp.Envelope != nil {
		t.Fatalf("named cancel of another recovery: %+v", resp)
	}
	if r, resp := rr.unlockResp(a, acPIN, client.UnlockOptions{}); r.OK || r.Code != "recovery_pending" || resp.Code != "" {
		t.Fatalf("R1 kept: %+v %q", r, resp.Code)
	}
	// The same cancel naming R1 cancels it, with no code.
	if resp := rr.w.RecoveryCancelNamed(ctx, in, a.vid, a.guid, q1.RecoveryID); resp == nil || resp.Code != "" || resp.Envelope != nil {
		t.Fatalf("named cancel of R1: %+v", resp)
	}
	if r, resp := rr.unlockResp(a, acPIN, client.UnlockOptions{}); !r.OK || resp.Code != "" {
		t.Fatalf("after R1's cancel: %+v %q", r, resp.Code)
	}
	rr.lock(a)

	// R2, cancelled by a seven-line cancel: whatever is in progress.
	rr.request(a)
	if resp := rr.w.RecoveryCancelNamed(ctx, in, a.vid, a.guid, ""); resp == nil || resp.Code != "" || resp.Envelope != nil {
		t.Fatalf("seven-line cancel: %+v", resp)
	}
	if r, _ := rr.unlockResp(a, acPIN, client.UnlockOptions{}); !r.OK {
		t.Fatalf("after the seven-line cancel: %+v", r)
	}
	rr.lock(a)

	// R3, cancelled by the owner app's unlock: the marker with R3's id,
	// and the unlocked event with it.
	q3, _ := rr.request(a)
	before := len(rr.w.Events())
	r, resp := rr.unlockResp(a, acPIN, client.UnlockOptions{CancelRecovery: true})
	if !r.OK || !r.RecoveryCancelled || resp.Code != enclave.CodeRecoveryCancelled || resp.Clear.CancelledRecoveryID != q3.RecoveryID {
		t.Fatalf("cancel by unlock: %+v %q %+v", r, resp.Code, resp.Clear)
	}
	found := false
	for _, ev := range rr.w.Events()[before:] {
		if ev.VaultID != a.vid {
			continue
		}
		switch {
		case ev.Event == "unlocked" && ev.CancelledRecoveryID == q3.RecoveryID:
			found = true
		case ev.CancelledRecoveryID != "":
			t.Fatalf("%s carries %q", ev.Event, ev.CancelledRecoveryID)
		}
	}
	if !found {
		t.Fatal("no unlocked event with the cancelled recovery's id")
	}
	// A later unlock reports nothing.
	rr.lock(a)
	if r, resp := rr.unlockResp(a, acPIN, client.UnlockOptions{CancelRecovery: true}); !r.OK || r.RecoveryCancelled || resp.Code != "" {
		t.Fatalf("no recovery left: %+v %q", r, resp.Code)
	}
}
