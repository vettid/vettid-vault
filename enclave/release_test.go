package enclave_test

import (
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vault/store"
)

func (f *fx) has(vid, release string) bool {
	_, _, err := f.w.Store.Get(f.ctx, store.HeaderKey(vid, release))
	return err == nil
}

func (f *fx) startRelease(r enclavetest.ReleaseSpec) {
	f.t.Helper()
	f.w.AddRelease(r)
	if _, err := f.w.Start(r.Number); err != nil {
		f.t.Fatal(err)
	}
}

// moveTo approves and runs a move from the vault's release to r.
func (f *fx) moveTo(a *app, r enclavetest.ReleaseSpec) {
	f.t.Helper()
	res := f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r.PCR0Hex(), ToRelease: r.Number}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "moved" || res.Update.To != r.PCR0Hex() {
		f.t.Fatalf("move: %+v %+v", res, res.Update)
	}
}

// §11.10.4: approve release N+1 at an unlock under N; the vault is sealed
// to N+1 and locked; the next unlock reaches N+1, which confirms the move
// and deletes header/N.
func TestReleaseMove(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", ios(0x71))
	f.enroll(a, pin)
	f.lock(a)
	f.startRelease(r4)
	before := f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	f.lock(a)
	res := f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r4.PCR0Hex(), ToRelease: 4}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "moved" || res.HeaderSeq <= before.HeaderSeq {
		t.Fatalf("move: %+v", res)
	}
	if f.w.Instance(3).Manager(a.vid) != nil {
		t.Fatal("vault resumed under N after the move")
	}
	if !f.has(a.vid, r4.PCR0Hex()) || !f.has(a.vid, r3.PCR0Hex()) {
		t.Fatal("headers after the move")
	}
	if got := f.w.SealedRelease(a.vid); got != r4.PCR0Hex() {
		t.Fatalf("lifecycle moved: %s", got)
	}
	st := a.dev.Alt()
	if st.Release != r4.PCR0Hex() || st.ReleaseNumber != 4 || st.PreviousRelease != r3.PCR0Hex() {
		t.Fatalf("app state %+v", st)
	}
	// The next unlock routes to release 4, which confirms the move.
	res = f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	if !res.OK || res.Release != r4.PCR0Hex() || res.ReleaseNumber != 4 || res.Update != nil {
		t.Fatalf("unlock under N+1: %+v", res)
	}
	if f.w.Instance(4).Manager(a.vid) == nil {
		t.Fatal("not running under N+1")
	}
	if f.has(a.vid, r3.PCR0Hex()) {
		t.Fatal("header/N not deleted after confirmation")
	}
	f.lock(a)
	if res := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !res.OK || res.Release != r4.PCR0Hex() {
		t.Fatalf("again under N+1: %+v", res)
	}
	// Forward only: an approval for release 3 (still active) or for the
	// running release is refused as a downgrade; the unlock succeeds.
	f.lock(a)
	for _, to := range []enclavetest.ReleaseSpec{r3, r4} {
		res = f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: to.PCR0Hex(), ToRelease: to.Number}}, "")
		if !res.OK || res.Update == nil || res.Update.Result != "refused" || res.Update.Code != "downgrade" {
			t.Fatalf("downgrade to %d: %+v %+v", to.Number, res, res.Update)
		}
		f.lock(a)
	}
	// A target that is not active, or not the listed number, is refused.
	f.startRelease(r5)
	f.w.SetStatus(5, "deprecated")
	res = f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r5.PCR0Hex(), ToRelease: 5}}, "")
	if res.Update == nil || res.Update.Code != "target" {
		t.Fatalf("deprecated target: %+v", res.Update)
	}
	f.lock(a)
	f.w.SetStatus(5, "active")
	res = f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r5.PCR0Hex(), ToRelease: 6}}, "")
	if res.Update == nil || res.Update.Code != "target" {
		t.Fatalf("wrong number: %+v", res.Update)
	}
}

// §11.10.4 "Abandoning an unconfirmed move": before N+1 ran the vault,
// the app can return it to N.
func TestAbandonMove(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	f.startRelease(r4)
	f.moveTo(a, r4)
	// Without the abandonment flag the app refuses to send a PIN to N.
	if _, err := f.unlock(a, pin, client.UnlockOptions{}, r3.PCR0Hex()); err != client.ErrRollbackRel {
		t.Fatalf("PIN to an older release: %v", err)
	}
	res := f.mustUnlock(a, pin, client.UnlockOptions{Abandon: true}, r3.PCR0Hex())
	if !res.OK || res.Update == nil || res.Update.Result != "abandoned" || res.Release != r3.PCR0Hex() {
		t.Fatalf("abandon: %+v %+v", res, res.Update)
	}
	if f.has(a.vid, r4.PCR0Hex()) {
		t.Fatal("header/N+1 not deleted")
	}
	if f.w.Instance(3).Manager(a.vid) == nil {
		t.Fatal("not resumed under N")
	}
	if got := f.w.SealedRelease(a.vid); got != r3.PCR0Hex() {
		t.Fatalf("routing after abandonment: %s", got)
	}
	f.lock(a)
	if res := f.mustUnlock(a, pin, client.UnlockOptions{}, ""); !res.OK || res.Release != r3.PCR0Hex() {
		t.Fatalf("after abandonment: %+v", res)
	}
}

// §11.10.4 failures: a move whose step 7 fails stays pending and is
// completed by the next unlock that reaches N, without a new approval; an
// approval for a different target while a move is pending does not
// change the target.
func TestPendingMoveCompletes(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	f.startRelease(r4)
	f.startRelease(r5)
	f.w.KMS.SetFailGenerate(true)
	res := f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r4.PCR0Hex(), ToRelease: 4}}, "")
	if res.OK || res.Code != "retry" {
		t.Fatalf("step 7 failure: %+v", res)
	}
	if f.w.Instance(3).Manager(a.vid) != nil || f.has(a.vid, r4.PCR0Hex()) {
		t.Fatal("vault resumed or sealed")
	}
	f.w.KMS.SetFailGenerate(false)
	res = f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r5.PCR0Hex(), ToRelease: 5}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "moved" || res.Update.To != r4.PCR0Hex() {
		t.Fatalf("completion: %+v %+v", res, res.Update)
	}
	if !f.has(a.vid, r4.PCR0Hex()) || f.has(a.vid, r5.PCR0Hex()) {
		t.Fatal("sealed to the wrong release")
	}
}

// §11.10.4: release N refuses a vault whose state names another release
// (a stale header served to a release the vault has left); N cannot open
// a header sealed to N+1.
func TestWrongReleaseRefused(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	stale, _ := a.dev.Save()
	h3, _, _ := f.w.Store.Get(f.ctx, store.HeaderKey(a.vid, r3.PCR0Hex()))
	f.startRelease(r4)
	f.moveTo(a, r4)
	f.mustUnlock(a, pin, client.UnlockOptions{}, "") // confirm under 4
	f.lock(a)
	// The host serves the old header/3 to release 3.
	if _, err := f.w.Store.Put(f.ctx, store.HeaderKey(a.vid, r3.PCR0Hex()), h3, ""); err != nil {
		t.Fatal(err)
	}
	old := staleApp(f, stale, a) // a device that never learned of the move
	if res := f.mustUnlock(old, pin, client.UnlockOptions{}, r3.PCR0Hex()); res.OK || res.Code != "wrong_release" {
		t.Fatalf("stale header: %+v", res)
	}
	// header/4 copied to header/3: release 3 cannot unseal it (KMS
	// Decrypt is refused to its PCR0): the request is dropped.
	h4, _, _ := f.w.Store.Get(f.ctx, store.HeaderKey(a.vid, r4.PCR0Hex()))
	_, v, _ := f.w.Store.Get(f.ctx, store.HeaderKey(a.vid, r3.PCR0Hex()))
	if _, err := f.w.Store.Put(f.ctx, store.HeaderKey(a.vid, r3.PCR0Hex()), h4, v); err != nil {
		t.Fatal(err)
	}
	if _, err := f.unlock(staleApp(f, stale, a), pin, client.UnlockOptions{}, r3.PCR0Hex()); err != client.ErrResult {
		t.Fatalf("N opened N+1's header: %v", err)
	}
}

// §11.10.7: a target key that fails the policy check is refused
// (seal_key) and the vault keeps running under N; enrollment into a
// release whose own key fails is refused (release_key).
func TestSealKeyPolicyRefused(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-1", android(0x61))
	f.enroll(a, pin)
	f.lock(a)
	f.startRelease(r4)
	admin := `{"Sid":"Admin","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"},`
	good := enclavetest.GoodPolicy(r4.PCR0Hex(), []string{r3.PCR0Hex(), r4.PCR0Hex()})
	f.w.KMS.SetPolicy(enclavetest.KeyARN(4), strings.Replace(good, `"Statement":[`, `"Statement":[`+admin, 1))
	res := f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r4.PCR0Hex(), ToRelease: 4}}, "")
	if !res.OK || res.Update == nil || res.Update.Result != "refused" || res.Update.Code != "seal_key" {
		t.Fatalf("bad target key: %+v %+v", res, res.Update)
	}
	if f.w.Instance(3).Manager(a.vid) == nil || f.has(a.vid, r4.PCR0Hex()) {
		t.Fatal("vault moved or stopped")
	}
	f.lock(a)
	// MultiRegion key.
	f.w.KMS.SetPolicy(enclavetest.KeyARN(4), good)
	f.w.KMS.SetDescribe(enclavetest.KeyARN(4), strings.Replace(enclavetest.GoodDescribe(enclavetest.KeyARN(4)), `"MultiRegion":false`, `"MultiRegion":true`, 1))
	res = f.mustUnlock(a, pin, client.UnlockOptions{Approve: &client.Approval{To: r4.PCR0Hex(), ToRelease: 4}}, "")
	if res.Update == nil || res.Update.Code != "seal_key" {
		t.Fatalf("multi-region: %+v", res.Update)
	}
	f.lock(a)
	// Enrollment into release 4, whose own key now fails.
	b := f.newApp("user-2", android(0x62))
	f.w.SetStatus(3, "deprecated") // routes enrollment to 4
	if r := f.enroll(b, pin); r.OK || r.Code != "release_key" {
		t.Fatalf("enroll with a failing key: %+v", r)
	}
	// A key outside the pinned namespace is refused before any KMS call.
	in, err := f.w.StartWith(4, func(c *enclave.Config) { c.SealAccount = "444455556666" })
	if err != nil {
		t.Fatal(err)
	}
	_ = in
	f.w.KMS.SetDescribe(enclavetest.KeyARN(4), enclavetest.GoodDescribe(enclavetest.KeyARN(4)))
	if r := f.enroll(b, pin); r.OK || r.Code != "release_key" {
		t.Fatalf("enroll outside the namespace: %+v", r)
	}
}
