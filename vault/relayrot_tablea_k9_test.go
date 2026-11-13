package vault

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// VAULT-MESSAGING 0.90.3 §3.4.1 Table A, "Earlier, after its cut-off", an
// identity.rotate whose every link is already followed: ignored, and
// R29-K9 is still judged; and only once the epoch's checks passed.

// R29-K9 still runs: side 0 began E1 and abandoned it while pending; side
// 1's identity.rotate (under E0, held back) reaches side 0 from side 1's
// earlier relay key after the cut-off, its link already followed. E1 is
// ended.
func TestTableAEarlierIgnoredRotateStillJudgesK9(t *testing.T) {
	f, e1 := k9Setup(t, true)
	rot := f.rkTake(kRotate, rkAfter)
	last, err := handshake.ParseRotation(f.m(1).st.Rotations[len(f.m(1).st.Rotations)-1])
	if err != nil {
		t.Fatal(err)
	}
	// The link is already followed (as if by a message K9 did not judge).
	p := f.p(0)
	p.IK, p.KEM = append([]byte(nil), last.NewIK...), last.NewKEM.Bytes()
	p.Chain = append(p.Chain, last.Marshal())
	f.rkFollow()
	if f.ended(0, e1) {
		t.Fatal("setup: E1 already ended")
	}
	f.process(0, rot)
	if f.superseded() != 0 || !f.ended(0, e1) {
		f.dump()
		t.Fatal("the ignored identity.rotate after the cut-off was refused, or R29-K9 not judged")
	}
}

// The ignore comes after the epoch's checks: such an identity.rotate under
// an epoch rule E destroyed is refused (superseded_epoch), not ignored.
func TestTableAEarlierIgnoredRotateEpochChecksFirst(t *testing.T) {
	d, td, p, k := rkConnU(t)
	k1 := rkKey(0x61)
	sendCFrom(d, td, rkPub(k), peerwire.TypeRelayAddressUpdate, rkMarshal(t, rkBody(t, d, k1, rkLink(t, k, k1))))
	if len(p.EarlierRelays) != 1 {
		t.Fatal("setup: not followed")
	}
	r := rkIKLink(t, d, 0x20)
	p.IK, p.KEM = append([]byte(nil), r.NewIK...), r.NewKEM.Bytes()
	p.Chain = append(p.Chain, r.Marshal())
	e := &p.Epochs[0]
	e.Destroyed, e.DestroyTS = true, time.Now().Add(time.Hour)
	body := `{"rotation":` + string(r.Marshal()) + `,"rotations":[` + string(r.Marshal()) + `]}`
	sendCFrom(d, td, rkPub(k), "identity.rotate", body)
	if refs := peerKeyRefs(d); len(refs) != 1 || refs[0] != "superseded_epoch" {
		t.Fatalf("not refused by the epoch's checks first: %v", refs)
	}
}
