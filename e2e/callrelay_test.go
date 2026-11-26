//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/features/calls"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// CALLS-PLAN §13.4 step 8, the re-signed relay (VAULT-MESSAGING §10.10
// "Call forms", "Key confirmation"), through real vaults and the real
// relay. C passes A's call on to B: C's device re-signs A's ek as its own
// call to B, under the same call_id, and answers A with B's answer
// re-signed as its own. Every vault check passes (each share is signed by
// the device of the vault that vouches for it, over that vault's own view
// of the call): B's vault rings B, and A's vault hands A's device the
// answer. Only the calling device stops it: k_call and confirm are bound
// to the two vaults' keys, so B's confirm, made for "C calls B", never
// verifies for "A calls C", and A's device sets no key and uses nothing of
// the answer. (k_call's binding alone already stops it, so a confirm not
// bound to the parties isn't seen here; confirm's own binding is the
// vectors' confirm_relayed.)
//
// The device side is form 2 built from vms/callwire with each test
// device's own key (the Go client speaks form 1 only).
//
// The re-vouched relay (C's vault vouching for A's device's share) is
// features/calls TestForm2RelayedCall: B's vault drops the offer.
func TestForm2ReSignedRelayStopsAtConfirm(t *testing.T) {
	// C is one member, connected to A and to B. Its vault keeps two call
	// books (relayingCalls, test code only): an honest vault answers its own
	// call.start busy while A's call rings, and refuses a call_id it holds.
	t.Run("one member", func(t *testing.T) {
		r := relaytest.Start(t, nil)
		rc := &relayingCalls{}
		a := newTestVault(t, r.URL, "a", nil)
		c := newTestVaultWrapped(t, r.URL, "c", nil, nil, rc.wrap)
		b := newTestVault(t, r.URL, "b", nil)
		aToC, cFromA := connect(t, a, c, 600)
		cToB, _ := connect(t, c, b, 600)
		rc.setFromA(cFromA)
		reSignedRelay(t, a, c, c, b, aToC, cToB)
	})
	// C is two members, C1 connected to A and C2 connected to B, working
	// together: every vault is an unmodified one.
	t.Run("two members", func(t *testing.T) {
		r := relaytest.Start(t, nil)
		a := newTestVault(t, r.URL, "a", nil)
		c1 := newTestVault(t, r.URL, "c1", nil)
		c2 := newTestVault(t, r.URL, "c2", nil)
		b := newTestVault(t, r.URL, "b", nil)
		aToC, _ := connect(t, a, c1, 600)
		cToB, _ := connect(t, c2, b, 600)
		reSignedRelay(t, a, c1, c2, b, aToC, cToB)
	})
}

// reSignedRelay runs the relay: cA is C's side connected to A (aToC, A's
// connection to it), cB the side connected to B (cToB, its connection to
// B); one vault when C is one member.
func reSignedRelay(t *testing.T, a, cA, cB, b *testVault, aToC, cToB string) {
	ctx := ctxT(t, 180*time.Second)
	aDev, aIK := deviceKeys(t, a.app)
	cADev, cAIK := deviceKeys(t, cA.app)
	cBDev, cBIK := deviceKeys(t, cB.app)
	bDev, bIK := deviceKeys(t, b.app)
	for _, k := range []ed25519.PrivateKey{aDev, cADev, cBDev, bDev} {
		defer suite.Wipe(k)
	}
	pAC := callwire.Parties{Caller: aIK, Callee: cAIK} // what A's vault and device know
	pCB := callwire.Parties{Caller: cBIK, Callee: bIK} // what B's vault and device know
	offered := []int{1}

	// A calls C.
	sk, err := callwire.NewOfferKey()
	if err != nil {
		t.Fatal(err)
	}
	defer sk.Destroy()
	ek := sk.Public().Bytes()
	id := newCallULID(t)
	start2(ctx, t, a.app, aDev, aToC, id, ek, offered, pAC)
	atC := obj(t, waitEvent(t, cA.app, "call.offer", has("call_id", id)).Body)
	if got, _ := atC.Base64("ek", callwire.EKSize); !bytes.Equal(got, ek) {
		t.Fatal("C's device got another ek")
	}

	// C re-signs A's ek as its own call to B, with A's call_id.
	start2(ctx, t, cB.app, cBDev, cToB, id, ek, offered, pCB)
	atB := waitEvent(t, b.app, "call.offer", has("call_id", id))
	// B's device checks find nothing wrong: a call from C, signed by C's
	// device and vouched by C's vault, in both forms, over "C calls B".
	if err := offerChecks(atB, cBIK, id, "audio", offered, pCB, ek); err != nil {
		t.Fatalf("B's device refused C's offer: %v", err)
	}

	// B answers C, as for any call from C.
	encB, kB, err := callwire.Answer2(ek, id, pCB)
	if err != nil {
		t.Fatal(err)
	}
	defer suite.Wipe(kB)
	kcB, err := callwire.ConfirmKey(kB, id)
	if err != nil {
		t.Fatal(err)
	}
	defer suite.Wipe(kcB)
	answer2(ctx, t, b.app, bDev, id, encB, 1, offered, callwire.Confirm(kcB, 1, offered, id, pCB), pCB)
	atCAnswer := obj(t, waitEvent(t, cB.app, "call.answer", has("call_id", id)).Body)
	enc, _ := atCAnswer.Base64("enc", callwire.EncSize)
	confirm, _ := atCAnswer.Base64("confirm", callwire.ConfirmSize)
	if !bytes.Equal(enc, encB) || len(confirm) != callwire.ConfirmSize {
		t.Fatal("C's device didn't get B's answer")
	}

	// C answers A with B's enc and confirm, re-signed by its own device
	// over "A calls C": A's vault checks C's vouch over its own view and
	// passes it on.
	answer2(ctx, t, cA.app, cADev, id, enc, 1, offered, confirm, pAC)
	atA := waitEvent(t, a.app, "call.answer", has("call_id", id))
	ao := obj(t, atA.Body)
	gotEnc, _ := ao.Base64("enc", callwire.EncSize)
	gotConfirm, _ := ao.Base64("confirm", callwire.ConfirmSize)
	peer, _ := ao.Base64("peer_ik", ed25519.PublicKeySize)
	// What reached A is B's, unchanged: B's confirm, good for "C calls B".
	if !bytes.Equal(gotEnc, encB) || !callwire.VerifyConfirm(kcB, 1, offered, id, pCB, gotConfirm) || !bytes.Equal(peer, cAIK) {
		t.Fatal("A's device didn't get B's answer as C's")
	}

	// A's device: the share verifies (C's device, vouched by C's vault, over
	// "A calls C"); confirm doesn't, and A sets no key.
	k, err := acceptForm2(atA, sk, id, offered, pAC)
	if !errors.Is(err, errConfirm) || k != nil {
		t.Fatalf("A's device took the relayed answer: %v", err)
	}
	// What A would have had differs from B's: C relayed nothing A and B
	// could talk over, and C, without A's or B's secret, has neither.
	kA, err := callwire.Accept2(sk, enc, id, pAC)
	if err != nil || bytes.Equal(kA, kB) {
		t.Fatalf("A's view of the relayed k_call: %v", err)
	}
	suite.Wipe(kA)

	// The same device code takes a call that isn't passed on: B ends C's
	// relayed call, C calls B with a key of its own, and the two derive one
	// key.
	if err := b.app.CallEnd(ctx, id, "hangup"); err != nil {
		t.Fatal(err)
	}
	waitEvent(t, cB.app, "call.end", has("call_id", id))
	own, err := callwire.NewOfferKey()
	if err != nil {
		t.Fatal(err)
	}
	defer own.Destroy()
	id2 := newCallULID(t)
	start2(ctx, t, cB.app, cBDev, cToB, id2, own.Public().Bytes(), offered, pCB)
	atB2 := waitEvent(t, b.app, "call.offer", has("call_id", id2))
	if err := offerChecks(atB2, cBIK, id2, "audio", offered, pCB, own.Public().Bytes()); err != nil {
		t.Fatal(err)
	}
	enc2, kB2, err := callwire.Answer2(own.Public().Bytes(), id2, pCB)
	if err != nil {
		t.Fatal(err)
	}
	defer suite.Wipe(kB2)
	kc2, err := callwire.ConfirmKey(kB2, id2)
	if err != nil {
		t.Fatal(err)
	}
	answer2(ctx, t, b.app, bDev, id2, enc2, 1, offered, callwire.Confirm(kc2, 1, offered, id2, pCB), pCB)
	suite.Wipe(kc2)
	kC, err := acceptForm2(waitEvent(t, cB.app, "call.answer", has("call_id", id2)), own, id2, offered, pCB)
	if err != nil || !bytes.Equal(kC, kB2) {
		t.Fatalf("a call not passed on: %v", err)
	}
	suite.Wipe(kC)
}

// deviceKeys returns a test device's identity key and its vault's, from
// its saved state (every seed in it wiped after).
func deviceKeys(t *testing.T, d *client.Device) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	raw, err := d.Save()
	if err != nil {
		t.Fatal(err)
	}
	defer suite.Wipe(raw)
	var st client.State
	err = json.Unmarshal(raw, &st)
	defer func() {
		for _, b := range [][]byte{st.IKSeed, st.KEMSeed, st.RelaySeed} {
			suite.Wipe(b)
		}
	}()
	if err != nil || st.Vault == nil || len(st.IKSeed) != ed25519.SeedSize {
		t.Fatalf("device state: %v", err)
	}
	return ed25519.NewKeyFromSeed(st.IKSeed), append(ed25519.PublicKey(nil), st.Vault.IK...)
}

func newCallULID(t *testing.T) string {
	t.Helper()
	id, err := envelope.NewULID(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func obj(t *testing.T, raw json.RawMessage) strictjson.Object {
	t.Helper()
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// start2 places a form 2 audio call from d (identity key dev) under p.
func start2(ctx context.Context, t *testing.T, d *client.Device, dev ed25519.PrivateKey, conn, id string, ek []byte, offered []int, p callwire.Parties) {
	t.Helper()
	sig, err1 := callwire.SignShare(dev, callwire.ShareMessage(callwire.RoleOffer, id, "audio", ek))
	sig2, err2 := callwire.SignShare(dev, callwire.OfferMessage2(id, "audio", offered, p, ek))
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	o, err := d.Op(ctx, "call.start", map[string]any{"connection_id": conn, "call_id": id, "media": "audio", "sdp": "v=0",
		"ek": ek, "ek_sig": sig, "suites": offered, "ek_sig2": sig2})
	if err != nil {
		t.Fatalf("call.start: %v", err)
	}
	if got, _ := o.String("call_id"); got != id {
		t.Fatalf("call.start answered %q", got)
	}
}

// answer2 sends a form 2 call.answer from d (identity key dev), enc_sig
// over m2 under p.
func answer2(ctx context.Context, t *testing.T, d *client.Device, dev ed25519.PrivateKey, id string, enc []byte, chosen int,
	offered []int, confirm []byte, p callwire.Parties) {
	t.Helper()
	sig, err := callwire.SignShare(dev, callwire.AnswerMessage2(id, chosen, offered, p, enc))
	if err != nil {
		t.Fatal(err)
	}
	list, _ := json.Marshal(offered)
	body := strictjson.NewBuilder().String("call_id", id).String("sdp", "v=0").Base64("enc", enc).Base64("enc_sig", sig).
		Uint("suite", uint64(chosen)).Raw("offered", list).Base64("confirm", confirm).Bytes()
	if _, err := d.Send(ctx, "call.answer", body); err != nil {
		t.Fatalf("call.answer: %v", err)
	}
}

var (
	errShare   = errors.New("the share doesn't verify")
	errConfirm = errors.New("confirm doesn't verify")
)

// offerChecks is what a called device checks of a form 2 call.offer
// (§10.10 "What each party checks"): peer_ik is the connection's key
// (peerIK), and both forms of the share are signed by the calling vault's
// device and vouched by that vault, form 2 over the call as this side's
// records name it.
func offerChecks(ev *envelope.Inner, peerIK ed25519.PublicKey, id, media string, offered []int, p callwire.Parties, ek []byte) error {
	o, err := strictjson.ParseObject(ev.Body)
	if err != nil {
		return err
	}
	got, _ := o.Base64("ek", callwire.EKSize)
	peer, _ := o.Base64("peer_ik", ed25519.PublicKeySize)
	devIK, _ := o.Base64("device_ik", ed25519.PublicKeySize)
	d1, _ := o.Base64("device_sig", ed25519.SignatureSize)
	v1, _ := o.Base64("vault_sig", ed25519.SignatureSize)
	d2, _ := o.Base64("device_sig2", ed25519.SignatureSize)
	v2, _ := o.Base64("vault_sig2", ed25519.SignatureSize)
	if !bytes.Equal(got, ek) || !bytes.Equal(peer, peerIK) ||
		callwire.VerifyShare(peerIK, devIK, callwire.ShareMessage(callwire.RoleOffer, id, media, ek), d1, v1) != nil ||
		callwire.VerifyShare(peerIK, devIK, callwire.OfferMessage2(id, media, offered, p, ek), d2, v2) != nil {
		return errShare
	}
	return nil
}

// acceptForm2 is what the calling device does with a form 2 call.answer
// (§10.10 "Key confirmation"): the share checked against the called
// vault's key (p.Callee), k_call derived under p, and confirm checked
// before any key is set from it. It returns k_call only when confirm
// verifies, and wipes it otherwise.
func acceptForm2(ev *envelope.Inner, sk *suite.PrivateKey, id string, offered []int, p callwire.Parties) ([]byte, error) {
	o, err := strictjson.ParseObject(ev.Body)
	if err != nil {
		return nil, err
	}
	enc, err1 := o.Base64("enc", callwire.EncSize)
	devIK, err2 := o.Base64("device_ik", ed25519.PublicKeySize)
	ds, err3 := o.Base64("device_sig", ed25519.SignatureSize)
	vs, err4 := o.Base64("vault_sig", ed25519.SignatureSize)
	chosen, err5 := o.Uint("suite", 1, callwire.MaxSuite)
	confirm, err6 := o.Base64("confirm", callwire.ConfirmSize)
	if err := errors.Join(err1, err2, err3, err4, err5, err6); err != nil {
		return nil, err
	}
	if callwire.VerifyShare(p.Callee, devIK, callwire.AnswerMessage2(id, int(chosen), offered, p, enc), ds, vs) != nil {
		return nil, errShare
	}
	k, err := callwire.Accept2(sk, enc, id, p)
	if err != nil {
		return nil, err
	}
	kc, err := callwire.ConfirmKey(k, id)
	if err != nil {
		suite.Wipe(k)
		return nil, err
	}
	defer suite.Wipe(kc)
	if !callwire.VerifyConfirm(kc, int(chosen), offered, id, p, confirm) {
		suite.Wipe(k)
		return nil, errConfirm
	}
	return k, nil
}

// relayingCalls is C's calls feature in the relay test (test code only):
// two call books, so that C can hold A's ringing call and place its own
// call to B under the same call_id, which an honest vault refuses (busy
// while a call rings; exists for a call_id it holds). The incoming book
// (the embedded Feature) has A's call and every device message but
// call.start; the outgoing book has C's call.start and the messages from
// B. So a device's call.end, call.ice or call.keepalive for the call to B
// would reach the wrong book: the test sends none. The vault's hooks
// (Tick, CallRinging, the hold, …) reach the incoming book only: the call
// to B never times out here. Each book is the real calls feature, so every
// check and every vouch is the vault's own.
type relayingCalls struct {
	*calls.Feature // A's call to C
	out            *calls.Feature
	mu             sync.Mutex
	fromA          string
}

func (r *relayingCalls) wrap(fs *all.Set, l []vault.Feature) []vault.Feature {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Feature, r.out = fs.Calls, calls.New(calls.Options{})
	for i, f := range l {
		if f == vault.Feature(fs.Calls) {
			l[i] = r
		}
	}
	return l
}

func (r *relayingCalls) setFromA(conn string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fromA = conn
}

func (r *relayingCalls) book(s *vault.Session, typ string) *calls.Feature {
	r.mu.Lock()
	defer r.mu.Unlock()
	if from := s.From(); from.Kind == vault.KindConnection && from.ID != r.fromA || from.Kind != vault.KindConnection && typ == "call.start" {
		return r.out
	}
	return r.Feature
}

func (r *relayingCalls) Handle(ctx context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	return r.book(s, in.Type).Handle(ctx, s, in)
}

func (r *relayingCalls) Opened(s *vault.Session) {
	r.Feature.Opened(s)
	r.out.Opened(s)
}

func (r *relayingCalls) Zeroize() {
	r.Feature.Zeroize()
	r.out.Zeroize()
}

func (r *relayingCalls) Save() (json.RawMessage, error) {
	in, err1 := r.Feature.Save()
	out, err2 := r.out.Save()
	if err := errors.Join(err1, err2); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]json.RawMessage{"in": in, "out": out})
}

func (r *relayingCalls) Load(data json.RawMessage) error {
	var books map[string]json.RawMessage
	if len(data) != 0 && string(data) != "null" {
		if err := json.Unmarshal(data, &books); err != nil {
			return err
		}
	}
	return errors.Join(r.Feature.Load(books["in"]), r.out.Load(books["out"]))
}
