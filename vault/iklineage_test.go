package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// A connection never returns to an identity key it rotated away from
// (VAULT-MESSAGING §3.4, §6.5, §6.6). A handshake pinned to the peer's old
// ik (our hs.init named it, or our hs.resp awaits an hs.fin signed with it)
// that is still open when the vault follows identity.rotate could otherwise
// be finished by an old copy of the peer (lost phone data, a replayed
// backup) that still holds the old ik, the old KEM and the relay key: the
// vault would take the old ik back and open an epoch with that copy.

// ikl is svcFx with the peer's first keys k0 and its next keys k1, and the
// link r1 from k0 to k1.
type ikl struct {
	*svcFx
	k0, k1 rcKeys
	r1     *handshake.Rotation
}

func newIKL(t *testing.T, kind string) *ikl {
	t.Helper()
	f := newSvcFx(t, kind)
	f.build(1)
	f.at(2 * time.Hour)
	k0 := rcKeys{ik: f.n.ik, kem: f.n.kem}
	k1 := rcKey(t, 0x20)
	return &ikl{svcFx: f, k0: k0, k1: k1, r1: rcLink(t, k0, k1)}
}

func (f *ikl) ik0() ed25519.PublicKey { return f.k0.ik.Public().(ed25519.PublicKey) }
func (f *ikl) ik1() ed25519.PublicKey { return f.k1.ik.Public().(ed25519.PublicKey) }

// rotate is the peer rotating to k1: identity.rotate sealed under ep, which
// the vault follows. From then on the fixture's peer is at k1.
func (f *ikl) rotate(ep *handshake.Epoch) {
	f.t.Helper()
	f.off += time.Minute
	id, _ := envelope.NewULID(f.now())
	body := strictjson.NewBuilder().Raw("rotation", f.r1.Marshal()).Bytes()
	raw, err := ep.Seal(&envelope.Inner{ID: id, Type: "identity.rotate", TS: f.now(), Body: body})
	if err != nil {
		f.t.Fatal(err)
	}
	f.deliver(raw, f.stJTI)
	if !bytes.Equal(f.p.IK, f.ik1()) || len(f.p.Chain) != 1 {
		f.t.Fatal("identity.rotate not followed")
	}
	f.n.ik, f.n.kem = f.k1.ik, f.k1.kem
}

// learnWithoutHandler moves the connection to k1 as a rotation learned
// other than through identity.rotate would (no handshake is touched).
func (f *ikl) learnWithoutHandler() {
	f.d.m.mu.Lock()
	f.p.IK, f.p.KEM, f.p.Chain = f.ik1(), f.k1.kem.Public().Bytes(), rawLinks(f.r1)
	f.d.m.mu.Unlock()
}

// ownReconnect makes the vault start its own reconnect and returns its
// record and hs.init.
func (f *ikl) ownReconnect() (*OutgoingHS, []byte) {
	f.t.Helper()
	m := f.d.m
	m.mu.Lock()
	defer m.mu.Unlock()
	f.p.Reconnect = HeldToken{Token: f.mint(), Exp: f.now().Add(24 * time.Hour)}
	m.startReconnect(f.p, f.now())
	for _, og := range m.st.Outgoing {
		if og.Purpose != handshake.PurposeReconnect {
			continue
		}
		for _, e := range m.st.Outbox {
			if e.ID == og.InitOutbox {
				return og, e.Payload
			}
		}
	}
	f.t.Fatal("no reconnect of the vault's own")
	return nil, nil
}

// answer is the peer at keys k answering the vault's reconnect hs.init with
// rotations rots; it delivers the hs.resp on the standing token the hs.init
// carried and returns the peer's responder.
func (f *ikl) answer(og *OutgoingHS, env []byte, k rcKeys, rots []*handshake.Rotation) *handshake.Responder {
	f.t.Helper()
	pi, err := handshake.OpenInit(env, func(kid suite.Kid) *suite.PrivateKey {
		for _, x := range []rcKeys{f.k0, f.k1} {
			if kid.Equal(x.kem.Public().Kid()) {
				return x.kem
			}
		}
		return nil
	}, f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	r, renv, err := pi.Respond(handshake.ResponderConfig{Identity: k.ik, Token: f.mint(), ReconnectToken: f.mint(),
		Policy: policyFor(KindConnection), CollectSender: f.vaultPK(), RecordRelayKey: f.vaultPK(),
		KnownInitiatorIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ExpectedCtx: pi.Init().Ctx, Rotations: rots, Now: f.now()})
	if err != nil {
		f.t.Fatal(err)
	}
	jti := ""
	for _, it := range og.Issued {
		if it.Kind == TokStanding {
			jti = it.JTI
		}
	}
	f.deliver(renv, jti)
	return r
}

// finOf takes the vault's hs.fin to r's handshake (nil when none was sent).
func (f *ikl) finOf(r *handshake.Responder) *handshake.FinResult {
	f.t.Helper()
	f.d.m.mu.Lock()
	f.d.m.flushThenDrain(context.Background())
	f.d.m.mu.Unlock()
	rk, _ := r.Kids()
	fin := f.takeFor(func(env *envelope.Envelope) bool {
		return env.Mode() == envelope.ModeSession && env.RecipientKid().Equal(rk)
	})
	if fin == nil {
		return nil
	}
	fr, err := r.HandleFin(fin, f.vaultPK(), f.now())
	if err != nil {
		f.t.Fatal(err)
	}
	return fr
}

func (f *ikl) outgoingFor(purpose handshake.Purpose) []*OutgoingHS {
	f.d.m.mu.Lock()
	defer f.d.m.mu.Unlock()
	var out []*OutgoingHS
	for _, og := range f.d.m.st.Outgoing {
		if og.Purpose == purpose {
			out = append(out, og)
		}
	}
	return out
}

// The attack on the vault's own reconnect: pinned to the peer's ik0, the
// peer rotates and the vault follows, then an old copy of the peer at ik0
// answers the hs.init.
func TestReconnectNeverRollsBackTheIK(t *testing.T) {
	t.Run("following identity.rotate restarts the reconnect under ik1", func(t *testing.T) {
		f := newIKL(t, "")
		og, env := f.ownReconnect()
		last := append([]byte(nil), f.p.LastEpochID...)
		f.rotate(f.cur)

		// The reconnect pinned to ik0 is gone, its tokens revoked, and a new
		// one pinned to ik1 is open.
		m := f.d.m
		m.mu.Lock()
		_, kept := m.st.Outgoing[og.ID]
		var renewed *OutgoingHS
		for id, o := range m.st.Outgoing {
			if o.Purpose == handshake.PurposeReconnect && id != og.ID && suite.EqualPublic(m.outgoing[id].ResponderIK(), f.ik1()) {
				renewed = o
			}
		}
		m.mu.Unlock()
		if kept || renewed == nil {
			t.Fatalf("the reconnect under ik0 was kept (%v) or none was started under ik1", kept)
		}
		for _, tk := range og.Issued {
			if !f.revoked(tk.JTI) {
				t.Fatal("a token of the reconnect under ik0 was not revoked")
			}
		}

		// The old copy answers the first hs.init: nothing changes.
		r := f.answer(og, env, f.k0, nil)
		if !bytes.Equal(f.p.IK, f.ik1()) || !bytes.Equal(f.p.LastEpochID, last) || f.finOf(r) != nil {
			t.Fatal("the old copy's hs.resp rolled the identity back or opened an epoch")
		}
		if !f.d.audited("unknown_kid") && !f.d.audited("rotation_rollback_refused") {
			t.Fatal("the old copy's hs.resp was not audited")
		}

		// The real peer at ik1 answers the new one: it completes.
		renv := f.takeFor(func(env *envelope.Envelope) bool {
			return env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(f.k1.kem.Public().Kid())
		})
		if renv == nil {
			t.Fatal("the reconnect under ik1 was not deposited")
		}
		r = f.answer(renewed, renv, f.k1, nil)
		fr := f.finOf(r)
		if fr == nil {
			t.Fatal("the reconnect under ik1 did not complete")
		}
		nid := fr.Epoch.ID()
		if !bytes.Equal(f.p.LastEpochID, nid[:]) || !bytes.Equal(f.p.IK, f.ik1()) || len(f.p.Chain) != 1 {
			t.Fatal("the reconnect under ik1 did not activate")
		}
	})

	t.Run("a hs.resp verified under an ancestor ik is refused (backstop)", func(t *testing.T) {
		f := newIKL(t, "")
		og, env := f.ownReconnect()
		last := append([]byte(nil), f.p.LastEpochID...)
		f.learnWithoutHandler()
		r := f.answer(og, env, f.k0, nil)
		if !bytes.Equal(f.p.IK, f.ik1()) || !bytes.Equal(f.p.KEM, f.k1.kem.Public().Bytes()) || len(f.p.Chain) != 1 ||
			!bytes.Equal(f.p.LastEpochID, last) || f.finOf(r) != nil || len(f.outgoingFor(handshake.PurposeReconnect)) != 0 {
			t.Fatal("the old copy's hs.resp rolled the identity back, opened an epoch or left the reconnect open")
		}
		if !f.d.audited("rotation_rollback_refused") {
			t.Fatal("not audited rotation_rollback_refused")
		}
		for _, tk := range og.Issued {
			if !f.revoked(tk.JTI) {
				t.Fatal("a token of the refused reconnect was not revoked")
			}
		}
	})

	t.Run("a rekey pinned to ik0 is restarted under ik1", func(t *testing.T) {
		f := newIKL(t, "")
		m := f.d.m
		m.mu.Lock()
		m.startRekey(f.p, f.now())
		m.mu.Unlock()
		old := f.outgoingFor(handshake.PurposeRekey)
		if len(old) != 1 {
			t.Fatal("setup: no rekey")
		}
		f.rotate(f.cur)
		now := f.outgoingFor(handshake.PurposeRekey)
		m.mu.Lock()
		ok := len(now) == 1 && now[0].ID != old[0].ID && suite.EqualPublic(m.outgoing[now[0].ID].ResponderIK(), f.ik1())
		m.mu.Unlock()
		if !ok {
			t.Fatal("the rekey under ik0 was kept or none started under ik1")
		}
	})
}

// A reconnect whose hs.resp carries the peer's rotations (the vault still at
// ik0, the peer at ik1) is the legitimate way to learn them (§6.6): it is
// accepted and the vault moves to ik1.
func TestReconnectCarryingRotationsAccepted(t *testing.T) {
	f := newIKL(t, "")
	og, env := f.ownReconnect()
	r := f.answer(og, env, f.k1, []*handshake.Rotation{f.r1})
	fr := f.finOf(r)
	if fr == nil || f.d.audited("rotation_rollback_refused") {
		t.Fatal("the reconnect carrying rotations was refused")
	}
	nid := fr.Epoch.ID()
	if !bytes.Equal(f.p.LastEpochID, nid[:]) || !bytes.Equal(f.p.IK, f.ik1()) || len(f.p.Chain) != 1 {
		t.Fatal("the vault did not move to ik1")
	}
	// A reconnect after it, pinned to ik1, completes as usual.
	og, env = f.ownReconnect()
	if f.finOf(f.answer(og, env, f.k1, nil)) == nil || !bytes.Equal(f.p.IK, f.ik1()) {
		t.Fatal("the next reconnect under ik1 did not complete")
	}
}

// The attack on an answer of the vault's: it answered the peer's reconnect
// or rekey made at ik0, the peer rotates and the vault follows, then the old
// copy sends the hs.fin.
func TestAnswerNeverFinishedUnderAnAncestorIK(t *testing.T) {
	// reconnect: the peer's reconnect at ik0, answered; the hs.fin held.
	reconnect := func(f *ikl) (*handshake.Result, []IssuedToken) {
		f.t.Helper()
		ini := f.initiate(f.p.LastEpochID, f.now(), nil)
		f.deliver(ini.Envelope(), "")
		cur, stJTI := f.cur, f.stJTI
		res := f.respOf(ini)
		if res == nil {
			f.t.Fatal("not answered")
		}
		f.cur, f.stJTI = cur, stJTI // the epoch in force until the hs.fin
		var issued []IssuedToken
		for _, a := range f.d.m.st.Awaiting {
			issued = a.Issued
		}
		return res, issued
	}
	// rekey: the peer's rekey at ik0, answered; the hs.fin held.
	rekey := func(f *ikl) (*handshake.Result, []IssuedToken) {
		f.t.Helper()
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeRekey, Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr,
			ResponderIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ResponderRelayKey: f.vaultPK(), Current: f.cur,
			Policy: policyFor(KindConnection), Now: f.now(),
		})
		if err != nil {
			f.t.Fatal(err)
		}
		f.deliver(ini.Envelope(), f.stJTI)
		resp := f.takeFor(func(env *envelope.Envelope) bool {
			return env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(ini.EphKid())
		})
		if resp == nil {
			f.t.Fatal("rekey not answered")
		}
		res, err := ini.HandleResp(resp, f.vaultPK(), f.now())
		if err != nil {
			f.t.Fatal(err)
		}
		var issued []IssuedToken
		for _, a := range f.d.m.st.Awaiting {
			issued = a.Issued
		}
		return res, issued
	}
	for _, c := range []struct {
		name string
		make func(*ikl) (*handshake.Result, []IssuedToken)
	}{{"reconnect", reconnect}, {"rekey", rekey}} {
		t.Run(c.name+": following identity.rotate abandons the answer", func(t *testing.T) {
			f := newIKL(t, "")
			res, issued := c.make(f)
			last := append([]byte(nil), f.p.LastEpochID...)
			f.rotate(f.cur)
			if f.awaiting() != 0 {
				t.Fatal("the answer to ik0 was kept")
			}
			for _, tk := range issued {
				if !f.revoked(tk.JTI) {
					t.Fatal("a token of the abandoned answer was not revoked")
				}
			}
			f.deliver(res.Fin, f.stJTI) // the old copy's hs.fin
			if !bytes.Equal(f.p.IK, f.ik1()) || !bytes.Equal(f.p.LastEpochID, last) {
				t.Fatal("the old copy's hs.fin rolled the identity back or opened an epoch")
			}
		})
		t.Run(c.name+": an hs.fin signed with an ancestor ik is refused (backstop)", func(t *testing.T) {
			f := newIKL(t, "")
			res, issued := c.make(f)
			last := append([]byte(nil), f.p.LastEpochID...)
			f.learnWithoutHandler()
			f.deliver(res.Fin, f.stJTI)
			if !bytes.Equal(f.p.IK, f.ik1()) || !bytes.Equal(f.p.LastEpochID, last) {
				t.Fatal("the old copy's hs.fin opened an epoch")
			}
			if !f.d.audited("rotation_rollback_refused") || f.awaiting() != 0 {
				t.Fatal("not refused and audited rotation_rollback_refused")
			}
			for _, tk := range issued {
				if !f.revoked(tk.JTI) {
					t.Fatal("a token of the refused answer was not revoked")
				}
			}
		})
	}

	// An answer the peer made at ik1 carrying its rotation, while the vault
	// was still at ik0, is kept when the vault then follows identity.rotate:
	// its hs.fin is signed with ik1, no ancestor.
	t.Run("an answer to the rotated peer is kept", func(t *testing.T) {
		f := newIKL(t, "")
		cur, stJTI := f.cur, f.stJTI
		f.n.ik, f.n.kem = f.k1.ik, f.k1.kem
		ini := f.initiate(f.p.LastEpochID, f.now(), []*handshake.Rotation{f.r1})
		f.deliver(ini.Envelope(), "")
		res := f.respOf(ini)
		if res == nil {
			t.Fatal("not answered")
		}
		f.cur, f.stJTI = cur, stJTI
		f.rotate(f.cur)
		if f.awaiting() != 1 {
			t.Fatal("the answer to ik1 was abandoned")
		}
		f.deliver(res.Fin, f.stJTI)
		nid := res.Epoch.ID()
		if !bytes.Equal(f.p.LastEpochID, nid[:]) || !bytes.Equal(f.p.IK, f.ik1()) || len(f.p.Chain) != 1 {
			t.Fatal("the reconnect from ik1 did not complete")
		}
	})
}

// A rekey the vault answered before a restore is kept as fork evidence
// (§6.6): a later rotation of the restored peer, followed through
// identity.rotate or carried by the restore's reconnect, does not abandon
// or refuse it, and the second copy's hs.fin (signed with the old ik)
// still suspends the connection.
func TestReplacedAnswerSurvivesPeerRotation(t *testing.T) {
	setup := func(t *testing.T, carried bool) (*ikl, *handshake.Result) {
		f := newIKL(t, "service")
		f.build(2)
		e := f.cur
		f.at(9 * time.Hour)
		ini, err := handshake.NewInitiator(handshake.InitiatorConfig{
			Purpose: handshake.PurposeRekey, Identity: f.n.ik, StaticKEM: f.n.kem.Public(), Relay: f.n.addr,
			ResponderIK: f.d.m.keys.ik.Public().(ed25519.PublicKey), ResponderRelayKey: f.vaultPK(), Current: e,
			Policy: policyFor(KindConnection), Now: f.now(),
		})
		if err != nil {
			t.Fatal(err)
		}
		f.deliver(ini.Envelope(), f.stJTI)
		resp := f.takeFor(func(env *envelope.Envelope) bool {
			return env.Mode() == envelope.ModeSealed && env.RecipientKid().Equal(ini.EphKid())
		})
		if resp == nil {
			t.Fatal("rekey not answered")
		}
		res, err := ini.HandleResp(resp, f.vaultPK(), f.base.Add(11*time.Hour)) // the copy that kept running
		if err != nil {
			t.Fatal(err)
		}
		// The restored copy reconnects naming an older epoch.
		f.at(10 * time.Hour)
		var rot []*handshake.Rotation
		if carried {
			f.n.ik, f.n.kem = f.k1.ik, f.k1.kem
			rot = []*handshake.Rotation{f.r1}
		}
		rini := f.initiate(f.ids[1], f.now(), rot)
		f.deliver(rini.Envelope(), "")
		if f.complete(rini) == nil {
			t.Fatal("restore not answered")
		}
		if !carried {
			f.rotate(f.cur)
		}
		if !bytes.Equal(f.p.IK, f.ik1()) {
			t.Fatal("setup: not at ik1")
		}
		f.d.m.mu.Lock()
		marked := 0
		for _, aw := range f.d.m.st.Awaiting {
			if aw.Replaced {
				marked++
			}
		}
		f.d.m.mu.Unlock()
		if marked != 1 {
			t.Fatal("the answered rekey of the replaced line was not kept")
		}
		return f, res
	}
	for _, carried := range []bool{false, true} {
		name := "followed through identity.rotate"
		if carried {
			name = "carried by the restore's reconnect"
		}
		t.Run(name, func(t *testing.T) {
			f, res := setup(t, carried)
			f.at(12 * time.Hour)
			f.deliver(res.Fin, f.stJTI)
			if f.p.Fork == nil || f.d.audited("rotation_rollback_refused") {
				t.Fatal("the second copy's hs.fin was not taken as fork evidence")
			}
		})
	}
}
