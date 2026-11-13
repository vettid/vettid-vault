package trustmodel

import "testing"

// A table test of acceptFrom: each case builds Q's record of P in one
// state, hands Q one message, and checks the outcome and the table cell
// against the text of §3.4.1. It covers the cells random runs rarely reach.

type tenv struct {
	w    *World
	P, Q *Party
	r    *PeerRec // Q's record of P
	K0   Key      // P's earlier relay key (followed away from)
	K1   Key      // P's current relay key at Q
	cut  Pos      // K0's cut-off
	ik0  Key      // ancestor ik
}

func newTenv() *tenv {
	w := setup(Config{Vaults: 2, OldRules: true}, 1) // the f4a4d97 tables; §6.3.1 cases switch optA on
	P, Q := w.P[0], w.P[1]
	e := &tenv{w: w, P: P, Q: Q, r: Q.st.peer(P.ID)}
	// P rotated once and Q followed both links (the state after an update at msg 100)
	e.K0, e.K1 = e.r.Relay, w.key()
	l := RLink{e.K0, e.K1}
	w.rlinkBy[l] = rot{P.ID, 1}
	e.cut = Pos{Q.st.Relay, 100, w.Now, 0}
	e.r.RChain = append(e.r.RChain, l)
	e.r.Earlier = append(e.r.Earlier, Earlier{Key: e.K0, Cut: e.cut, Until: w.Now + 30*day})
	e.r.Relay = e.K1
	e.ik0 = e.r.IK
	ik1 := w.key()
	il := IKLink{e.ik0, ik1, w.key()}
	e.r.Chain = append(e.r.Chain, il)
	e.r.IK, e.r.KEM = ik1, il.KEM
	return e
}

// msg: a message from P deposited with sender at msg_id id (the cut-off is 100).
func (e *tenv) msg(sender Key, id int, m Msg) *RMsg {
	if m.Epoch == 0 && m.Kind != KResp && m.Kind != KFin && !(m.Kind == KInit && m.Reconnect) {
		m.Epoch = e.r.Cur
	}
	if m.Inner == 0 {
		m.Inner = e.w.id()
	}
	return &RMsg{ID: id, Box: e.Q.st.Relay, DepAt: e.w.Now, Sender: sender, P: &m, Actor: e.P.ID}
}

func (e *tenv) tok(iss Key) Token { return e.w.mint(iss, e.Q.st.Relay, false) }

func (e *tenv) newRLink(a, b Key) RLink {
	l := RLink{a, b}
	e.w.rlinkBy[l] = rot{e.P.ID, 9}
	return l
}

func TestTableCells(t *testing.T) {
	type tc struct {
		name     string
		prep     func(e *tenv) *RMsg
		out, why string
		cell     string
	}
	K := func(e *tenv) Key { return e.w.key() }
	cases := []tc{
		{"foreign update", func(e *tenv) *RMsg {
			k := K(e)
			return e.msg(k, 200, Msg{Kind: KUpdate, RelayPK: K(e)})
		}, "refuse", "foreign_sender", "A:foreign:update"},
		{"suspended hs.resp", func(e *tenv) *RMsg {
			e.r.Own = &HS{ID: 77, PeerIK: e.r.IK, OwnIK: e.Q.st.IK, Started: e.w.Now}
			e.r.Status = stSuspended
			return e.msg(e.K1, 200, Msg{Kind: KResp, HS: 77, Sig: e.r.IK})
		}, "refuse", "suspended", "A:suspended:hs.resp/fin"},
		{"hs.init sender is not from.relay", func(e *tenv) *RMsg {
			return e.msg(e.K1, 200, Msg{Kind: KInit, HS: 5, Ctx: e.r.Cur, FromIK: e.r.IK, FromRelay: e.K0})
		}, "refuse", "foreign_sender", "A:hs.init-sender-not-from.relay"},
		{"update from current to a kept key", func(e *tenv) *RMsg {
			l := e.newRLink(e.K1, e.K0)
			return e.msg(e.K1, 200, Msg{Kind: KUpdate, RelayPK: e.K0, RLinks: []RLink{l}, Toks: []Token{e.tok(e.K0)}})
		}, "refuse", "relay_rollback", "U(current):new-is-kept"},
		{"update from current, token for another mailbox", func(e *tenv) *RMsg {
			k2 := K(e)
			l := e.newRLink(e.K1, k2)
			return e.msg(e.K1, 200, Msg{Kind: KUpdate, RelayPK: k2, RLinks: []RLink{l}, Toks: []Token{e.tok(e.K1)}})
		}, "refuse", "token_unusable", "U(current):token"},
		{"update from current, unlinked", func(e *tenv) *RMsg {
			k2 := K(e)
			l := e.newRLink(K(e), k2)
			return e.msg(e.K1, 200, Msg{Kind: KUpdate, RelayPK: k2, RLinks: []RLink{l}, Toks: []Token{e.tok(k2)}})
		}, "refuse", "relay_unlinked", "U(current):unlinked"},
		{"update from earlier key before its cut-off follows", func(e *tenv) *RMsg {
			k2 := K(e)
			l := e.newRLink(e.K1, k2)
			return e.msg(e.K0, 50, Msg{Kind: KUpdate, RelayPK: k2, RLinks: []RLink{{e.K0, e.K1}, l}, Toks: []Token{e.tok(k2)}})
		}, "follow", "", "U(earlier-before):follow"},
		{"update from earlier key before its cut-off, token", func(e *tenv) *RMsg {
			k2 := K(e)
			l := e.newRLink(e.K1, k2)
			return e.msg(e.K0, 50, Msg{Kind: KUpdate, RelayPK: k2, RLinks: []RLink{{e.K0, e.K1}, l}})
		}, "refuse", "token_unusable", "U(earlier-before):token"},
		{"update from earlier key after its cut-off, kept key", func(e *tenv) *RMsg {
			l := e.newRLink(e.K1, e.K0)
			return e.msg(e.K0, 200, Msg{Kind: KUpdate, RelayPK: e.K0, RLinks: []RLink{{e.K0, e.K1}, l}, Toks: []Token{e.tok(e.K0)}})
		}, "refuse", "relay_rollback", "U(earlier-after):new-is-kept"},
		{"update from earlier key after its cut-off, token", func(e *tenv) *RMsg {
			k2 := K(e)
			l := e.newRLink(e.K1, k2)
			return e.msg(e.K0, 200, Msg{Kind: KUpdate, RelayPK: k2, RLinks: []RLink{{e.K0, e.K1}, l}})
		}, "refuse", "token_unusable", "U(earlier-after):token"},
		{"identity.rotate after the cut-off, all followed", func(e *tenv) *RMsg {
			return e.msg(e.K0, 200, Msg{Kind: KIdRot, Rot: []IKLink{e.r.Chain[0]}})
		}, "ignore", "", "A:earlier-after:identity.rotate:all-followed"},
		{"identity.rotate after the cut-off, a new link", func(e *tenv) *RMsg {
			return e.msg(e.K0, 200, Msg{Kind: KIdRot, Rot: []IKLink{e.r.Chain[0], {e.r.IK, K(e), K(e)}}})
		}, "refuse", "superseded_relay", "A:earlier-after:identity.rotate"},
		{"identity.rotate from an unknown ik", func(e *tenv) *RMsg {
			return e.msg(e.K1, 200, Msg{Kind: KIdRot, Rot: []IKLink{{K(e), K(e), K(e)}}})
		}, "refuse", "unknown_ik", "B:unknown:identity.rotate"},
		{"identity.rotate from a rejected ik", func(e *tenv) *RMsg {
			x := K(e)
			e.r.Dropped = append(e.r.Dropped, IKLink{e.r.IK, x, K(e)})
			return e.msg(e.K1, 200, Msg{Kind: KIdRot, Rot: []IKLink{{x, K(e), K(e)}}})
		}, "refuse", "rejected_ik", "B:rejected:identity.rotate"},
		{"identity.rotate to an ancestor (rollback)", func(e *tenv) *RMsg {
			return e.msg(e.K1, 200, Msg{Kind: KIdRot, Rot: []IKLink{{e.r.IK, e.ik0, K(e)}}})
		}, "refuse", "ik_rollback", "B:current:identity.rotate:rollback"},
		{"hs.init from an unknown ik", func(e *tenv) *RMsg {
			return e.msg(e.K1, 200, Msg{Kind: KInit, HS: 5, Ctx: e.r.Cur, FromIK: K(e), FromRelay: e.K1})
		}, "refuse", "unknown_ik", "B:unknown:hs.init"},
		{"hs.init from a rejected ik", func(e *tenv) *RMsg {
			x := K(e)
			e.r.Dropped = append(e.r.Dropped, IKLink{e.r.IK, x, K(e)})
			return e.msg(e.K1, 200, Msg{Kind: KInit, HS: 5, Ctx: e.r.Cur, FromIK: x, FromRelay: e.K1})
		}, "refuse", "rejected_ik", "B:rejected:hs.init"},
		{"hs.init from an ancestor ik", func(e *tenv) *RMsg {
			return e.msg(e.K1, 200, Msg{Kind: KInit, HS: 5, Ctx: e.r.Cur, FromIK: e.ik0, FromRelay: e.K1})
		}, "refuse", "ancestor_ik", "B:ancestor:hs.init"},
		{"hs.resp signed by an unknown ik", func(e *tenv) *RMsg {
			e.r.Own = &HS{ID: 77, PeerIK: e.r.IK, OwnIK: e.Q.st.IK, Started: e.w.Now}
			return e.msg(e.K1, 200, Msg{Kind: KResp, HS: 77, Sig: K(e)})
		}, "abort", "unknown_ik", "B:unknown:hs.resp"},
		{"hs.resp signed by a rejected ik", func(e *tenv) *RMsg {
			x := K(e)
			e.r.Dropped = append(e.r.Dropped, IKLink{e.r.IK, x, K(e)})
			e.r.Own = &HS{ID: 77, PeerIK: e.r.IK, OwnIK: e.Q.st.IK, Started: e.w.Now}
			return e.msg(e.K1, 200, Msg{Kind: KResp, HS: 77, Sig: x})
		}, "abort", "rejected_ik", "B:rejected:hs.resp"},
		{"hs.resp from an earlier key after the cut-off keeps the handshake", func(e *tenv) *RMsg {
			e.r.Own = &HS{ID: 77, PeerIK: e.r.IK, OwnIK: e.Q.st.IK, Started: e.w.Now}
			return e.msg(e.K0, 200, Msg{Kind: KResp, HS: 77, Sig: e.r.IK})
		}, "refuse", "superseded_relay", "A:earlier-after:hs.resp/fin:handshake-kept"},
		{"hs.fin to an answer pinned to an ancestor (not fork evidence)", func(e *tenv) *RMsg {
			e.r.Ans = append(e.r.Ans, HS{ID: 78, PeerIK: e.ik0, NewEpoch: 999, Started: e.w.Now})
			return e.msg(e.K1, 200, Msg{Kind: KFin, HS: 78, Sig: e.ik0, Epoch: 999})
		}, "refuse", "ancestor_ik", "B:ancestor:hs.fin"},
		{"hs.fin to a fork-evidence answer pinned to an ancestor", func(e *tenv) *RMsg {
			e.r.Ans = append(e.r.Ans, HS{ID: 78, PeerIK: e.ik0, NewEpoch: 999, Started: e.w.Now, Fork: true, Reconnect: true})
			return e.msg(e.K1, 200, Msg{Kind: KFin, HS: 78, Sig: e.ik0, Epoch: 999})
		}, "suspend", "fork", "B:ancestor:hs.fin:fork-evidence"},
		{"hs.fin to a fork-evidence answer pinned to the current ik", func(e *tenv) *RMsg {
			e.r.Ans = append(e.r.Ans, HS{ID: 78, PeerIK: e.r.IK, NewEpoch: 999, Started: e.w.Now, Fork: true, Reconnect: true})
			return e.msg(e.K1, 200, Msg{Kind: KFin, HS: 78, Sig: e.r.IK, Epoch: 999})
		}, "suspend", "fork", "B:current:hs.fin:fork-evidence"},
		{"hs.fin to an answer pinned to a rejected ik", func(e *tenv) *RMsg {
			x := K(e)
			e.r.Dropped = append(e.r.Dropped, IKLink{e.r.IK, x, K(e)})
			e.r.Ans = append(e.r.Ans, HS{ID: 78, PeerIK: x, NewEpoch: 999, Started: e.w.Now})
			return e.msg(e.K1, 200, Msg{Kind: KFin, HS: 78, Sig: x, Epoch: 999})
		}, "refuse", "rejected_ik", "B:rejected:hs.fin"},
		{"a message under a demoted epoch deposited after the link", func(e *tenv) *RMsg {
			ep := e.r.epoch(e.r.Cur)
			ep.Demoted, ep.DemotedAt = true, Pos{e.Q.st.Relay, 150, e.w.Now, 0}
			return e.msg(e.K1, 200, Msg{Kind: KSession, Probe: 1})
		}, "refuse", "ancestor_ik", "E:demoted-epoch"},
		{"a rekey naming an epoch superseded by one an ancestor signed", func(e *tenv) *RMsg {
			old := e.r.Cur
			e.r.Epochs = append(e.r.Epochs, Epoch{ID: 555, Signer: e.ik0, Own: e.Q.st.IK, EstAt: e.w.Now})
			e.r.Cur = 555
			return e.msg(e.K1, 200, Msg{Kind: KInit, HS: 5, Ctx: old, Epoch: old, FromIK: e.r.IK, FromRelay: e.K1})
		}, "suspend", "fork", "B:current:hs.init:fork-epoch"},
		{"§6.3.1: a rekey naming the confirmed epoch, superseded by a demoted one", func(e *tenv) *RMsg {
			e.w.optA = true
			old := e.r.Cur
			e.r.Epochs = append(e.r.Epochs, Epoch{ID: 555, Signer: e.ik0, Own: e.Q.st.IK, EstAt: e.w.Now, Demoted: true})
			e.r.Cur, e.r.ConfID = 0, old
			return e.msg(e.K1, 200, Msg{Kind: KInit, HS: 5, Ctx: old, Epoch: old, FromIK: e.r.IK, FromRelay: e.K1})
		}, "answer", "", "B:current:hs.init:confirmed-epoch"}, // 2da316e (F2): ordinary
		{"§6.3.1: a rekey naming the confirmed epoch, superseded by one signed before the link", func(e *tenv) *RMsg {
			e.w.optA = true
			old := e.r.Cur
			e.r.Epochs = append(e.r.Epochs, Epoch{ID: 555, Signer: e.ik0, Own: e.Q.st.IK, EstAt: e.w.Now})
			e.r.Cur, e.r.ConfID = 555, old
			return e.msg(e.K1, 200, Msg{Kind: KInit, HS: 5, Ctx: old, Epoch: old, FromIK: e.r.IK, FromRelay: e.K1})
		}, "answer", "", "B:current:hs.init:confirmed-epoch"},
		{"rule C: a second relay successor from an earlier key after its cut-off", func(e *tenv) *RMsg {
			k := K(e)
			l := e.newRLink(e.K0, k)
			return e.msg(e.K0, 200, Msg{Kind: KUpdate, RelayPK: k, RLinks: []RLink{l}, Toks: []Token{e.tok(k)}})
		}, "suspend", "fork", "C:relay"},
	}
	for _, c := range cases {
		e := newTenv()
		m := c.prep(e)
		r, _ := e.Q.locate(m.P)
		if r == nil {
			t.Errorf("%s: Q cannot open the message", c.name)
			continue
		}
		d := e.Q.acceptFrom(r, m, Pos{m.Box, m.ID, m.DepAt, m.Seq}, []Key{e.Q.st.Relay})
		if d.Out != c.out || d.Reason != c.why || d.Cell != c.cell {
			t.Errorf("%s: got %s, want %s (%s) [%s]", c.name, d, c.out, c.why, c.cell)
		}
	}
}
