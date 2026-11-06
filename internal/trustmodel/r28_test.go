package trustmodel

import "slices"

// Release 28 as the code is (vettid-vault tag release/staging/28 =
// 0ee0078), not f4a4d97's §3.4.1, which release 28 never implemented.
// References are file:line in that tree. TRUSTMODEL_R28=spec restores the
// earlier model (acceptFrom for release-28 parties too).
//
// What release 28 does with a message from a connection:
//   - the peer is found only by the collect sender equal to the relay key
//     on record (vault/inbound.go:300, peerByRelayKey :387); no Table A,
//     no relay-key history (an earlier key is unknown);
//   - a session-mode message opens under the current epoch or one retired
//     less than 16 days ago (vms/handshake/epoch.go:36, :235, :278); no
//     identity check on it at all (inbound.go:306);
//   - nothing is accepted from a connection suspended by a rotation
//     conflict except identity.rotate, which then changes nothing
//     (inbound.go:416, vault/core.go:586-590);
//   - identity.rotate: only its `rotation` (one link, the last); a link
//     whose old_ik already has another followed successor suspends
//     (vault/rotateconflict.go:32-63); otherwise it is followed only if
//     old_ik is the stored ik (core.go:592, rotation.go ResolveChain),
//     else ignored (bad_rotation);
//   - no fork detection between persons: §6.6 fork evidence needs a
//     restore's watch, kept for services only (vault/restore.go:206,
//     classifyCtx; handshakes.go:341);
//   - a rekey hs.init must travel under the current epoch
//     (handshakes.go:496), come from the record relay key and carry the
//     stored ik exactly (vms/handshake/responder.go:279-285); crossing
//     rekeys: the lower th1 wins, against its own rekey only
//     (handshakes.go:506-517);
//   - a reconnect hs.init: replay refused (handshakes.go:68), sender on
//     record (:322), its rotations checked for conflict (:330), ctx must
//     name the last (current) epoch (restore.go classifyCtx: persons get
//     ctxCurrent or ctxNone), the chain resolved from the stored ik
//     (responder.go:297); crossing reconnects: the higher th1 abandons
//     its own (handshakes.go:464);
//   - hs.resp: verified under the responder's ik as it was when the rekey
//     started, a reconnect's through its rotations (initiator.go:328); a
//     failure aborts; the initiator activates at once and queues hs.fin;
//     only crossing reconnect answers are dropped (handshakes.go:906);
//   - hs.fin: verified under the hs.init's ik (responder.go:349); the
//     responder activates; no hs.confirm (:571-627); a reconnect's fin
//     drops its own reconnect (handshakes.go:690);
//   - an unknown type (hs.confirm) is answered unsupported_type
//     (inbound.go:480); unknown inner members (features) are ignored
//     (vms/envelope/inner.go:205);
//   - relay.address.update is followed with its token, no link checks
//     (core.go:604-648).
func (q *Party) acceptR28(r *PeerRec, m *RMsg, pos Pos, set []Key) dec {
	M := m.P
	col := colName[M.Kind]
	if r.Status == stStale {
		return dec{"drop", "stale", "model:stale"}
	}
	if m.Sender != r.Relay {
		return dec{"drop", "unknown_kid", "r28:sender-not-on-record:" + col}
	}
	if r.Status == stSuspended {
		return refuse("suspended", "r28:suspended:"+col)
	}
	if M.Epoch != 0 && M.Kind != KFin {
		if ep := r.epoch(M.Epoch); ep == nil || (M.Epoch != r.Cur && ep.Superseded != 0 && q.w.Now-ep.Superseded > 16*day) {
			return dec{"drop", "unknown_kid", "r28:epoch-not-retained:" + col}
		}
	}
	cell := "r28:" + col
	switch M.Kind {
	case KSession:
		q.w.probes[M.Probe] = true
		return dec{"accept", "", cell}
	case KTokIssued:
		kept, _ := q.ruleT(r, M.Toks, r.Relay)
		q.keepTokens(r, kept)
		return dec{"accept", "", cell}
	case KUpdate:
		kept, _ := q.ruleT(r, M.Toks, M.RelayPK)
		standing := false
		for _, t := range kept {
			standing = standing || !t.Reconnect
		}
		if !standing || M.RelayPK == 0 {
			return refuse("bad_request", cell+":no-token")
		}
		r.RChain = append(r.RChain, M.RLinks...)
		r.Relay = M.RelayPK
		r.Toks = slices.DeleteFunc(r.Toks, func(t Token) bool { return t.Iss != r.Relay })
		q.keepTokens(r, kept)
		q.enqueue(r.ID, Msg{Kind: KTokIssued, Toks: []Token{{}, {Reconnect: !r.Device}}}, nil)
		return dec{"follow", "", cell}
	case KIdRot:
		if len(M.Rot) == 0 {
			return refuse("bad_request", cell)
		}
		l := M.Rot[len(M.Rot)-1] // the body's `rotation`
		if d, stop := q.r28Conflict(r, []IKLink{l}); stop {
			return d
		}
		if r.followed(l) {
			return dec{"ignore", "", cell + ":same-statement"}
		}
		if l.Old != r.IK || l.Old == l.New {
			return dec{"ignore", "bad_rotation", cell + ":bad_rotation"}
		}
		q.followIK(r, []IKLink{l}, pos)
		return dec{"follow", "", cell}
	case KInit:
		if M.FromRelay != m.Sender {
			return refuse("hs_init_sender_mismatch", cell)
		}
		if !M.Reconnect {
			if M.Epoch != r.Cur || M.Ctx != r.Cur {
				return refuse("rekey_not_current_epoch", cell+":not-current")
			}
			if M.FromIK != r.IK {
				return refuse("rekey_refused", cell+":identity")
			}
			if o := r.Own; o != nil && !o.Reconnect {
				if o.ID < M.HS {
					return dec{"drop", "crossing", cell + ":crossing-own-lower"}
				}
				q.abandonOwn(r)
				cell += ":crossing-own-higher"
			}
			return q.answerInit(r, m, cell, nil, false, false)
		}
		if slices.Contains(r.Answered, M.HS) {
			return refuse("reconnect_refused", cell+":replay")
		}
		if d, stop := q.r28Conflict(r, M.Rot); stop {
			return d
		}
		if M.Ctx != r.Cur {
			return refuse("reconnect_refused", cell+":ctx")
		}
		st, app := r.ikState(M.FromIK, M.Rot)
		if st != ikCurrent && st != ikReached {
			return refuse("reconnect_refused", cell+":chain")
		}
		if o := r.Own; o != nil && o.Reconnect && o.ID > M.HS {
			q.abandonOwn(r) // between persons: the higher th1 abandons its own
		}
		for _, a := range slices.Clone(r.Ans) {
			if a.Reconnect {
				q.dropAnswer(r, a.ID)
			}
		}
		return q.answerInit(r, m, cell, app, false, false)
	case KResp:
		o := r.Own
		if q.w.Now-o.Started > r28HSLife {
			q.abandonOwn(r)
			return dec{"drop", "expired", cell + ":own-expired"}
		}
		var app []IKLink
		if o.Reconnect {
			st, a := ikCurrent, []IKLink(nil)
			if M.Sig != o.PeerIK {
				st, a = r.ikState(M.Sig, M.Rot)
			}
			if st != ikCurrent && st != ikReached {
				q.abandonOwn(r)
				return dec{"abort", "sig_R", cell + ":chain"}
			}
			app = a
		} else if M.Sig != o.PeerIK {
			q.abandonOwn(r)
			return dec{"abort", "sig_R", cell + ":sig"}
		}
		if len(app) > 0 {
			q.followIK(r, app, pos)
		}
		q.establish(r, M.NewEpoch, M.Sig, o.OwnIK, pos)
		q.w.noteEst(q, r, q.w.hsOrigin[o.ID])
		r.Epochs[len(r.Epochs)-1].MineInit = true
		if o.Reconnect {
			for _, a := range slices.Clone(r.Ans) {
				if a.Reconnect {
					q.dropAnswer(r, a.ID)
				}
			}
			toks, _ := q.ruleT(r, M.Toks, r.Relay)
			q.keepTokens(r, toks)
		}
		r.Own = nil
		fin := Msg{Kind: KFin, Epoch: M.NewEpoch, HS: M.HS, NewEpoch: M.NewEpoch, Sig: o.OwnIK, Reconnect: o.Reconnect}
		q.enqueue(r.ID, fin, nil)
		r.LastFin, r.LastFinHS, r.LastFinRC = q.st.Out[len(q.st.Out)-1].M.Inner, M.HS, o.Reconnect
		return dec{"accept", "", cell}
	case KFin:
		var a HS
		for _, x := range r.Ans {
			if x.ID == M.HS {
				a = x
			}
		}
		if M.Sig != a.PeerIK {
			return dec{"drop", "sig_I", cell + ":sig-invalid:handshake-kept"}
		}
		if q.w.Now-a.Started > r28HSLife {
			q.w.ttlFin[[2]PID{r.ID, q.ID}] = "arrived-after-answer-expired"
			q.w.noteFinLost(r.ID, q.ID)
			q.dropAnswer(r, a.ID)
			return dec{"drop", "expired", cell + ":answer-expired"}
		}
		q.removeAnswer(r, a.ID)
		var app []IKLink
		if a.Reconnect && len(a.Links) > 0 {
			st, x := r.ikState(a.PeerIK, a.Links)
			if st != ikCurrent && st != ikReached {
				return refuse("reconnect_refused", cell+":chain-at-fin")
			}
			app = x
		}
		if len(app) > 0 {
			q.followIK(r, app, pos)
		}
		q.establish(r, a.NewEpoch, a.PeerIK, a.OwnIK, pos)
		q.w.noteEst(q, r, q.w.hsOrigin[a.ID])
		if a.Reconnect {
			toks, _ := q.ruleT(r, a.Toks, r.Relay)
			q.keepTokens(r, toks)
			for _, x := range slices.Clone(r.Ans) {
				if x.Reconnect {
					q.dropAnswer(r, x.ID)
				}
			}
			if r.Own != nil && r.Own.Reconnect {
				q.abandonOwn(r)
			}
		}
		return dec{"accept", "", cell}
	case KConfirm:
		q.enqueue(r.ID, Msg{Kind: KSession, Probe: -1}, nil) // the unsupported_type answer
		return dec{"accept", "unsupported_type", "rel28:hs.confirm-unsupported"}
	}
	return refuse("unexpected", cell)
}

// r28HSLife: vault/handshakes.go:27 HandshakeTTL, for rekeys and
// reconnects awaiting hs.resp or hs.fin (vault/outbox.go:421-430).
const r28HSLife = 16 * day

// r28Conflict: vault/rotateconflict.go:32 against followed links only.
func (q *Party) r28Conflict(r *PeerRec, links []IKLink) (dec, bool) {
	if r.Device {
		return dec{}, false // connections only (rotateconflict.go:33)
	}
	for _, l := range links {
		for _, f := range r.Chain {
			if f.Old == l.Old && f.New != l.New {
				q.w.stat("r28:rotate_conflict")
				r.CandA, r.CandB = f, l
				q.suspend(r, "identity.rotate_conflict")
				return dec{"suspend", "conflict", "r28:C:identity"}, true
			}
		}
	}
	return dec{}, false
}

// r28Code: a release-28 vault follows the release-28 code (the default).
// Devices are apps, whose code is not the vault's: a release-28 device
// keeps the earlier model (f4a4d97 §3.4.1), a stated gap.
func (p *Party) r28Code() bool { return p.Rel28 && !p.Device && !p.w.r28Spec }
