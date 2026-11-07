package trustmodel

import "slices"

// The rotating side (§3.4 "The order of a relay-key rotation", (a), (b),
// §3.4.1 S1-S9), handshake starts, unlock and timers.

const (
	pathCred = iota
	pathRecovery
	pathTransfer
	pathDevice
)

var pathName = [...]string{"credential.rotate", "recovery", "transfer", "device relay rotation"}

// rotate is one of the three paths (abstract), or a device's relay rotation.
func (p *Party) rotate(path int) {
	w := p.w
	if p.Device {
		path = pathDevice
	}
	w.logf("%s: ROTATE (%s)", p.Name, pathName[path])
	w.stat("rotate:" + pathName[path])
	if !p.Copy && path != pathDevice {
		w.rotTimes[p.ID] = append(w.rotTimes[p.ID], w.Now) // the rapid-rotation residual (M2)
	}
	if !w.relayRot {
		if path == pathDevice {
			return // release 29 rotates no relay key (the oracle config)
		}
	} else if p.st.Pend != nil {
		if p.st.Pend.Refused && path == pathCred {
			w.logf("%s: credential.rotate discards refused key %d", p.Name, p.st.Pend.Key)
			p.st.Pend = nil
			p.st.Owed = false
			p.newPending(path)
		} else {
			p.st.Owed = true // a relay-key rotation is owed
		}
	} else {
		p.newPending(path)
	}
	if path != pathDevice {
		ik, kem := w.key(), w.key()
		l := IKLink{p.st.IK, ik, kem}
		w.iklinkBy[l] = rot{p.ID, p.writes + 1}
		p.st.Chain = append(p.st.Chain, l)
		p.st.IK, p.st.KEM = ik, kem
		for i := range p.st.Peers {
			r := &p.st.Peers[i]
			if r.Status != stActive {
				continue
			}
			p.enqueue(r.ID, Msg{Kind: KIdRot, Rot: []IKLink{l}}, nil)
			// S5: abandon own rekeys and reconnects (and pending epochs, §6.3.1),
			// start again after identity.rotate.
			if o := r.Own; o != nil {
				rc := o.Reconnect
				p.abandonOwn(r)
				p.startHS(r, rc)
			} else if r.Pend != nil {
				w.hit("K2:S5-pending-abandoned")
				p.abandonPending(r, "S5: own ik rotated", true)
			}
			if p.newSpec() { // R29-K2: S5 drops every answer awaiting hs.fin, toward every peer
				for len(r.Ans) > 0 {
					p.dropAnswer(r, r.Ans[0].ID)
					w.stat("A:S5-answer-dropped")
					w.hit("K2:S5-answer-dropped")
				}
				if r.Own == nil && r.Pend == nil {
					p.startHS(r, false)
				}
			}
		}
	}
	p.st.LastRot = w.Now
	p.write() // the first write
	p.flush()
	p.completePending(false)
}

// newPending stores a new relay key as pending with its signed link and
// held updates (§3.4 step 1).
func (p *Party) newPending(path int) {
	w := p.w
	k := w.key()
	l := RLink{p.st.Relay, k}
	w.rlinkBy[l] = rot{p.ID, p.writes + 1}
	p.st.RLinks = append(p.st.RLinks, l)
	fresh := p.st.Pend != nil && p.st.Pend.Fresh
	p.st.Pend = &Pending{Key: k, Path: path, Fresh: fresh}
	p.rotOK = false
	for i := range p.st.Out {
		e := &p.st.Out[i]
		if e.M.Kind == KUpdate && !e.Done && e.Target != p.st.Relay && p.keyRank(e.Target) < 0 {
			e.Target = k // a discarded key's held update now waits for this one
		}
	}
	for i := range p.st.Peers {
		r := &p.st.Peers[i]
		if r.Status == stActive && !p.hasUpdate(r.ID, k) {
			p.enqueue(r.ID, Msg{Kind: KUpdate}, func(e *Entry) { e.Target = k })
		}
	}
}

func (p *Party) hasUpdate(to PID, k Key) bool {
	return slices.ContainsFunc(p.st.Out, func(e Entry) bool {
		return e.M.Kind == KUpdate && e.To == to && e.Target == k && !e.Done && !e.Resend
	})
}

// completePending: the relay's rotate (or the registration), then the
// second write. atUnlock: the one attempt of the refused state.
func (p *Party) completePending(atUnlock bool) {
	w := p.w
	pd := p.st.Pend
	if pd == nil || p.Locked || (pd.Refused && !atUnlock) {
		return
	}
	err := w.R.rotate(p.st.Relay, pd.Key)
	if err == mailboxUnknown {
		err = w.R.register(pd.Key)
	}
	w.stat("relay-rotate:" + string(err))
	switch {
	case err == rateLimited:
		return
	case err.definite():
		if pd.Path == pathRecovery && !pd.Fresh && !pd.Refused {
			// O5 (b): a recovery takes credential.rotate's way out once
			w.logf("%s: rotate refused; recovery mints a fresh key once (O5 b)", p.Name)
			p.st.Pend.Fresh = true
			p.newPending(pathRecovery)
			p.write()
			p.completePending(false)
			return
		}
		w.logf("%s: pending key %d REFUSED", p.Name, pd.Key)
		p.st.Pend.Refused = true
		p.write()
		return
	}
	p.rotOK = true
	// the second write
	old := p.st.Relay
	ge := w.Now
	if b := w.R.boxes[old]; b != nil && b.deleteAt != 0 {
		ge = b.deleteAt
	}
	p.st.Old = append(p.st.Old, OldKey{Key: old, GraceEnd: ge, Since: w.Now})
	p.st.Relay = pd.Key
	p.st.Pend = nil
	p.rotOK = false
	if p.st.Owed {
		p.st.Owed = false
		p.newPending(pd.Path)
	}
	w.logf("%s: relay key %d current (old %d deposit-only)", p.Name, p.st.Relay, old)
	p.write()
	p.flush()
	if p.st.Pend != nil {
		p.completePending(false)
	}
}

// startHS starts a rekey (reconnect=false) or a reconnect with r.
func (p *Party) startHS(r *PeerRec, reconnect bool) {
	w := p.w
	origin := w.nextOrigin
	w.nextOrigin = ""
	defer func() {
		if r.Own != nil && w.hsOrigin[r.Own.ID] == "" {
			w.hsOrigin[r.Own.ID] = origin
		}
	}()
	if r.Status != stActive || (reconnect && r.Device) {
		return
	}
	if p.newSpec() && p.Device && r.Device && !p.OldApp {
		w.hit("D2:device-starts-no-rekey")
		return // R29-D2: a device runs only the responder half
	}
	if o := r.Own; o != nil {
		if reconnect && o.Reconnect {
			w.hit("X4:one-reconnect-at-a-time")
		}
		return
	}
	if p.w.optA && r.Pend != nil {
		if !reconnect || r.Pend.Reconnect {
			if reconnect {
				w.hit("X4:one-reconnect-at-a-time")
			} else {
				w.hit("I4:no-rekey-while-pending")
			}
			return
		}
		p.abandonPending(r, "a reconnect starts", false) // R29-I7: a reconnect names the current epoch, never a pending one
	}
	if len(r.Ans) > 0 {
		if p.newSpec() && !reconnect {
			w.hit("I4:no-rekey-while-answer-awaits-fin")
		}
		return // S5 / §6.6: none while an answer of mine awaits hs.fin
	}
	var ep *Epoch
	switch {
	case reconnect && p.newSpec():
		id := r.rcName() // R29-X5, K5, K7
		if id == 0 {
			w.hit("K5:no-epoch-to-name-stale")
			p.markStale(r, "K5: no epoch to name")
			p.h5(r, -1)
			return
		}
		ep = r.epoch(id)
		if r.Cur == 0 {
			w.hit("K5:reconnect-after-demotion")
			if r.DemName == id {
				w.hit("K7:reconnect-names-E")
			}
		}
	case p.newSpec():
		ep = r.epoch(r.Cur) // a rekey only from the current epoch (§6.5; R29-X6: never sealed)
	default:
		ep = r.epoch(r.Cur)
		if ep == nil || reconnect {
			ep = r.lastEpoch()
		}
	}
	if ep == nil {
		return
	}
	h := &HS{ID: w.id(), Reconnect: reconnect, Ctx: ep.ID, PeerIK: r.IK, OwnIK: p.st.IK, Started: w.Now, Relay: r.KeyFor}
	m := Msg{Kind: KInit, HS: h.ID, Reconnect: reconnect, Ctx: ep.ID, FromIK: p.st.IK, FromKEM: p.st.KEM,
		FromRelay: r.KeyFor, Rot: p.ownLinks(ep.Own)}
	var f func(*Entry)
	if reconnect {
		rt := r.reconnectTok(r.KeyFor, r.Relay, w.Now)
		box := r.KeyFor // the tokens are minted by the mailbox of the key it deposits with
		if rt.JTI == 0 && p.newSpec() {
			w.hit("K6:no-reconnect-token-stale")
			p.markStale(r, "K6: no reconnect token")
			p.h5(r, -1)
			return
		}
		if rt.JTI == 0 || !w.R.live(box) {
			return
		}
		if p.newSpec() && ep.ID != r.RCNamed {
			r.RCNamed, r.RCFails = ep.ID, 0 // R29-K6: tries are counted per named epoch
		}
		h.Toks = p.issue(r, box, true)
		m.Toks = h.Toks
		f = func(e *Entry) { e.Tok, e.With = rt, r.KeyFor }
	} else if r.Cur != 0 {
		m.Epoch = r.Cur
	}
	r.Own = h
	if p.newSpec() && len(m.Rot) > 1 {
		w.hit("K1:hs.init-whole-chain")
	}
	w.stat("start:" + map[bool]string{false: "rekey", true: "reconnect"}[reconnect])
	w.hsOrigin[h.ID] = origin
	if origin == "" {
		w.hsOrigin[h.ID] = map[bool]string{false: "rekey", true: "reconnect"}[reconnect]
	}
	if reconnect {
		r.RCs++
	}
	p.enqueue(r.ID, m, f)
}

// unlock: §12.2 "On unlock", plus the resends of §3.4 (b).
func (p *Party) unlock() {
	if !p.Locked {
		return
	}
	p.Locked = false
	p.w.lockedFor[p.ID] = 0
	p.collectedSinceUnlock = false
	p.unlocks++
	w := p.w
	p.guard(func() {
		for i := range p.st.Peers {
			r := &p.st.Peers[i]
			if r.Status != stActive {
				continue
			}
			p.refresh(r)
			if !r.Device && r.standing(r.KeyFor, r.Relay, w.Now).JTI == 0 {
				w.nextOrigin = "token expiry reconnect"
				p.startHS(r, true)
			}
			if !p.Device && r.Device {
				p.startHS(r, false) // device sessions rekey at every unlock
			}
			// (b) resend
			if r.KeyFor != p.st.Relay && p.st.Pend == nil && !r.ResendEnd && w.Now-r.LastSend >= hour &&
				r.standing(r.KeyFor, r.Relay, w.Now).JTI != 0 {
				r.LastSend = w.Now
				w.stat("resend(b)")
				p.enqueue(r.ID, Msg{Kind: KUpdate}, func(e *Entry) { e.Target, e.Resend = p.st.Relay, true })
			}
		}
		p.write()
		p.completePending(true)
		p.flush()
		p.startWanted()
	})
	p.w.unlockExchange(p)
}

// unlockExchange: §7.2 "Unlock exchange": the member's app unlocks its
// vault, and the unlock request carries a fresh app token and the result
// a fresh vault token, without the relay. The model's device is the
// member's app: when a vault unlocks while its app is online (unlocked),
// the unlock came from the app, and each gets a fresh standing token from
// the other. The app merely coming online exchanges nothing. (A desktop or
// agent has no such exchange; one offline past its token is paired again,
// a member's action the model does not run.)
func (w *World) unlockExchange(p *Party) {
	if p.Copy || !p.newSpec() || p.Device {
		return
	}
	for _, q := range w.real() {
		if q == p || q.Locked || p.Locked || q.Device == p.Device || q.Desktop || p.Desktop {
			continue
		}
		V, D := p, q
		if p.Device {
			V, D = q, p
		}
		rv, rd := V.st.peer(D.ID), D.st.peer(V.ID)
		if rv == nil || rd == nil || rv.Status != stActive || rd.Status != stActive {
			continue
		}
		for _, x := range [][2]*Party{{V, D}, {D, V}} {
			iss, hold := x[0], x[1]
			ri, rh := iss.st.peer(hold.ID), hold.st.peer(iss.ID)
			if ri.Relay != hold.st.Relay || rh.Relay != iss.st.Relay {
				continue // the exchange names the keys each side knows; a rotation in flight goes by the relay
			}
			var ts []Token
			if iss.guard(func() { ts = iss.issue(ri, iss.st.Relay, false); iss.write() }) || iss.Locked || hold.Locked {
				continue
			}
			hold.guard(func() {
				kept, _ := hold.ruleT(rh, ts, rh.Relay)
				hold.keepTokens(rh, kept)
				hold.write()
			})
		}
		w.stat("unlock exchange")
	}
}

// refresh re-mints tokens near their end (§7.2), sent in relay.token.issued.
func (p *Party) refresh(r *PeerRec) {
	var s, rc int64
	for _, t := range r.Issued {
		if t.Iss == p.st.Relay && t.Sub == r.Relay {
			if t.Reconnect {
				rc = max(rc, t.Exp)
			} else {
				s = max(s, t.Exp)
			}
		}
	}
	now := p.w.Now
	if s-now < 10*day || (!r.Device && rc-now < 60*day) {
		p.enqueue(r.ID, Msg{Kind: KTokIssued, Toks: []Token{{}, {Reconnect: !r.Device}}}, nil)
	}
}

func (p *Party) startWanted() {
	any := false
	for i := range p.st.Peers {
		r := &p.st.Peers[i]
		for _, id := range r.DropAns { // §6.3.1 (J): an undepositable answer ends at once
			p.dropAnswer(r, id)
			p.w.stat("A:answer-undepositable")
			p.w.hit("X3:undepositable-answer-destroyed")
			any = true
		}
		r.DropAns = nil
		if r.WantRC {
			r.WantRC = false
			if r.Own == nil || !r.Own.Reconnect {
				p.abandonOwn(r)
				p.w.nextOrigin = "token_expired reconnect"
				p.startHS(r, true)
				any = true
			}
		}
	}
	if any {
		p.write()
		p.flush()
	}
}

func (p *Party) wantReconnect(r *PeerRec) { r.WantRC = true }

// tick: timers of an unlocked party after time passed.
func (p *Party) tick() {
	if p.Locked {
		return
	}
	w := p.w
	p.guard(func() {
		for i := range p.st.Peers {
			r := &p.st.Peers[i]
			if r.Status != stActive {
				continue
			}
			if o := r.Own; o != nil {
				if o.Reconnect && w.Now-o.Started > w.hsLifeFor(true) && p.newSpec() {
					// R29-K6: a try fails when its handshake expires unanswered
					// (tokens revoked); the third failure for the same named
					// epoch makes the connection stale
					p.abandonOwn(r)
					if o.Ctx != r.RCNamed {
						r.RCNamed, r.RCFails = o.Ctx, 0
					}
					r.RCFails++
					w.hit("K6:try-failed")
					if r.RCFails >= 3 {
						w.hit("K6:third-failure-stale")
						p.markStale(r, "K6: third failed try")
						p.h5(r, -1)
						continue
					}
					w.nextOrigin = "K6 retry"
					p.startHS(r, true)
				} else if o.Reconnect && w.Now-o.Started > w.hsLifeFor(true) {
					p.markStale(r, "reconnect failed")
					p.h5(r, -1)
					w.logf("%s: %s STALE (reconnect not completed in 7 days)", p.Name, w.party(r.ID).Name)
					continue
				}
				if !o.Reconnect && w.Now-o.Started > w.hsLifeFor(false) {
					if p.newSpec() {
						w.hit("L1:rekey-unanswered-16d")
					}
					p.abandonOwn(r)
					p.startHS(r, o.Reconnect)
				}
			}
			life := w.answerLife()
			for _, a := range slices.Clone(r.Ans) {
				if w.Now-a.Started > life {
					if p.newSpec() {
						w.hit("L1:answer-expired-L")
					}
					p.dropAnswer(r, a.ID)
				}
			}
			r.Earlier = slices.DeleteFunc(r.Earlier, func(e Earlier) bool { return w.Now > e.Until })
			if p.newSpec() {
				p.tickA(r)
			}
			r.Epochs = slices.DeleteFunc(r.Epochs, func(e Epoch) bool {
				if p.newSpec() && (e.ID == r.ConfID || slices.Contains(r.AbanIDs, e.ID) || e.ID == r.DemName) {
					return false // §6.3.1 (G): the id is kept (K7: E, until a new epoch is current)
				}
				return e.ID != r.Cur && e.Superseded != 0 && w.Now-e.Superseded > 16*day
			})
			p.refresh(r)
			if ep := r.epoch(r.Cur); ep != nil {
				due := day
				if r.Device || p.Device {
					due = 7 * day
				}
				if w.Now-ep.EstAt > due && (!p.Device || p.OldApp) { // R29-D2: a device starts no rekey (an old app does)
					p.startHS(r, false)
				}
			}
			if p.needsReconnect(r) {
				w.nextOrigin = "K5 reconnect (retry)"
				p.startHS(r, true) // R29-K5: the reconnect after a demotion, once nothing holds it back
			}
			// (0.87.1) no automatic stale between a vault and its device
			// when tokens lapse: the vault keeps rekeying (R29-D1), and a
			// split that follows is finding F, part of the device exception
			// (§3.4.1 Invariants). §7.2's re-pairing of a desktop offline
			// past its token is a member's action, not modelled.
			if !r.Device && r.standing(r.KeyFor, r.Relay, w.Now).JTI == 0 {
				w.nextOrigin = "token expiry reconnect"
				p.startHS(r, true)
			}
			// S1: stale 30 days after the second write
			for _, o := range p.st.Old {
				if o.Key == r.KeyFor && w.Now-p.sinceAfter(o.Key) > staleAfter {
					p.markStale(r, "S1: not followed in 30 days")
					p.h5(r, -1)
					w.logf("%s: %s STALE (S1)", p.Name, w.party(r.ID).Name)
				}
			}
			// S9
			if r.RevokedAt != 0 && !r.S9Audited && r.KeyFor != p.st.Relay && w.Now-r.RevokedAt > day {
				r.S9Audited = true
				w.stat("S9:fork_suspected")
				w.feedItem(p.ID, r.ID, "S9 fork_suspected (relay_revoked)")
				w.logf("%s: S9 connection.fork_suspected (relay_revoked) for %s", p.Name, w.party(r.ID).Name)
			}
		}
		// old relay keys: deleted when every recipient acknowledged or is stale
		p.st.Old = slices.DeleteFunc(p.st.Old, func(o OldKey) bool {
			for _, r := range p.st.Peers {
				if r.Status == stActive && p.keyRank(r.KeyFor) <= p.keyRank(o.Key) {
					return false
				}
			}
			for i := range p.st.Peers {
				r := &p.st.Peers[i]
				r.Toks = slices.DeleteFunc(r.Toks, func(t Token) bool { return t.Sub == o.Key })
			}
			return true
		})
		p.write()
		p.completePending(false)
		p.flush()
		p.startWanted()
	})
}

// sinceAfter: when the key after k became current (its second write).
func (p *Party) sinceAfter(k Key) int64 {
	for _, o := range p.st.Old {
		if o.Key == k {
			return o.Since // k became old when the next key's second write landed
		}
	}
	return p.w.Now
}
