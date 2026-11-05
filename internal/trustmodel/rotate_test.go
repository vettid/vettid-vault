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
	if p.Rel28 || p.Opt != optFull {
		if path == pathDevice {
			return // releases 28 and 29 rotate no relay key (the relay-key gate)
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
			// start again after identity.rotate. Release 28: rekeys only
			// (vault/core.go:747-757: dropRekey, startRekey).
			if p.r28Code() {
				if o := r.Own; o != nil && !o.Reconnect {
					p.abandonOwn(r)
				}
				if r.Own == nil {
					p.startHS(r, false)
				}
			} else if o := r.Own; o != nil {
				rc := o.Reconnect
				p.abandonOwn(r)
				p.startHS(r, rc)
			} else if r.Pend != nil {
				p.abandonPending(r, "S5: own ik rotated", true)
			}
			if p.newSpec() && r.PeerA { // S5 answer drop only toward peers that advertise hs_confirm (lead item 1)
				for len(r.Ans) > 0 {
					p.dropAnswer(r, r.Ans[0].ID)
					w.stat("A:S5-answer-dropped")
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
	if r.Status != stActive || r.Own != nil || (reconnect && r.Device) || (p.w.optA && r.Pend != nil) {
		return
	}
	if len(r.Ans) > 0 && !p.Rel28 {
		return // S5 / §6.6: none while an answer of mine awaits hs.fin (release <= 28: not checked)
	}
	ep := r.epoch(r.Cur)
	if ep == nil || reconnect {
		ep = r.lastEpoch()
	}
	if reconnect && r.RCCtx != 0 {
		if e := r.epoch(r.RCCtx); e != nil {
			ep = e
		}
		r.RCCtx = 0
	}
	if ep == nil {
		return
	}
	h := &HS{ID: w.id(), Reconnect: reconnect, Ctx: ep.ID, PeerIK: r.IK, OwnIK: p.st.IK, Started: w.Now, Relay: r.KeyFor,
		InitHalf: p.initHalf(r)}
	m := Msg{Kind: KInit, HS: h.ID, Reconnect: reconnect, Ctx: ep.ID, FromIK: p.st.IK, FromKEM: p.st.KEM,
		FromRelay: r.KeyFor, Rot: p.ownLinks(ep.Own)}
	if p.r28Code() && !reconnect {
		m.Rot = nil // release 28: a rekey carries no rotations (vault/handshakes.go:972)
	}
	var f func(*Entry)
	if reconnect {
		rt := r.reconnectTok(r.KeyFor, r.Relay, w.Now)
		box := r.KeyFor // the tokens are minted by the mailbox of the key it deposits with
		if rt.JTI == 0 || !w.R.live(box) {
			return
		}
		h.Toks = p.issue(r, box, true)
		m.Toks = h.Toks
		f = func(e *Entry) { e.Tok, e.With = rt, r.KeyFor }
	} else if r.Cur != 0 {
		m.Epoch = r.Cur
	}
	r.Own = h
	w.stat("start:" + map[bool]string{false: "rekey", true: "reconnect"}[reconnect])
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
			any = true
		}
		r.DropAns = nil
		if r.WantRC {
			r.WantRC = false
			if r.Own == nil || !r.Own.Reconnect {
				p.abandonOwn(r)
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
			if o := r.Own; o != nil && p.r28Code() {
				if w.Now-o.Started > r28HSLife { // vault/outbox.go:427: dropped, never stale
					p.abandonOwn(r)
					w.stat("r28:own-handshake-expired")
				}
			} else if o != nil {
				if o.Reconnect && w.Now-o.Started > w.hsLifeFor(true) {
					p.markStale(r, "reconnect failed")
					p.h5(r, -1)
					w.logf("%s: %s STALE (reconnect not completed in 7 days)", p.Name, w.party(r.ID).Name)
					continue
				}
				if !o.Reconnect && w.Now-o.Started > w.hsLifeFor(false) {
					p.abandonOwn(r)
					if !p.rekeyRefusedRC(r, o, "own rekey unanswered") {
						p.startHS(r, o.Reconnect)
					}
				}
			}
			life := w.answerLife()
			if p.r28Code() {
				life = r28HSLife // vault/outbox.go:421
			}
			for _, a := range slices.Clone(r.Ans) {
				if w.Now-a.Started > life && !a.Reconnect {
					p.rekeyRefusedRC(r, nil, "my answer expired without hs.fin")
				}
				if w.Now-a.Started > life {
					p.dropAnswer(r, a.ID)
				}
			}
			r.Earlier = slices.DeleteFunc(r.Earlier, func(e Earlier) bool { return w.Now > e.Until })
			if p.newSpec() {
				p.tickA(r)
			}
			r.Epochs = slices.DeleteFunc(r.Epochs, func(e Epoch) bool {
				if e.ID == r.RevOld {
					return false // Deployment: the old epoch kept toward an ungated peer
				}
				if p.newSpec() && (e.ID == r.ConfID || slices.Contains(r.AbanIDs, e.ID)) {
					return false // §6.3.1 (G): the id is kept
				}
				return e.ID != r.Cur && e.Superseded != 0 && w.Now-e.Superseded > 16*day
			})
			p.refresh(r)
			if ep := r.epoch(r.Cur); ep != nil {
				due := day
				if r.Device || p.Device {
					due = 7 * day
				}
				if w.Now-ep.EstAt > due && !(p.Device && !r.Device) {
					p.startHS(r, false)
				}
			}
			if r.Device && r.standing(r.KeyFor, r.Relay, w.Now).JTI == 0 && !p.r28Code() {
				p.markStale(r, "tokens expired (needs pairing)")
				p.h5(r, -1)
				continue
			}
			if !r.Device && r.standing(r.KeyFor, r.Relay, w.Now).JTI == 0 {
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
