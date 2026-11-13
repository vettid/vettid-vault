package trustmodel

// Action generators for reach (R29 rule list §9.4): an old copy that
// answers and confirms a handshake as responder, one that makes a
// handshake as initiator, and hs.fin loss around a rotation. They drive
// the paths that rarely occur by chance (demotion by position, strict F1,
// rule E's fork evidence, F1 by rekey).

// stepTime: a short pause in which the relay's leases expire.
func (w *World) stepTime() { w.advance(visTimeout + freshWindow + 1) }

// copyCollects: the copy collects (and acks) every mailbox it holds; in
// the oracle config that is the original's live mailbox (a stated
// residual: §3.4.1 Residuals, the copy keeps the live mailbox).
func (w *World) copyCollects(c *Party, rounds int) {
	for i := 0; i < rounds; i++ {
		c.collectRound(maxCollect)
	}
}

// copyRespond: Q starts a handshake with the original P; the copy answers
// it first, collects Q's hs.fin, activates and sends hs.confirm (and, for
// N%2 == 0, a session message) under the new epoch, which Q confirms.
// For N%3 == 0 the original then rotates its ik (a link reaches Q).
func (w *World) copyRespond(c *Party, a Action) {
	if len(c.st.Peers) == 0 {
		return
	}
	orig := w.party(c.Origin)
	q := w.party(c.st.Peers[a.B%len(c.st.Peers)].ID)
	qr := q.st.peer(orig.ID)
	if q.Locked || qr == nil || qr.Status != stActive || (q.Device && qr.Device) {
		return
	}
	w.stat("reach:copy-responds")
	q.guard(func() { q.startHS(qr, a.N%4 == 1 && !qr.Device); q.write(); q.flush() })
	c.unlock()
	w.copyCollects(c, 2) // the copy answers first
	w.stepTime()
	q.collectRound(maxCollect) // Q: pending, hs.fin
	w.stepTime()
	w.copyCollects(c, 2) // the copy activates and sends hs.confirm
	if a.N%2 == 0 {
		c.guard(func() {
			if r := c.st.peer(q.ID); r != nil {
				c.enqueue(q.ID, Msg{Kind: KSession, Probe: w.id()}, nil)
				c.write()
				c.flush()
			}
		})
	}
	w.stepTime()
	q.collectRound(maxCollect) // Q confirms the copy's epoch
	c.Locked = true
	c.st = c.stored.clone()
	if a.N%3 == 0 && !orig.Locked && !orig.Device {
		orig.guard(func() { orig.rotate(a.N % 3) })
	}
}

// copyInit: the copy rekeys with Q. For N%3 == 1 the original rotated
// first and Q gets the link late (demotion by position). For N%2 == 0 the
// copy also collects Q's hs.confirm and sends a session message under the
// new epoch (it sets the flag); otherwise it sends nothing but hs.fin (the
// §3.4.1 residual). For N%3 == 0 the original rotates afterwards (strict
// F1). For N%8 == 5 the copy also deposits a sealed-mode rekey (R29-X6,
// an adversarial input). For N%5 == 2 the original then rekeys from Q's
// confirmed epoch and the copy sends under the destroyed one (R29-R6).
func (w *World) copyInit(c *Party, a Action) {
	if c.Device || len(c.st.Peers) == 0 {
		return
	}
	orig := w.party(c.Origin)
	cr := &c.st.Peers[a.B%len(c.st.Peers)]
	q := w.party(cr.ID)
	if q.Locked || q.st.peer(orig.ID) == nil {
		return
	}
	w.stat("reach:copy-initiates")
	late := a.N%3 == 1 && !orig.Locked
	if late {
		orig.guard(func() { orig.rotate(pathCred) })
		for _, b := range q.boxes() {
			if mb := w.R.boxes[b]; mb != nil {
				for _, m := range mb.msgs {
					if m.P.Kind == KIdRot && m.Actor == orig.ID {
						m.leaseUntil = w.Now + 2*hour // the link reaches Q late
					}
				}
			}
		}
	}
	c.unlock()
	c.guard(func() {
		cr = c.st.peer(q.ID)
		c.abandonOwn(cr)
		c.startHS(cr, false)
		if a.N%8 == 5 && cr.Cur != 0 {
			c.enqueue(q.ID, Msg{Kind: KInit, HS: w.id(), Ctx: cr.Cur, FromIK: c.st.IK, FromKEM: c.st.KEM, FromRelay: cr.KeyFor},
				func(e *Entry) { e.M.Epoch = 0 })
		}
		c.write()
		c.flush()
	})
	w.stepTime()
	q.collectRound(maxCollect) // Q answers
	w.stepTime()
	w.copyCollects(c, 2) // the copy: pending, hs.fin
	w.stepTime()
	q.collectRound(maxCollect) // Q activates the copy's epoch, hs.confirm
	if a.N%2 == 0 {
		w.stepTime()
		w.copyCollects(c, 2) // the copy confirms
		c.guard(func() {
			c.enqueue(q.ID, Msg{Kind: KSession, Probe: w.id()}, nil)
			c.write()
			c.flush()
		})
		w.stepTime()
		q.collectRound(maxCollect)
	}
	if a.N%5 == 2 && !late && !orig.Locked {
		// rule E: the original rekeys from the epoch Q still has as
		// confirmed; at its hs.fin Q destroys the copy's epoch; the copy
		// then sends under it (a later ts: fork evidence, R29-R6)
		w.stat("reach:copy-epoch-destroyed-then-used")
		if a.N%2 != 0 {
			w.stepTime()
			w.copyCollects(c, 2) // the copy confirms its epoch with Q's hs.confirm (Q's confirmed epoch stays E0)
		}
		orig.guard(func() {
			r := orig.st.peer(q.ID)
			orig.startHS(r, false)
			orig.write()
			orig.flush()
		})
		for i := 0; i < 3; i++ {
			w.stepTime()
			q.collectRound(maxCollect)
			orig.collectRound(maxCollect)
		}
		w.stepTime()
		c.guard(func() {
			c.enqueue(q.ID, Msg{Kind: KSession, Probe: w.id()}, nil)
			c.write()
			c.flush()
		})
		w.stepTime()
		q.collectRound(maxCollect)
	}
	c.Locked = true
	c.st = c.stored.clone()
	if a.N%3 == 0 && !orig.Locked {
		orig.guard(func() { orig.rotate(pathCred) })
	}
}

// finLoss: every hs.fin waiting in p's mailboxes is lost; then (N%4) its
// sender rotates its ik, or p does, or p stays locked (its peer's pending
// epoch runs into B), or nothing.
func (w *World) finLoss(p *Party, a Action) {
	var senders []PID
	for _, b := range p.boxes() {
		mb := w.R.boxes[b]
		if mb == nil {
			continue
		}
		kept := mb.msgs[:0]
		for _, m := range mb.msgs {
			if m.P.Kind == KFin {
				senders = append(senders, m.Actor)
				w.ttlFin[[2]PID{m.Actor, p.ID}] = "lost (fin-loss action)"
				continue
			}
			kept = append(kept, m)
		}
		mb.msgs = kept
	}
	if len(senders) == 0 {
		return
	}
	w.injLoss = true // M2: an injected loss
	w.stat("reach:hs.fin-lost")
	var rot *Party
	switch a.N % 4 {
	case 0:
		rot = w.party(senders[0])
	case 1:
		rot = p
	case 2:
		w.stat("reach:hs.fin-lost-receiver-away")
		p.Locked = true
		p.st = p.stored.clone()
		w.advance(aPendLife + day) // B for the sender's pending epoch
		return
	}
	if rot != nil && !rot.Copy && !rot.Device && !rot.Locked {
		w.stat("reach:hs.fin-lost-then-rotation")
		rot.guard(func() { rot.rotate(pathCred) })
	}
}
