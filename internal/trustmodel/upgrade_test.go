package trustmodel

import (
	"fmt"
	"strings"
)

// Upgrade mode (TRUSTMODEL_UPGRADE=1): every party starts on release 28
// and upgrades to release 29 at a random point. Each party sends its
// features with its first message to each peer after its upgrade; a
// release-29 party opens the gate toward a peer (PeerA) when it accepts a
// message carrying that peer's features. A release-28 party does not keep
// features it receives (assumed). TRUSTMODEL_FEATMODE=echo: a party that
// first sees a peer's features also owes its own at its next contact;
// =always: every message from a release-29 party carries its features.

// upgrade: the binary changes; stored and memory state are migrated alike
// (the confirmed epoch starts as the current one; features owed to every peer).
func (p *Party) upgrade() {
	p.Rel28 = false
	p.Name = strings.TrimSuffix(p.Name, "(r28)")
	p.w.upAt[p.ID] = p.w.Now
	for _, st := range []*State{&p.st, &p.stored} {
		for i := range st.Peers {
			r := &st.Peers[i]
			r.FeatOwed = true
			if r.Cur != 0 {
				r.ConfID = r.Cur
			}
		}
	}
	p.w.stat("F:upgraded")
	p.w.logf("%s: UPGRADED to release 29", p.Name)
}

// seeFeatures: q accepted a message carrying r's features.
func (q *Party) seeFeatures(r *PeerRec) {
	if r.PeerA {
		return
	}
	r.PeerA = true
	k := [2]PID{q.ID, r.ID}
	if _, ok := q.w.gateOpenAt[k]; !ok {
		q.w.gateOpenAt[k] = q.w.Now
	}
	q.w.stat("F:gate opened")
	q.w.logf("%s: gate toward %s OPEN (features seen)", q.Name, q.w.party(r.ID).Name)
	if q.w.featMode == "echo" {
		r.FeatOwed = true
	}
}

// gateStats: for each ordered pair (q, r) of real parties that both
// upgraded, the hours from the later upgrade until q saw r's features
// (or until the end of the run, if q never did).
func (w *World) gateStats() {
	for k, qa := range w.upAt {
		for k2, ra := range w.upAt {
			if k == k2 || w.party(k).Copy || w.party(k2).Copy || w.party(k).st.peer(k2) == nil {
				continue
			}
			start := max(qa, ra)
			if at, ok := w.gateOpenAt[[2]PID{k, k2}]; ok {
				w.stat(fmt.Sprintf("G:ungated-hours open %05d", (at-start)/hour))
			} else {
				w.stat(fmt.Sprintf("G:ungated-hours never %05d", (w.Now-start)/hour))
				if w.Now-start > 7*day {
					w.stat("G:never opened, over 7 days")
					q, r := w.party(k), w.party(k2)
					why := "other"
					switch {
					case w.dead[k] != "" || w.dead[k2] != "":
						why = "a party dead"
					case q.st.peer(k2).Status == stSuspended || r.st.peer(k) != nil && r.st.peer(k).Status == stSuspended:
						why = "suspended"
					case q.st.peer(k2).Status == stStale || r.st.peer(k) != nil && r.st.peer(k).Status == stStale:
						why = "stale"
					case q.Locked || r.Locked:
						why = "a party locked"
					}
					w.stat("G:never opened, over 7 days: " + why)
				}
			}
		}
	}
}
