package trustmodel

import (
	"fmt"
	"sort"
	"strings"
)

// r10 instrumentation (stats only; no behaviour): split episodes and what
// ends them, the visibility of each run's first violation, and the
// ungated window per pair in upgrade mode.

type episode struct {
	start   int64
	lostFin bool
	dir     string // releases: "29 init>28 resp" etc., for a lost hs.fin
}

func pairKey(a, b PID) [2]PID { return [2]PID{min(a, b), max(a, b)} }

func (w *World) rel(id PID) string {
	if w.party(id).Rel28 {
		return "28"
	}
	return "29"
}

func (w *World) noteEst(q *Party, r *PeerRec, origin string) {
	if q.Copy {
		return
	}
	w.lastEst[pairKey(q.ID, r.ID)] = origin
}

// noteFinLost: an hs.fin from init to resp is gone (relay TTL, deleted with
// a mailbox, or arrived after the answer ended).
func (w *World) noteFinLost(init, resp PID) {
	if init < 0 || resp < 0 || int(init) >= len(w.P) || int(resp) >= len(w.P) || w.party(init).Copy || w.party(resp).Copy {
		return
	}
	k := pairKey(init, resp)
	if ep := w.episodes[k]; ep != nil && !ep.lostFin {
		ep.lostFin, ep.dir = true, w.rel(init)+" init>"+w.rel(resp)+" resp"
		return
	}
	w.finLost[k] = init
}

// monitor: after each action, open or close split episodes per pair.
func (w *World) monitor() {
	ps := w.real()
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			a, b := ps[i], ps[j]
			ra, rb := a.st.peer(b.ID), b.st.peer(a.ID)
			if ra == nil || rb == nil {
				continue
			}
			k := pairKey(a.ID, b.ID)
			dead := ra.Status != stActive || rb.Status != stActive
			split := !dead && !consistent(ra, rb, a.respHalf(), b.respHalf())
			ep := w.episodes[k]
			switch {
			case split && ep == nil:
				ep = &episode{start: w.Now}
				if init, ok := w.finLost[k]; ok {
					resp := a.ID
					if init == a.ID {
						resp = b.ID
					}
					ep.lostFin, ep.dir = true, w.rel(init)+" init>"+w.rel(resp)+" resp"
				}
				delete(w.finLost, k)
				w.episodes[k] = ep
				if _, ok := w.firstSplit[k]; !ok {
					w.firstSplit[k] = w.Now
				}
			case !split && ep != nil:
				res := w.lastEst[k]
				if dead {
					res = "ended stale or suspended (visible)"
				}
				w.closeEpisode(ep, res)
				delete(w.episodes, k)
			case !split:
				delete(w.finLost, k)
			}
		}
	}
}

func (w *World) closeEpisode(ep *episode, res string) {
	if !ep.lostFin {
		return
	}
	w.stat("S:lost-fin split " + ep.dir + " | " + res)
	w.stat(fmt.Sprintf("S:lost-fin hours %s | %s %05d", ep.dir, res, (w.Now-ep.start)/hour))
}

// pairOf: the first two parties a violation names (an old copy counts as
// its original).
func (w *World) pairOf(d string) (PID, PID, bool) {
	var ids []PID
	seen := map[string]bool{}
	for _, m := range partyName.FindAllString(d, -1) {
		base := strings.TrimSuffix(strings.TrimSuffix(m, "'"), "(r28)")
		if seen[base] {
			continue
		}
		seen[base] = true
		for _, p := range w.P {
			if !p.Copy && strings.TrimSuffix(p.Name, "(r28)") == base {
				ids = append(ids, p.ID)
			}
		}
	}
	if len(ids) < 2 {
		return 0, 0, false
	}
	return ids[0], ids[1], true
}

func (w *World) endStats() {
	for k, ep := range w.episodes {
		res := "unresolved at the end, both active"
		a, b := w.party(k[0]), w.party(k[1])
		if ra, rb := a.st.peer(b.ID), b.st.peer(a.ID); ra != nil && rb != nil && (ra.Status != stActive || rb.Status != stActive) {
			res = "ended stale or suspended (visible)"
		}
		w.closeEpisode(ep, res)
	}
	// Q3: the ungated window per pair (upgrade mode)
	window := map[[2]PID][2]int64{} // start, end (0: not closed)
	keys := make([][2]PID, 0)
	for a, ua := range w.upAt {
		for b, ub := range w.upAt {
			if a >= b || w.party(a).Copy || w.party(b).Copy || w.party(a).st.peer(b) == nil {
				continue
			}
			k := pairKey(a, b)
			start := min(ua, ub)
			oa, okA := w.gateOpenAt[[2]PID{a, b}]
			ob, okB := w.gateOpenAt[[2]PID{b, a}]
			end := int64(0)
			if okA && okB {
				end = max(oa, ob)
				w.stat(fmt.Sprintf("W:window hours closed %05d", (end-start)/hour))
			} else {
				w.stat(fmt.Sprintf("W:window hours open at end %05d", (w.Now-start)/hour))
			}
			window[k] = [2]int64{start, end}
			keys = append(keys, k)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i][0] < keys[j][0] })
	if len(w.viol) == 0 {
		return
	}
	v := w.viol[0]
	inv := v.Inv
	a, b, ok := w.pairOf(v.Detail)
	if !ok {
		w.stat("V:" + inv + " | no pair named")
		return
	}
	// Q2: visible (stale or suspended: a feed item), audited only, or silent
	k := pairKey(a, b)
	ra, rb := w.party(a).st.peer(b), w.party(b).st.peer(a)
	vis := "silent"
	switch {
	case ra != nil && ra.Status != stActive || rb != nil && rb.Status != stActive:
		vis = "visible (stale or suspended)"
	case w.audits[k] > 0:
		vis = "audited only"
	}
	w.stat("V:" + inv + " | " + vis)
	// Q3: inside or after the pair's ungated window
	if len(w.upAt) == 0 {
		return
	}
	at := v.At
	if t, ok := w.suspAt[[2]PID{a, b}]; ok {
		at = t
	} else if t, ok := w.suspAt[[2]PID{b, a}]; ok {
		at = t
	} else if t, ok := w.firstSplit[k]; ok {
		at = t
	}
	win, ok := window[k]
	where := "no window (a side never upgraded)"
	switch {
	case !ok:
	case at < win[0]:
		where = "before the first upgrade"
	case win[1] == 0 || at <= win[1]:
		where = "inside the window"
	default:
		where = "after the window"
	}
	w.stat("WV:" + inv + " | " + where)
}
