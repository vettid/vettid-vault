package trustmodel

import (
	"fmt"
	"sort"
)

// Ground truth for the visibility of splits (§3.4.1 I7): which pairs
// split, and stats.

func pairKey(a, b PID) [2]PID { return [2]PID{min(a, b), max(a, b)} }

// monitor: after each action, note the pairs whose epochs split while
// both sides are active.
func (w *World) monitor() {
	ps := w.real()
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			a, b := ps[i], ps[j]
			ra, rb := a.st.peer(b.ID), b.st.peer(a.ID)
			if ra == nil || rb == nil || ra.Status != stActive || rb.Status != stActive {
				continue
			}
			if !consistent(ra, rb, a.respHalf(), b.respHalf()) {
				w.everSplit[pairKey(a.ID, b.ID)] = true
			}
		}
	}
}

// rcStats: the most reconnects started toward one peer in the run.
func (w *World) rcStats() {
	most := 0
	for _, p := range w.real() {
		for _, r := range p.st.Peers {
			most = max(most, r.RCs)
		}
	}
	w.stat(fmt.Sprintf("X:max reconnects per pair %03d", most))
}

// visible: the pair's end is visible to a member (§3.4.1 I7): a side is
// suspended, stale or conflicted, or a feed item about the pair was made.
// A History line or an audit entry alone is not visible.
func (w *World) visible(a, b PID) bool {
	for _, x := range [][2]PID{{a, b}, {b, a}} {
		if r := w.party(x[0]).st.peer(x[1]); r != nil && (r.Status != stActive || r.Warned) {
			return true
		}
	}
	return len(w.feed[pairKey(a, b)]) > 0
}

// checkI7: R29 I7, visible ends. Every pair whose epochs split, and every
// pair the old-copy actor touched (read: an epoch made with the copy
// became current at the honest side, which then used it), ends suspended,
// stale, or with a feed item, or is a residual of §3.4.1 (each exemption
// is counted with its reason).
func (w *World) checkI7() {
	ps := w.real()
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			a, b := ps[i], ps[j]
			ra, rb := a.st.peer(b.ID), b.st.peer(a.ID)
			k := pairKey(a.ID, b.ID)
			if ra == nil || rb == nil || !w.everSplit[k] {
				continue
			}
			if w.visible(a.ID, b.ID) {
				w.stat("I7: split ended visibly")
				continue
			}
			if ra.Status == stActive && rb.Status == stActive && ra.Cur != 0 && ra.Cur == rb.Cur {
				w.stat("I7: split healed")
				continue
			}
			switch res := w.residualOf(a.ID, b.ID); {
			case a.OldApp || b.OldApp:
				w.violate("D4", "%s: an app from before release 29 split from its vault with no device.update_needed notice", pairName(w, a.ID, b.ID))
			case res != "":
				w.exempt("I7", res)
			case w.dead[a.ID] != "" || w.dead[b.ID] != "":
				w.exempt("I7", resLiveMailbox)
			default:
				w.violate("I7", "%s: epochs split (E%d vs E%d) and the pair ends with nothing visible", pairName(w, a.ID, b.ID), ra.Cur, rb.Cur)
			}
		}
	}
	keys := make([][2]int, 0, len(w.copyExpo))
	for k := range w.copyExpo {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i][0] < keys[j][0] || (keys[i][0] == keys[j][0] && keys[i][1] < keys[j][1])
	})
	for _, k := range keys {
		q, e := w.party(PID(k[0])), k[1]
		var copyP *Party
		init := false
		for n, a := range w.epTruth[e] {
			if c := w.party(a); c.Copy {
				copyP, init = c, n == 0
			}
		}
		if copyP == nil || q.Copy {
			continue
		}
		if !w.copyCur[[2]int{int(q.ID), e}] {
			w.stat("I7: copy epoch never current (abandoned while pending; nothing sent but hs.fin)")
			continue
		}
		r := q.st.peer(copyP.Origin)
		if r == nil {
			continue
		}
		switch {
		case w.visible(q.ID, copyP.Origin):
			w.stat("I7: copy epoch, the pair ends visibly")
		case !w.copyEpochAfterR(q, r, e):
			w.exempt("I7", resBeforeRotation)
		case init && !w.copyFlag[[2]int{int(q.ID), e}]:
			w.exempt("I7", resCopyInit)
		default:
			w.violate("I7", "%s used E%d, made with old copy %s, after %s's rotation, and nothing is visible",
				q.Name, e, copyP.Name, w.party(copyP.Origin).Name)
		}
	}
}
