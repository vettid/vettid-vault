package trustmodel

import (
	"fmt"
	"slices"
	"sort"
	"strings"
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
			k := pairKey(a.ID, b.ID)
			split := !consistent(ra, rb, a.respHalf(), b.respHalf())
			if split {
				w.everSplit[k] = true
				if !w.splitNow[k] {
					w.splitAt[k] = w.Now
				}
			}
			w.splitNow[k] = split
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

// abandonedResidualAll: epoch e, which Q began and abandoned while pending
// (not by a link), is within the residual "A copy using an epoch Q
// abandoned while pending, outside R29-K9" for every link of the original
// made after copy c was taken that Q followed: R29-K9 never judged it.
func (w *World) abandonedResidualAll(q *Party, r *PeerRec, e int, c *Party) bool {
	for _, f := range w.ikPos[[2]PID{q.ID, r.ID}] {
		if by := w.iklinkBy[f.L]; !r.followed(f.L) || by.By != r.ID || by.Write <= c.SnapW {
			continue
		}
		if slices.Contains(r.IdRotLinks, f.L) && !slices.Contains(r.K9Spared, k9Spared{e, f.L}) {
			return false
		}
		if ep := r.epoch(e); ep != nil && ep.Ended {
			return false
		}
	}
	return true
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
			switch {
			case w.dead(a.ID, b.ID) && w.deadAt[k] <= w.splitAt[k]:
				// only a split that began once the copy took a message
				// meant for the pair (or the mailbox)
				w.exempt("I7", w.deadRes[k])
			case w.fDue[k]:
				w.exempt("I7", resDeviceF)
			case w.residualOf(a.ID, b.ID) == resOldApp:
				w.violate("I7", "%s: an app from before release 29, epochs split (E%d vs E%d), and no device.update_needed was shown", pairName(w, a.ID, b.ID), ra.Cur, rb.Cur)
			default:
				w.violate("I7", "%s: epochs split (E%d vs E%d) and the pair ends with nothing visible", pairName(w, a.ID, b.ID), ra.Cur, rb.Cur)
			}
		}
	}
	// an app from before release 29 whose pair split or is down at
	// quiescence: the residual covers only the notice's wording, so the
	// member must have been shown device.update_needed (R29-D4)
	olds := make([][2]PID, 0, len(w.oldApp))
	for k := range w.oldApp {
		olds = append(olds, k)
	}
	sort.Slice(olds, func(i, j int) bool {
		return olds[i][0] < olds[j][0] || (olds[i][0] == olds[j][0] && olds[i][1] < olds[j][1])
	})
	for _, k := range olds {
		switch {
		case slices.Contains(w.feed[k], "device.update_needed"):
			w.exempt("I1", resOldApp) // the notice was shown; only its wording is the residual
		case w.visible(k[0], k[1]):
			w.stat("I7: old app, the pair ends visibly")
		default:
			w.violate("I7", "%s: an app from before release 29, the pair is down at quiescence (%s), and no device.update_needed was shown", pairName(w, k[0], k[1]), w.oldApp[k])
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
		r := q.st.peer(copyP.Origin)
		if !w.copyCur[[2]int{int(q.ID), e}] {
			// never current at Q: touched only if Q accepted the copy's
			// messages under it, abandoned while pending, after the rotation
			ab := w.copyAban[[2]int{int(q.ID), e}]
			switch {
			case ab == nil:
				w.stat("I7: copy epoch never current, nothing accepted under it after the rotation")
			case w.visible(q.ID, copyP.Origin):
				w.stat("I7: copy epoch abandoned while pending, used after the rotation, the pair ends visibly")
			case q.Device:
				w.exempt("I7", resDevice)
			case r != nil && !ab.byLink && w.abandonedResidualAll(q, r, e, copyP):
				w.exempt("I7", resAbandonedEarlier)
			default:
				w.violate("I7", "%s accepted %d message(s) under E%d, made with old copy %s and abandoned while pending, after %s's rotation, and nothing is visible",
					q.Name, ab.n, e, copyP.Name, w.party(copyP.Origin).Name)
			}
			continue
		}
		if r == nil {
			continue
		}
		switch {
		case w.visible(q.ID, copyP.Origin):
			w.stat("I7: copy epoch, the pair ends visibly")
		case q.Device:
			w.exempt("I7", resDevice)
		case !w.copyEpochAfterR(q, r, e):
			w.exempt("I7", resBeforeRotation)
		case init && !w.copyFlag[[2]int{int(q.ID), e}] && w.copyFlagLate[[2]int{int(q.ID), e}]:
			// 0.88.2: its other messages, deposited before P's link, were
			// processed only after strict F1 or K4 had demoted the epoch
			w.exempt("I7", resCopyInitLate)
		case init && !w.copyFlag[[2]int{int(q.ID), e}]:
			w.exempt("I7", resCopyInit)
		default:
			w.violate("I7", "%s used E%d, made with old copy %s, after %s's rotation, and nothing is visible",
				q.Name, e, copyP.Name, w.party(copyP.Origin).Name)
		}
	}
}

// rapidRotations: (0.88.2, the rapid-rotation residual) the vault rotated
// its ik 3 or more times in quick succession: three consecutive
// rotations, each within 2 hours of the one before.
func (w *World) rapidRotations(p PID) bool {
	ts := w.rotTimes[p]
	for i := 2; i < len(ts); i++ {
		if ts[i]-ts[i-1] <= 2*hour && ts[i-1]-ts[i-2] <= 2*hour {
			return true
		}
	}
	return false
}

// resHonestStaleQuota: the known honest cause of a stale pair (M2): rapid
// rotations spend the reconnect token's 4 deposits and a reconnect hs.init
// is refused quota_exceeded (§3.4.1 "The reconnect bound").
const resHonestStaleQuota = "rapid rotations: an honest pair stale by quota_exceeded after 3 or more rotations of one side in quick succession (§3.4.1 Residuals, 0.88.2)"

// noteLocked: time d passed; real parties locked through it add to their
// stretch (M2).
func (w *World) noteLocked(d int64) {
	for _, p := range w.real() {
		if p.Locked {
			w.lockedFor[p.ID] += d
			w.maxLock = max(w.maxLock, w.lockedFor[p.ID])
		}
	}
}

// checkHonestStale: M2 (review of #207 at 90a0ff0), an honest pair must
// not end stale. In a run with no old copy, no injected loss and no party
// locked longer than T (14 days) at a stretch, a pair that ends stale is a
// violation; by quota_exceeded it is counted (resHonestStaleQuota) only when
// one side rotated 3 or more times in quick succession (rapidRotations).
func (w *World) checkHonestStale() {
	switch {
	case len(w.copies()) > 0:
		w.stat("M2: not checked (an old copy)")
		return
	case w.injLoss:
		w.stat("M2: not checked (an injected loss)")
		return
	case w.maxLock > 14*day:
		w.stat("M2: not checked (a party locked longer than T)")
		return
	}
	w.stat("M2: checked")
	ps := w.real()
	for i := range ps {
		for j := i + 1; j < len(ps); j++ {
			a, b := ps[i], ps[j]
			ra, rb := a.st.peer(b.ID), b.st.peer(a.ID)
			if ra == nil || rb == nil {
				continue
			}
			var refs []string
			for _, r := range []*PeerRec{ra, rb} {
				if r.Status == stStale {
					refs = append(refs, r.Ref)
				}
			}
			if len(refs) == 0 {
				continue
			}
			if slices.ContainsFunc(refs, func(s string) bool { return strings.Contains(s, "quota_exceeded") }) {
				if w.rapidRotations(a.ID) || w.rapidRotations(b.ID) {
					w.exempt("M2", resHonestStaleQuota) // 0.88.2: 3 or more rotations in quick succession
					continue
				}
				w.violate("M2", "%s: an honest pair ends stale by quota_exceeded without 3 rotations in quick succession (%s)", pairName(w, a.ID, b.ID), strings.Join(refs, "; "))
				continue
			}
			w.violate("M2", "%s: an honest pair ends stale (%s)", pairName(w, a.ID, b.ID), strings.Join(refs, "; "))
		}
	}
}
