package trustmodel

import "fmt"

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
