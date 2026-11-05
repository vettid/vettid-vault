package trustmodel

import (
	"regexp"
	"strings"
)

var partyName = regexp.MustCompile(`\bD?[PQR](\(r28\))?'?`)

// pairType: the releases of the first two distinct parties a violation's
// detail names, as they are when it is found (an old copy counts as its
// original's release). "29>28" means the first named runs 29 and the
// second 28: for a suspension the first is the suspender, for I1 the pair
// as listed, for I3/I4 the party that accepted or failed to suspend.
func (w *World) pairType(d string) string {
	var rel []string
	seen := map[string]bool{}
	for _, m := range partyName.FindAllString(d, -1) {
		base := strings.TrimSuffix(strings.TrimSuffix(m, "'"), "(r28)")
		if seen[base] {
			continue
		}
		seen[base] = true
		for _, p := range w.P {
			if p.Copy || strings.TrimSuffix(p.Name, "(r28)") != base {
				continue
			}
			if p.Rel28 {
				rel = append(rel, "28")
			} else {
				rel = append(rel, "29")
			}
		}
		if len(rel) == 2 {
			break
		}
	}
	switch len(rel) {
	case 0:
		return "none"
	case 1:
		return "one:" + rel[0]
	}
	if rel[0] == rel[1] {
		return rel[0] + "<>" + rel[1]
	}
	return rel[0] + ">" + rel[1]
}
