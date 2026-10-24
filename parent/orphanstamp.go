package parent

// The orphan clear (app_key_next_clear) removes only the entry that this
// parent's own live confirmation made. Two instances of a split brain can
// confirm the same key at the same header_seq; the winner's entry matches
// the loser's key and header_seq but carries the winner parent's stamp, so
// the loser's clear leaves it. The parent remembers the stamp of its last
// confirmation per (vault, kid, header_seq); a clear whose stamp it no
// longer knows (a restart) is skipped, never made unstamped.

const (
	// maxStampsPerVault and maxStampVaults bound the memory.
	maxStampsPerVault = 8
	maxStampVaults    = 4096
)

type nextStamp struct {
	kid string
	hs  uint64
	att int64
}

// noteStamp records the stamp of a live confirmation. A confirmation at a
// higher header_seq replaces the vault's entries of lower ones (the row
// holds one app_key_next, and a higher header_seq replaces a lower).
func (p *Parent) noteStamp(vaultID, kid string, hs uint64, att int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.stamps == nil {
		p.stamps = map[string][]nextStamp{}
	}
	if _, ok := p.stamps[vaultID]; !ok && len(p.stamps) >= maxStampVaults {
		for k := range p.stamps { // full: forget an arbitrary vault's
			delete(p.stamps, k)
			break
		}
	}
	var out []nextStamp
	for _, st := range p.stamps[vaultID] {
		if st.hs >= hs && !(st.kid == kid && st.hs == hs) {
			out = append(out, st)
		}
	}
	out = append(out, nextStamp{kid, hs, att})
	if len(out) > maxStampsPerVault {
		out = out[1:]
	}
	p.stamps[vaultID] = out
}

// stampFor is the stamp of the last confirmation of (vault, kid, hs).
func (p *Parent) stampFor(vaultID, kid string, hs uint64) (int64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, st := range p.stamps[vaultID] {
		if st.kid == kid && st.hs == hs {
			return st.att, true
		}
	}
	return 0, false
}

// dropStamp forgets an entry (att 0: whatever its stamp).
func (p *Parent) dropStamp(vaultID, kid string, hs uint64, att int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []nextStamp
	for _, st := range p.stamps[vaultID] {
		if st.kid == kid && st.hs == hs && (att == 0 || st.att == att) {
			continue
		}
		out = append(out, st)
	}
	if len(out) == 0 {
		delete(p.stamps, vaultID)
		return
	}
	p.stamps[vaultID] = out
}

// dropStampsFor forgets the stamps an event makes useless: an app_key
// event ends the replacements up to its header_seq.
func (p *Parent) dropStampsFor(ev Lifecycle) {
	if ev.Event != EventAppKey || len(ev.AppKey) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []nextStamp
	for _, st := range p.stamps[ev.VaultID] {
		if st.hs > ev.HeaderSeq {
			out = append(out, st) // a later replacement's
		}
	}
	if len(out) == 0 {
		delete(p.stamps, ev.VaultID)
		return
	}
	p.stamps[ev.VaultID] = out
}
