package audit

import (
	"strings"
	"time"
)

// ConnEntry is what a connection may see of an audit entry about itself
// (the audit.recent action, §10.14): no ref, no other ids.
type ConnEntry struct {
	Kind      string
	At        time.Time
	Direction string
}

// ForConnection returns the newest entries whose connection_id is conn,
// at most limit, newest first, excluding drop.* entries.
func (f *Feature) ForConnection(conn string, limit int) []ConnEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []ConnEntry
	for i := len(f.st.Entries) - 1; i >= 0 && len(out) < limit; i-- {
		e := f.st.Entries[i]
		if conn == "" || e.ConnectionID != conn || strings.HasPrefix(e.Kind, "drop.") {
			continue
		}
		out = append(out, ConnEntry{Kind: e.Kind, At: e.At, Direction: e.Direction})
	}
	return out
}
