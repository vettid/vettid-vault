//go:build vettid_emu28

package vault

import (
	"sync"
	"testing"
)

// The release-28 stand-in (tests only, -tags vettid_emu28): a vault marked
// here behaves as release 28 toward its connections in the respects
// 0.86.0 changed.
var emu28Marked sync.Map // *Manager -> bool

func (m *Manager) emu28() bool {
	v, ok := emu28Marked.Load(m)
	return ok && v.(bool)
}

// setEmu28 marks m as a release-28 stand-in.
func setEmu28(_ testing.TB, m *Manager) { emu28Marked.Store(m, true) }
