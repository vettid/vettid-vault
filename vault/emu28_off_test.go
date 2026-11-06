//go:build !vettid_emu28

package vault

import "testing"

// setEmu28 needs the release-28 stand-in, built only with -tags
// vettid_emu28: without it the test is skipped.
func setEmu28(t testing.TB, _ *Manager) {
	t.Skip("needs -tags vettid_emu28 (the release-28 stand-in)")
}
