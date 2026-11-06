//go:build !vettid_emu28

package vault

// emu28 reports whether this vault stands in for a release-28 peer in a
// test (the build tag vettid_emu28, test files only: emu28_on_test.go).
// In every other build it is the constant false, so the branches that
// read it compile away. A non-test build with the tag does not compile
// (the method then exists only in a _test.go file).
func (m *Manager) emu28() bool { return false }
