package selftest

import "testing"

func TestUserNamespaceClosed(t *testing.T) {
	for s, want := range map[string]bool{
		UserNamespaceRefused:      true,
		UserNamespaceNotBuilt:     true,
		UserNamespaceCreated:      false,
		"operation not permitted": false,
		"":                        false,
	} {
		if got := UserNamespaceClosed(s); got != want {
			t.Errorf("UserNamespaceClosed(%q) = %v", s, got)
		}
	}
}
