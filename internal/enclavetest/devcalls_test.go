package enclavetest_test

import (
	"testing"

	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// The development path to the calling service's issuer stand-in: -calls-url reaches the vault process's
// configuration and the supervisor's, its host is allowlisted for egress, and anything but https://host is refused.
func TestDevCallsURL(t *testing.T) {
	const url = "https://calls.vettid.test"
	p, err := enclavetest.DevVaultPlatform(append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), enclavetest.DevVaultCallsArgs(url)...))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Config("v1").CallsURL; got != url {
		t.Fatalf("vault process: %q", got)
	}
	if enclavetest.DevVaultCallsArgs("") != nil {
		t.Fatal("args for no stand-in")
	}
	cfg, err := enclavetest.DevSupervisor(enclavetest.DevOptions{Release: 3, RelayURL: "https://relay.vettid.test", CallsURL: url,
		Egress: "127.0.0.1:1", Control: "127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Enclave("v1").CallsURL != url || !cfg.Egress.Allowed("calls.vettid.test") {
		t.Fatalf("supervisor: %q, allowed %v", cfg.Enclave("v1").CallsURL, cfg.Egress.Allowed("calls.vettid.test"))
	}
	none, err := enclavetest.DevSupervisor(enclavetest.DevOptions{Release: 3, RelayURL: "https://relay.vettid.test", Egress: "127.0.0.1:1", Control: "127.0.0.1:1"})
	if err != nil || none.Egress.Allowed("calls.vettid.test") || none.Enclave("v1").CallsURL != "" {
		t.Fatal("a calls host without a stand-in")
	}
	for _, bad := range []string{"http://calls.vettid.test", "https://calls.vettid.test:8443", "https://calls.vettid.test/x", "calls.vettid.test"} {
		if _, err := enclavetest.DevSupervisor(enclavetest.DevOptions{Release: 3, RelayURL: "https://relay.vettid.test", CallsURL: bad,
			Egress: "127.0.0.1:1", Control: "127.0.0.1:1"}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
