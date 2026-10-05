package enclavetest_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// The dev recovery clock follows the file: real time plus its duration,
// zero when the file is missing or malformed.
func TestDevRecoveryClock(t *testing.T) {
	f := filepath.Join(t.TempDir(), "recovery-clock")
	clock := enclavetest.DevRecoveryClock(f)
	near := func(off time.Duration) bool {
		d := clock().Sub(time.Now().Add(off))
		return d > -time.Minute && d < time.Minute
	}
	if !near(0) {
		t.Fatal("missing file")
	}
	for _, c := range []struct {
		content string
		off     time.Duration
	}{{"24h\n", 24 * time.Hour}, {"48h0m0s", 48 * time.Hour}, {"junk", 0}, {"-5h", 0}, {string(make([]byte, 100)), 0}} {
		if err := os.WriteFile(f, []byte(c.content), 0o600); err != nil {
			t.Fatal(err)
		}
		if !near(c.off) {
			t.Errorf("%q: %v", c.content, time.Until(clock()))
		}
	}
	if got := enclavetest.DevVaultRecoveryClockArgs(""); got != nil {
		t.Fatal(got)
	}
	p, err := enclavetest.DevVaultPlatform(append(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"), enclavetest.DevVaultRecoveryClockArgs(f)...))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte("24h"), 0o600); err != nil {
		t.Fatal(err)
	}
	if c := p.Config("i-1"); c.RecoveryNow == nil || time.Until(c.RecoveryNow()) < 23*time.Hour {
		t.Fatal("vault process recovery clock")
	}
	p, _ = enclavetest.DevVaultPlatform(enclavetest.DevVaultArgs(3, "https://relay.vettid.test"))
	if p.Config("i-1").RecoveryNow != nil {
		t.Fatal("recovery clock without the argument")
	}
}
