//go:build vettid_channel_prod

package releasecfg

import (
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
)

// TestProductionImageRecoveryRules is the test on the production image
// that §11.14.14 and VAULT-RELEASES §5.2 require: the embedded wait unit
// is at least a day, the quiet period at least 72 hours, the counter is
// production's own bucket, and the recovery derivation cannot run at test
// cost (no test clock exists in the image: the counter's clock is S3's).
func TestProductionImageRecoveryRules(t *testing.T) {
	if channel != ChannelProd {
		t.Fatal("not the production channel")
	}
	f, err := Parse(embedded)
	if err != nil {
		t.Fatal(err)
	}
	c := f.Config
	if c.RecoveryWaitUnitSeconds < ProdMinWaitUnitSeconds || c.RecoveryQuietSeconds < MinQuietSeconds {
		t.Fatalf("production recovery times %d/%d", c.RecoveryWaitUnitSeconds, c.RecoveryQuietSeconds)
	}
	if c.RecoveryCounter.Account != c.SealAccount || !strings.HasSuffix(c.RecoveryCounter.Bucket, c.SealAccount) {
		t.Fatalf("production counter %+v", c.RecoveryCounter)
	}
	if c.CounterLock() != ProdCounterLock || ProdCounterLock != recovery.CounterLockYears*365*24*time.Hour {
		t.Fatalf("production counter lock %v", c.CounterLock())
	}
	if recovery.TestCost {
		t.Fatal("a production image built with vettid_testcost")
	}
}
