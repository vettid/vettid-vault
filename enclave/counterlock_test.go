package enclave

import (
	"os"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
)

// VAULT-MESSAGING 0.33.2 §11.14.4: the channel's counter lock period goes
// from the channel constants into the enclave configuration and from
// there into every vault's options (Core.vaultOptions), without the
// channel files' recovery keys.
func TestCounterLockReachesVaultOptions(t *testing.T) {
	for _, tc := range []struct {
		c    *releasecfg.Config
		want time.Duration
	}{
		{&releasecfg.Config{Channel: releasecfg.ChannelStaging}, 24 * time.Hour},
		{&releasecfg.Config{Channel: releasecfg.ChannelProd}, 100 * 365 * 24 * time.Hour},
		{nil, 0}, // no channel constants: the counter's own default (100 years)
	} {
		cfg := releaseConfigFor(tc.c, "i-1", DefaultRelayURL)
		if cfg.Recovery.CounterLock != tc.want {
			t.Fatalf("%+v: configuration counter lock %v, want %v", tc.c, cfg.Recovery.CounterLock, tc.want)
		}
		c := &Core{cfg: cfg, now: time.Now}
		if got := c.vaultOptions(nil).RecoveryCounterLock; got != tc.want {
			t.Fatalf("%+v: vault options counter lock %v, want %v", tc.c, got, tc.want)
		}
	}
}

// The committed staging file builds the enclave configuration a staging
// image runs with: the pinned recovery request key, the counter bucket,
// staging's counter lock period, (0.43.0) its 3-hour quiet period and time
// scale 24, and the minimum app version (101) reach
// Config.Recovery, the device policy and the vault options.
func TestCommittedStagingFileReachesTheConfig(t *testing.T) {
	b, err := os.ReadFile("releasecfg/staging.json")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := releasecfg.Check(releasecfg.ChannelStaging, b)
	if err != nil {
		t.Fatal(err)
	}
	cfg := releaseConfigFor(rc, "i-1", DefaultRelayURL)
	r := cfg.Recovery
	if len(r.RequestKeys) != 1 || r.RequestKeys[0].KeyID != "83d194b2-b474-429f-bed1-6eea4c80cede" || r.RequestKeys[0].Key == nil {
		t.Fatalf("request keys %+v", r.RequestKeys)
	}
	if r.Counter.Host() != "vettid-org-vault-recovery-347272280361.s3.us-east-1.amazonaws.com" || r.WaitUnit != 600*time.Second ||
		r.Quiet != 3*time.Hour || !r.Offered || r.CounterLock != 24*time.Hour || cfg.TimeScale != 24 {
		t.Fatalf("recovery config %+v", r)
	}
	if r.AndroidMinVersionCode != 101 || cfg.DeviceAttest == nil || cfg.DeviceAttest.AndroidMinVersionCode != 101 {
		t.Fatalf("minimum app version: recovery %d, device policy %+v", r.AndroidMinVersionCode, cfg.DeviceAttest)
	}
	c := &Core{cfg: cfg, now: time.Now}
	if o := c.vaultOptions(nil); o.RecoveryCounterLock != 24*time.Hour || o.RecoveryWaitUnit != 600*time.Second {
		t.Fatalf("vault options %v %v", o.RecoveryCounterLock, o.RecoveryWaitUnit)
	}
}

// Owner decision of 2026-10-16 (VAULT-MESSAGING 0.34.0 §11.10.9): the
// measured release constant recovery_offered goes into the enclave
// configuration, the vault options (a transfer bundle's capabilities) and
// the instance's descriptor (recovery_offered listed only when true).
func TestRecoveryOfferedReachesCapabilities(t *testing.T) {
	for _, offered := range []bool{true, false} {
		cfg := releaseConfigFor(&releasecfg.Config{Channel: releasecfg.ChannelStaging, RecoveryOffered: offered}, "i-1", DefaultRelayURL)
		if cfg.Recovery.Offered != offered {
			t.Fatalf("configuration offered %v, want %v", cfg.Recovery.Offered, offered)
		}
		c := &Core{cfg: cfg, now: time.Now}
		if got := c.vaultOptions(nil).RecoveryNotOffered; got == offered {
			t.Fatalf("vault options not offered %v with recovery_offered %v", got, offered)
		}
	}
	// The committed files: staging offers recovery.
	b, err := os.ReadFile("releasecfg/staging.json")
	if err != nil {
		t.Fatal(err)
	}
	rc, err := releasecfg.Check(releasecfg.ChannelStaging, b)
	if err != nil {
		t.Fatal(err)
	}
	if cfg := releaseConfigFor(rc, "i-1", DefaultRelayURL); !rc.RecoveryOffered || cfg.Recovery.Offered != rc.RecoveryOffered {
		t.Fatal("staging's recovery_offered lost on the way to the configuration")
	}
}
