package enclave_test

import (
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/enclavetest"
)

// The staging time scale in the enclave (VAULT-MESSAGING 0.43.0 §11.10.8,
// §11.10.9, STAGING-TIME-SCALE §4, §5.6): a release configuration takes
// the measured channel's scale (the staging file's value, 1 for any
// other channel whatever its file says), and an image without a channel
// tag runs at the configuration's scale.
func TestReleaseConfigTimeScale(t *testing.T) {
	cases := []struct {
		name string
		c    *releasecfg.Config
		want uint64
	}{
		{"no constants", nil, 0},
		{"production holding 24", &releasecfg.Config{Channel: releasecfg.ChannelProd, FileTimeScale: 24}, 1},
		{"production at 1", &releasecfg.Config{Channel: releasecfg.ChannelProd, FileTimeScale: 1}, 1},
		{"staging at 24", &releasecfg.Config{Channel: releasecfg.ChannelStaging, FileTimeScale: 24}, 24},
		{"staging at 1", &releasecfg.Config{Channel: releasecfg.ChannelStaging, FileTimeScale: 1}, 1},
		{"staging holding 3600", &releasecfg.Config{Channel: releasecfg.ChannelStaging, FileTimeScale: 3600}, 1},
	}
	for _, tc := range cases {
		cfg := enclave.ReleaseConfigFor(tc.c, "i-1", enclave.DefaultRelayURL)
		if cfg.TimeScale != tc.want {
			t.Errorf("%s: %d, want %d", tc.name, cfg.TimeScale, tc.want)
		}
		// Without a channel tag the instance runs at the configuration's
		// scale (1 for 0); a production build at 1 whatever it says; a
		// staging build at 1 or 24 (make channels runs both).
		want := max(tc.want, 1)
		if ch := enclave.ReleaseChannel(); ch == releasecfg.ChannelProd || ch == releasecfg.ChannelStaging && want != 24 {
			want = 1
		}
		if got := enclave.TimeScaleOf(cfg); got != want {
			t.Errorf("%s: instance scale %d, want %d", tc.name, got, want)
		}
	}
	switch enclave.ReleaseChannel() {
	case "":
		if enclave.TimeScaleOf(enclave.Config{TimeScale: 3600}) != 3600 || enclave.TimeScaleOf(enclave.Config{TimeScale: 1 << 40}) != releasecfg.MaxDevTimeScale {
			t.Fatal("development scale")
		}
	case releasecfg.ChannelProd:
		// STAGING-TIME-SCALE §4 item 2: a production image is at 1
		// whatever its configuration says.
		for _, n := range []uint64{0, 1, 24, 3600, 1 << 40} {
			if enclave.TimeScaleOf(enclave.Config{TimeScale: n}) != 1 {
				t.Fatalf("production image scales by %d", n)
			}
		}
	case releasecfg.ChannelStaging:
		if enclave.TimeScaleOf(enclave.Config{TimeScale: 24}) != 24 || enclave.TimeScaleOf(enclave.Config{TimeScale: 3600}) != 1 {
			t.Fatal("staging image scale")
		}
	}
}

// At scale 24 the descriptor says so, bound by the attestation, and the
// provisional window (S13) is 1 hour: a second enrollment is refused for
// the hour and accepted after it. At scale 1 the descriptor says 1. In a
// build for the production channel (make channels) the instance runs at
// 1 whatever its configuration says: the descriptor says 1 and the window
// is 24 hours for both (STAGING-TIME-SCALE §4 item 2).
func TestTimeScaleDescriptorAndEnrollWindow(t *testing.T) {
	for _, configured := range []uint64{1, 24} {
		scale := configured
		if enclave.ReleaseChannel() == releasecfg.ChannelProd {
			scale = 1
		}
		clk := &clock{t: time.Now().UTC().Truncate(time.Millisecond)}
		w := enclavetest.NewWorld(clk.Now, relayURL)
		w.AddRelease(r3)
		if _, err := w.StartWith(3, func(c *enclave.Config) { c.TimeScale = configured }); err != nil {
			t.Fatal(err)
		}
		f := &fx{t: t, clk: clk, w: w, ctx: t.Context(), trust: w.Trust()}
		a := f.newApp("user-1", android(0x61))
		e, _ := f.enclaveFor(a, "", true)
		if e.Descriptor.TimeScale != scale {
			t.Fatalf("scale %d: descriptor time_scale %d", scale, e.Descriptor.TimeScale)
		}
		if r := f.enroll(a, pin); !r.OK {
			t.Fatal(r)
		}
		b := f.newApp("user-1", android(0x62))
		clk.Add(59 * time.Minute)
		if r := f.enroll(b, pin); r.OK || r.Code != "vault_exists" {
			t.Fatalf("scale %d, after 59 minutes: %+v", scale, r)
		}
		clk.Add(2 * time.Minute)
		r := f.enroll(b, pin)
		if scale == 24 && !r.OK {
			t.Fatalf("scale 24, after 61 minutes: %+v", r)
		}
		if scale == 1 && (r.OK || r.Code != "vault_exists") {
			t.Fatalf("scale 1, after 61 minutes: %+v", r)
		}
		w.Close()
	}
}
