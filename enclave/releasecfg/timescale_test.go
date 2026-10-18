package releasecfg

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// The staging time scale (VAULT-MESSAGING 0.43.0 §11.10.8, VAULT-RELEASES
// 0.1.32 §5.2, STAGING-TIME-SCALE §4, §5.6): production exactly 1 (a
// missing value or a placeholder refused), staging 1 or 24 with the quiet
// period tied to it, and the accessor 1 for every channel but staging
// whatever the file says.
func TestTimeScaleRules(t *testing.T) {
	prod := complete(t)
	c, err := Check(ChannelProd, []byte(prod))
	if err != nil || c.FileTimeScale != 1 || c.TimeScale() != 1 {
		t.Fatalf("production at 1: %v %+v", err, c)
	}
	for _, v := range []string{"0", "2", "24", "3600", "86400", "-1", "1.5", `"1"`, `"TODO-time-scale"`, "null"} {
		if _, err := Parse([]byte(strings.Replace(prod, `"time_scale":1`, `"time_scale":`+v, 1))); err == nil {
			t.Errorf("production time_scale %s accepted", v)
		}
		if _, err := Check(ChannelProd, []byte(strings.Replace(prod, `"time_scale":1`, `"time_scale":`+v, 1))); err == nil {
			t.Errorf("release gate: production time_scale %s accepted", v)
		}
	}
	if _, err := Parse([]byte(strings.Replace(prod, `,"time_scale":1`, ``, 1))); err == nil {
		t.Error("production without time_scale accepted")
	}

	st := staging(prod) // scale 1, quiet 72 h: a real-time staging run
	if c, err := Check(ChannelStaging, []byte(st)); err != nil || c.TimeScale() != 1 || c.RecoveryQuietSeconds != 259200 {
		t.Fatalf("staging at 1: %v", err)
	}
	st24 := strings.Replace(strings.Replace(st, `"time_scale":1`, `"time_scale":24`, 1), `"recovery_quiet_seconds":259200`, `"recovery_quiet_seconds":10800`, 1)
	c, err = Check(ChannelStaging, []byte(st24))
	if err != nil || c.FileTimeScale != 24 || c.TimeScale() != 24 || c.RecoveryQuietSeconds != 10800 {
		t.Fatalf("staging at 24: %v %+v", err, c)
	}
	refused := map[string]string{
		"staging scale 2":                strings.Replace(st, `"time_scale":1`, `"time_scale":2`, 1),
		"staging scale 12":               strings.Replace(st, `"time_scale":1`, `"time_scale":12`, 1),
		"staging scale 48":               strings.Replace(st, `"time_scale":1`, `"time_scale":48`, 1),
		"staging scale 3600":             strings.Replace(st, `"time_scale":1`, `"time_scale":3600`, 1),
		"staging scale 0":                strings.Replace(st, `"time_scale":1`, `"time_scale":0`, 1),
		"staging placeholder":            strings.Replace(st, `"time_scale":1`, `"time_scale":"TODO-x"`, 1),
		"staging missing":                strings.Replace(st, `,"time_scale":1`, ``, 1),
		"staging 24 with 72 h quiet":     strings.Replace(st, `"time_scale":1`, `"time_scale":24`, 1),
		"staging 24 with 10,801 s quiet": strings.Replace(st24, `"recovery_quiet_seconds":10800`, `"recovery_quiet_seconds":10801`, 1),
		"staging 1 with 3 h quiet":       strings.Replace(st, `"recovery_quiet_seconds":259200`, `"recovery_quiet_seconds":10800`, 1),
	}
	for name, s := range refused {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A production file can never carry staging's quiet period.
	if _, err := Parse([]byte(strings.Replace(prod, `"recovery_quiet_seconds":259200`, `"recovery_quiet_seconds":10800`, 1))); err == nil {
		t.Error("production quiet period of 3 h accepted")
	}
}

// The accessor decides by the measured channel, never by the file alone:
// a production Config holding 24 (as if the gate were bypassed) scales
// nothing, nor does no configuration, nor a staging Config holding a value
// staging's rule does not allow.
func TestTimeScaleAccessorIgnoresFileOutsideStaging(t *testing.T) {
	var none *Config
	cases := []struct {
		c    *Config
		want uint64
	}{
		{none, 1},
		{&Config{}, 1},
		{&Config{Channel: ChannelProd, FileTimeScale: 24}, 1},
		{&Config{Channel: ChannelProd, FileTimeScale: 86400}, 1},
		{&Config{Channel: "other", FileTimeScale: 24}, 1},
		{&Config{Channel: ChannelStaging, FileTimeScale: 0}, 1},
		{&Config{Channel: ChannelStaging, FileTimeScale: 1}, 1},
		{&Config{Channel: ChannelStaging, FileTimeScale: 3600}, 1},
		{&Config{Channel: ChannelStaging, FileTimeScale: 24}, 24},
	}
	for _, tc := range cases {
		if got := tc.c.TimeScale(); got != tc.want {
			t.Errorf("%+v: %d, want %d", tc.c, got, tc.want)
		}
	}
}

// The committed files: production says 1, staging 24 with a 3-hour quiet
// period, and staging's file passes the release gate.
func TestCommittedTimeScale(t *testing.T) {
	pb, err := os.ReadFile("prod.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(pb)
	if err != nil || f.Config.FileTimeScale != 1 || f.Config.TimeScale() != 1 || f.Config.RecoveryQuietSeconds != MinQuietSeconds {
		t.Fatalf("prod.json: %v", err)
	}
	if c, err := Check(ChannelProd, fillReleaseR(t, bytes.Replace(pb, []byte(`"release": 0`), []byte(`"release": 1`), 1))); err != nil || c.TimeScale() != 1 {
		t.Fatalf("prod.json filled: %v", err)
	}
	sb, err := os.ReadFile("staging.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := Check(ChannelStaging, sb)
	if err != nil || c.FileTimeScale != 24 || c.TimeScale() != 24 || c.RecoveryQuietSeconds != 10800 || c.RecoveryWaitUnitSeconds != 600 {
		t.Fatalf("staging.json: %v %+v", err, c)
	}
}
