package main

import (
	"testing"
	"time"
)

func TestCapacityRequestFlags(t *testing.T) {
	c, err := capacityRequest(200, 1024, 0, "1, 2,4", 8, 150*time.Second, time.Minute, 90*time.Minute)
	if err != nil || c.MaxVaults != 200 || len(c.UnlockConcurrency) != 3 || c.UnlockConcurrency[1] != 2 || c.SettleSeconds != 150 ||
		c.IdleSeconds != 60 || c.BudgetMinutes != 90 {
		t.Fatalf("%v %+v", err, c)
	}
	for name, f := range map[string]func() error{
		"too many": func() error {
			_, err := capacityRequest(5000, 1024, 0, "1", 8, time.Minute, time.Minute, time.Hour)
			return err
		},
		"bad unlocks": func() error {
			_, err := capacityRequest(5, 1024, 0, "1,x", 8, time.Minute, time.Minute, time.Hour)
			return err
		},
		"level 16": func() error {
			_, err := capacityRequest(5, 1024, 0, "16", 8, time.Minute, time.Minute, time.Hour)
			return err
		},
		"no settle": func() error { _, err := capacityRequest(5, 1024, 0, "1", 8, 0, time.Minute, time.Hour); return err },
		"budget": func() error {
			_, err := capacityRequest(5, 1024, 0, "1", 8, time.Minute, time.Minute, 5*time.Hour)
			return err
		},
	} {
		if f() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
