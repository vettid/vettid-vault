package votewire_test

import (
	"errors"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/votetest"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// Bundles made by internal/votetest (the extension bundle, for which the
// staging test vote has no real one) verify, and each check fails where it
// should.
func TestSyntheticBundle(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	auth := votetest.NewAuthority(now)
	svc := votetest.NewService(auth)
	doc := []byte(`{"v":1}`)
	key := [][]byte{svc.Anchor.SPKI}
	b := auth.Bundle(doc, svc.Anchor, now)
	info, err := votewire.VerifyBundle(doc, b, key, auth.Roots, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if info.GenTime.Unix() != now.Unix() {
		t.Errorf("gen %v", info.GenTime)
	}
	cases := []struct {
		name string
		doc  []byte
		b    []byte
		keys [][]byte
		na   time.Time
		now  time.Time
		want error
	}{
		{"wrong key", doc, b, [][]byte{votetest.NewAnchorKey().SPKI}, now.Add(time.Minute), now, votewire.ErrAnchorKey},
		{"other document", []byte(`{"v":2}`), b, key, now.Add(time.Minute), now, votewire.ErrAnchor},
		{"late", doc, b, key, now.Add(-time.Second), now, votewire.ErrAnchorLate},
		{"t_int - t_tsa = 601 s", doc, auth.BundleStamped(doc, svc.Anchor, now, now.Add(-601*time.Second)), key, now.Add(time.Minute), now, votewire.ErrAnchor},
		{"t_int - t_tsa = 600 s", doc, auth.BundleStamped(doc, svc.Anchor, now, now.Add(-600*time.Second)), key, now.Add(time.Minute), now, nil},
		{"t_int - t_tsa = 0 s", doc, auth.BundleStamped(doc, svc.Anchor, now, now), key, now.Add(time.Minute), now, nil},
		{"t_int - t_tsa = -60 s", doc, auth.BundleStamped(doc, svc.Anchor, now, now.Add(60*time.Second)), key, now.Add(2 * time.Minute), now, nil},
		{"t_int - t_tsa = -61 s", doc, auth.BundleStamped(doc, svc.Anchor, now, now.Add(61*time.Second)), key, now.Add(2 * time.Minute), now, votewire.ErrAnchor},
		{"no limit (relay time unknown)", doc, auth.Bundle(doc, svc.Anchor, now), key, time.Time{}, now, nil},
		{"clock: stamp 301 s ahead", doc, b, key, now.Add(time.Hour), now.Add(-301 * time.Second), votewire.ErrBundleClock},
		{"clock: stamp 300 s ahead", doc, b, key, now.Add(time.Hour), now.Add(-300 * time.Second), nil},
		{"clock: t_int ahead, t_tsa not", doc, auth.BundleStamped(doc, svc.Anchor, now.Add(400*time.Second), now), key, now.Add(time.Hour), now.Add(99 * time.Second), votewire.ErrBundleClock},
		{"clock: t_int 300 s ahead", doc, auth.BundleStamped(doc, svc.Anchor, now.Add(400*time.Second), now), key, now.Add(time.Hour), now.Add(100 * time.Second), nil},
		// Certificate validity is judged at t_tsa and t_int, never at now.
		{"certificates expired by now", doc, b, key, now.Add(time.Hour), now.Add(100 * 24 * time.Hour), nil},
		{"another authority", doc, votetest.NewAuthority(now).Bundle(doc, svc.Anchor, now), key, now.Add(time.Minute), now, votewire.ErrBundleRoot},
	}
	for _, c := range cases {
		_, err := votewire.VerifyBundle(c.doc, c.b, c.keys, auth.Roots, c.na, c.now)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
