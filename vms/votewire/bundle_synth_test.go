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
		{"vault clock behind the stamp", doc, b, key, now.Add(time.Hour), now.Add(-time.Hour), votewire.ErrBundleClock},
		{"stamp long before the log entry", doc, auth.BundleStamped(doc, svc.Anchor, now, now.Add(-votewire.StampBeforeLog-time.Minute)), key, now.Add(time.Minute), now, votewire.ErrBundleRoot},
		{"stamp just before the log entry", doc, auth.BundleStamped(doc, svc.Anchor, now, now.Add(-time.Minute)), key, now.Add(time.Minute), now, nil},
		{"another authority", doc, votetest.NewAuthority(now).Bundle(doc, svc.Anchor, now), key, now.Add(time.Minute), now, votewire.ErrBundleRoot},
	}
	for _, c := range cases {
		_, err := votewire.VerifyBundle(c.doc, c.b, c.keys, auth.Roots, c.na, c.now)
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
	}
}
