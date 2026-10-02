package store

import (
	"context"
	"errors"
	"sync"
	"testing"
)

func stores(t *testing.T) map[string]Store {
	d, err := NewDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d2, _ := NewDir(d.root) // a second handle on the same directory
	return map[string]Store{"memory": NewMemory(), "dir": d, "dir2": d2}
}

func TestConditionalWrites(t *testing.T) {
	ctx := context.Background()
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			k := StateKey("v1-" + name)
			if _, _, err := s.Get(ctx, k); !errors.Is(err, ErrNotFound) {
				t.Fatal("get missing")
			}
			v1, err := s.Put(ctx, k, []byte("one"), "")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Put(ctx, k, []byte("x"), ""); !errors.Is(err, ErrConflict) {
				t.Fatal("create-only overwrote")
			}
			v2, err := s.Put(ctx, k, []byte("two"), v1)
			if err != nil || v2 == v1 {
				t.Fatal("conditional put")
			}
			// A stale writer (still holding v1) is refused: the split-brain guard.
			if _, err := s.Put(ctx, k, []byte("stale"), v1); !errors.Is(err, ErrConflict) {
				t.Fatal("stale write accepted")
			}
			b, v, err := s.Get(ctx, k)
			if err != nil || string(b) != "two" || v != v2 {
				t.Fatal("get")
			}
			if err := s.Delete(ctx, k, v1); !errors.Is(err, ErrConflict) {
				t.Fatal("stale delete")
			}
			if err := s.Delete(ctx, k, v2); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// Exactly one of many racing writers holding the same version wins.
func TestRacingWriters(t *testing.T) {
	ctx := context.Background()
	for name, s := range stores(t) {
		k := StateKey("race-" + name)
		v0, _ := s.Put(ctx, k, []byte("0"), "")
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := s.Put(ctx, k, []byte("w"), v0); err == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%s: %d winners", name, wins)
		}
	}
}

func TestValidKey(t *testing.T) {
	for _, k := range []string{"vaults/abc/state", "a", "a-b_c.d/e"} {
		if !ValidKey(k) {
			t.Errorf("%q rejected", k)
		}
	}
	for _, k := range []string{"", "/a", "a/", "a//b", "../a", "a/../b", "A", "a b", "a\\b"} {
		if ValidKey(k) {
			t.Errorf("%q accepted", k)
		}
	}
}
