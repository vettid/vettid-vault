package vaultproc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vettid/vettid-vault/vms/recovery"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/paircode"
)

// A synthetic vault: one unlock (Argon2id at the release's parameters,
// then its state), stats, nothing else.
func TestCapacityVault(t *testing.T) {
	if testing.Short() {
		t.Skip("Argon2id at 64 MiB")
	}
	if recovery.TestCost {
		t.Skip("a vettid_testcost build derives at test cost, not the release's parameters")
	}
	a, b := net.Pipe()
	var lists atomic.Int32
	sup := hostproto.NewConn(a, func(_ context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind == vaultipc.KindStatusList {
			lists.Add(1)
			return hostproto.Strings(hostproto.StatusNotFound)
		}
		return nil
	}, nil)
	defer sup.Close()
	vp := hostproto.NewConn(b, nil, nil)
	defer vp.Close()
	cv := &capacityVault{}
	call := func(op, arg string) [][]byte { return cv.handle(channel{c: vp}, vp.Done(), hostproto.Strings(op, arg)) }
	for _, bad := range [][2]string{{"unlock", "-1"}, {"unlock", "67108865"}, {"unlock", "x"}, {"open", "0"}} {
		if r := call(bad[0], bad[1]); string(r[0]) != hostproto.StatusInvalid {
			t.Fatalf("%v: %q", bad, r)
		}
	}
	if r := cv.handle(channel{c: vp}, vp.Done(), hostproto.Strings("stats")); string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("one field: %q", r)
	}
	r := call("unlock", "65536")
	var st selftest.CapacityStats
	if string(r[0]) != hostproto.StatusOK || json.Unmarshal(r[1], &st) != nil {
		t.Fatalf("unlock %q", r)
	}
	if st.KDFMicros <= 0 || st.PeakRSS < 64<<20 || len(cv.state) != 65536 {
		t.Fatalf("stats %+v state %d", st, len(cv.state))
	}
	if r := call("unlock", "0"); string(r[0]) != hostproto.StatusInvalid {
		t.Fatalf("second unlock: %q", r)
	}
	if r := call("stats", "0"); string(r[0]) != hostproto.StatusOK {
		t.Fatalf("stats %q", r)
	}
}

// The idle loop makes one channel round trip per period and ends with the
// channel.
func TestCapacityIdleLoop(t *testing.T) {
	a, b := net.Pipe()
	var lists atomic.Int32
	sup := hostproto.NewConn(a, func(_ context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind == vaultipc.KindStatusList {
			lists.Add(1)
		}
		return hostproto.Strings(hostproto.StatusNotFound)
	}, nil)
	vp := hostproto.NewConn(b, nil, nil)
	ended := make(chan struct{})
	go func() { idleLoop(channel{c: vp}, vp.Done(), make([]byte, 10000), 10*time.Millisecond); close(ended) }()
	deadline := time.Now().Add(5 * time.Second)
	for lists.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if lists.Load() < 2 {
		t.Fatal("no round trips")
	}
	sup.Close()
	vp.Close()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("idle loop did not end with the channel")
	}
}

// A real vault process does not answer the self-test's capacity requests.
func TestServeRefusesCapacity(t *testing.T) {
	a, b := net.Pipe()
	done := make(chan int, 1)
	go func() {
		done <- Serve(b, Platform{Config: func(string) enclave.Config { return enclave.Config{} }})
	}()
	sup := hostproto.NewConn(a, nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, k := range []hostproto.Kind{vaultipc.KindSelftestCapacity, vaultipc.KindSelftest} {
		if r, err := sup.Call(ctx, k, hostproto.Strings("unlock", "0")...); err != nil || string(r[0]) != hostproto.StatusInvalid {
			t.Fatalf("kind %x: %q %v", k, r, err)
		}
	}
	sup.Close()
	<-done
}

// A synthetic code request: x then the tag, each under its own code
// permit asked for over the channel ("acquire_code", then "release"), as a
// vault asks; "-" is no room at once; a permit held by another past the
// request's wait is busy.
func TestCapacityCode(t *testing.T) {
	if !paircode.TestCost {
		t.Skip("code derivations at 256 MiB: run with -tags vettid_testcost")
	}
	for _, c := range []struct {
		answer string // the permit's answer to acquire_code
		want   string
		grants int
	}{
		{"1", "done", 2},
		{"-", "no_room", 0},
		{"0", "busy", 0},
	} {
		t.Run(c.want, func(t *testing.T) {
			a, b := net.Pipe()
			var mu sync.Mutex
			var asked []string
			var acquired, released []time.Time
			sup := hostproto.NewConn(a, func(_ context.Context, f *hostproto.Frame) [][]byte {
				if f.Kind != vaultipc.KindHeavyPermit || len(f.Fields) != 1 {
					return hostproto.Strings(hostproto.StatusInvalid)
				}
				mu.Lock()
				asked = append(asked, string(f.Fields[0]))
				if string(f.Fields[0]) == vaultipc.HeavyRelease {
					released = append(released, time.Now())
				} else if c.answer == "1" {
					acquired = append(acquired, time.Now())
				}
				mu.Unlock()
				if string(f.Fields[0]) == vaultipc.HeavyRelease {
					return hostproto.Strings(hostproto.StatusOK, "1")
				}
				return hostproto.Strings(hostproto.StatusOK, c.answer)
			}, nil)
			defer sup.Close()
			vp := hostproto.NewConn(b, nil, nil)
			defer vp.Close()
			cv := &capacityVault{}
			start := time.Now()
			r := cv.handle(channel{c: vp}, vp.Done(), hostproto.Strings("code", "0"))
			var st selftest.CapacityStats
			if string(r[0]) != hostproto.StatusOK || json.Unmarshal(r[1], &st) != nil {
				t.Fatalf("code %q", r)
			}
			if st.Code != c.want || len(st.GrantedAtsMs) != c.grants {
				t.Fatalf("%+v", st)
			}
			mu.Lock()
			defer mu.Unlock()
			switch c.want {
			case "done":
				want := []string{vaultipc.HeavyAcquireCode, vaultipc.HeavyRelease, vaultipc.HeavyAcquireCode, vaultipc.HeavyRelease}
				if fmt.Sprint(asked) != fmt.Sprint(want) || st.XMicros <= 0 || st.TagMicros <= 0 {
					t.Fatalf("asked %v, %+v", asked, st)
				}
				// Each derivation ran while its permit was held: released only after it.
				for i, us := range []int64{st.XMicros, st.TagMicros} {
					if held := released[i].Sub(acquired[i]).Microseconds(); held < us {
						t.Fatalf("derivation %d: the permit was held %dus for a %dus derivation", i, held, us)
					}
				}
			case "no_room":
				if len(asked) != 1 || time.Since(start) > 2*time.Second {
					t.Fatalf("no room waited: asked %v in %v", asked, time.Since(start))
				}
			case "busy":
				if d := time.Since(start); d < vault.PairCodePermitWait || len(asked) < 2 {
					t.Fatalf("busy after %v, asked %d times", d, len(asked))
				}
			}
		})
	}
}
