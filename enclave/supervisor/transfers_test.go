package supervisor

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave/egress"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
)

// memModel is an instance's memory as the admission sees it: what idle
// vaults hold, plus each transfer's use, which grows to its peak while it
// runs (so an admitted transfer that has not reached its peak yet is
// still to be counted, §10.5.1).
type memModel struct {
	mu    sync.Mutex
	total uint64
	idle  uint64
	use   map[int]uint64
	min   uint64 // the lowest MemAvailable seen
}

func (m *memModel) avail() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	used := m.idle
	for _, u := range m.use {
		used += u
	}
	a := m.total - used
	if a < m.min {
		m.min = a
	}
	return a
}

func (m *memModel) set(id int, u uint64) {
	m.mu.Lock()
	if u == 0 {
		delete(m.use, id)
	} else {
		m.use[id] = u
	}
	m.mu.Unlock()
}

// MUST-COVERAGE (§10.5.1 "A test"): an instance with many unlocked idle
// vaults and as many 8 MiB transfers queued as the admission allows, plus
// more waiting, never reaches the memory-pressure threshold, and every
// queued transfer completes. The model's transfer peaks at 60 MiB (6 to
// 8 copies of 8 MiB plus headroom, under the 64 MiB budget), reached in
// steps after admission.
func TestTransferAdmissionKeepsReserve(t *testing.T) {
	const (
		mib     = uint64(1 << 20)
		vaults  = 60 // unlocked, idle
		perIdle = 40 * mib
		peak    = 60 * mib
	)
	m := &memModel{total: 4096 * mib, idle: vaults * perIdle, use: map[int]uint64{}}
	m.min = m.total
	reserve := m.total * 15 / 100 // MemoryReserve's default share
	a := newAdmission(m.avail, reserve)
	var done atomic.Int32
	var wg sync.WaitGroup
	var inflight atomic.Int32
	var maxIn atomic.Int32
	id := 0
	for v := 0; v < vaults; v++ {
		owner := &struct{ v int }{v}
		for k := 0; k < 2; k++ { // each vault's 2, half of them reuploads
			id++
			n := id
			prio := vault.PrioTransfer
			if k == 1 {
				prio = vault.PrioReupload
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				tk, err := a.admit(ctx, owner, strconv.Itoa(n), prio)
				if err != nil {
					t.Errorf("transfer %d never admitted", n)
					return
				}
				in := inflight.Add(1)
				for {
					old := maxIn.Load()
					if in <= old || maxIn.CompareAndSwap(old, in) {
						break
					}
				}
				for step := uint64(1); step <= 4; step++ { // the use grows to its peak
					m.set(n, peak*step/4)
					time.Sleep(2 * time.Millisecond)
				}
				m.set(n, 0)
				inflight.Add(-1)
				a.release(owner, tk.id)
				done.Add(1)
			}()
		}
	}
	wg.Wait()
	if int(done.Load()) != 2*vaults {
		t.Fatalf("%d of %d transfers completed", done.Load(), 2*vaults)
	}
	if m.min < reserve {
		t.Fatalf("available memory fell to %d MiB, below the reserve of %d MiB", m.min/mib, reserve/mib)
	}
	if maxIn.Load() > MaxTransfers {
		t.Fatalf("%d transfers at once; at most %d until measured", maxIn.Load(), MaxTransfers)
	}
	if in, w := a.counts(); in != 0 || w != 0 {
		t.Fatalf("left: %d in flight, %d waiting", in, w)
	}
}

// Short of memory, nothing is admitted (an owner's fetch is then answered
// busy by its vault); admission resumes when memory comes back. Owner
// fetches go before every other transfer, and a vault never has more than
// its 2.
func TestTransferAdmissionOrder(t *testing.T) {
	var avail atomic.Uint64
	avail.Store(100 << 20)
	a := newAdmission(func() uint64 { return avail.Load() }, 50<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := a.admit(ctx, "v1", "x", vault.PrioOwnerFetch); err == nil {
		t.Fatal("admitted below one budget above the reserve")
	}
	avail.Store(4 << 30)
	order := make(chan string, 8)
	hold := func(owner, id string, prio int) *admitTicket {
		tk, err := a.admit(context.Background(), owner, id, prio)
		if err != nil {
			t.Fatal(err)
		}
		return tk
	}
	t1, t2 := hold("v1", "a", vault.PrioTransfer), hold("v1", "b", vault.PrioTransfer)
	// v1's third waits for its own slot whatever the memory.
	ctx3, cancel3 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel3()
	if _, err := a.admit(ctx3, "v1", "c", vault.PrioOwnerFetch); err == nil {
		t.Fatal("a vault got a third transfer")
	}
	t3, t4 := hold("v2", "a", vault.PrioTransfer), hold("v2", "b", vault.PrioTransfer)
	// The instance is full (4): a reupload and an owner's fetch wait; the
	// fetch goes first.
	go func() { _, _ = a.admit(context.Background(), "v3", "r", vault.PrioReupload); order <- "reupload" }()
	time.Sleep(20 * time.Millisecond)
	go func() { _, _ = a.admit(context.Background(), "v4", "f", vault.PrioOwnerFetch); order <- "fetch" }()
	time.Sleep(20 * time.Millisecond)
	a.release("v1", t1.id)
	if got := <-order; got != "fetch" {
		t.Fatalf("%s admitted before the owner's fetch", got)
	}
	a.release("v1", t2.id)
	if got := <-order; got != "reupload" {
		t.Fatal(got)
	}
	_ = t3
	_ = t4
	a.releaseAll("v2")
	if in, _ := a.counts(); in != 2 {
		t.Fatalf("%d in flight after a process ended", in)
	}
}

// The channel request: a vault process's Transfer is admitted, answered
// busy after its wait, and ended by TransferDone or by its exit.
func TestTransferThroughChannel(t *testing.T) {
	s := &Supervisor{xfers: newAdmission(func() uint64 { return 4 << 30 }, 0)}
	h := &procHost{s: s, procs: map[string]*vproc{}}
	p := &vproc{h: h, vaultID: "aaaa"}
	call := func(ticket, prio, ms string) string {
		r := p.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindTransfer, ID: 1, Fields: hostproto.Strings(ticket, prio, ms)})
		return string(r[0])
	}
	if call("a", "1", "1000") != "ok" || call("b", "0", "1000") != "ok" {
		t.Fatal("not admitted")
	}
	if got := call("c", "0", "50"); got != vaultipc.StatusBusy {
		t.Fatalf("third transfer of one process: %s", got)
	}
	for _, bad := range [][]string{{"A", "1", "10"}, {"a", "3", "10"}, {"a", "1", "-1"}, {"", "1", "10"}} {
		if got := call(bad[0], bad[1], bad[2]); got != "denied" {
			t.Errorf("%v: %s", bad, got)
		}
	}
	p.notify(&hostproto.Frame{Kind: vaultipc.KindTransferDone, Fields: hostproto.Strings("a")})
	if call("d", "1", "1000") != "ok" {
		t.Fatal("not admitted after TransferDone")
	}
	s.xfers.releaseAll(p) // as procHost.exited does
	if in, _ := s.xfers.counts(); in != 0 {
		t.Fatalf("%d transfers left after the process ended", in)
	}
}

// A vault process is not trusted with its transfers (§10.5.1): an
// admitted transfer it never ends is reclaimed after the lease; an end that
// arrives before its request (a lost or reordered TransferDone) refuses
// that request; it has at most 2 requests waiting; its declared owner-fetch
// priority is honoured for one transfer at a time; unknown memory admits
// nothing.
func TestTransferAdmissionUntrusted(t *testing.T) {
	var clock atomic.Int64
	clock.Store(time.Now().UnixNano())
	now := func() time.Time { return time.Unix(0, clock.Load()) }
	a := newAdmission(func() uint64 { return 4 << 30 }, 0)
	a.now = now
	bg := context.Background()
	short := func() context.Context {
		ctx, cancel := context.WithTimeout(bg, 100*time.Millisecond)
		t.Cleanup(cancel)
		return ctx
	}
	// A process holding two tickets and never ending them: reclaimed.
	if _, err := a.admit(bg, "greedy", "1", vault.PrioTransfer); err != nil {
		t.Fatal(err)
	}
	if _, err := a.admit(bg, "greedy", "2", vault.PrioTransfer); err != nil {
		t.Fatal(err)
	}
	if a.held("greedy") != 2 {
		t.Fatal("holds")
	}
	if _, err := a.admit(short(), "greedy", "3", vault.PrioTransfer); err == nil {
		t.Fatal("a third transfer")
	}
	clock.Add(int64(transferLease))
	if a.held("greedy") != 0 {
		t.Fatal("tickets kept past the lease")
	}
	if _, err := a.admit(short(), "greedy", "4", vault.PrioTransfer); err != nil {
		t.Fatal("not admitted after the lease")
	}
	a.releaseAll("greedy")

	// TransferDone before Transfer: the request is refused, not admitted
	// for ever.
	a.release("late", "x")
	if _, err := a.admit(short(), "late", "x", vault.PrioTransfer); err == nil {
		t.Fatal("a request ended before it came was admitted")
	}
	if in, _ := a.counts(); in != 0 {
		t.Fatalf("%d in flight", in)
	}
	if _, err := a.admit(short(), "late", "y", vault.PrioTransfer); err != nil {
		t.Fatal("another request of the process")
	}
	a.releaseAll("late")

	// At most 2 waiting per process.
	full := newAdmission(func() uint64 { return 4 << 30 }, 0)
	full.max = 0
	for i, want := range []bool{true, true, false} {
		ctx, cancel := context.WithTimeout(bg, 300*time.Millisecond)
		started := time.Now()
		_, err := full.admit(ctx, "w", strconv.Itoa(i), vault.PrioTransfer)
		cancel()
		_ = err
		waited := time.Since(started) > 200*time.Millisecond
		if waited != want {
			t.Fatalf("request %d waited %v", i, waited)
		}
		if i < 2 {
			// keep it waiting: start it again in the background
			go func() { _, _ = full.admit(context.Background(), "w", "bg"+strconv.Itoa(i), vault.PrioTransfer) }()
			time.Sleep(20 * time.Millisecond)
		}
	}
	full.releaseAll("w")

	// The owner fetch's priority is honoured once at a time per process.
	b := newAdmission(func() uint64 { return 4 << 30 }, 0)
	b.mu.Lock()
	b.max = 0 // queue everything
	b.mu.Unlock()
	go func() { _, _ = b.admit(bg, "p", "f1", vault.PrioOwnerFetch) }()
	go func() { _, _ = b.admit(bg, "q", "t1", vault.PrioTransfer) }()
	time.Sleep(30 * time.Millisecond)
	go func() { _, _ = b.admit(bg, "p", "f2", vault.PrioOwnerFetch) }()
	time.Sleep(30 * time.Millisecond)
	b.mu.Lock()
	prios := map[string]int{}
	for _, w := range b.waiters {
		prios[w.t.id] = w.prio
	}
	b.mu.Unlock()
	if prios["f1"] != vault.PrioOwnerFetch || prios["f2"] != vault.PrioTransfer {
		t.Fatalf("priorities %v", prios)
	}
	b.releaseAll("p")
	b.releaseAll("q")

	// Unknown memory: nothing is admitted.
	z := newAdmission(func() uint64 { return 0 }, 0)
	if _, err := z.admit(short(), "v", "1", vault.PrioOwnerFetch); err == nil {
		t.Fatal("admitted with unknown memory")
	}
}

// The relay proxy carries blob bodies (downloads, uploads over 1 MiB) only
// within a process's admitted transfers, one body per transfer at a time,
// and only on plain clean paths: escaped or uncleaned forms of a blob path
// are refused whatever the process holds.
func TestBlobBodiesNeedAdmission(t *testing.T) {
	var seen []string
	rt := rtFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.URL.EscapedPath())
		return &http.Response{StatusCode: 200, Header: http.Header{}, Body: http.NoBody, Request: r}, nil
	})
	s := &Supervisor{xfers: newAdmission(func() uint64 { return 4 << 30 }, 0), relays: map[string]bool{"relay.example": true},
		relayHTTP: &http.Client{Transport: rt}, activity: map[string]time.Time{}}
	p := &vproc{h: &procHost{s: s}, vaultID: "aaaa"}
	call := func(method, path string, body []byte) string {
		r := p.handle(context.Background(), &hostproto.Frame{Kind: vaultipc.KindHTTP, ID: 1,
			Fields: [][]byte{[]byte(method), []byte("https://relay.example" + path), vaultipc.EncodeHeaders(http.Header{}), body}})
		return string(r[0])
	}
	const id = "/v1/blob/01JB2Z6V9K3M4N5P6Q7R8S9T60"
	big := make([]byte, blobBodyThreshold+1)
	if call("GET", id, nil) != "denied" || call("PUT", "/v1/blob/mbx", big) != "denied" {
		t.Fatal("a blob body without an admitted transfer")
	}
	for _, c := range [][2]string{{"PUT", "/v1/blob/mbx"}, {"DELETE", id}, {"POST", "/v1/blobs"}, {"GET", "/v1/mailbox"}} {
		if got := call(c[0], c[1], []byte("x")); got != "ok" {
			t.Errorf("%s %s: %s", c[0], c[1], got)
		}
	}
	if _, err := s.xfers.admit(context.Background(), p, "t", vault.PrioTransfer); err != nil {
		t.Fatal(err)
	}
	if call("GET", id, nil) != "ok" || call("PUT", "/v1/blob/mbx", big) != "ok" {
		t.Fatal("refused with an admitted transfer")
	}
	// One body per admitted transfer at a time.
	end, ok := p.blobBody("GET", id, 0)
	if !ok {
		t.Fatal("first body")
	}
	if _, ok := p.blobBody("GET", id, 0); ok {
		t.Fatal("two bodies on one transfer")
	}
	end()
	// Escaped and uncleaned forms, with a transfer held.
	for _, bad := range []string{"/v1/%62lob/01JB2Z6V9K3M4N5P6Q7R8S9T60", "/v1//blob/01JB2Z6V9K3M4N5P6Q7R8S9T60",
		"/v1/./blob/01JB2Z6V9K3M4N5P6Q7R8S9T60", "/v1/blob/../blob/01JB2Z6V9K3M4N5P6Q7R8S9T60", "/v1/mailbox/", "/v1/%2e%2e/x"} {
		n := len(seen)
		if got := call("GET", bad, nil); got != "denied" || len(seen) != n {
			t.Errorf("%s: %s", bad, got)
		}
	}
}

// The relay proxy's client never follows a redirect (a redirect to a
// blob route would otherwise skip the proxy's checks).
func TestEgressClientNoRedirects(t *testing.T) {
	c := (&egress.Transport{}).Client(time.Second)
	if c.CheckRedirect == nil || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Fatal("the egress client follows redirects")
	}
}
