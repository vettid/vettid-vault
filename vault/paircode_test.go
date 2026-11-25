package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/paircode"
)

// pcRelay is the fixture's relay with code claims (RELAY-PROTOCOL
// §6.9.1): it lists salts by the vault's clock and records each PUT and
// DELETE; putErrs answer the PUTs in order (then success).
type pcRelay struct {
	*stubRelay
	mu sync.Mutex
	// permitHeld, when set, says whether a derivation permit is held now:
	// a PUT made while one is held fails the test.
	permitHeld   func() bool
	putWhileHeld bool
	offers       bool
	clock        func() time.Time
	salts        func(now time.Time) []paircode.Salt
	saltErr      error
	putErrs      []error
	deleteErr    error // when set, every DeletePairCode fails (after it is recorded)
	puts         []pcPut
	deletes      []string
}

type pcPut struct {
	claimID, saltID string
	tag, salt, blob []byte
}

func (r *pcRelay) OffersPairCodes() bool { return r.offers }

func (r *pcRelay) PairCodeSalts(context.Context) ([]paircode.Salt, error) {
	if r.saltErr != nil {
		return nil, r.saltErr
	}
	return r.salts(r.clock()), nil
}

func (r *pcRelay) PutPairCode(_ context.Context, claimID, saltID string, tag, salt, blob []byte) (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.puts = append(r.puts, pcPut{claimID, saltID, bytes.Clone(tag), bytes.Clone(salt), bytes.Clone(blob)})
	if r.permitHeld != nil && r.permitHeld() {
		r.putWhileHeld = true
	}
	if n := len(r.puts) - 1; n < len(r.putErrs) && r.putErrs[n] != nil {
		return time.Time{}, r.putErrs[n]
	}
	return r.clock().Add(paircode.TTL), nil
}

func (r *pcRelay) DeletePairCode(_ context.Context, claimID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deletes = append(r.deletes, claimID)
	return r.deleteErr
}

const pcR = "https://relay.example.org"

func pcSalt(epoch int64, b byte) paircode.Salt {
	n := bytes.Repeat([]byte{b}, paircode.NonceSize)
	return paircode.Salt{SaltID: paircode.SaltID(paircode.SaltR(pcR, epoch, n)), Epoch: epoch, Nonce: n}
}

// currentSalts lists the clock's epoch, and the next one in its last 2
// minutes, as a relay does.
func currentSalts(now time.Time) []paircode.Salt {
	e := paircode.Epoch(now)
	l := []paircode.Salt{pcSalt(e, 0x51)}
	if now.Unix() >= (e+1)*paircode.Hour-120 {
		l = append(l, pcSalt(e+1, 0x52))
	}
	return l
}

// requirePairCodeTestCost skips a handler test in a build at the specified
// cost: every request derives Argon2id at 256 MiB, slow under -race. The
// derivations at that cost are vms/paircode's known-answer tests.
func requirePairCodeTestCost(t *testing.T) {
	t.Helper()
	if !paircode.TestCost {
		t.Skip("code pairing at 256 MiB: run with -tags vettid_testcost")
	}
}

func newPCFixture(t *testing.T) (*devFixture, *pcRelay) {
	t.Helper()
	requirePairCodeTestCost(t)
	d := newDevFixture(t)
	// The vault's clock mid-hour (ahead of the real one, never behind):
	// near an hour's edge the relay lists two salts, which would change
	// what a test sees (one PUT, or two).
	at := time.Unix((paircode.Epoch(d.m.now())+1)*paircode.Hour+30*60, 0)
	d.m.now = func() time.Time { return at }
	pr := &pcRelay{stubRelay: d.relay, offers: true, clock: d.m.now, salts: currentSalts}
	d.m.relay = pr
	return d, pr
}

type pcAnswer struct {
	PairingID string `json:"pairing_id"`
	Code      string `json:"code"`
	Exp       string `json:"exp"`
	R         string `json:"r"`
}

// create sends device.pair.create and returns the answer, or the error
// code.
func (d *devFixture) pcCreate(t *testing.T, body string) (pcAnswer, string) {
	t.Helper()
	r, _ := d.request(t, "device.pair.create", body)
	if r == nil {
		t.Fatal("no answer")
	}
	if r.Error != nil {
		return pcAnswer{}, r.Error.Code
	}
	var a pcAnswer
	if err := json.Unmarshal(r.Body, &a); err != nil {
		t.Fatal(err)
	}
	return a, ""
}

func (d *devFixture) outboxOps(op string) []string {
	var v []string
	for _, e := range d.m.st.Outbox {
		if e.Op == op {
			v = append(v, e.Value)
		}
	}
	return v
}

func TestPairCodeCreate(t *testing.T) {
	for _, role := range []string{KindAgent, KindDesktop} {
		t.Run(role, func(t *testing.T) {
			d, pr := newPCFixture(t)
			if role == KindAgent {
				d.m.addFeature(&namedFeature{name: featureLeash}) // an agent needs leash (§11.10.8)
			}
			now := d.m.now()
			a, code := d.pcCreate(t, `{"role":"`+role+`","form":"code"}`)
			if code != "" {
				t.Fatalf("error %s", code)
			}
			if !paircode.ValidCode([]byte(a.Code)) || a.R != pcR || a.PairingID == "" {
				t.Fatalf("answer: valid code %v, r %q", paircode.ValidCode([]byte(a.Code)), a.R)
			}
			exp, err := time.Parse(time.RFC3339, a.Exp)
			if err != nil || !exp.Equal(now.UTC().Truncate(time.Second).Add(600*time.Second)) {
				t.Fatalf("exp %s, created %s", a.Exp, now)
			}
			if len(pr.puts) != 1 {
				t.Fatalf("%d PUTs", len(pr.puts))
			}
			p := pr.puts[0]
			purpose := map[string]string{KindAgent: "a", KindDesktop: "d"}[role]
			salt := currentSalts(now)[0]
			salt.SR = paircode.SaltR(pcR, salt.Epoch, salt.Nonce)
			tag, _ := paircode.Tag(purpose, pcR, []byte(a.Code), salt.SR)
			if p.saltID != salt.SaltID || !bytes.Equal(p.tag, tag) || len(p.salt) != 16 || !paircode.ValidClaimID(p.claimID) {
				t.Fatal("the PUT's salt_id, tag, s_c or claim id")
			}
			// The blob opens with the code as the device computes it.
			x, _ := paircode.X(purpose, pcR, []byte(a.Code), p.salt)
			kw, _ := paircode.KW(x)
			bj, err := paircode.Open(kw, purpose, pcR, p.claimID, p.salt, p.blob)
			if err != nil {
				t.Fatal("the blob does not open")
			}
			b, err := invite.ParseBundle(bj)
			if err != nil || b.Kind != role || b.Remote || b.InviteID != a.PairingID || !b.Exp.Equal(exp) || b.HintName != "" || b.Token == "" {
				t.Fatalf("bundle %+v %v", b, err)
			}
			inv := d.m.st.Invites[a.PairingID]
			if inv == nil || !inv.Code || inv.ClaimID != p.claimID || inv.Kind != role || !inv.Exp.Equal(exp) || inv.OpenJTI == "" {
				t.Fatalf("invite %+v", inv)
			}
			// The code is never stored: not in the response cache (kept
			// for a retransmission) or anywhere else in the state.
			st, _ := json.Marshal(d.m.st)
			if bytes.Contains(st, []byte(a.Code)) {
				t.Fatal("the code is in the state")
			}
			cachedOne := false
			for _, c := range d.m.st.Responses {
				if bytes.Contains(c.Inner, []byte(a.PairingID)) {
					cachedOne = true
					if bytes.Contains(c.Inner, []byte(a.Code)) || bytes.Contains(c.Inner, []byte(`"code"`)) {
						t.Fatal("the code is in the response cache")
					}
				}
			}
			if !cachedOne {
				t.Fatal("no cached answer for a retransmission")
			}
		})
	}
}

func TestPairCodeForm(t *testing.T) {
	d, pr := newPCFixture(t)
	for _, body := range []string{`{"role":"desktop","form":"qr"}`, `{"role":"desktop","form":1}`, `{"role":"desktop","form":null}`, `{"role":"app","form":"code"}`} {
		if _, code := d.pcCreate(t, body); code != "bad_request" && !(strings.Contains(body, "app") && code == "one_app") {
			t.Errorf("%s: %q", body, code)
		}
	}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"link"}`); code != "" {
		t.Fatalf("link: %s", code)
	}
	if _, code := d.pcCreate(t, `{"role":"desktop"}`); code != "" {
		t.Fatalf("no form: %s", code)
	}
	if len(pr.puts) != 0 {
		t.Fatal("a link pairing made a code claim")
	}
}

func TestPairCodeClaimUnavailable(t *testing.T) {
	for name, set := range map[string]func(*pcRelay, *devFixture){
		"no pair_codes": func(pr *pcRelay, _ *devFixture) { pr.offers = false },
		"a relay without code claims": func(pr *pcRelay, d *devFixture) {
			d.m.relay = pr.stubRelay
		},
		"a relay a code cannot name": func(pr *pcRelay, _ *devFixture) { pr.stubRelay.base = "http://127.0.0.1:8080" },
	} {
		t.Run(name, func(t *testing.T) {
			d, pr := newPCFixture(t)
			permits := 0
			d.m.opt.CodePermit = func(context.Context) (func(), bool) { permits++; return func() {}, true }
			set(pr, d)
			if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" {
				t.Fatalf("%q", code)
			}
			if len(pr.puts) != 0 || permits != 0 {
				t.Fatalf("%d PUTs, %d permits", len(pr.puts), permits)
			}
		})
	}
}

// A refused salt list answers claim_unavailable with its reason in the
// audit log, before any derivation.
func TestPairCodeSaltsRefused(t *testing.T) {
	for _, c := range []struct {
		name, reason string
		salts        func(now time.Time) []paircode.Salt
	}{
		{"three entries", paircode.ReasonCount, func(now time.Time) []paircode.Salt {
			e := paircode.Epoch(now)
			return []paircode.Salt{pcSalt(e-1, 1), pcSalt(e, 2), pcSalt(e+1, 3)}
		}},
		{"a salt_id that does not recompute", paircode.ReasonSaltID, func(now time.Time) []paircode.Salt {
			s := pcSalt(paircode.Epoch(now), 1)
			s.SaltID = "00000000"
			return []paircode.Salt{s}
		}},
		{"an epoch outside its window", paircode.ReasonClock, func(now time.Time) []paircode.Salt {
			return []paircode.Salt{pcSalt(paircode.Epoch(now)+3, 1)}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d, pr := newPCFixture(t)
			permits := 0
			d.m.opt.CodePermit = func(context.Context) (func(), bool) { permits++; return func() {}, true }
			pr.salts = c.salts
			if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" {
				t.Fatalf("%q", code)
			}
			if len(pr.puts) != 0 || permits != 0 {
				t.Fatalf("%d PUTs, %d permits", len(pr.puts), permits)
			}
			last := d.m.st.Audit[len(d.m.st.Audit)-1]
			if last.Event != EventSaltsRefused || last.Ref != c.reason {
				t.Fatalf("audit %+v", last)
			}
		})
	}
}

// An epoch seen before with another nonce refuses the list.
func TestPairCodeSeenNonce(t *testing.T) {
	d, pr := newPCFixture(t)
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatal(code)
	}
	pr.salts = func(now time.Time) []paircode.Salt { return []paircode.Salt{pcSalt(paircode.Epoch(now), 0x77)} }
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" {
		t.Fatalf("%q", code)
	}
	if last := d.m.st.Audit[len(d.m.st.Audit)-1]; last.Ref != paircode.ReasonChanged {
		t.Fatalf("audit %+v", last)
	}
}

func TestPairCodeBusy(t *testing.T) {
	d, pr := newPCFixture(t)
	pairCodePermitWait = 300 * time.Millisecond
	defer func() { pairCodePermitWait = PairCodePermitWait }()
	asked := 0
	d.m.opt.CodePermit = func(context.Context) (func(), bool) { asked++; return nil, false }
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "busy" {
		t.Fatalf("%q", code)
	}
	if len(pr.puts) != 0 || asked < 2 {
		t.Fatalf("%d PUTs, asked %d times (it waits)", len(pr.puts), asked)
	}
	if len(d.m.st.Invites) != 0 {
		t.Fatal("a busy answer left an invite")
	}
	// Given late within the wait, it goes on; the permit is returned.
	n, released := 0, 0
	d.m.opt.CodePermit = func(context.Context) (func(), bool) {
		n++
		if n < 2 {
			return nil, false
		}
		return func() { released++ }, true
	}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" || released != 1 {
		t.Fatalf("%q, released %d", code, released)
	}
}

func TestPairCodeOtherSaltOnce(t *testing.T) {
	d, pr := newPCFixture(t)
	// The two entries near the hour: the vault's clock 60 s past it.
	pr.salts = func(now time.Time) []paircode.Salt {
		e := paircode.Epoch(now)
		return []paircode.Salt{pcSalt(e-1, 1), pcSalt(e, 2)}
	}
	base := d.m.now()
	at := time.Unix((paircode.Epoch(base)+1)*paircode.Hour+60, 0)
	d.m.now = func() time.Time { return at }
	pr.clock = d.m.now
	bad := &relayclient.Error{Status: 400, Code: "bad_request"}
	pr.putErrs = []error{bad}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatalf("%q", code)
	}
	if len(pr.puts) != 2 || pr.puts[0].saltID == pr.puts[1].saltID || pr.puts[0].claimID != pr.puts[1].claimID ||
		!bytes.Equal(pr.puts[0].blob, pr.puts[1].blob) || bytes.Equal(pr.puts[0].tag, pr.puts[1].tag) {
		t.Fatal("the second PUT is not the same claim under the other salt")
	}
	// Both refused: claim_unavailable, recorded; no third PUT.
	pr.puts, pr.putErrs = nil, []error{bad, bad, bad}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" || len(pr.puts) != 2 {
		t.Fatalf("%q, %d PUTs", code, len(pr.puts))
	}
	if last := d.m.st.Audit[len(d.m.st.Audit)-1]; last.Event != EventSaltsRefused || last.Ref != "put_refused" {
		t.Fatalf("audit %+v", last)
	}
	// One entry only: a bad_request is not retried.
	pr.salts = func(now time.Time) []paircode.Salt { return []paircode.Salt{pcSalt(paircode.Epoch(now), 2)} } // the nonce seen
	pr.puts, pr.putErrs = nil, []error{bad}
	d.m.now = func() time.Time { return at.Add(30 * time.Minute) }
	pr.clock = d.m.now
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" || len(pr.puts) != 1 {
		t.Fatalf("%q, %d PUTs", code, len(pr.puts))
	}
}

func TestPairCodeTaken(t *testing.T) {
	d, pr := newPCFixture(t)
	taken := &relayclient.Error{Status: 409, Code: "code_taken"}
	pr.putErrs = []error{taken}
	a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" || len(pr.puts) != 2 || pr.puts[0].claimID == pr.puts[1].claimID || bytes.Equal(pr.puts[0].salt, pr.puts[1].salt) {
		t.Fatalf("%q, %d PUTs", code, len(pr.puts))
	}
	if d.m.st.Invites[a.PairingID].ClaimID != pr.puts[1].claimID {
		t.Fatal("the invite holds the taken claim")
	}
	// Taken four times (the first and 3 retries): relay_error.
	pr.puts, pr.putErrs = nil, []error{taken, taken, taken, taken, taken}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "relay_error" || len(pr.puts) != 4 {
		t.Fatalf("%q, %d PUTs", code, len(pr.puts))
	}
	// (0.94.1) A failed PUT (here a 5xx): not retried, claim_unavailable.
	pr.puts, pr.putErrs = nil, []error{&relayclient.Error{Status: 503, Code: "unavailable"}}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" || len(pr.puts) != 1 {
		t.Fatalf("%q, %d PUTs", code, len(pr.puts))
	}
}

// One live code per vault: a new code pairing ends the last, whatever its
// role; its claim is deleted by the code claim route and its token
// denylisted.
func TestPairCodeOneLive(t *testing.T) {
	d, pr := newPCFixture(t)
	a1, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" {
		t.Fatal(code)
	}
	inv1 := *d.m.st.Invites[a1.PairingID]
	link, code := d.pcCreate(t, `{"role":"desktop"}`) // a link pairing is not cancelled
	if code != "" {
		t.Fatal(code)
	}
	a2, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" {
		t.Fatal(code)
	}
	if d.m.st.Invites[a1.PairingID] != nil || d.m.st.Invites[a2.PairingID] == nil || d.m.st.Invites[link.PairingID] == nil {
		t.Fatal("the live code was not replaced (or the link was)")
	}
	if !d.denied(inv1.OpenJTI) {
		t.Fatal("the replaced code's token is not denylisted")
	}
	// The batch's drain sends the delete by the code claim route.
	if !slices.Contains(pr.deletes, inv1.ClaimID) {
		t.Fatalf("the replaced code's claim is not deleted (queued %v)", d.outboxOps(OpDeletePairCode))
	}
	if slices.Contains(d.outboxOps(OpDeleteClaim), inv1.ClaimID) || slices.Contains(d.relay.claimDeletes, inv1.ClaimID) {
		t.Fatal("a code claim deleted by the claim route")
	}
}

func TestPairCodeLimit(t *testing.T) {
	d, _ := newPCFixture(t)
	now := d.m.now()
	for i := range PairCodesPerHour {
		if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
			t.Fatalf("%d: %s", i, code)
		}
	}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "limit" {
		t.Fatalf("the 6th in an hour: %q", code)
	}
	// An hour later 5 more, then the day's 20 are reached.
	d.m.st.PairCodeIssued = nil
	for i := range PairCodesPerDay {
		d.m.st.PairCodeIssued = append(d.m.st.PairCodeIssued, now.Add(-2*time.Hour-time.Duration(i)*time.Minute))
	}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "limit" {
		t.Fatalf("the 21st in a day: %q", code)
	}
	// Stamps older than a day are dropped.
	for i := range d.m.st.PairCodeIssued {
		d.m.st.PairCodeIssued[i] = now.Add(-25 * time.Hour)
	}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" || len(d.m.st.PairCodeIssued) != 1 {
		t.Fatalf("%q, %d stamps", code, len(d.m.st.PairCodeIssued))
	}
	// Refusals do not count.
	n := len(d.m.st.PairCodeIssued)
	d.m.relay.(*pcRelay).offers = false
	_, _ = d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if len(d.m.st.PairCodeIssued) != n {
		t.Fatal("a refusal counted")
	}
}

// device.pair.reject of a pairing no device has opened ends it: a code
// pairing's claim deleted by its route, its token denylisted.
func TestPairCodeRejectUnopened(t *testing.T) {
	d, pr := newPCFixture(t)
	a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" {
		t.Fatal(code)
	}
	inv := *d.m.st.Invites[a.PairingID]
	if c := d.errorCode(t, "device.pair.reject", `{"pairing_id":"`+a.PairingID+`"}`); c != "" {
		t.Fatalf("reject: %q", c)
	}
	if d.m.st.Invites[a.PairingID] != nil || !d.denied(inv.OpenJTI) {
		t.Fatal("the pairing was not ended")
	}
	if !slices.Contains(pr.deletes, inv.ClaimID) {
		t.Fatal("its claim is not deleted")
	}
	if c := d.errorCode(t, "device.pair.reject", `{"pairing_id":"`+a.PairingID+`"}`); c != "not_found" {
		t.Fatalf("again: %q", c)
	}
	// A link pairing unopened ends the same way, by the claim route.
	l, _ := d.pcCreate(t, `{"role":"desktop"}`)
	li := *d.m.st.Invites[l.PairingID]
	if c := d.errorCode(t, "device.pair.reject", `{"pairing_id":"`+l.PairingID+`"}`); c != "" || d.m.st.Invites[l.PairingID] != nil {
		t.Fatalf("link reject: %q", c)
	}
	if slices.Contains(pr.deletes, li.ClaimID) {
		t.Fatal("a link claim deleted by the code route")
	}
}

// A code pairing that expires unredeemed has its claim deleted by the
// code claim route.
func TestPairCodeExpiryDeletesTheClaim(t *testing.T) {
	d, pr := newPCFixture(t)
	a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" {
		t.Fatal(code)
	}
	inv := *d.m.st.Invites[a.PairingID]
	later := d.m.now().Add(11 * time.Minute)
	d.m.now = func() time.Time { return later }
	d.m.mu.Lock()
	d.m.housekeeping(later)
	d.m.mu.Unlock()
	if !slices.Contains(pr.deletes, inv.ClaimID) && !slices.Contains(d.outboxOps(OpDeletePairCode), inv.ClaimID) {
		t.Fatal("the expired code's claim is not deleted")
	}
}

func (d *devFixture) denied(jti string) bool {
	for _, it := range d.m.st.Issued {
		if it.JTI == jti && it.Denied {
			return true
		}
	}
	return false
}

// The vault derives and answers with the relay's canonical form, whatever
// the spelling of its own relay URL.
func TestPairCodeCanonicalRelay(t *testing.T) {
	d, pr := newPCFixture(t)
	pr.stubRelay.base = "https://Relay.Example.org:443/"
	a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" || a.R != pcR {
		t.Fatalf("%q, r %q", code, a.R)
	}
}

// retransmit sends the same request (one inner id) twice, as a device
// whose answer was lost does, and returns both answers' bodies.
func (d *devFixture) retransmit(t *testing.T, typ, body string) (first, second json.RawMessage) {
	t.Helper()
	id, _ := envelope.NewULID(testNow())
	send := func(n int) {
		raw, err := d.ep.Seal(&envelope.Inner{ID: id, Type: typ, TS: testNow(), Body: []byte(body), Features: []string{handshake.CapConfirm}})
		if err != nil {
			t.Fatal(err)
		}
		d.seq++
		msg := Message{MsgID: fmt.Sprintf("rt%d-%d", d.seq, n), Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw}
		_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, []Message{msg})
	}
	send(1)
	send(2)
	var got []json.RawMessage
	for _, x := range d.appInbox() {
		if x.Re == id {
			got = append(got, x.Body)
		}
	}
	if len(got) != 2 {
		t.Fatalf("%d answers", len(got))
	}
	return got[0], got[1]
}

// A retransmitted code request is answered from the response cache: the
// same pairing, without the code (never in saved state); no new code is
// made, nothing is cancelled and the hourly limit is not used.
func TestPairCodeRetransmission(t *testing.T) {
	d, pr := newPCFixture(t)
	first, second := d.retransmit(t, "device.pair.create", `{"role":"desktop","form":"code"}`)
	var a, b map[string]string
	if json.Unmarshal(first, &a) != nil || json.Unmarshal(second, &b) != nil {
		t.Fatal("answers")
	}
	if !paircode.ValidCode([]byte(a["code"])) || a["pairing_id"] == "" {
		t.Fatal("the first answer")
	}
	if _, has := b["code"]; has || b["pairing_id"] != a["pairing_id"] || b["exp"] != a["exp"] || b["r"] != a["r"] {
		t.Fatalf("the cached answer: %s", second)
	}
	if len(pr.puts) != 1 || len(d.m.st.PairCodeIssued) != 1 || d.m.st.Invites[a["pairing_id"]] == nil {
		t.Fatalf("%d PUTs, %d issued", len(pr.puts), len(d.m.st.PairCodeIssued))
	}
}

func (d *devFixture) deniedOpenTokens() int {
	n := 0
	for _, it := range d.m.st.Issued {
		if it.Kind == TokOpen && it.Denied {
			n++
		}
	}
	return n
}

// Every code pairing not made after its open token was minted denylists
// that token (with its revocation queued).
func TestPairCodeFailuresDenyTheToken(t *testing.T) {
	taken := &relayclient.Error{Status: 409, Code: "code_taken"}
	bad := &relayclient.Error{Status: 400, Code: "bad_request"}
	for name, errs := range map[string][]error{
		"relay_error":   {&relayclient.Error{Status: 503, Code: "unavailable"}},
		"put_refused":   {bad},
		"taken 4 times": {taken, taken, taken, taken},
	} {
		t.Run(name, func(t *testing.T) {
			d, pr := newPCFixture(t)
			pr.putErrs = errs
			before := d.deniedOpenTokens()
			if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code == "" {
				t.Fatal("made")
			}
			if d.deniedOpenTokens() != before+1 {
				t.Fatal("the minted token is not denylisted")
			}
		})
	}
}

// A PUT whose outcome is not known (no answer, a 5xx) has its claim
// deleted: the relay may hold it.
func TestPairCodeUnknownPutDeletesTheClaim(t *testing.T) {
	d, pr := newPCFixture(t)
	pr.putErrs = []error{&relayclient.Error{Status: 503, Code: "unavailable"}}
	pr.deleteErr = &relayclient.Error{Status: 503, Code: "unavailable"} // the deletion stays queued for its retries
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" {
		t.Fatalf("%q", code)
	}
	if len(pr.puts) != 1 || !slices.Contains(pr.deletes, pr.puts[0].claimID) {
		t.Fatalf("the claim is not deleted (%d PUTs, deletes %d)", len(pr.puts), len(pr.deletes))
	}
	// Retried until the pairing's 10 minutes end (0.94.1).
	found := false
	for _, e := range d.m.st.Outbox {
		if e.Op == OpDeletePairCode && e.Value == pr.puts[0].claimID {
			found = true
			want := d.m.now().UTC().Truncate(time.Second).Add(paircode.TTL + time.Minute)
			if e.NotAfter.IsZero() || e.NotAfter.After(want) {
				t.Fatalf("its retries end at %v, want by %v", e.NotAfter, want)
			}
		}
	}
	if !found {
		t.Fatal("the deletion is not in the outbox")
	}
	// A code_taken (deleted by the relay) and a refused salt (never
	// stored) delete nothing.
	pr.deleteErr = nil
	for _, e := range []error{&relayclient.Error{Status: 409, Code: "code_taken"}, &relayclient.Error{Status: 400, Code: "bad_request"}} {
		pr.puts, pr.deletes, pr.putErrs = nil, nil, []error{e, e, e, e}
		_, _ = d.pcCreate(t, `{"role":"desktop","form":"code"}`)
		for _, p := range pr.puts {
			if slices.Contains(pr.deletes, p.claimID) {
				t.Fatalf("%v: a claim the relay never kept was deleted", e)
			}
		}
	}
}

// The derivation permit is held for the derivations only, never across a
// request to the relay, and taken again for the other salt's tag.
func TestPairCodePermitNotHeldAcrossAPut(t *testing.T) {
	d, pr := newPCFixture(t)
	held, taken := false, 0
	d.m.opt.CodePermit = func(context.Context) (func(), bool) {
		if held {
			t.Error("a permit taken twice")
		}
		held = true
		taken++
		return func() { held = false }, true
	}
	pr.permitHeld = func() bool { return held }
	pr.salts = func(now time.Time) []paircode.Salt {
		e := paircode.Epoch(now)
		return []paircode.Salt{pcSalt(e-1, 1), pcSalt(e, 2)}
	}
	at := time.Unix((paircode.Epoch(d.m.now())+1)*paircode.Hour+60, 0)
	d.m.now = func() time.Time { return at }
	pr.clock = d.m.now
	pr.putErrs = []error{&relayclient.Error{Status: 400, Code: "bad_request"}}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatalf("%q", code)
	}
	if pr.putWhileHeld || held {
		t.Fatal("a permit held across a PUT, or not given back")
	}
	if taken != 2 || len(pr.puts) != 2 {
		t.Fatalf("%d permits for %d PUTs (the other salt's tag takes its own)", taken, len(pr.puts))
	}
}

// After the relay refused the first salt and the code was taken under
// the other, the next code goes to the other salt at once.
func TestPairCodeRefusedSaltNotRetried(t *testing.T) {
	d, pr := newPCFixture(t)
	pr.salts = func(now time.Time) []paircode.Salt {
		e := paircode.Epoch(now)
		return []paircode.Salt{pcSalt(e-1, 1), pcSalt(e, 2)}
	}
	at := time.Unix((paircode.Epoch(d.m.now())+1)*paircode.Hour+60, 0)
	d.m.now = func() time.Time { return at }
	pr.clock = d.m.now
	pr.putErrs = []error{&relayclient.Error{Status: 400, Code: "bad_request"}, &relayclient.Error{Status: 409, Code: "code_taken"}}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatalf("%q", code)
	}
	if len(pr.puts) != 3 || pr.puts[2].saltID != pr.puts[1].saltID || pr.puts[2].saltID == pr.puts[0].saltID {
		t.Fatalf("%d PUTs; the third should use the second's salt", len(pr.puts))
	}
}

// A code pairing a device has opened (hs.init: Used) is not the live code
// any more: a new code does not cancel it.
func TestPairCodeOpenedIsNotCancelled(t *testing.T) {
	d, _ := newPCFixture(t)
	a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" {
		t.Fatal(code)
	}
	d.m.st.Invites[a.PairingID].Used = true
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatal(code)
	}
	if d.m.st.Invites[a.PairingID] == nil {
		t.Fatal("an opened pairing was cancelled")
	}
}

// Seen salts older than the previous hour are dropped; the previous
// hour's nonce is still held to.
func TestPairCodeSeenSaltsPruned(t *testing.T) {
	d, pr := newPCFixture(t)
	cur := paircode.Epoch(d.m.now())
	d.m.st.PairCodeSeen = []SeenSalt{{Epoch: cur - 5, Nonce: bytes.Repeat([]byte{9}, 16)}, {Epoch: cur - 1, Nonce: bytes.Repeat([]byte{8}, 16)}}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatal(code)
	}
	for _, s := range d.m.st.PairCodeSeen {
		if s.Epoch == cur-5 {
			t.Fatal("an old epoch kept")
		}
	}
	// An hour later the hour seen now is the previous one, listed again
	// with another nonce than the one seen: refused.
	pr.salts = func(now time.Time) []paircode.Salt { return []paircode.Salt{pcSalt(cur, 0x77), pcSalt(cur+1, 0x52)} }
	at := time.Unix((cur+1)*paircode.Hour+60, 0)
	d.m.now = func() time.Time { return at }
	pr.clock = d.m.now
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" {
		t.Fatalf("%q", code)
	}
	if last := d.m.st.Audit[len(d.m.st.Audit)-1]; last.Ref != paircode.ReasonChanged {
		t.Fatalf("audit %+v", last)
	}
}

// A relay whose open tokens cannot live 660 s takes no code pairing.
func TestPairCodeTokenLimit(t *testing.T) {
	d, pr := newPCFixture(t)
	d.m.limits.OpenTokenMaxLifetimeSeconds = 600
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" || len(pr.puts) != 0 {
		t.Fatalf("%q", code)
	}
}

// The answer with the code is never in saved state: no stored outbox
// deposit opens, with the state's own session keys, to an inner that holds
// the code; the device got it once, from memory.
func TestPairCodeNotInTheStoredOutbox(t *testing.T) {
	d, _ := newPCFixture(t)
	// Deposits to the device fail, so whatever was queued stays stored.
	d.relay.failMailbox = map[string]error{d.devPeer.Relay.Mailbox: errors.New("relay down")}
	d.sendAs(d.self(), "device.pair.create", `{"role":"desktop","form":"code"}`)
	made := false
	for _, inv := range d.m.st.Invites {
		made = made || inv.Code
	}
	if !made {
		t.Fatal("no code pairing made")
	}
	// A positive control: a durable message to the same device, stored.
	d.m.mu.Lock()
	d.m.sendTo(d.m.st.Devices[d.devPeer.ID], "sync.event", []byte(`{"kind":"control"}`), d.m.now())
	if err := d.m.persist(context.Background(), false); err != nil {
		d.m.mu.Unlock()
		t.Fatal(err)
	}
	raw, err := json.Marshal(d.m.st)
	d.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// Open with the keys of the state as stored, not the keyring in memory.
	var st State
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	kr, err := handshake.ImportKeyring(st.Devices[d.devPeer.ID].Sessions)
	if err != nil || kr.Current() == nil {
		t.Fatalf("the stored keyring: %v", err)
	}
	opened, control := 0, false
	for _, e := range st.Outbox {
		if e.Op != OpDeposit || len(e.Payload) == 0 {
			continue
		}
		env, err := envelope.Parse(e.Payload)
		if err != nil {
			continue
		}
		in, err := kr.Current().OpenSent(env)
		if err != nil {
			continue
		}
		opened++
		control = control || bytes.Contains(in.Body, []byte(`"control"`))
		var b map[string]json.RawMessage
		if json.Unmarshal(in.Body, &b) == nil && b["code"] != nil {
			t.Fatal("a stored deposit holds the answer with the code")
		}
	}
	if opened < 1 || !control {
		t.Fatalf("the positive control did not open (%d opened): the check proves nothing", opened)
	}
}

// Fail closed: without a code permit the heavy-derivation permit admits
// the derivations; refused, the answer is busy.
func TestPairCodeFallsBackToTheHeavyPermit(t *testing.T) {
	d, pr := newPCFixture(t)
	pairCodePermitWait = 50 * time.Millisecond
	defer func() { pairCodePermitWait = PairCodePermitWait }()
	d.m.opt.CodePermit = nil
	asked := 0
	d.m.opt.HeavyPermit = func(context.Context) (func(), bool) { asked++; return nil, false }
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "busy" || asked == 0 || len(pr.puts) != 0 {
		t.Fatalf("%q, asked %d", code, asked)
	}
	d.m.opt.HeavyPermit = func(context.Context) (func(), bool) { asked++; return func() {}, true }
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatalf("%q", code)
	}
}

// One wait for room per request (0.94.1): the other salt's permit waits
// only for what is left of it.
func TestPairCodeOneDeadlinePerRequest(t *testing.T) {
	d, pr := newPCFixture(t)
	var fake time.Time
	pcNow = func() time.Time { return fake }
	defer func() { pcNow = time.Now }()
	fake = time.Unix(1_000_000, 0)
	pr.salts = func(now time.Time) []paircode.Salt {
		e := paircode.Epoch(now)
		return []paircode.Salt{pcSalt(e-1, 1), pcSalt(e, 2)}
	}
	at := time.Unix((paircode.Epoch(d.m.now())+1)*paircode.Hour+60, 0)
	d.m.now = func() time.Time { return at }
	pr.clock = d.m.now
	pr.putErrs = []error{&relayclient.Error{Status: 400, Code: "bad_request"}}
	calls := 0
	d.m.opt.CodePermit = func(context.Context) (func(), bool) {
		calls++
		if calls == 1 {
			fake = fake.Add(4 * time.Second) // the first took 4 of the 5 s
			return func() {}, true
		}
		fake = fake.Add(time.Second / 4)
		return nil, false
	}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "busy" {
		t.Fatalf("%q", code)
	}
	// 1 s was left: 4 refused asks of 250 ms, then busy (a 5 s wait of its
	// own would ask 20 times).
	if calls > 7 {
		t.Fatalf("the other salt's permit was asked %d times: a wait of its own", calls-1)
	}
}

// A limit refusal leaves the live code as it was.
func TestPairCodeLimitKeepsTheLiveCode(t *testing.T) {
	d, _ := newPCFixture(t)
	a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
	if code != "" {
		t.Fatal(code)
	}
	now := d.m.now()
	for range PairCodesPerHour {
		d.m.st.PairCodeIssued = append(d.m.st.PairCodeIssued, now)
	}
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "limit" {
		t.Fatalf("%q", code)
	}
	if d.m.st.Invites[a.PairingID] == nil {
		t.Fatal("a refusal cancelled the live code")
	}
}

// The windows' edges: an hour and a day, exactly.
func TestPairCodeLimitEdges(t *testing.T) {
	d, _ := newPCFixture(t)
	now := d.m.now()
	stamps := func(age time.Duration, n int) {
		d.m.st.PairCodeIssued = nil
		for range n {
			d.m.st.PairCodeIssued = append(d.m.st.PairCodeIssued, now.Add(-age))
		}
	}
	stamps(time.Hour-time.Second, PairCodesPerHour)
	if d.m.pairCodeIssuable(now) {
		t.Fatal("5 within the hour")
	}
	stamps(time.Hour, PairCodesPerHour)
	if !d.m.pairCodeIssuable(now) {
		t.Fatal("an hour old counts in the hour")
	}
	stamps(24*time.Hour-time.Second, PairCodesPerDay)
	if d.m.pairCodeIssuable(now) {
		t.Fatal("20 within the day")
	}
	stamps(24*time.Hour, PairCodesPerDay)
	if !d.m.pairCodeIssuable(now) || len(d.m.st.PairCodeIssued) != 0 {
		t.Fatal("a day old is dropped")
	}
}

// An agent pairing counts for the limit as a desktop's does.
func TestPairCodeAgentCounts(t *testing.T) {
	d, _ := newPCFixture(t)
	d.m.addFeature(&namedFeature{name: featureLeash})
	if _, code := d.pcCreate(t, `{"role":"agent","form":"code"}`); code != "" || len(d.m.st.PairCodeIssued) != 1 {
		t.Fatalf("%q, %d stamps", code, len(d.m.st.PairCodeIssued))
	}
}

// The previous hour's nonce is held to across the hour: seen at minute 1
// of hour N+1, listed again with another nonce at minute 5, refused.
func TestPairCodePreviousEpochAcrossTheHour(t *testing.T) {
	d, pr := newPCFixture(t)
	n := paircode.Epoch(d.m.now()) + 1
	at := time.Unix((n+1)*paircode.Hour+60, 0)
	d.m.now = func() time.Time { return at }
	pr.clock = d.m.now
	pr.salts = func(time.Time) []paircode.Salt { return []paircode.Salt{pcSalt(n, 0x61), pcSalt(n+1, 0x62)} }
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatal(code)
	}
	// A request at minute 3 whose list (allowed) leaves the previous hour
	// out: what was seen of it is kept.
	at = at.Add(2 * time.Minute)
	pr.salts = func(time.Time) []paircode.Salt { return []paircode.Salt{pcSalt(n+1, 0x62)} }
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "" {
		t.Fatal(code)
	}
	at = at.Add(2 * time.Minute)
	pr.salts = func(time.Time) []paircode.Salt { return []paircode.Salt{pcSalt(n, 0x6f), pcSalt(n+1, 0x62)} }
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" {
		t.Fatalf("%q", code)
	}
	if last := d.m.st.Audit[len(d.m.st.Audit)-1]; last.Ref != paircode.ReasonChanged {
		t.Fatalf("audit %+v", last)
	}
}

// (0.94.1) A salts read that fails answers claim_unavailable, with nothing
// minted or sent.
func TestPairCodeSaltsReadFails(t *testing.T) {
	d, pr := newPCFixture(t)
	pr.saltErr = &relayclient.Error{Status: 503, Code: "unavailable"}
	issued := len(d.m.st.Issued)
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "claim_unavailable" || len(pr.puts) != 0 || len(d.m.st.Issued) != issued {
		t.Fatalf("%q", code)
	}
}

// busy after the token was minted denylists it too.
func TestPairCodeBusyDeniesTheToken(t *testing.T) {
	d, _ := newPCFixture(t)
	pairCodePermitWait = 50 * time.Millisecond
	defer func() { pairCodePermitWait = PairCodePermitWait }()
	d.m.opt.CodePermit = func(context.Context) (func(), bool) { return nil, false }
	before := d.deniedOpenTokens()
	if _, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`); code != "busy" || d.deniedOpenTokens() != before+1 {
		t.Fatalf("%q", code)
	}
}

// device.pair.reject of an invite that is not an unopened desktop or agent
// pairing (a connection's, a transfer's, an app's, an opened one) is
// not_found, and the invite stays.
func TestPairRejectLeavesOtherInvites(t *testing.T) {
	d, _ := newPCFixture(t)
	exp := d.m.now().Add(time.Hour)
	for id, inv := range map[string]*Invite{
		"inv-connection": {Kind: KindConnection, Exp: exp, OpenJTI: "j-c", ClaimID: "abcdefghijklmnopqrstuvwxya"},
		"inv-transfer":   {Kind: KindApp, Transfer: true, Exp: exp, OpenJTI: "j-t"},
		"inv-app":        {Kind: KindApp, Exp: exp, OpenJTI: "j-a"},
		"inv-opened":     {Kind: KindDesktop, Used: true, Exp: exp, OpenJTI: "j-o", Code: true},
	} {
		inv.ID = id
		d.m.st.Invites[id] = inv
		if c := d.errorCode(t, "device.pair.reject", `{"pairing_id":"`+id+`"}`); c != "not_found" {
			t.Errorf("%s: %q", id, c)
		}
		if d.m.st.Invites[id] == nil {
			t.Errorf("%s: dropped", id)
		}
	}
}

// A code invite's claim is deleted by the code claim route at hs.init and
// when the vault is deleted; a mailbox deletion settles those deletes.
func TestPairCodeClaimDeletedElsewhere(t *testing.T) {
	t.Run("hs.init", func(t *testing.T) {
		d, _ := newPCFixture(t)
		a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
		if code != "" {
			t.Fatal(code)
		}
		inv := *d.m.st.Invites[a.PairingID]
		n := newNewcomer(t, 0x50)
		n.hsInit(t, d.m, handshake.PurposeDesktop, a.PairingID, "p1")
		if !d.m.st.Invites[a.PairingID].Used {
			t.Fatal("hs.init did not open the pairing")
		}
		if !slices.Contains(d.outboxOps(OpDeletePairCode), inv.ClaimID) && !slices.Contains(d.m.relay.(*pcRelay).deletes, inv.ClaimID) {
			t.Fatal("the claim is not deleted at hs.init")
		}
		if slices.Contains(d.outboxOps(OpDeleteClaim), inv.ClaimID) {
			t.Fatal("deleted by the claim route")
		}
	})
	t.Run("vault deleted", func(t *testing.T) {
		d, _ := newPCFixture(t)
		a, code := d.pcCreate(t, `{"role":"desktop","form":"code"}`)
		if code != "" {
			t.Fatal(code)
		}
		inv := *d.m.st.Invites[a.PairingID]
		d.m.mu.Lock()
		d.m.beginDelete("app", d.m.now())
		var e *OutboxEntry
		for _, x := range d.m.st.Outbox {
			if x.Op == OpDeletePairCode && x.Value == inv.ClaimID {
				e = x
			}
		}
		d.m.mu.Unlock()
		if e == nil || !e.NotAfter.Equal(inv.Exp.Add(time.Minute)) {
			t.Fatalf("the claim's deletion: %+v", e)
		}
		// The mailbox deletion settles it (once the deletion is recorded:
		// the host's mark, NoHostMark here).
		d.m.mu.Lock()
		d.m.markOK = true
		d.m.deleteMailbox(context.Background())
		d.m.mu.Unlock()
		if !e.Done {
			t.Fatal("not settled by the mailbox deletion")
		}
	})
}

// (0.94.1 step 6 e) A duplicate of a request still running is answered
// only once the first completes, from the cache: in one batch, the first
// answer has the code and the second none.
func TestPairCodeDuplicateInOneBatch(t *testing.T) {
	d, pr := newPCFixture(t)
	id, _ := envelope.NewULID(testNow())
	var msgs []Message
	for n := range 2 {
		raw, err := d.ep.Seal(&envelope.Inner{ID: id, Type: "device.pair.create", TS: testNow(), Body: []byte(`{"role":"desktop","form":"code"}`),
			Features: []string{handshake.CapConfirm}})
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, Message{MsgID: fmt.Sprintf("dup%d", n), Sender: relayauth.EncodeKey(d.devPeer.Relay.PK), Payload: raw})
	}
	_ = d.m.ProcessBatch(context.Background(), &fakeCollector{}, msgs)
	var bodies []map[string]string
	for _, x := range d.appInbox() {
		if x.Re == id {
			var b map[string]string
			_ = json.Unmarshal(x.Body, &b)
			bodies = append(bodies, b)
		}
	}
	if len(pr.puts) != 1 || len(bodies) != 2 || bodies[0]["code"] == "" || bodies[1]["code"] != "" || bodies[1]["pairing_id"] != bodies[0]["pairing_id"] {
		t.Fatalf("%d PUTs, %d answers: %v", len(pr.puts), len(bodies), func() []string {
			var k []string
			for _, b := range bodies {
				k = append(k, b["pairing_id"]+"/"+fmt.Sprint(len(b["code"])))
			}
			return k
		}())
	}
}

// Only an answer marked sent-once (the pairing code) leaves the stored
// outbox: any other with a cached copy (a LEASH value, a TURN credential)
// keeps its durable deposit and its retries.
func TestSentOnceIsOnlyForTheMarkedAnswer(t *testing.T) {
	d := newDevFixture(t)
	req := &envelope.Inner{ID: "01JB2Z6V9K3M4N5P6Q7R8S9TB0", Type: "item.get"}
	stored := func(id string) bool {
		for _, e := range d.m.st.Outbox {
			if e.Op == OpDeposit && e.InnerID == id {
				return true
			}
		}
		return false
	}
	inMemory := func(id string) bool {
		for _, e := range d.m.volatile {
			if e.ID == id {
				return true
			}
		}
		return false
	}
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	out := &envelope.Inner{Type: req.Type, Re: req.ID, Status: envelope.StatusOK, Body: []byte(`{"value":"s3cr3t"}`)}
	d.m.sendResponseCached(d.devPeer, req, "k1", out, json.RawMessage(`{"withheld":true}`), false, d.m.now())
	if !stored(out.ID) || inMemory(out.ID) {
		t.Fatal("a cached-copy answer not marked sent-once lost its durable deposit")
	}
	out2 := &envelope.Inner{Type: "device.pair.create", Re: "01JB2Z6V9K3M4N5P6Q7R8S9TB1", Status: envelope.StatusOK, Body: []byte(`{"code":"ABCDEFGH"}`)}
	d.m.sendResponseCached(d.devPeer, &envelope.Inner{ID: out2.Re, Type: out2.Type}, "k2", out2, json.RawMessage(`{}`), true, d.m.now())
	if stored(out2.ID) || !inMemory(out2.ID) {
		t.Fatal("the sent-once answer is in the stored outbox")
	}
	if !bytes.Equal(out2.Body, make([]byte, len(out2.Body))) {
		t.Fatal("the sent-once answer's body was not wiped once sealed")
	}
}
