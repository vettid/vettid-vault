package wallet_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/wallet"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/btc"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Spend caps (VAULT-MESSAGING 0.82.0 §10.18 "Spend caps", first specified
// in 0.56.0) and the tests that section requires.

const day = 24 * time.Hour

// capW is one regtest wallet (BIP84 receiving, both accounts), unlocked.
type capW struct {
	e  *env
	id string
	a  *btc.Account // BIP84
	tr *btc.Account // BIP86
}

func newCapEnv(t *testing.T) *capW {
	t.Helper()
	e := newEnv(t, &fakeChain{})
	id, accts := e.importAs(btc.P2WPKH)
	e.unlock()
	return &capW{e: e, id: id, a: accts[btc.P2WPKH], tr: accts[btc.P2TR]}
}

func (c *capW) w() wallet.Wallet {
	c.e.t.Helper()
	for _, w := range c.e.wl.Wallets() {
		if w.ID == c.id {
			return w
		}
	}
	c.e.t.Fatal("no wallet")
	return wallet.Wallet{}
}

// psbt is a spend of two coins (110,000 sats) paying `to` out-1000 sats
// with a fee of 1,000, so that the outflow (payees and fee) is out; the
// rest is change to chg (nil: the BIP84 account).
func (c *capW) psbtTo(to string, out int64, chg *btc.Account) []byte {
	c.e.t.Helper()
	f1, _ := btc.FundingTx(c.a, 0, 0, 60000, 1)
	f2, _ := btc.FundingTx(c.a, 0, 1, 50000, 2)
	payees := []btc.Payee{{Address: to, Amount: out - 1000}}
	if change := 110000 - out; change > 0 {
		payees = append(payees, btc.Payee{Change: true, Chain: 1, Index: 0, Amount: change, Acct: chg})
	}
	raw, err := btc.BuildPSBT(c.a, []btc.Coin{{PrevTx: f1, Vout: 0}, {PrevTx: f2, Vout: 0, Chain: 0, Index: 1}}, payees)
	if err != nil {
		c.e.t.Fatal(err)
	}
	return raw
}

func (c *capW) psbt(out int64) []byte { return c.psbtTo(payee, out, nil) }

func (c *capW) ledger() []wallet.LedgerEntry { return c.w().Ledger }

func (c *capW) spent() int64 {
	var n int64
	for _, e := range c.ledger() {
		n += e.Sats
	}
	return n
}

func (c *capW) set(members map[string]any) featuretest.Result {
	body := map[string]any{"wallet_id": c.id, "version": c.w().Version}
	for k, v := range members {
		body[k] = v
	}
	return c.e.call("app", "wallet.caps.set", js(body))
}

func (c *capW) mustSet(members map[string]any) {
	c.e.t.Helper()
	c.e.ok(c.set(members))
}

// bind is the payload_sha256 of wallet.caps.raise, computed here from the
// text of the spec, not from the implementation.
func bind(id string, version uint64, perTx, perPeriod string) string {
	h := sha256.Sum256([]byte("vettid/wallet.caps/1\x00" + id + "\x00" + strconv.FormatUint(version, 10) + "\x00" + perTx + "\x00" + perPeriod))
	return base64.StdEncoding.EncodeToString(h[:])
}

// after is what the binding names: the wallet's caps after a request
// whose members are given (nil: null).
func (c *capW) after(members map[string]any) (string, string) {
	f := func(cur int64, k string) string {
		v, ok := members[k]
		switch {
		case !ok && cur == 0, ok && v == nil:
			return "none"
		case !ok:
			return strconv.FormatInt(cur, 10)
		}
		return fmt.Sprint(v)
	}
	w := c.w()
	return f(w.Caps.PerTx, "per_tx_sats"), f(w.Caps.PerPeriod, "per_period_sats")
}

// raise sends wallet.caps.raise with the right PIN, password and binding.
func (c *capW) raise(members map[string]any) featuretest.Result {
	tx, per := c.after(members)
	return c.raiseWith(members, c.e.h.PIN, pw, bind(c.id, c.w().Version, tx, per))
}

func (c *capW) raiseWith(members map[string]any, pin, password, payloadHash string) featuretest.Result {
	outer := map[string]any{"wallet_id": c.id, "version": c.w().Version}
	for k, v := range members {
		outer[k] = v
	}
	return c.e.sealed("app", "wallet.caps.raise", outer,
		map[string]any{"pin": pin, "password": password, "item_id": c.id, "payload_sha256": payloadHash}, true, false)
}

// signAt signs psbt with the clock set so that the request arrives at t.
func (c *capW) signAt(t time.Time, raw []byte) featuretest.Result {
	c.e.t.Helper()
	c.e.ensureUTK()
	c.e.clk.T = t.Add(-time.Second) // sealed advances it by a second
	return c.e.sign(c.id, raw, nil)
}

func (e *env) ensureUTK() {
	e.t.Helper()
	if len(e.utks) == 0 {
		e.ok(e.call("app", "credential.utk.get", `{}`))
	}
}

func refusal(t *testing.T, r featuretest.Result, reason string) strictjson.Object {
	t.Helper()
	if r.Code != "cap_exceeded" || r.Message != reason {
		t.Fatalf("got %q %q, want cap_exceeded %s", r.Code, r.Message, reason)
	}
	o := r.Obj(t)
	if got, _ := o.String("reason"); got != reason {
		t.Fatalf("body reason %q", got)
	}
	return o
}

func num(t *testing.T, o strictjson.Object, k string) int64 {
	t.Helper()
	v, err := o.Uint(k, 0, strictjson.MaxSafeInteger)
	if err != nil {
		t.Fatalf("%s: %v", k, err)
	}
	return int64(v)
}

func rfc(ms int64) string { return envelope.FormatTS(time.UnixMilli(ms).UTC()) }

// numberIn reports whether n appears as a JSON number in b.
func numberIn(b []byte, n int64) bool {
	return regexp.MustCompile(`[:\[,"]` + strconv.FormatInt(n, 10) + `[,}\]"]`).Match(b)
}

// noValues fails if the audit log, the feed or a sync.event the host
// recorded holds one of the numbers.
func noValues(t *testing.T, e *env, ns ...int64) {
	t.Helper()
	var all [][]byte
	for _, a := range e.h.Activities {
		b, _ := json.Marshal(a)
		all = append(all, b)
	}
	for _, s := range e.h.Sent {
		all = append(all, s.Body)
	}
	for _, b := range all {
		for _, n := range ns {
			if numberIn(b, n) {
				t.Fatalf("the number %d is in %s", n, b)
			}
		}
	}
}

func hasActivity(e *env, kind string) (a struct {
	Ref, Conn, Priority string
	Feed, Audit         bool
}, ok bool) {
	for _, x := range e.h.Activities {
		if x.Kind == kind {
			a.Ref, a.Conn, a.Priority, a.Feed, a.Audit = x.Ref, x.ConnectionID, x.Priority, x.Feed, x.Audit
			ok = true
		}
	}
	return
}

// Per transaction: an outflow equal to per_tx_sats signs; one sat more is
// cap_exceeded per_tx with limit_sats; nothing is signed, no CEK rotated,
// the password backoff untouched, the UTK spent; wallet.cap_refused is
// audited and in the feed, with no amount in either.
func TestCapPerTx(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_tx_sats": 71003})
	e.ok(e.sign(c.id, c.psbt(71003), nil)) // equal is allowed
	if l := c.ledger(); len(l) != 1 || l[0].Sats != 71003 {
		t.Fatalf("ledger %v", l)
	}

	blob, ver := e.blob, c.w().Version
	e.ensureUTK()
	u := e.utks[0]
	e.h.Reset()
	o := refusal(t, e.sign(c.id, c.psbt(71004), nil), "per_tx")
	if num(t, o, "limit_sats") != 71003 || o.Has("remaining_sats") || o.Has("allowed_after") {
		t.Fatalf("body %s", js(o))
	}
	if e.blob != blob || c.w().Version != ver || len(c.ledger()) != 1 {
		t.Fatal("a refused sign changed something")
	}
	// The UTK it presented is spent.
	e.utks = append([]utk{u}, e.utks...)
	e.code(e.sign(c.id, c.psbt(71003), nil), "utk_invalid")
	// The audit entry and the feed item carry no amount; the connection
	// field is empty for the member's own spend.
	a, ok := hasActivity(e, "wallet.cap_refused")
	if !ok || !a.Audit || !a.Feed || a.Priority != "high" || a.Ref != c.id || a.Conn != "" {
		t.Fatalf("activity %+v", a)
	}
	noValues(t, e, 71003, 71004)

	// The password is never tried by a refusal: no guess, no count, no
	// backoff, however often; the next good sign still works with the same
	// credential.
	for i := 0; i < 7; i++ {
		raw := c.psbt(71004)
		h := sha256.Sum256(raw)
		r := e.sealed("app", "wallet.sign", map[string]any{"wallet_id": c.id, "psbt": base64.StdEncoding.EncodeToString(raw)},
			map[string]any{"password": "not the password 91", "item_id": c.id, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}, true, false)
		refusal(t, r, "per_tx")
	}
	if len(e.h.CheckFailed) != 0 {
		t.Fatal("a refusal counted a failed check")
	}
	e.ok(e.sign(c.id, c.psbt(2000), nil))
}

// Per period: signs that together reach per_period_sats, then one more is
// per_period with remaining_sats 0 and an exact allowed_after; the same
// sign succeeds when the clock passes it. Equal signs. A transaction
// larger than per_period_sats alone has no allowed_after.
func TestCapPerPeriod(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_period_sats": 100000})
	e.ok(e.sign(c.id, c.psbt(50000), nil))
	e.ok(e.sign(c.id, c.psbt(50000), nil)) // equal to the cap: allowed
	if c.spent() != 100000 {
		t.Fatalf("spent %d", c.spent())
	}
	first := c.ledger()[0].AtMS
	o := refusal(t, e.sign(c.id, c.psbt(1330), nil), "per_period")
	if num(t, o, "limit_sats") != 100000 || !o.Has("remaining_sats") || num(t, o, "remaining_sats") != 0 {
		t.Fatalf("body %s", js(o))
	}
	// The earliest time it fits: when the first entry leaves the period.
	if got, _ := o.String("allowed_after"); got != rfc(first+day.Milliseconds()) {
		t.Fatalf("allowed_after %s, want %s", got, rfc(first+day.Milliseconds()))
	}
	// A second before: still refused. At that time: signs.
	after := time.UnixMilli(first).Add(day)
	e.clk.T = after.Add(-4 * time.Second)
	e.unlock() // the window of the first spends has passed
	e.ensureUTK()
	refusal(t, e.sign(c.id, c.psbt(1330), nil), "per_period")
	e.ok(c.signAt(after, c.psbt(1330)))
	if c.spent() != 51330 { // the first entry dropped at this write
		t.Fatalf("spent %d", c.spent())
	}

	// Larger than the cap alone: no allowed_after, even in an empty period.
	d := newCapEnv(t)
	d.mustSet(map[string]any{"per_period_sats": 100000})
	o = refusal(t, d.e.sign(d.id, d.psbt(100001), nil), "per_period")
	if num(t, o, "remaining_sats") != 100000 || o.Has("allowed_after") {
		t.Fatalf("body %s", js(o))
	}
	// remaining_sats after some spending.
	d.e.ok(d.e.sign(d.id, d.psbt(40000), nil))
	o = refusal(t, d.e.sign(d.id, d.psbt(60001), nil), "per_period")
	if num(t, o, "remaining_sats") != 60000 {
		t.Fatalf("body %s", js(o))
	}
	if got, _ := o.String("allowed_after"); got != rfc(d.ledger()[0].AtMS+day.Milliseconds()) {
		t.Fatalf("allowed_after %s", got)
	}
	// per_tx is tested first.
	d.mustSet(map[string]any{"per_tx_sats": 50000})
	refusal(t, d.e.sign(d.id, d.psbt(60001), nil), "per_tx")
}

// What counts: change to either of the wallet's own accounts is not
// counted; an output to another wallet of the vault is; the fee is; a
// PSBT invalid_psbt refuses (fee_rate included) is refused with that
// reason first and counts nothing; a refused sign counts nothing.
func TestCapWhatCounts(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_tx_sats": 71000})

	// Change to the BIP84 account and to the BIP86 account: only the
	// payee and the fee leave the wallet.
	e.ok(e.sign(c.id, c.psbtTo(payee, 71000, c.a), nil))
	e.ok(e.sign(c.id, c.psbtTo(payee, 71000, c.tr), nil))
	if l := c.ledger(); len(l) != 2 || l[0].Sats != 71000 || l[1].Sats != 71000 {
		t.Fatalf("ledger %v", l)
	}
	// The fee is counted: a payee of per_tx_sats alone, with its 1,000 fee,
	// is over.
	refusal(t, e.sign(c.id, c.psbtTo(payee, 72000, nil), nil), "per_tx")

	// Moving coins between the wallet's own accounts costs only its fee
	// (an output with the account derivation is change).
	f1, _ := btc.FundingTx(c.a, 0, 0, 60000, 1)
	self, err := btc.BuildPSBT(c.a, []btc.Coin{{PrevTx: f1, Vout: 0}}, []btc.Payee{{Change: true, Chain: 1, Index: 0, Amount: 59000, Acct: c.tr}})
	if err != nil {
		t.Fatal(err)
	}
	c.mustSet(map[string]any{"per_tx_sats": 1000})
	e.ok(e.sign(c.id, self, nil))
	if l := c.ledger(); l[len(l)-1].Sats != 1000 {
		t.Fatalf("a move between the accounts counted %d", l[len(l)-1].Sats)
	}

	// An output to another wallet of the same vault is a payee like any
	// other.
	o := e.ok(e.sealed("app", "wallet.create", map[string]any{"name": "Other", "network": "regtest"}, map[string]any{"password": pw}, true, false))
	other, _ := o.String("wallet_id")
	ad := e.ok(e.call("app", "wallet.address.new", js(map[string]any{"wallet_id": other})))
	otherAddr, _ := ad.String("address")
	n := len(c.ledger())
	c.e.ok(c.raise(map[string]any{"per_tx_sats": 70999}))
	refusal(t, e.sign(c.id, c.psbtTo(otherAddr, 71000, nil), nil), "per_tx")
	c.e.ok(c.raise(map[string]any{"per_tx_sats": 71000}))
	e.ok(e.sign(c.id, c.psbtTo(otherAddr, 71000, nil), nil))
	if l := c.ledger(); len(l) != n+1 || l[n].Sats != 71000 {
		t.Fatalf("ledger %v", l)
	}

	// invalid_psbt first: a fee above 1,000 sat/vB is refused as fee_rate
	// whatever the caps say, and counts nothing.
	n = len(c.ledger())
	f2, _ := btc.FundingTx(c.a, 0, 2, 900000, 3)
	rich, err := btc.BuildPSBT(c.a, []btc.Coin{{PrevTx: f2, Vout: 0, Chain: 0, Index: 2}}, []btc.Payee{{Address: payee, Amount: 1000}})
	if err != nil {
		t.Fatal(err)
	}
	c.mustSet(map[string]any{"per_tx_sats": 1000})
	r := e.sign(c.id, rich, nil)
	if r.Code != "invalid_psbt" || r.Message != "fee_rate" {
		t.Fatalf("got %q %q, want invalid_psbt fee_rate", r.Code, r.Message)
	}
	if len(c.ledger()) != n {
		t.Fatal("a refused PSBT counted")
	}
	// A refused sign counts nothing.
	refusal(t, e.sign(c.id, c.psbt(50000), nil), "per_tx")
	if len(c.ledger()) != n {
		t.Fatal("a cap refusal counted")
	}
}

// wallet.request-payment: the same refusal, the invocation stays pending,
// wallet.cap_refused carries the connection_id, the connection learns
// nothing of the cap.
func TestCapRequestPayment(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_tx_sats": 71000})
	e.ok(e.call("app", "action.configure", js(map[string]any{"action_id": "wallet.request-payment", "mode": "prompt-each-time",
		"connections": []string{cA}, "items": []string{c.id}})))
	inv := invoke(e, cA, "wallet.request-payment", map[string]any{"asset": "BTC", "amount_sats": 70500, "address": payee})
	approve := func(raw []byte) featuretest.Result {
		h := sha256.Sum256(raw)
		return e.sealed("app", "action.respond", map[string]any{"invocation_id": inv, "approve": true, "psbt": base64.StdEncoding.EncodeToString(raw)},
			map[string]any{"password": pw, "item_id": c.id, "request_id": inv, "payload_sha256": base64.StdEncoding.EncodeToString(h[:])}, true, false)
	}
	e.h.Reset()
	// 70,500 to the payee and a fee of 1,000: 71,500, over the cap.
	refusal(t, approve(c.psbt(71500)), "per_tx")
	if len(e.act.PendingInvocations()) != 1 {
		t.Fatal("a cap refusal must leave the invocation pending")
	}
	a, ok := hasActivity(e, "wallet.cap_refused")
	if !ok || a.Conn != cA || a.Ref != c.id || !a.Feed || a.Priority != "high" {
		t.Fatalf("activity %+v", a)
	}
	if len(e.h.SentOfType("action.result")) != 0 {
		t.Fatal("the connection was told something")
	}
	noValues(t, e, 71000, 71500, 70500)
	if len(c.ledger()) != 0 {
		t.Fatal("counted")
	}
	// Raised, the same approval signs.
	c.e.ok(c.raise(map[string]any{"per_tx_sats": 71500}))
	e.h.Reset()
	e.ok(approve(c.psbt(71500)))
	if len(e.act.PendingInvocations()) != 0 {
		t.Fatal("approved")
	}
	if l := c.ledger(); len(l) != 1 || l[0].Sats != 71500 {
		t.Fatalf("ledger %v", l)
	}
}

// Setting: wallet.caps.set sets a cap where there was none and lowers
// one; a larger value, null and per_tx_sats above per_period_sats are
// bad_request (the first two use_wallet_caps_raise); a desktop is
// forbidden; a stale version is conflict; a lower cap applies at once
// against what the period holds.
func TestCapsSet(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	v := c.w().Version
	r := c.set(map[string]any{"per_tx_sats": 5000, "per_period_sats": 20000})
	if got := num(t, e.ok(r), "version"); got != int64(v+1) {
		t.Fatalf("version %d", got)
	}
	if w := c.w(); w.Caps.PerTx != 5000 || w.Caps.PerPeriod != 20000 {
		t.Fatalf("caps %+v", w.Caps)
	}
	if _, ok := hasActivity(e, "wallet.caps_lowered"); !ok {
		t.Fatal("not audited")
	}
	if a, _ := hasActivity(e, "wallet.caps_lowered"); a.Ref != c.id || a.Feed {
		t.Fatalf("audit %+v", a)
	}
	changed := e.h.SentOfType("sync.event")
	if len(changed) == 0 || !strings.Contains(string(changed[len(changed)-1].Body), "wallet.changed") {
		t.Fatal("no wallet.changed")
	}
	noValues(t, e, 5000, 20000)
	// Lower one.
	e.ok(c.set(map[string]any{"per_tx_sats": 4000}))
	if c.w().Caps.PerTx != 4000 {
		t.Fatal("not lowered")
	}
	// The same value changes nothing: no new version.
	v = c.w().Version
	if got := num(t, e.ok(c.set(map[string]any{"per_tx_sats": 4000})), "version"); got != int64(v) || c.w().Version != v {
		t.Fatal("a no-op changed the version")
	}
	// A larger value and null are for wallet.caps.raise.
	for _, m := range []map[string]any{{"per_tx_sats": 4001}, {"per_period_sats": 20001}, {"per_tx_sats": nil}, {"per_period_sats": nil}} {
		r := c.set(m)
		if r.Code != "bad_request" || r.Message != "use_wallet_caps_raise" {
			t.Fatalf("%v: %q %q", m, r.Code, r.Message)
		}
	}
	// per_tx_sats above per_period_sats (the effective values).
	if r := c.set(map[string]any{"per_period_sats": 3000}); r.Code != "bad_request" {
		t.Fatalf("period below tx: %q", r.Code)
	}
	d := newCapEnv(t)
	if r := d.set(map[string]any{"per_tx_sats": 9000, "per_period_sats": 8000}); r.Code != "bad_request" {
		t.Fatalf("tx above period: %q", r.Code)
	}
	// Out of range, wrong type, nothing to set.
	for _, m := range []map[string]any{{"per_tx_sats": 0}, {"per_tx_sats": -1}, {"per_tx_sats": 2100000000000001}, {"per_tx_sats": "5"}, {"per_tx_sats": 1.5}, {}} {
		if r := d.set(m); r.Code != "bad_request" {
			t.Fatalf("%v: %q", m, r.Code)
		}
	}
	e.ok(d.set(map[string]any{"per_tx_sats": 2100000000000000})) // the largest
	// A desktop is forbidden; a stale version is a conflict; no wallet.
	e.code(e.call("desktop", "wallet.caps.set", js(map[string]any{"wallet_id": c.id, "version": c.w().Version, "per_tx_sats": 1})), "forbidden")
	e.code(e.call("app", "wallet.caps.set", js(map[string]any{"wallet_id": c.id, "version": c.w().Version - 1, "per_tx_sats": 1})), "conflict")
	e.code(e.call("app", "wallet.caps.set", js(map[string]any{"wallet_id": "01JB2Z6V9K3M4N5P6Q7R8S9T0V", "version": 1, "per_tx_sats": 1})), "not_found")

	// A lower cap applies at once and counts what the period holds.
	f := newCapEnv(t)
	f.e.ok(f.e.sign(f.id, f.psbt(80000), nil))
	f.mustSet(map[string]any{"per_period_sats": 90000})
	o := refusal(t, f.e.sign(f.id, f.psbt(20000), nil), "per_period")
	if num(t, o, "remaining_sats") != 10000 {
		t.Fatalf("body %s", js(o))
	}
	f.mustSet(map[string]any{"per_period_sats": 50000}) // below what is already spent
	o = refusal(t, f.e.sign(f.id, f.psbt(1330), nil), "per_period")
	if num(t, o, "remaining_sats") != 0 {
		t.Fatalf("body %s", js(o))
	}
}

// wallet.create may carry caps, validated as wallet.caps.set validates.
func TestCapsAtCreate(t *testing.T) {
	e := newEnv(t, nil)
	mk := func(caps any) featuretest.Result {
		return e.sealed("app", "wallet.create", map[string]any{"name": "C", "network": "regtest", "caps": caps}, map[string]any{"password": pw}, true, false)
	}
	for _, bad := range []any{map[string]any{"per_tx_sats": 9, "per_period_sats": 8}, map[string]any{"per_tx_sats": 0}, map[string]any{"per_tx_sats": nil},
		map[string]any{"per_period_sats": "x"}, 5, "x", []int{1}} {
		if r := mk(bad); r.Code != "bad_request" {
			t.Fatalf("%v: %q", bad, r.Code)
		}
	}
	o := e.ok(mk(map[string]any{"per_tx_sats": 500000, "per_period_sats": 2000000}))
	caps, _ := o.Object("caps")
	if num(t, caps, "per_tx_sats") != 500000 || num(t, caps, "per_period_sats") != 2000000 || num(t, caps, "period_seconds") != 86400 || num(t, caps, "spent_sats") != 0 {
		t.Fatalf("caps %s", js(caps))
	}
	// Without caps: present, with the period and the total only.
	o = e.ok(e.sealed("app", "wallet.create", map[string]any{"name": "N", "network": "regtest"}, map[string]any{"password": pw}, true, false))
	caps, _ = o.Object("caps")
	if caps.Has("per_tx_sats") || caps.Has("per_period_sats") || num(t, caps, "period_seconds") != 86400 || !caps.Has("spent_sats") {
		t.Fatalf("caps %s", js(caps))
	}
}

// Raising: a wrong PIN or password is bad_pin or bad_password, counts as
// a failed check, changes nothing; a payload_sha256 over other values or
// another wallet is bad_request; a request that raises nothing is
// bad_request; a success rotates the CEK, audits wallet.caps_raised,
// makes the feed item and leaves the ledger as it was; null removes a
// cap; it works with the unlock window closed.
func TestCapsRaise(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_tx_sats": 1000000, "per_period_sats": 2000000})
	e.ok(e.sign(c.id, c.psbt(50000), nil))
	ledger := c.ledger()
	e.ok(e.call("app", "credential.lock", `{}`)) // no unlock window: not needed
	was := c.w()
	same := func(what string) {
		t.Helper()
		if w := c.w(); w.Caps != was.Caps || w.Version != was.Version {
			t.Fatalf("%s changed the wallet", what)
		}
	}

	// A wrong PIN: bad_pin, a failed check, the password not tried.
	m := map[string]any{"per_period_sats": 3000000}
	tx, per := c.after(m)
	good := bind(c.id, c.w().Version, tx, per)
	e.code(c.raiseWith(m, "000001", pw, good), "bad_pin")
	if len(e.h.CheckFailed) != 1 || e.h.CheckFailed[0] != "pin" {
		t.Fatalf("failed checks %v", e.h.CheckFailed)
	}
	same("a wrong PIN")
	e.code(c.raiseWith(m, e.h.PIN, "not the password 91", good), "bad_password")
	if len(e.h.CheckFailed) != 2 || e.h.CheckFailed[1] != "password" {
		t.Fatalf("failed checks %v", e.h.CheckFailed)
	}
	same("a wrong password")

	// The binding: other values, another wallet, another version.
	other := "01JB2Z6V9K3M4N5P6Q7R8S9T0V"
	for name, h := range map[string]string{
		"other values":   bind(c.id, c.w().Version, tx, "3000001"),
		"other wallet":   bind(other, c.w().Version, tx, per),
		"other version":  bind(c.id, c.w().Version+1, tx, per),
		"none vs number": bind(c.id, c.w().Version, "none", per),
		"not a hash":     base64.StdEncoding.EncodeToString([]byte("short")),
	} {
		if r := c.raiseWith(m, e.h.PIN, pw, h); r.Code != "bad_request" {
			t.Fatalf("%s: %q", name, r.Code)
		}
	}
	// The sealed item_id must be the wallet.
	{
		h := bind(c.id, c.w().Version, tx, per)
		r := e.sealed("app", "wallet.caps.raise", map[string]any{"wallet_id": c.id, "version": c.w().Version, "per_period_sats": 3000000},
			map[string]any{"pin": e.h.PIN, "password": pw, "item_id": "01JB2Z6V9K3M4N5P6Q7R8S9T0V", "payload_sha256": h}, true, false)
		e.code(r, "bad_request")
	}
	same("a bad binding")
	if len(e.h.CheckFailed) != 2 {
		t.Fatal("a bad binding counted as a failed check")
	}
	// Raises nothing: equal values, lower values, a cap set where none was,
	// a null where none is.
	for name, mm := range map[string]map[string]any{
		"equal":  {"per_period_sats": 2000000},
		"lower":  {"per_tx_sats": 900000},
		"nobody": {},
	} {
		if r := c.raise(mm); r.Code != "bad_request" {
			t.Fatalf("%s: %q", name, r.Code)
		}
	}
	// per_tx above per_period after the request.
	if r := c.raise(map[string]any{"per_tx_sats": 2500000}); r.Code != "bad_request" {
		t.Fatalf("tx above period: %q", r.Code)
	}
	same("a request that raises nothing")
	// A desktop and a stale version.
	e.code(e.call("desktop", "wallet.caps.raise", js(map[string]any{"wallet_id": c.id, "version": c.w().Version, "per_period_sats": 3000000})), "forbidden")
	{
		old := c.w().Version - 1
		tx2, per2 := c.after(m)
		r := c.e.sealed("app", "wallet.caps.raise", map[string]any{"wallet_id": c.id, "version": old, "per_period_sats": 3000000},
			map[string]any{"pin": e.h.PIN, "password": pw, "item_id": c.id, "payload_sha256": bind(c.id, old, tx2, per2)}, true, false)
		e.code(r, "conflict")
	}
	same("a stale version")

	// The good request: raised with the window closed; the CEK rotates, the
	// ledger stays, the audit entry and the feed item carry no value.
	blob := e.blob
	e.h.Reset()
	o := e.ok(c.raise(m))
	if e.blob == blob || !o.Has("credential") || !o.Has("credential_version") || !o.Has("utks") {
		t.Fatal("the credential did not rotate")
	}
	if got := num(t, o, "version"); got != int64(was.Version+1) || c.w().Caps.PerPeriod != 3000000 || c.w().Caps.PerTx != 1000000 {
		t.Fatalf("version %d caps %+v", got, c.w().Caps)
	}
	if got := c.ledger(); len(got) != len(ledger) || got[0] != ledger[0] {
		t.Fatalf("the ledger changed: %v", got)
	}
	a, ok := hasActivity(e, "wallet.caps_raised")
	if !ok || a.Ref != c.id || !a.Audit || !a.Feed || a.Priority != "high" {
		t.Fatalf("activity %+v", a)
	}
	if sy := e.h.SentOfType("sync.event"); len(sy) == 0 || !strings.Contains(string(sy[len(sy)-1].Body), "wallet.changed") {
		t.Fatal("no wallet.changed")
	}
	noValues(t, e, 3000000, 2000000, 1000000)
	// It is not an owner check.
	if len(e.h.Passed) != 0 {
		t.Fatal("an owner check was recorded")
	}

	// null removes a cap; the other may be lowered in the same request.
	e.ok(c.raise(map[string]any{"per_period_sats": nil, "per_tx_sats": 900000}))
	if w := c.w(); w.Caps.PerPeriod != 0 || w.Caps.PerTx != 900000 {
		t.Fatalf("caps %+v", w.Caps)
	}
	// Unlimited again: a spend over the old cap signs.
	e.unlock()
	e.ok(e.sign(c.id, c.psbt(80000), nil))
}

// The ledger is kept whether or not caps are set, so a cap set later
// counts what was already spent; a duplicate import (same account keys)
// is exists.
func TestLedgerKeptWithoutCapsAndExists(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	e.ok(e.sign(c.id, c.psbt(60000), nil))
	if c.spent() != 60000 {
		t.Fatal("not kept")
	}
	view := e.ok(e.call("app", "wallet.get", js(map[string]any{"wallet_id": c.id})))
	caps, _ := view.Object("caps")
	if caps.Has("per_period_sats") || num(t, caps, "spent_sats") != 60000 {
		t.Fatalf("caps %s", js(caps))
	}
	c.mustSet(map[string]any{"per_period_sats": 100000})
	refusal(t, e.sign(c.id, c.psbt(40001), nil), "per_period")
	e.ok(e.sign(c.id, c.psbt(40000), nil))

	// The same phrase again: exists, in the same vault, whatever the name
	// or the receiving account; a passphrase makes other keys.
	imp := func(extra map[string]any, item map[string]any) featuretest.Result {
		outer := map[string]any{"name": "Copy", "network": "regtest"}
		for k, v := range extra {
			outer[k] = v
		}
		return e.sealed("app", "wallet.create", outer, map[string]any{"password": pw, "item": item}, true, false)
	}
	e.code(imp(nil, map[string]any{"mnemonic": abandon}), "exists")
	e.code(imp(map[string]any{"address_type": "p2tr", "caps": map[string]any{"per_tx_sats": 5}}, map[string]any{"mnemonic": strings.ToUpper(abandon)}), "exists")
	if n := len(e.wl.Wallets()); n != 1 {
		t.Fatalf("%d wallets", n)
	}
	e.ok(imp(nil, map[string]any{"mnemonic": abandon, "passphrase": "other keys"}))
}

// Two signing requests for one wallet cannot both pass on the same
// allowance, even with no flush between them; an RBF re-sign and the same
// PSBT under a new inner id are each counted in full.
func TestCapsAtomicAndRebuilt(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_period_sats": 100000})
	raw := c.psbt(60000)
	e.ok(e.sign(c.id, raw, nil))
	// The same PSBT under a new inner id (every call has one) counts again.
	refusal(t, e.sign(c.id, raw, nil), "per_period")
	// A fee bump: a PSBT for the same payment with a higher fee is a new
	// signing and counts in full.
	refusal(t, e.sign(c.id, c.psbt(61000), nil), "per_period")
	if c.spent() != 60000 {
		t.Fatalf("spent %d", c.spent())
	}
	e.ok(e.sign(c.id, c.psbt(40000), nil))
	if c.spent() != 100000 || len(c.ledger()) != 2 {
		t.Fatalf("ledger %v", c.ledger())
	}
}

// The period is a rolling window: an entry falls out exactly at at_ms +
// period; a clock that steps back counts future entries as now and never
// rewrites them; on a scaled build the period is 86,400 / time_scale and
// an entry made before a change of scale keeps its time.
func TestCapsTime(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_period_sats": 100000})
	e.ok(e.sign(c.id, c.psbt(100000), nil))
	at := time.UnixMilli(c.ledger()[0].AtMS)
	inspect := func(out int64) strictjson.Object {
		t.Helper()
		return e.ok(e.call("app", "wallet.psbt.inspect", js(map[string]any{"wallet_id": c.id, "psbt": base64.StdEncoding.EncodeToString(c.psbt(out))})))
	}
	// An entry counts while now < at + period: one millisecond short and it
	// does; at the instant it does not.
	e.clk.T = at.Add(day - time.Millisecond - time.Second)
	if cp, _ := inspect(1330).Object("cap"); cp == nil || func() bool { ok, _ := cp.Bool("ok"); return ok }() {
		t.Fatal("an entry fell out early")
	}
	e.clk.T = at.Add(day - time.Second) // the next call is a second later: exactly at+period
	if cp, _ := inspect(1330).Object("cap"); func() bool { ok, _ := cp.Bool("ok"); return !ok }() {
		t.Fatal("an entry did not fall out at at_ms + period")
	}

	// A clock stepped back: the future entry keeps counting until its own
	// at_ms + period, is not rewritten, and a new entry sorts before it.
	d := newCapEnv(t)
	d.mustSet(map[string]any{"per_period_sats": 100000})
	d.e.ok(d.e.sign(d.id, d.psbt(60000), nil))
	first := d.ledger()[0].AtMS
	d.e.clk.T = time.UnixMilli(first).Add(-2 * time.Hour)
	d.e.unlock()
	refusal(t, d.e.sign(d.id, d.psbt(50000), nil), "per_period") // counts as now
	d.e.ok(d.e.sign(d.id, d.psbt(40000), nil))
	l := d.ledger()
	if len(l) != 2 || l[1].AtMS != first || l[0].AtMS >= first || l[1].Sats != 60000 {
		t.Fatalf("ledger %v (first %d)", l, first)
	}
	// Its refusal's allowed_after is its own at_ms + period.
	o := refusal(t, d.e.sign(d.id, d.psbt(1330), nil), "per_period")
	if got, _ := o.String("allowed_after"); got != rfc(l[0].AtMS+day.Milliseconds()) {
		t.Fatalf("allowed_after %s", got)
	}

	// A scaled build: the period is 86,400 / time_scale, divided when the
	// check runs.
	s := newCapEnv(t)
	s.mustSet(map[string]any{"per_period_sats": 100000})
	s.e.ok(s.e.sign(s.id, s.psbt(100000), nil))
	made := s.ledger()[0]
	s.e.h.Scale = 24
	view := s.e.ok(s.e.call("app", "wallet.get", js(map[string]any{"wallet_id": s.id})))
	caps, _ := view.Object("caps")
	if num(t, caps, "period_seconds") != 3600 || num(t, caps, "spent_sats") != 100000 {
		t.Fatalf("caps %s", js(caps))
	}
	o = refusal(t, s.e.sign(s.id, s.psbt(1330), nil), "per_period")
	if got, _ := o.String("allowed_after"); got != rfc(made.AtMS+time.Hour.Milliseconds()) {
		t.Fatalf("allowed_after %s", got)
	}
	s.e.clk.T = time.UnixMilli(made.AtMS).Add(time.Hour)
	s.e.unlock()
	s.e.ok(s.e.sign(s.id, s.psbt(1330), nil)) // the entry has left the 1-hour period
	if l := s.ledger(); len(l) != 1 || l[0].Sats != 1330 {
		t.Fatalf("ledger %v", l)
	}
	// A change of scale moves no entry: back to 1, an entry made at 24
	// keeps its time and counts for the day.
	at24 := s.ledger()[0]
	s.e.h.Scale = 1
	view = s.e.ok(s.e.call("app", "wallet.get", js(map[string]any{"wallet_id": s.id})))
	caps, _ = view.Object("caps")
	if num(t, caps, "period_seconds") != 86400 || num(t, caps, "spent_sats") != 1330 || s.ledger()[0] != at24 {
		t.Fatalf("caps %s", js(caps))
	}
}

// 201 entries in a period merge the two oldest and never lower the total.
func TestCapsLedgerMerge(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_period_sats": 2100000000000000})
	total := int64(0)
	for i := 0; i < wallet.MaxLedger+1; i++ {
		out := int64(1330 + i)
		e.ok(e.sign(c.id, c.psbt(out), nil))
		total += out
		l := c.ledger()
		if len(l) > wallet.MaxLedger {
			t.Fatalf("%d entries", len(l))
		}
		if c.spent() != total {
			t.Fatalf("after %d signs: total %d, want %d", i+1, c.spent(), total)
		}
	}
	l := c.ledger()
	if len(l) != wallet.MaxLedger {
		t.Fatalf("%d entries", len(l))
	}
	// The merged entry has the later of the two times: the allowance is
	// never given back early. The first two signs (1330 and 1331) are one.
	if l[0].Sats != 1330+1331 {
		t.Fatalf("merged entry %v", l[0])
	}
	for i := 1; i < len(l); i++ {
		if l[i].AtMS < l[i-1].AtMS {
			t.Fatal("ledger out of order")
		}
	}
}

// Reveal: item.reveal of a capped wallet's item without pin is bad_request
// pin_required, with a wrong PIN is bad_pin and a failed check, with the
// right PIN works and is not an owner check; a wallet without caps reveals
// with the password alone; a pin that is present is checked whatever the
// wallet's caps.
func TestCapsReveal(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	reveal := func(extra map[string]any) featuretest.Result {
		p := map[string]any{"password": pw, "item_id": c.id}
		for k, v := range extra {
			p[k] = v
		}
		return e.sealed("app", "item.reveal", map[string]any{"item_id": c.id}, p, true, true)
	}
	// Without caps: the password alone.
	e.ok(reveal(nil))
	// A wrong PIN that is present is checked anyway.
	e.code(reveal(map[string]any{"pin": "000000"}), "bad_pin")
	if len(e.h.CheckFailed) != 1 || e.h.CheckFailed[0] != "pin" {
		t.Fatalf("failed checks %v", e.h.CheckFailed)
	}
	e.ok(reveal(map[string]any{"pin": e.h.PIN}))

	c.mustSet(map[string]any{"per_tx_sats": 1000})
	r := reveal(nil)
	if r.Code != "bad_request" || r.Message != "pin_required" {
		t.Fatalf("got %q %q", r.Code, r.Message)
	}
	e.code(reveal(map[string]any{"pin": "000000"}), "bad_pin")
	if len(e.h.CheckFailed) != 2 {
		t.Fatalf("failed checks %v", e.h.CheckFailed)
	}
	e.code(e.sealed("app", "item.reveal", map[string]any{"item_id": c.id},
		map[string]any{"password": "not the password 91", "pin": e.h.PIN, "item_id": c.id}, true, true), "bad_password")
	if len(e.h.CheckFailed) != 3 || e.h.CheckFailed[2] != "password" {
		t.Fatalf("failed checks %v", e.h.CheckFailed)
	}
	passed := len(e.h.Passed)
	e.ok(reveal(map[string]any{"pin": e.h.PIN}))
	if len(e.h.Passed) != passed {
		t.Fatal("a reveal is not an owner check")
	}
	// Only a per_period cap also counts, and removing every cap frees it.
	c.mustSet(map[string]any{"per_period_sats": 5000})
	c.e.ok(c.raise(map[string]any{"per_tx_sats": nil, "per_period_sats": nil}))
	e.ok(reveal(nil))
}

// wallet.psbt.inspect returns cap, the same check wallet.sign makes now,
// and writes nothing.
func TestCapsInspect(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	insp := func(kind string, out int64) strictjson.Object {
		t.Helper()
		o := e.ok(e.call(kind, "wallet.psbt.inspect", js(map[string]any{"wallet_id": c.id, "psbt": base64.StdEncoding.EncodeToString(c.psbt(out))})))
		cp, err := o.Object("cap")
		if err != nil {
			t.Fatalf("no cap in %s", js(o))
		}
		return cp
	}
	if ok, _ := insp("desktop", 5000).Bool("ok"); !ok {
		t.Fatal("a wallet without caps")
	}
	c.mustSet(map[string]any{"per_tx_sats": 9000, "per_period_sats": 10000})
	e.ok(e.sign(c.id, c.psbt(6000), nil))
	e.h.Reset()
	before := c.w()
	if ok, _ := insp("app", 3000).Bool("ok"); !ok {
		t.Fatal("it fits")
	}
	cp := insp("app", 4001)
	if ok, _ := cp.Bool("ok"); ok {
		t.Fatalf("cap %s", js(cp))
	}
	if r, _ := cp.String("reason"); r != "per_period" || num(t, cp, "limit_sats") != 10000 || num(t, cp, "remaining_sats") != 4000 {
		t.Fatalf("cap %s", js(cp))
	}
	if got, _ := cp.String("allowed_after"); got != rfc(c.ledger()[0].AtMS+day.Milliseconds()) {
		t.Fatalf("allowed_after %s", got)
	}
	if r, _ := insp("app", 9001).String("reason"); r != "per_tx" {
		t.Fatalf("reason %s", r)
	}
	if ok, _ := insp("desktop", 4000).Bool("ok"); !ok {
		t.Fatal("equal is allowed")
	}
	// It changes nothing and writes no audit entry.
	if len(e.h.Activities) != 0 || len(c.ledger()) != 1 || c.w().Version != before.Version || c.w().Caps != before.Caps {
		t.Fatalf("inspect changed state: %v", e.h.Activities)
	}
	// invalid_psbt first.
	e.code(e.call("app", "wallet.psbt.inspect", js(map[string]any{"wallet_id": c.id, "psbt": base64.StdEncoding.EncodeToString([]byte("nope"))})), "invalid_psbt")
}

// State: caps and ledger survive a lock and unlock (a save and load); a
// wallet's deletion removes them; a wallet from before caps has none and
// signs as before.
func TestCapsState(t *testing.T) {
	c := newCapEnv(t)
	e := c.e
	c.mustSet(map[string]any{"per_tx_sats": 80000, "per_period_sats": 100000})
	e.ok(e.sign(c.id, c.psbt(60000), nil))
	want := c.w()

	raw, err := e.wl.Save()
	if err != nil {
		t.Fatal(err)
	}
	wl2 := wallet.New(e.cred, e.it, e.opt)
	if err := wl2.Load(raw); err != nil {
		t.Fatal(err)
	}
	got := wl2.Wallets()[0]
	if got.Caps != want.Caps || len(got.Ledger) != 1 || got.Ledger[0] != want.Ledger[0] {
		t.Fatalf("restored %+v %v", got.Caps, got.Ledger)
	}
	// The restored feature enforces them, and the guard follows.
	e.it.SetGuard(wl2)
	for _, ts := range wl2.Types() {
		e.owner[ts.Type] = wl2
	}
	e.wl = wl2
	refusal(t, e.sign(c.id, c.psbt(40001), nil), "per_period")
	if !wl2.RevealNeedsPIN(c.id) {
		t.Fatal("the reveal guard was not restored")
	}

	// A wallet from before this release: no caps, no ledger, no fields.
	var st map[string]map[string]map[string]json.RawMessage
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	for _, w := range st["wallets"] {
		delete(w, "caps")
		delete(w, "ledger")
	}
	old, _ := json.Marshal(st)
	wl3 := wallet.New(e.cred, e.it, e.opt)
	if err := wl3.Load(old); err != nil {
		t.Fatal(err)
	}
	e.it.SetGuard(wl3)
	for _, ts := range wl3.Types() {
		e.owner[ts.Type] = wl3
	}
	e.wl = wl3
	view := e.ok(e.call("app", "wallet.get", js(map[string]any{"wallet_id": c.id})))
	caps, _ := view.Object("caps")
	if caps.Has("per_tx_sats") || caps.Has("per_period_sats") || num(t, caps, "spent_sats") != 0 {
		t.Fatalf("caps %s", js(caps))
	}
	e.ok(e.sign(c.id, c.psbt(90000), nil))
	if wl3.RevealNeedsPIN(c.id) {
		t.Fatal("no caps, no PIN")
	}

	// Deleting the wallet deletes its caps and ledger: the same phrase
	// imported again starts with neither.
	e.ok(e.sealed("app", "item.delete", map[string]any{"item_id": c.id}, map[string]any{"password": pw, "item_id": c.id}, true, false))
	e.ok(e.call("app", "wallet.list", `{}`))
	if len(e.wl.Wallets()) != 0 || e.wl.RevealNeedsPIN(c.id) {
		t.Fatal("the wallet survived its item")
	}
	id2, _ := e.importAs(btc.P2WPKH)
	d := &capW{e: e, id: id2}
	if w := d.w(); w.Caps != (wallet.Caps{}) || len(w.Ledger) != 0 {
		t.Fatalf("a new wallet inherited %+v", w)
	}
}

// Nothing the feature records holds an amount or a cap, and the feature
// writes no log line at all: it does not import a logger or print.
func TestCapsNoValuesInLogs(t *testing.T) {
	for _, f := range []string{"wallet.go", "caps.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		for _, bad := range []string{`"log"`, `"log/slog"`, "fmt.Print", "fmt.Fprint", "println(", "os.Stderr", "os.Stdout"} {
			if strings.Contains(src, bad) {
				t.Fatalf("%s uses %s", f, bad)
			}
		}
	}
}
