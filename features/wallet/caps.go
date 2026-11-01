package wallet

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/items"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Spend caps (VAULT-MESSAGING 0.82.0 §10.18 "Spend caps"; first specified
// in 0.56.0). A wallet has two optional limits on what leaves it in
// transactions the vault signs: per transaction and per period (a rolling
// 24 hours, divided by the release's time scale, STAGING-TIME-SCALE S17).
// Both are in satoshis. The caps and the period's ledger are part of the
// wallet's record in DEK state.
//
// Nothing here puts an amount or a cap into the audit log, the feed, a
// sync.event or a log line (§10.18): the activities carry kinds and ids
// only, and the amounts reach the member's app in sealed responses.
const (
	// MaxCapSats is the largest cap: 21 million BTC in satoshis.
	MaxCapSats = 2_100_000_000_000_000
	// Period is the cap period before the time scale divides it.
	Period = 24 * time.Hour
	// MaxLedger is the most entries the period's ledger keeps.
	MaxLedger = 200
	// CapsLabel is the label of wallet.caps.raise's binding.
	CapsLabel = credwire.WalletCapsLabel
)

// Caps are a wallet's limits; zero is no limit (a cap is at least 1).
type Caps struct {
	PerTx     int64 `json:"per_tx,omitempty"`
	PerPeriod int64 `json:"per_period,omitempty"`
}

// LedgerEntry is one signed transaction's outflow. Entries are kept sorted
// by AtMS; the absolute time is never rewritten.
type LedgerEntry struct {
	AtMS int64 `json:"at_ms"`
	Sats int64 `json:"sats"`
}

// periodOf is the period of s's release: 86,400 seconds divided by the
// time scale (S17), in milliseconds.
func periodOf(s *vault.Session) int64 {
	return vault.Scale(Period, s.TimeScale()).Milliseconds()
}

// satCeil is where sums of satoshis saturate: one above the largest cap,
// so a saturated total is over every cap and never wraps.
const satCeil = MaxCapSats + 1

// sat adds two amounts, each at most satCeil, saturating at satCeil.
func sat(a, b int64) int64 { return min(a+b, satCeil) }

// spent is the ledger's total within the period: an entry counts while
// now < at + period.
func (w *Wallet) spent(nowMS, periodMS int64) int64 {
	var n int64
	for _, e := range w.Ledger {
		if nowMS < e.AtMS+periodMS {
			n = sat(n, e.Sats)
		}
	}
	return n
}

// record appends a signed transaction's outflow. Entries that have left
// the period are dropped; at the limit the two oldest entries merge into
// one with the later time, so the allowance is never given back early.
func (w *Wallet) record(nowMS, periodMS, sats int64) {
	kept := make([]LedgerEntry, 0, len(w.Ledger)+1)
	for _, e := range w.Ledger {
		if nowMS < e.AtMS+periodMS {
			kept = append(kept, e)
		}
	}
	if len(kept) >= MaxLedger {
		kept[1] = LedgerEntry{AtMS: kept[1].AtMS, Sats: sat(kept[0].Sats, kept[1].Sats)}
		kept = kept[1:]
	}
	i := len(kept)
	for i > 0 && kept[i-1].AtMS > nowMS { // a clock stepped back: keep the order
		i--
	}
	kept = append(kept, LedgerEntry{})
	copy(kept[i+1:], kept[i:])
	kept[i] = LedgerEntry{AtMS: nowMS, Sats: min(sats, satCeil)}
	w.Ledger = kept
}

// capRefusal is why a spend does not pass the caps (§10.18 "The refusal").
type capRefusal struct {
	reason    string // "per_tx" or "per_period"
	limit     int64
	remaining int64 // per_period only
	afterMS   int64 // per_period only; 0 when absent
}

// capCheck tests an outflow against the caps: per_tx first, then
// per_period against the ledger's total of the period. Equal is allowed.
// It changes nothing.
func (w *Wallet) capCheck(outflow, nowMS, periodMS int64) *capRefusal {
	if w.Caps.PerTx > 0 && outflow > w.Caps.PerTx {
		return &capRefusal{reason: "per_tx", limit: w.Caps.PerTx}
	}
	if w.Caps.PerPeriod == 0 {
		return nil
	}
	spent := w.spent(nowMS, periodMS)
	if sat(outflow, spent) <= w.Caps.PerPeriod {
		return nil
	}
	r := &capRefusal{reason: "per_period", limit: w.Caps.PerPeriod, remaining: max(w.Caps.PerPeriod-spent, 0)}
	if outflow > w.Caps.PerPeriod {
		return r // it would not fit even in an empty period: no allowed_after
	}
	// The earliest time it fits: when enough of the oldest entries have
	// left the period (entries are sorted, so they leave in order).
	room := w.Caps.PerPeriod - outflow
	var in []LedgerEntry
	for _, e := range w.Ledger {
		if nowMS < e.AtMS+periodMS {
			in = append(in, e)
		}
	}
	// rest[i] is the total of in[i:], saturating (the total spent may be
	// saturated, so it is not reduced entry by entry).
	rest := make([]int64, len(in)+1)
	for i := len(in) - 1; i >= 0; i-- {
		rest[i] = sat(rest[i+1], in[i].Sats)
	}
	for i, e := range in {
		if rest[i+1] <= room {
			r.afterMS = e.AtMS + periodMS
			break
		}
	}
	return r
}

// members adds the refusal's members to a body (cap_exceeded's, or
// wallet.psbt.inspect's `cap`).
func (r *capRefusal) members(b *strictjson.Builder) {
	b.String("reason", r.reason).Uint("limit_sats", uint64(r.limit))
	if r.reason == "per_period" {
		b.Uint("remaining_sats", uint64(r.remaining))
		if r.afterMS != 0 {
			b.String("allowed_after", envelope.FormatTS(time.UnixMilli(r.afterMS).UTC()))
		}
	}
}

// err is the cap_exceeded answer: the reason as message, the rest in the
// body (for the member's app, in the sealed response).
func (r *capRefusal) err() error {
	b := strictjson.NewBuilder()
	r.members(b)
	return &vault.HandlerError{Code: "cap_exceeded", Message: r.reason, Body: b.Bytes()}
}

// capsView is `<wallet>.caps`: always present; the caps absent when
// unlimited; period_seconds and spent_sats always.
func (w *Wallet) capsView(nowMS, periodMS int64) []byte {
	b := strictjson.NewBuilder()
	if w.Caps.PerTx > 0 {
		b.Uint("per_tx_sats", uint64(w.Caps.PerTx))
	}
	if w.Caps.PerPeriod > 0 {
		b.Uint("per_period_sats", uint64(w.Caps.PerPeriod))
	}
	return b.Uint("period_seconds", uint64(periodMS/1000)).Uint("spent_sats", uint64(w.spent(nowMS, periodMS))).Bytes()
}

// capMember is one cap member of a request: absent, null (no limit) or a
// value.
type capMember struct {
	present, null bool
	v             int64
}

var errUseRaise = vault.NewError("bad_request", "use_wallet_caps_raise")

// parseCapMember reads a cap member: an integer 1 to MaxCapSats, or null.
func parseCapMember(o strictjson.Object, name string) (capMember, error) {
	raw, ok := o[name]
	if !ok {
		return capMember{}, nil
	}
	if string(raw) == "null" {
		return capMember{present: true, null: true}, nil
	}
	v, err := strictjson.AsUint(raw, 1, MaxCapSats)
	if err != nil {
		return capMember{}, errBad
	}
	return capMember{present: true, v: int64(v)}, nil
}

// capMembers reads per_tx_sats and per_period_sats of o.
func capMembers(o strictjson.Object) (tx, per capMember, err error) {
	if tx, err = parseCapMember(o, "per_tx_sats"); err != nil {
		return
	}
	per, err = parseCapMember(o, "per_period_sats")
	return
}

// with returns the caps after a request: a present member replaces the
// current one (null removes it), an absent one is unchanged.
func (c Caps) with(tx, per capMember) Caps {
	if tx.present {
		c.PerTx = tx.v
	}
	if per.present {
		c.PerPeriod = per.v
	}
	return c
}

// consistent: when both are set per_tx MUST NOT exceed per_period.
func (c Caps) consistent() bool { return c.PerTx == 0 || c.PerPeriod == 0 || c.PerTx <= c.PerPeriod }

// parseNewCaps reads wallet.create's `caps`: the values a new wallet
// starts with, as wallet.caps.set would set them from none.
func parseNewCaps(o strictjson.Object) (Caps, error) {
	if !o.Has("caps") {
		return Caps{}, nil
	}
	co, err := o.Object("caps")
	if err != nil {
		return Caps{}, errBad
	}
	tx, per, err := capMembers(co)
	if err != nil {
		return Caps{}, err
	}
	if tx.null || per.null {
		return Caps{}, errUseRaise
	}
	c := Caps{}.with(tx, per)
	if !c.consistent() {
		return Caps{}, errBad
	}
	return c, nil
}

// capsSet is wallet.caps.set (app only, a versioned change): it may only
// lower. A member is accepted if it sets a cap where there was none or
// sets a smaller value; the same value changes nothing; a null or a
// larger value is bad_request (use_wallet_caps_raise), as is a per_tx
// above per_period. It applies at once and counts what the period holds.
func (f *Feature) capsSet(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	if s.From().Kind != vault.KindApp || s.From().Recovering {
		return nil, errForbid
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	version, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	tx, per, err := capMembers(o)
	if err != nil {
		return nil, err
	}
	if !tx.present && !per.present {
		return nil, errBad // nothing to set
	}
	if version != w.Version {
		return nil, vault.NewError("conflict", "")
	}
	changed := false
	for _, m := range []struct {
		new capMember
		cur int64
	}{{tx, w.Caps.PerTx}, {per, w.Caps.PerPeriod}} {
		if !m.new.present {
			continue
		}
		if m.new.null || m.cur != 0 && m.new.v > m.cur {
			return nil, errUseRaise
		}
		changed = changed || m.new.v != m.cur
	}
	next := w.Caps.with(tx, per)
	if !next.consistent() {
		return nil, errBad
	}
	if !changed {
		return strictjson.NewBuilder().Uint("version", w.Version).Bytes(), nil
	}
	w.Caps = next
	w.Version++
	f.syncOwned()
	s.SyncEvent("wallet.changed", strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).Bytes())
	s.Record(vault.Activity{Kind: "wallet.caps_lowered", Ref: w.ID, Audit: true})
	return strictjson.NewBuilder().Uint("version", w.Version).Bytes(), nil
}

// capsRaise is wallet.caps.raise: a credential operation of the holder
// with the PIN and the password (checked as an owner check checks them,
// not itself one; no unlock window needed) that raises or removes a cap.
// The UTK payload's item_id is the wallet and payload_sha256 the binding
// of the values the wallet will have. Any error leaves the caps as they
// were.
func (f *Feature) capsRaise(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	if s.From().Kind != vault.KindApp || s.From().Recovering {
		return nil, errForbid
	}
	if f.cred == nil {
		return nil, errUnavail
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	version, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	tx, per, err := capMembers(o)
	if err != nil {
		return nil, err
	}
	next := w.Caps.with(tx, per)
	check := func(p *credential.Payload) error {
		if version != w.Version {
			return vault.NewError("conflict", "")
		}
		// The values the wallet will have obey the model's rule; at least
		// one cap must be raised or removed.
		raises := false
		for _, m := range []struct {
			new capMember
			cur int64
		}{{tx, w.Caps.PerTx}, {per, w.Caps.PerPeriod}} {
			raises = raises || m.new.present && m.cur != 0 && (m.new.null || m.new.v > m.cur)
		}
		if !next.consistent() || !raises {
			return errBad
		}
		h := credwire.WalletCapsBinding(w.ID, w.Version, optCap(next.PerTx), optCap(next.PerPeriod))
		if p.ItemID != w.ID || !suite.Equal(p.PayloadHash, h[:]) {
			return errBad // the password and PIN authorise these numbers on this wallet only
		}
		return nil
	}
	res, err := f.cred.OperateSpec(s, in, credential.OpSpec{Need: credential.NeedItemID | credential.NeedHash | credential.NeedPIN, Check: check},
		func(*credential.Inner, *credential.Payload) error { return nil })
	if err != nil {
		return nil, err
	}
	w.Caps = next // the ledger is not cleared
	w.Version++
	f.syncOwned()
	s.SyncEvent("wallet.changed", strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).Bytes())
	s.Record(vault.Activity{Kind: "wallet.caps_raised", Ref: w.ID, Audit: true, Feed: true, Priority: "high"})
	b := strictjson.NewBuilder().Uint("version", w.Version)
	res.Members(b)
	return b.Bytes(), nil
}

func optCap(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

// capRefused audits a refused spend and makes a feed item of priority
// high; conn names the connection of a payment request. No amount, cap or
// reason is in either.
func (f *Feature) capRefused(s *vault.Session, w *Wallet, conn string) {
	s.Record(vault.Activity{Kind: "wallet.cap_refused", ConnectionID: conn, Ref: w.ID, Audit: true, Feed: true, Priority: "high"})
}

var _ items.RevealGuard = (*Feature)(nil)

// RevealNeedsPIN implements items.RevealGuard: the reveal of the phrase of
// a wallet that has a cap carries the PIN as well (§10.18).
func (f *Feature) RevealNeedsPIN(id string) bool {
	f.gmu.Lock()
	defer f.gmu.Unlock()
	return f.capped[id]
}
