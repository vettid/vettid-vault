package counter

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// ModeCompliance is the only lock mode the counter accepts.
const ModeCompliance = "COMPLIANCE"

// Retention periods (§8.1).
const (
	PresentLock = recovery.PresentLockHours * time.Hour
	// LongLock is production's lock period of token, success and close
	// records, and the period of a counter not given one (WithRecordLock).
	LongLock = recovery.CounterLockYears * 365 * 24 * time.Hour
	// TokenWaitMargin is how long a token's lock outlasts its wait at
	// least (Spend): the token defines the attempt, and the wait record
	// counts only while its token is listed, so a token must never be
	// deletable while its wait runs, whatever the channel's period.
	TokenWaitMargin = 24 * time.Hour
)

// ErrUnavailable: the counter could not be read or nothing was recorded
// (`unavailable`, answered only when nothing was used, G8).
var ErrUnavailable = errors.New("counter: unavailable")

// Spend outcomes (§11.14.4).
const (
	Spent       = "spent"
	Lost        = "lost"
	Exhausted   = "exhausted"
	Closed      = "closed"
	Wait        = "wait"
	Unavailable = "unavailable"
)

// SpendResult is Spend's answer.
type SpendResult struct {
	Outcome   string
	At        time.Time // spent: the token's counter time
	WaitUntil time.Time // spent, lost, wait: when the next attempt is possible (zero: at once)
	Used      int
}

// Counter is one vault's attempt counter.
type Counter struct {
	b     Bucket
	names *recovery.Names
	unit  time.Duration
	// presentLock is the present records' lock: 96 hours, or the quiet
	// period plus a day if that is longer (WithQuiet), so that it always
	// exceeds the quiet period plus the 10-minute window (G5).
	presentLock time.Duration
	// recordLock is the channel's lock period of token, success and
	// close records (VAULT-MESSAGING 0.33.2 §11.14.4): LongLock unless
	// WithRecordLock set it.
	recordLock time.Duration
}

// WithQuiet makes the present records' lock at least quiet + 24 h.
func (c *Counter) WithQuiet(quiet time.Duration) *Counter {
	if l := quiet + 24*time.Hour; l > c.presentLock {
		c.presentLock = l
	}
	return c
}

// WithRecordLock sets the lock period of token, success and close records
// to the measured channel's (releasecfg.CounterLock: production 100
// years, staging one day). Zero or less leaves LongLock.
func (c *Counter) WithRecordLock(d time.Duration) *Counter {
	if d > 0 {
		c.recordLock = d
	}
	return c
}

// RecordLock returns the lock period of token, success and close records.
func (c *Counter) RecordLock() time.Duration { return c.recordLock }

// tokenLock is how long a token of attempt n is locked from the counter
// time of Spend's listing: the record period, or the attempt's wait plus
// TokenWaitMargin if that is longer (the token's own LastModified is a
// moment after now; the margin covers that).
func (c *Counter) tokenLock(n int) time.Duration {
	return max(c.recordLock, time.Duration(recovery.WaitUnits(n))*c.unit+TokenWaitMargin)
}

// New returns the counter of the vault whose names n are; unit is
// recovery_wait_unit_seconds (§11.10.8).
func New(b Bucket, n *recovery.Names, unit time.Duration) *Counter {
	return &Counter{b: b, names: n, unit: unit, presentLock: PresentLock, recordLock: LongLock}
}

// Names returns the vault's counter names.
func (c *Counter) Names() *recovery.Names { return c.names }

func (c *Counter) view(ctx context.Context, g uint64) (*View, Listing, error) {
	l, err := c.b.List(ctx, c.names.Prefix())
	if err != nil || l.Date.IsZero() {
		return nil, Listing{}, ErrUnavailable
	}
	v := parse(l, c.names, g)
	if err := c.computeWait(ctx, v, l); err != nil {
		return nil, Listing{}, ErrUnavailable
	}
	return v, l, nil
}

// Status reads the generation's attempts, close and waits, and the
// vault's presence. Every time is the counter's own.
func (c *Counter) Status(ctx context.Context, g uint64) (*View, error) {
	v, _, err := c.view(ctx, g)
	return v, err
}

// Confirm is the read after a confirmed Spend (step 4b): the same listing,
// begun only after Spend answered.
func (c *Counter) Confirm(ctx context.Context, g uint64) (*View, error) { return c.Status(ctx, g) }

func lockedUntil(r Retention, want time.Time) bool {
	return r.Mode == ModeCompliance && !r.Until.Before(want)
}

// Spend takes attempt n of generation g and records the wait after it, in
// the order of §8.1. The caller never tries another number and never
// repeats a Spend by itself.
func (c *Counter) Spend(ctx context.Context, g uint64, n int) SpendResult {
	v, _, err := c.view(ctx, g)
	if err != nil {
		return SpendResult{Outcome: Unavailable}
	}
	switch {
	case v.Closed:
		return SpendResult{Outcome: Closed, Used: v.Used}
	case v.Exhausted():
		return SpendResult{Outcome: Exhausted, Used: v.Used}
	case n != v.Next() || n < 1 || n > recovery.MaxAttempts:
		return SpendResult{Outcome: Wait, Used: v.Used, WaitUntil: v.WaitUntil}
	case !v.WaitUntil.IsZero():
		return SpendResult{Outcome: Wait, Used: v.Used, WaitUntil: v.WaitUntil}
	}
	lost := func() SpendResult {
		return SpendResult{Outcome: Lost, Used: v.Used + 1, WaitUntil: v.Now.Add(time.Duration(recovery.WaitUnits(n)) * c.unit)}
	}
	// (2) the token, create-only, with a fresh random body.
	body, err := suite.RandomBytes(32)
	if err != nil {
		return SpendResult{Outcome: Unavailable, Used: v.Used}
	}
	name := c.names.Token(g, n)
	tokenUntil := v.Now.Add(c.tokenLock(n))
	status, myVersion, perr := c.b.PutCreate(ctx, name, body, tokenUntil)
	switch {
	case perr == nil && status == PutPrecondition:
		return SpendResult{Outcome: Wait, Used: v.Used} // another caller's: never another name
	case perr == nil && status == PutOK && myVersion != "":
	default:
		myVersion = "" // unknown outcome: go on without a version id
	}
	// (3) exactly one entry, a version, and mine.
	l, err := c.b.List(ctx, name)
	if err != nil {
		return lost()
	}
	var mine *Entry
	count := 0
	for i := range l.Entries {
		if l.Entries[i].Key == name {
			count++
			mine = &l.Entries[i]
		}
	}
	if count != 1 || mine.DeleteMarker || mine.VersionID == "" {
		return lost()
	}
	if myVersion != "" && mine.VersionID != myVersion {
		return lost()
	}
	if myVersion == "" {
		b, err := c.b.GetVersion(ctx, name, mine.VersionID)
		if err != nil || !bytes.Equal(b, body) {
			return lost()
		}
	}
	// (4) the lock read back. It must also outlast the wait the token
	// starts; it does unless the token's time is more than
	// TokenWaitMargin after the listing's, and then the attempt is lost.
	at := mine.LastModified
	waitUntil := at.Add(time.Duration(recovery.WaitUnits(n)) * c.unit)
	if r, err := c.b.GetRetention(ctx, name, mine.VersionID); err != nil || !lockedUntil(r, tokenUntil) || r.Until.Before(waitUntil) {
		return lost()
	}
	// (5) the wait record, create-only; a 412 is another caller's.
	if waitUntil.After(at) {
		wname := c.names.Wait(g, n)
		st, wv, err := c.b.PutCreate(ctx, wname, body, waitUntil)
		if err != nil || st != PutPrecondition && (st != PutOK || wv == "") {
			return SpendResult{Outcome: Lost, Used: v.Used + 1, WaitUntil: waitUntil}
		}
		if st == PutOK {
			if r, err := c.b.GetRetention(ctx, wname, wv); err != nil || !lockedUntil(r, waitUntil) {
				return SpendResult{Outcome: Lost, Used: v.Used + 1, WaitUntil: waitUntil}
			}
		}
	}
	return SpendResult{Outcome: Spent, At: at, WaitUntil: waitUntil, Used: v.Used + 1}
}

// createLocked writes a create-only record locked for the record period
// (100 years in production, a day on staging) and reads the lock back. A
// 412 means the record exists (precondition true).
func (c *Counter) createLocked(ctx context.Context, name string, now time.Time) (exists bool, err error) {
	body, err := suite.RandomBytes(32)
	if err != nil {
		return false, ErrUnavailable
	}
	until := now.Add(c.recordLock)
	st, ver, err := c.b.PutCreate(ctx, name, body, until)
	if err != nil {
		return false, ErrUnavailable
	}
	if st == PutPrecondition {
		return true, nil
	}
	if st != PutOK || ver == "" {
		return false, ErrUnavailable
	}
	r, err := c.b.GetRetention(ctx, name, ver)
	if err != nil || !lockedUntil(r, until) {
		return false, ErrUnavailable
	}
	return false, nil
}

// counterNow is the counter's time, from a listing of the vault's prefix.
func (c *Counter) counterNow(ctx context.Context) (time.Time, error) {
	l, err := c.b.List(ctx, c.names.Present())
	if err != nil || l.Date.IsZero() {
		return time.Time{}, ErrUnavailable
	}
	return l.Date, nil
}

// Succeed records that attempt n was a success, which ends its wait.
// Called only after the wrap opened.
func (c *Counter) Succeed(ctx context.Context, g uint64, n int) error {
	now, err := c.counterNow(ctx)
	if err != nil {
		return err
	}
	_, err = c.createLocked(ctx, c.names.Success(g, n), now)
	return err
}

// Close ends generation g for ever; it may be repeated.
func (c *Counter) Close(ctx context.Context, g uint64) error {
	now, err := c.counterNow(ctx)
	if err != nil {
		return err
	}
	_, err = c.createLocked(ctx, c.names.Close(g), now)
	return err
}

// MarkPresent records that the member is present now: one new version of
// the marker, locked for 96 hours, read back; at is its LastModified.
func (c *Counter) MarkPresent(ctx context.Context) (at time.Time, err error) {
	name := c.names.Present()
	now, err := c.counterNow(ctx)
	if err != nil {
		return time.Time{}, err
	}
	body, err := suite.RandomBytes(32)
	if err != nil {
		return time.Time{}, ErrUnavailable
	}
	until := now.Add(c.presentLock)
	ver, err := c.b.Put(ctx, name, body, until)
	if err != nil || ver == "" {
		return time.Time{}, ErrUnavailable
	}
	r, err := c.b.GetRetention(ctx, name, ver)
	if err != nil || !lockedUntil(r, until) {
		return time.Time{}, ErrUnavailable
	}
	l, err := c.b.List(ctx, name)
	if err != nil {
		return time.Time{}, ErrUnavailable
	}
	for _, e := range l.Entries {
		if e.Key == name && e.VersionID == ver {
			return e.LastModified, nil
		}
	}
	return time.Time{}, ErrUnavailable
}
