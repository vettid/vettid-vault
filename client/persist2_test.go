package client

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Config.Persist follow-ups: the retry after a Persist error, what the
// waiting calls see before a batch is saved, and the outbox's rules.

// After a Persist error the next Poll saves again before collecting,
// even when the relay has nothing to deliver (here: it still holds the
// batch under its visibility timeout), and the deposits go out then.
// The batch's events reach the caller only once it is saved.
func TestPersistRetriedWithoutRedelivery(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	fail := true
	d.cfg.Persist = func(b []byte) error {
		if fail {
			return errors.New("disk full")
		}
		return keep(&saved, r)(b)
	}
	r.mu.Lock()
	r.lease = true
	r.mu.Unlock()
	ids, _, _ := sendBatch(v)
	if err := d.Poll(context.Background()); err == nil {
		t.Fatal("no Persist error")
	}
	if ev := d.Events(); len(ev) != 0 {
		t.Fatalf("%d events of an unsaved batch reached the caller", len(ev))
	}
	fail = false
	mark := len(r.entries())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.entries()[mark:]
	want := []string{"persist", "deposit " + v.mailbox()}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("relay calls %v, want %v (saved and sent with the batch still leased)", got, want)
	}
	if ev := d.Events(); len(ev) != 2 { // device.paired, relay.token.issued
		t.Fatalf("%d events after the save, want 2", len(ev))
	}
	if st := loadState(t, saved); st.DeviceID != "dev-1" {
		t.Fatal("not saved")
	}
	// The relay delivers the batch again: acknowledged, nothing to save.
	r.mu.Lock()
	r.lease, r.leased = false, nil
	r.mu.Unlock()
	mark = len(r.entries())
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	got = r.entries()[mark:]
	want = []string{"ack " + ids[0], "ack " + ids[1], "ack " + ids[2]}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("relay calls %v, want %v", got, want)
	}
	checkRekeyed(t, r, v, d)
}

// A pairing's SAS is returned only once its hs.fin is saved and
// deposited: with a failing first Persist, awaitHandshake keeps polling
// until the retry saved it and the hs.fin reached the vault's mailbox.
func TestAwaitHandshakeAfterFinSent(t *testing.T) {
	r, v, d := startPair(t)
	calls := 0
	var saved []byte
	d.cfg.Persist = func(b []byte) error {
		calls++
		if calls == 1 {
			return errors.New("disk full")
		}
		return keep(&saved, nil)(b)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sas, err := d.awaitHandshake(ctx)
	if err != nil || sas == "" {
		t.Fatalf("awaitHandshake: %q %v", sas, err)
	}
	if calls != 2 || len(r.pending(v.mailbox())) != 1 {
		t.Fatalf("returned with %d Persist calls and %d messages for the vault, want 2 and the hs.fin", calls, len(r.pending(v.mailbox())))
	}
	if st := loadState(t, saved); st.Outgoing != nil || st.Vault == nil {
		t.Fatal("handshake not saved")
	}
	v.process()
	if v.kr.Current() == nil {
		t.Fatal("vault did not complete the handshake")
	}
}

// An hs.fin the relay refuses for good fails awaitHandshake instead of
// returning a SAS for a handshake the vault cannot finish.
func TestAwaitHandshakeFinRefused(t *testing.T) {
	for _, c := range []struct {
		code string
		want error
	}{{"injected", ErrHandshakeUnsent}, {"token_revoked", ErrRefused}} {
		t.Run(c.code, func(t *testing.T) {
			r, _, d := startPair(t)
			d.cfg.Persist = keep(new([]byte), nil)
			r.mu.Lock()
			r.failDeposit, r.depositStatus, r.depositCode = 1, http.StatusForbidden, c.code
			r.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if sas, err := d.awaitHandshake(ctx); !errors.Is(err, c.want) {
				t.Fatalf("awaitHandshake: %q %v, want %v", sas, err, c.want)
			}
		})
	}
}

// token_revoked on the vault's mailbox: Poll returns ErrRefused, still
// acknowledges the batch (§8.6: a refused answer does not block the
// mailbox), drops the outbox and sends nothing more; Refused reports it.
func TestPersistTokenRevoked(t *testing.T) {
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), nil)
	v.startRekey()
	r.mu.Lock()
	r.failDeposit, r.depositStatus, r.depositCode = 1, http.StatusForbidden, "token_revoked"
	r.mu.Unlock()
	if err := d.Poll(context.Background()); !errors.Is(err, ErrRefused) {
		t.Fatalf("Poll: %v, want ErrRefused", err)
	}
	if got := r.pending(v.dev.Mailbox); len(got) != 0 {
		t.Fatalf("batch not acknowledged after the refusal: %v", got)
	}
	if !errors.Is(d.Refused(), ErrRefused) || d.st.Outbox != nil {
		t.Fatal("refusal not recorded, or outbox kept")
	}
	mark := len(r.entries())
	if _, err := d.Send(context.Background(), "vault.status", []byte(`{}`)); !errors.Is(err, ErrRefused) {
		t.Fatalf("Send after the refusal: %v", err)
	}
	for _, e := range r.entries()[mark:] {
		if strings.HasPrefix(e, "deposit") {
			t.Fatal("deposited after the refusal")
		}
	}
	// The device keeps collecting its own mailbox.
	v.send("device.unlinked", []byte(`{}`))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ev := d.Events(); len(ev) != 1 || ev[0].Type != "device.unlinked" {
		t.Fatal("device.unlinked not received after the refusal")
	}
}

// Without Persist, a direct deposit answered token_revoked is ErrRefused
// too, and nothing more is sent.
func TestNoPersistTokenRevoked(t *testing.T) {
	r, _, d := pair(t)
	r.mu.Lock()
	r.failDeposit, r.depositStatus, r.depositCode = 1, http.StatusForbidden, "token_revoked"
	r.mu.Unlock()
	if _, err := d.Send(context.Background(), "vault.status", []byte(`{}`)); !errors.Is(err, ErrRefused) {
		t.Fatalf("Send: %v, want ErrRefused", err)
	}
	mark := len(r.entries())
	if _, err := d.Send(context.Background(), "vault.status", []byte(`{}`)); !errors.Is(err, ErrRefused) {
		t.Fatalf("second Send: %v", err)
	}
	if len(r.entries()) != mark {
		t.Fatal("deposited after the refusal")
	}
}

// Outbox rules: an entry for another relay URL or mailbox than the vault
// record's is dropped unsent; token and refresh entries keep only the
// newest; past outboxCap entries the oldest goes.
func TestOutboxRules(t *testing.T) {
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), nil)
	now := time.Now()
	d.mu.Lock()
	d.batching = true
	d.queueLocked(OutboxEntry{Kind: "token", RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte("t1"), Created: now})
	d.queueLocked(OutboxEntry{Kind: "refresh", RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte("r1"), Created: now})
	d.queueLocked(OutboxEntry{Kind: "token", RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte("t2"), Created: now})
	d.queueLocked(OutboxEntry{Kind: "refresh", RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte("r2"), Created: now})
	var got []string
	for _, e := range d.st.Outbox {
		got = append(got, string(e.Payload))
	}
	if strings.Join(got, ",") != "t2,r2" {
		t.Fatalf("outbox %v, want the newest token and refresh only", got)
	}
	d.st.Outbox = nil
	for i := 0; i < outboxCap+6; i++ {
		d.queueLocked(OutboxEntry{RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte{byte(i)}, Created: now})
	}
	if len(d.st.Outbox) != outboxCap || d.st.Outbox[0].Payload[0] != 6 {
		t.Fatalf("outbox of %d starting at %d, want %d starting at 6", len(d.st.Outbox), d.st.Outbox[0].Payload[0], outboxCap)
	}
	d.st.Outbox = []OutboxEntry{
		{RelayURL: r.url(), Mailbox: "aaaaaaaaaaaaaaaaaaaaaaaaaa", Payload: []byte("x"), Created: now},
		{RelayURL: "http://127.0.0.2:1", Mailbox: v.mailbox(), Payload: []byte("y"), Created: now},
		{RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte("z"), Created: now.Add(-outboxMaxAge - time.Minute)},
	}
	d.outboxSaved = 3
	d.batching = false
	d.mu.Unlock()
	mark := len(r.entries())
	if err := d.flushOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.entries()) != mark || d.st.Outbox != nil || d.outboxSaved != 0 {
		t.Fatal("stale entries were deposited or kept")
	}
}

// 429 (and other transient failures) back the outbox off instead of
// retrying its head at every Poll.
func TestOutboxBackoff(t *testing.T) {
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), nil)
	v.startRekey()
	r.mu.Lock()
	r.failDeposit, r.depositStatus = 3, http.StatusTooManyRequests // the relay client's 3 attempts
	r.mu.Unlock()
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(d.st.Outbox) != 1 || d.outboxFails != 1 || d.outboxNext.IsZero() {
		t.Fatal("no backoff after a 429")
	}
	mark := len(r.entries())
	d.mu.Lock()
	d.outboxNext = time.Now().Add(time.Hour) // a backoff still running
	d.mu.Unlock()
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r.entries()) != mark {
		t.Fatal("outbox tried during its backoff")
	}
	d.cfg.Now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.st.Outbox != nil || d.outboxFails != 0 {
		t.Fatal("not sent after the backoff")
	}
	checkRekeyed(t, r, v, d)
	for n := 1; n < 20; n++ {
		if b := outboxBackoff(n); b <= 0 || b > 30*time.Second {
			t.Fatalf("backoff %d: %v", n, b)
		}
	}
}
