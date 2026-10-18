package client

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// A refused device cannot start a pairing: its relay key is refused and a
// re-pairing needs a new one (§6.7).
func TestRefusedDeviceCannotPair(t *testing.T) {
	r, _, d := pair(t)
	r.mu.Lock()
	r.failDeposit, r.depositStatus, r.depositCode = 1, http.StatusForbidden, "token_revoked"
	r.mu.Unlock()
	if _, err := d.Send(context.Background(), "vault.status", []byte(`{}`)); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
	d.mu.Lock()
	err := d.startInit(handshake.PurposeApp, testVaultID, d.st.Vault.Token, nil)
	d.mu.Unlock()
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("startInit on a refused device: %v", err)
	}
}

// Without Persist, an hs.fin whose direct deposit fails ends
// awaitHandshake with the error, not a SAS.
func TestAwaitHandshakeFinRefusedNoPersist(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
		want   error
	}{{http.StatusForbidden, "injected", ErrHandshakeUnsent}, {http.StatusForbidden, "token_revoked", ErrRefused},
		{http.StatusServiceUnavailable, "injected", ErrHandshakeUnsent}} {
		t.Run(c.code, func(t *testing.T) {
			r, _, d := startPair(t)
			r.mu.Lock()
			r.failDeposit, r.depositStatus, r.depositCode = 3, c.status, c.code // past the relay client's attempts
			r.mu.Unlock()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if sas, err := d.awaitHandshake(ctx); !errors.Is(err, c.want) {
				t.Fatalf("awaitHandshake: %q %v, want %v", sas, err, c.want)
			}
		})
	}
}

// A new pairing removes an earlier pairing's hs.fin still waiting, and
// its failure, so they cannot fail or delay the new one.
func TestNewPairingDropsOldFin(t *testing.T) {
	r, v, d := pair(t)
	d.mu.Lock()
	d.batching = true
	d.queueLocked(OutboxEntry{Kind: "hs.fin", RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte("old"), Created: time.Now()})
	d.queueLocked(OutboxEntry{Kind: "token", RelayURL: r.url(), Mailbox: v.mailbox(), Payload: []byte("t"), Created: time.Now()})
	d.batching = false
	d.finErr = ErrHandshakeUnsent
	err := d.startInit(handshake.PurposeApp, testVaultID, d.st.Vault.Token, nil)
	queued, finErr, n := d.queued("hs.fin"), d.finErr, len(d.st.Outbox)
	d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if queued || finErr != nil || n != 1 {
		t.Fatalf("after a new pairing: hs.fin queued %v, finErr %v, %d entries (want the token only)", queued, finErr, n)
	}
}

// retry_after is honoured up to an hour, and a huge one does not
// overflow.
func TestRetryAfterClamp(t *testing.T) {
	for _, c := range []struct {
		ra   int
		want time.Duration
	}{{0, 0}, {5, 5 * time.Second}, {3600, time.Hour}, {7200, time.Hour}, {1 << 62, time.Hour}} {
		if got := retryAfter(&relayclient.Error{Status: 429, RetryAfter: c.ra}); got != c.want {
			t.Errorf("retry_after %d: %v, want %v", c.ra, got, c.want)
		}
	}
}

// While Persist keeps failing, a waiting call ends with its context and
// says why: the last Persist error, also from PersistError.
func TestWaitReportsPersistError(t *testing.T) {
	_, v, d := pair(t)
	errDisk := errors.New("disk full")
	failing := true
	d.cfg.Persist = func([]byte) error {
		if failing {
			return errDisk
		}
		return nil
	}
	v.send("test.ping", []byte(`{}`))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := d.WaitEvent(ctx, "test.ping", nil)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, errDisk) {
		t.Fatalf("WaitEvent: %v, want the deadline and the Persist error", err)
	}
	if !errors.Is(d.PersistError(), errDisk) {
		t.Fatal("PersistError not set")
	}
	failing = false
	if _, err := d.WaitEvent(context.Background(), "test.ping", nil); err != nil {
		t.Fatal(err)
	}
	if d.PersistError() != nil {
		t.Fatal("PersistError kept after a save")
	}
}

// Without Persist, a refusal of a deposit made while handling (a rekey's
// hs.resp) is returned by Poll.
func TestNoPersistPollReturnsRefusal(t *testing.T) {
	r, v, d := pair(t)
	v.startRekey()
	r.mu.Lock()
	r.failDeposit, r.depositStatus, r.depositCode = 1, http.StatusForbidden, "token_revoked"
	r.mu.Unlock()
	if err := d.Poll(context.Background()); !errors.Is(err, ErrRefused) {
		t.Fatalf("Poll: %v, want ErrRefused", err)
	}
}

// Deliver under Persist saves before the message counts as seen: after a
// Persist error it is held and saved by the next Poll.
func TestDeliverPersists(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	fail := true
	d.cfg.Persist = func(b []byte) error {
		if fail {
			return errors.New("disk full")
		}
		return keep(&saved, nil)(b)
	}
	id := v.send("test.ping", []byte(`{}`))
	m := r.take(v.dev.Mailbox)[0]
	d.Deliver(context.Background(), m)
	if d.PersistError() == nil || len(d.Events()) != 0 {
		t.Fatal("an unsaved delivered message reached the caller")
	}
	fail = false
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ev := d.Events(); len(ev) != 1 {
		t.Fatalf("%d events after the save", len(ev))
	}
	if _, ok := loadState(t, saved).Seen[id]; !ok {
		t.Fatal("delivered message not saved as seen")
	}
}
