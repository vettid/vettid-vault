package client

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/suite"
)

// countRequests wraps the relay's handler to count every request.
func countRequests(r *fakeRelay) func() int {
	n := 0
	inner := r.srv.Config.Handler
	var mu = make(chan struct{}, 1)
	r.srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		mu <- struct{}{}
		n++
		<-mu
		inner.ServeHTTP(w, req)
	})
	return func() int { mu <- struct{}{}; defer func() { <-mu }(); return n }
}

// A refused device's Pair returns the refusal before touching the link:
// no claim is fetched (it is single use) and the vault record stays.
func TestRefusedPairFetchesNoClaim(t *testing.T) {
	r, _, d := pair(t)
	key, _ := suite.RandomBytes(suite.KeySize)
	q := &invite.QR{Kind: invite.KindApp, Relay: r.url(), ClaimID: relayauth.NewClaimID(), Key: key, Exp: time.Now().Add(time.Hour).Unix()}
	link, err := q.Link()
	if err != nil {
		t.Fatal(err)
	}
	requests := countRequests(r)
	// The link is good: an unrefused device fetches its claim.
	if _, err := d.Pair(context.Background(), link); err == nil || requests() != 1 {
		t.Fatalf("control: %v, %d requests", err, requests())
	}
	r.mu.Lock()
	r.failDeposit, r.depositStatus, r.depositCode = 1, http.StatusForbidden, "token_revoked"
	r.mu.Unlock()
	if _, err := d.Send(context.Background(), "vault.status", []byte(`{}`)); !errors.Is(err, ErrRefused) {
		t.Fatal(err)
	}
	d.mu.Lock()
	before := *d.st.Vault
	d.mu.Unlock()
	n := requests()
	if _, err := d.Pair(context.Background(), link); !errors.Is(err, ErrRefused) {
		t.Fatalf("Pair: %v, want ErrRefused", err)
	}
	if requests() != n {
		t.Fatal("the refused device contacted the relay (claim fetched)")
	}
	d.mu.Lock()
	after := *d.st.Vault
	d.mu.Unlock()
	if !reflect.DeepEqual(before, after) {
		t.Fatal("vault record changed")
	}
}

// CompleteEnrollment and CompleteRecoveryHandshake end with the error when
// the hs.fin is refused for good, instead of waiting for a device.paired
// the vault will never send.
func TestCompleteHandshakeFinRefused(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		for _, c := range []struct {
			code string
			want error
		}{{"injected", ErrHandshakeUnsent}, {"token_revoked", ErrRefused}} {
			name := c.code
			if recovery {
				name = "recovery/" + name
			}
			t.Run(name, func(t *testing.T) {
				r := newFakeRelay(t)
				v := newFakeVault(t, r)
				d, err := Generate(Config{Role: "app", Name: "phone", RelayURL: r.url(), HTTP: r.srv.Client(), PollWait: time.Second})
				if err != nil {
					t.Fatal(err)
				}
				v.dev, v.devIK = d.RelayAddr(), d.IdentityKey()
				d.st.VaultID = testVaultID
				d.st.Vault = &VaultRecord{IK: v.ik.Public().(ed25519.PublicKey), KEM: v.kem.Public().Bytes(), RelayURL: r.url(), Mailbox: v.mailbox(), RelayPK: v.relayPK()}
				tok := v.token(30 * 24 * time.Hour)
				if d.st.Vault.TokenExp, err = d.heldFromVault(tok); err != nil {
					t.Fatal(err)
				}
				d.st.Vault.Token = tok
				if recovery {
					d.st.Recovery = &RecoveryState{RecoveryID: "rec-1"}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				res := make(chan error, 1)
				go func() {
					if recovery {
						res <- d.CompleteRecoveryHandshake(ctx)
					} else {
						res <- d.CompleteEnrollment(ctx)
					}
				}()
				var in []byte
				for in == nil {
					if m := r.take(v.mailbox()); len(m) > 0 {
						in = m[0].Payload
					}
					time.Sleep(time.Millisecond)
				}
				now := time.Now()
				pi, err := handshake.OpenInit(in, func(k suite.Kid) *suite.PrivateKey { return v.kem }, now)
				if err != nil {
					t.Fatal(err)
				}
				_, env, err := pi.Respond(handshake.ResponderConfig{Identity: v.ik, Policy: handshake.PolicyVaultToDevice,
					CollectSender: v.dev.PK, Token: v.token(30 * 24 * time.Hour), Now: now})
				if err != nil {
					t.Fatal(err)
				}
				r.mu.Lock()
				r.failDeposit, r.depositStatus, r.depositCode = 3, http.StatusForbidden, c.code
				r.mu.Unlock()
				r.put(v.dev.Mailbox, v.relayPK(), env)
				select {
				case err := <-res:
					if !errors.Is(err, c.want) {
						t.Fatalf("got %v, want %v", err, c.want)
					}
				case <-time.After(15 * time.Second):
					t.Fatal("still waiting for device.paired")
				}
			})
		}
	}
}

// device.pair.rejected ends the pending handshake (and empties the
// outbox with the vault record).
func TestPairRejectedClearsPending(t *testing.T) {
	_, v, d := pair(t)
	if !d.st.PairingPending {
		t.Fatal("no pending handshake after startInit")
	}
	v.send(devicePairRejected, []byte(`{}`))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.st.PairingPending || d.st.Vault != nil || d.st.Outbox != nil {
		t.Fatalf("after device.pair.rejected: pending %v, vault %v, outbox %d", d.st.PairingPending, d.st.Vault != nil, len(d.st.Outbox))
	}
}

// Under Persist, a replayed device.paired (new msg_id) is dropped too:
// the state saved after it still holds the first one's id and token.
func TestPairedReplayDroppedPersist(t *testing.T) {
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	v.send("device.paired", pairedWith(v, "dev-1", "", 0))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := loadState(t, saved)
	if first.DeviceID != "dev-1" || first.PairingPending || len(d.Events()) != 1 {
		t.Fatal("first device.paired not saved")
	}
	v.send("device.paired", pairedWith(v, "dev-other", "", 0))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	after := loadState(t, saved)
	if after.DeviceID != "dev-1" || after.Vault.Token != first.Vault.Token || len(d.Events()) != 0 {
		t.Fatal("a replayed device.paired changed the saved state or reached the caller")
	}
}

// enrollFixture is a device with a vault record and token, before its
// first handshake (CompleteEnrollment) or a recovery's.
func enrollFixture(t *testing.T, recovery bool) (*fakeRelay, *fakeVault, *Device) {
	t.Helper()
	r := newFakeRelay(t)
	v := newFakeVault(t, r)
	d, err := Generate(Config{Role: "app", Name: "phone", RelayURL: r.url(), HTTP: r.srv.Client(), PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	v.dev, v.devIK = d.RelayAddr(), d.IdentityKey()
	d.st.VaultID = testVaultID
	d.st.Vault = &VaultRecord{IK: v.ik.Public().(ed25519.PublicKey), KEM: v.kem.Public().Bytes(), RelayURL: r.url(), Mailbox: v.mailbox(), RelayPK: v.relayPK()}
	tok := v.token(30 * 24 * time.Hour)
	if d.st.Vault.TokenExp, err = d.heldFromVault(tok); err != nil {
		t.Fatal(err)
	}
	d.st.Vault.Token = tok
	if recovery {
		d.st.Recovery = &RecoveryState{RecoveryID: "rec-1"}
	}
	return r, v, d
}

// answerInit waits for the device's hs.init and answers it as identity.
func answerInit(t *testing.T, r *fakeRelay, v *fakeVault, identity ed25519.PrivateKey) *handshake.Responder {
	t.Helper()
	var in []byte
	for in == nil {
		if m := r.take(v.mailbox()); len(m) > 0 {
			in = m[0].Payload
		}
		time.Sleep(time.Millisecond)
	}
	now := time.Now()
	pi, err := handshake.OpenInit(in, func(k suite.Kid) *suite.PrivateKey { return v.kem }, now)
	if err != nil {
		t.Fatal(err)
	}
	resp, env, err := pi.Respond(handshake.ResponderConfig{Identity: identity, Policy: handshake.PolicyVaultToDevice,
		CollectSender: v.dev.PK, Token: v.token(30 * 24 * time.Hour), Now: now})
	if err != nil {
		t.Fatal(err)
	}
	r.put(v.dev.Mailbox, v.relayPK(), env)
	return resp
}

// A handshake whose hs.resp aborted (signed by another identity than the
// pinned vault's) fails; a retry on the same Device then completes: the
// earlier failure does not carry over (CompleteEnrollment and
// CompleteRecoveryHandshake).
func TestCompleteHandshakeRetryAfterAbort(t *testing.T) {
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "enrollment", true: "recovery"}[recovery], func(t *testing.T) {
			r, v, d := enrollFixture(t, recovery)
			complete := func(ctx context.Context) error {
				if recovery {
					return d.CompleteRecoveryHandshake(ctx)
				}
				return d.CompleteEnrollment(ctx)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			res := make(chan error, 1)
			go func() { res <- complete(ctx) }()
			other := ed25519.NewKeyFromSeed(make([]byte, 32))
			answerInit(t, r, v, other)
			if err := <-res; !errors.Is(err, ErrProtocol) {
				t.Fatalf("aborted handshake: %v, want ErrProtocol", err)
			}

			go func() { res <- complete(ctx) }()
			v.resp = answerInit(t, r, v, v.ik)
			for v.kr.Current() == nil { // the hs.fin
				v.process()
				time.Sleep(time.Millisecond)
			}
			v.send("device.paired", pairedWith(v, "dev-1", "", 0))
			select {
			case err := <-res:
				if err != nil {
					t.Fatalf("retry: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("retry did not complete")
			}
			if d.DeviceID() != "dev-1" {
				t.Fatal("no device id")
			}
		})
	}
}
