package vault

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// heldUnlink holds the old app's notice at t0 with a token valid for ttl.
func heldUnlink(t *testing.T, d *devFixture, t0 time.Time, ttl time.Duration) *PendingUnlink {
	t.Helper()
	d.m.mu.Lock()
	defer d.m.mu.Unlock()
	d.m.holdUnlink(d.devPeer, "t1", 2, t0)
	pu := d.m.st.PendingUnlink
	if pu == nil {
		t.Fatal("not held")
	}
	pu.TokenExp = t0.Add(ttl)
	return pu
}

// deliver sends the held notice at now and returns what the old app opens.
func deliver(t *testing.T, d *devFixture, now time.Time) []*envelope.Inner {
	t.Helper()
	d.relay.mu.Lock()
	d.relay.deposits = nil
	d.relay.mu.Unlock()
	d.m.mu.Lock()
	d.m.sendPendingUnlink(now)
	d.m.drainOutbox(context.Background())
	d.m.mu.Unlock()
	return d.inbox(d.self())["dev1"]
}

// §11.14.10 (owner decision 2026-10-23, vettid.org #404): the held notice
// keeps only the sending half of the old app's epoch, and the sealed copy
// a release before this one would send.
func TestPendingUnlinkKeepsSendHalfOnly(t *testing.T) {
	d := newDevFixture(t)
	pu := heldUnlink(t, d, time.Now().UTC(), 30*24*time.Hour)
	if pu.Epoch == nil || len(pu.Epoch.SendKey) != 32 || pu.Epoch.RecvKey != nil || pu.Epoch.RK != nil || pu.Epoch.Received != 0 {
		t.Fatalf("kept epoch %+v", pu.Epoch)
	}
	if len(pu.Payload) == 0 {
		t.Fatal("no sealed copy for an earlier release")
	}
	raw, err := json.Marshal(d.m.st)
	if err != nil {
		t.Fatal(err)
	}
	var st struct {
		PendingUnlink map[string]json.RawMessage `json:"pending_unlink"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	ep := string(st.PendingUnlink["epoch"])
	if ep == "" || strings.Contains(ep, `"recv_key"`) && !strings.Contains(ep, `"recv_key":null`) || strings.Contains(ep, `"rk"`) {
		t.Fatalf("stored epoch carries a receive key or rk: %s", ep)
	}
	if _, ok := st.PendingUnlink["until"]; ok {
		t.Fatal("a 7-day deletion time is still stored")
	}
	if _, err := handshake.ImportEpoch(*pu.Epoch); err == nil {
		t.Fatal("the send half imports as a full epoch")
	}
}

// The notice is delivered whatever its age while the token lives, sealed
// at delivery: its ts is fresh, so the old phone's 16-day rule for durable
// types (§8.4) does not refuse it, and its seq follows the copy sealed at
// the approval.
func TestPendingUnlinkSealedAtDelivery(t *testing.T) {
	for _, age := range []time.Duration{time.Hour, 8 * 24 * time.Hour, 20 * 24 * time.Hour, 30*24*time.Hour - time.Minute} {
		d := newDevFixture(t)
		sinkOf(d)
		t0 := time.Now().UTC().Add(-age)
		pu := heldUnlink(t, d, t0, 30*24*time.Hour)
		old, err := d.ep.Open(mustParse(t, pu.Payload))
		if err != nil {
			t.Fatalf("age %v: sealed copy: %v", age, err)
		}
		now := time.Now().UTC()
		got := deliver(t, d, now)
		if len(got) != 1 || got[0].Type != "device.unlinked" {
			t.Fatalf("age %v: delivered %+v", age, got)
		}
		in := got[0]
		if !strings.Contains(string(in.Body), `"reason":"transferred"`) || !strings.Contains(string(in.Body), `"transfer_id":"t1"`) {
			t.Fatalf("age %v: body %s", age, in.Body)
		}
		if in.TS.Before(now.Add(-time.Second)) || in.CheckTime(now, true) != nil {
			t.Fatalf("age %v: ts %v not fresh", age, in.TS)
		}
		if in.Seq != old.Seq+1 || in.ID == old.ID {
			t.Fatalf("age %v: seq %d after %d, id %s / %s", age, in.Seq, old.Seq, in.ID, old.ID)
		}
		if age > 16*24*time.Hour && !errors.Is(old.CheckTime(now, true), envelope.ErrClockPast) {
			t.Fatalf("age %v: the copy sealed at the approval would still pass", age)
		}
		if d.m.st.PendingUnlink != nil || !d.hasActivity("device.unlinked_sent") {
			t.Fatalf("age %v: not deleted or not audited", age)
		}
		if pu.Epoch.SendKey != nil || pu.Payload != nil {
			t.Fatalf("age %v: the kept send key or copy was not zeroized", age)
		}
	}
}

// A notice whose token has expired is deleted unsent and zeroized, at the
// first unlock and by housekeeping.
func TestPendingUnlinkTokenExpired(t *testing.T) {
	d := newDevFixture(t)
	t0 := time.Now().UTC().Add(-31 * 24 * time.Hour)
	pu := heldUnlink(t, d, t0, 30*24*time.Hour)
	if got := deliver(t, d, time.Now().UTC()); len(got) != 0 || d.m.st.PendingUnlink != nil {
		t.Fatalf("expired notice sent: %+v", got)
	}
	if pu.Epoch.SendKey != nil {
		t.Fatal("send key not zeroized")
	}
	d2 := newDevFixture(t)
	pu2 := heldUnlink(t, d2, t0, 30*24*time.Hour)
	d2.m.mu.Lock()
	d2.m.expirePendingUnlink(t0.Add(30*24*time.Hour - time.Second))
	kept := d2.m.st.PendingUnlink != nil
	d2.m.expirePendingUnlink(t0.Add(30 * 24 * time.Hour))
	gone := d2.m.st.PendingUnlink == nil
	d2.m.mu.Unlock()
	if !kept || !gone || pu2.Epoch.SendKey != nil {
		t.Fatalf("housekeeping: kept %v, gone %v", kept, gone)
	}
}

// A token without an expiry (not issued so) is bounded by the longest
// standing token from the approval.
func TestPendingUnlinkNoTokenExp(t *testing.T) {
	d := newDevFixture(t)
	t0 := time.Now().UTC()
	pu := heldUnlink(t, d, t0, 0)
	pu.TokenExp = time.Time{}
	if pu.expired(t0.Add(StandingMax-time.Second)) || !pu.expired(t0.Add(StandingMax)) {
		t.Fatal("bound")
	}
}

// A notice held by a release before this one (no epoch, a 7-day `until`)
// is kept while its token lives and sent as it was sealed.
func TestPendingUnlinkFromEarlierRelease(t *testing.T) {
	d := newDevFixture(t)
	t0 := time.Now().UTC().Add(-10 * 24 * time.Hour)
	pu := heldUnlink(t, d, t0, 30*24*time.Hour)
	legacy, _ := json.Marshal(map[string]any{"relay_url": pu.RelayURL, "mailbox": pu.Mailbox, "token": pu.Token,
		"token_exp": pu.TokenExp, "payload": pu.Payload, "transfer_id": "t1", "dek_version": 2, "at": t0,
		"until": t0.Add(7 * 24 * time.Hour)})
	var old PendingUnlink
	if err := json.Unmarshal(legacy, &old); err != nil {
		t.Fatal(err)
	}
	if old.Epoch != nil {
		t.Fatal("epoch from nowhere")
	}
	d.m.mu.Lock()
	d.m.st.PendingUnlink = &old
	d.m.expirePendingUnlink(time.Now().UTC())
	kept := d.m.st.PendingUnlink != nil
	d.m.mu.Unlock()
	if !kept {
		t.Fatal("deleted at its old 7 days")
	}
	got := deliver(t, d, time.Now().UTC())
	if len(got) != 1 || got[0].Type != "device.unlinked" || got[0].TS.Sub(t0).Abs() > time.Millisecond {
		t.Fatalf("legacy notice %+v", got)
	}
}

// The send half seals and cannot open; a full epoch state is refused by
// ImportSendOnly.
func TestSendOnlyEpoch(t *testing.T) {
	d := newDevFixture(t)
	kr := d.m.sessions[d.devPeer.ID]
	full := kr.Current().Export()
	if _, err := handshake.ImportSendOnly(full); err == nil {
		t.Fatal("a full epoch imported as a send half")
	}
	half, err := kr.Current().ExportSendOnly()
	if err != nil {
		t.Fatal(err)
	}
	e, err := handshake.ImportSendOnly(half)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := e.Seal(&envelope.Inner{ID: "01JAAAAAAAAAAAAAAAAAAAAAAA", Type: "x", TS: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Open(mustParse(t, raw)); !errors.Is(err, handshake.ErrEpochRetired) {
		t.Fatalf("send half opened: %v", err)
	}
	if in, err := d.ep.Open(mustParse(t, raw)); err != nil || in.Type != "x" {
		t.Fatalf("device cannot open: %v", err)
	}
}

func mustParse(t *testing.T, raw []byte) *envelope.Envelope {
	t.Helper()
	env, err := envelope.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// The old app renews the vault's standing token at the approval (owner
// decision 2026-10-23): the held notice takes the renewed token, and with
// it the token's full life (the fixture's token had 20 days left).
func TestPendingUnlinkTakesRenewedToken(t *testing.T) {
	d := newDevFixture(t)
	vaultPK := d.m.keys.relay.Public().(ed25519.PublicKey)
	tok, err := relayclient.New(d.devPeer.Relay.URL, d.devKey).MintToken(relayauth.EncodeKey(vaultPK), d.devPeer.Relay.URL,
		relayclient.TokenOptions{TTL: 30 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	before := d.devPeer.Standing.Exp
	d.sendAs(d.self(), "relay.token.issued", string(strictjson.NewBuilder().String("kind", "standing").String("token", tok).Bytes()))
	d.m.mu.Lock()
	d.m.holdUnlink(d.devPeer, "t1", 2, time.Now().UTC())
	pu := d.m.st.PendingUnlink
	d.m.mu.Unlock()
	if pu == nil || pu.Token != tok || !pu.TokenExp.After(before) || pu.TokenExp.Before(time.Now().Add(29*24*time.Hour)) {
		t.Fatalf("held notice token exp %v (was %v)", pu.TokenExp, before)
	}
}

// F1: the held notice is deleted at most StandingMax after the approval,
// even when its token claims a longer life.
func TestPendingUnlinkCappedAt30Days(t *testing.T) {
	d := newDevFixture(t)
	t0 := time.Now().UTC()
	pu := heldUnlink(t, d, t0, 400*24*time.Hour)
	if !pu.until().Equal(pu.At.Add(StandingMax)) {
		t.Fatalf("until %v, want the approval + 30 days", pu.until())
	}
	d.m.mu.Lock()
	d.m.expirePendingUnlink(pu.At.Add(StandingMax - time.Second))
	kept := d.m.st.PendingUnlink != nil
	d.m.expirePendingUnlink(pu.At.Add(StandingMax))
	gone := d.m.st.PendingUnlink == nil
	d.m.mu.Unlock()
	if !kept || !gone || pu.Epoch.SendKey != nil {
		t.Fatalf("kept %v, gone %v at 30 days", kept, gone)
	}
	// Delivery after the cap: deleted unsent.
	d2 := newDevFixture(t)
	heldUnlink(t, d2, t0.Add(-StandingMax-time.Minute), 400*24*time.Hour)
	if got := deliver(t, d2, time.Now().UTC()); len(got) != 0 {
		t.Fatalf("sent past 30 days: %+v", got)
	}
}

// F2: a lock zeroizes the kept send key in memory (the state was stored,
// under the DEK, before).
func TestPendingUnlinkWipedAtLock(t *testing.T) {
	d := newDevFixture(t)
	pu := heldUnlink(t, d, time.Now().UTC(), 30*24*time.Hour)
	if err := d.m.Lock(context.Background()); err != nil {
		t.Fatal(err)
	}
	if pu.Epoch.SendKey != nil || pu.Payload != nil {
		t.Fatal("kept send key not zeroized at the lock")
	}
}

// F3: a second transfer's notice replaces the first, whose kept send key
// is zeroized.
func TestPendingUnlinkReplacedWiped(t *testing.T) {
	d := newDevFixture(t)
	first := heldUnlink(t, d, time.Now().UTC(), 30*24*time.Hour)
	second := heldUnlink(t, d, time.Now().UTC(), 30*24*time.Hour)
	if first == second || first.Epoch.SendKey != nil || first.Payload != nil || second.Epoch.SendKey == nil {
		t.Fatal("the earlier notice was not zeroized when replaced")
	}
}
