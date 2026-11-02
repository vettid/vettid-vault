package client

import (
	"context"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-vault/vms/envelope"
)

func pingCount(d *Device) int {
	n := 0
	for _, e := range d.Events() {
		if e.Type == "test.ping" {
			n++
		}
	}
	return n
}

// §6.5, §8.3: a message of the new epoch that reaches the device before
// hs.fin cannot be opened yet. It is neither acknowledged nor marked
// seen, so that the relay delivers it again; once hs.fin has activated
// the epoch, the redelivery is handled.
func TestNewEpochBeforeFinUnacked(t *testing.T)          { newEpochBeforeFin(t, true) }
func TestNewEpochBeforeFinUnackedNoPersist(t *testing.T) { newEpochBeforeFin(t, false) }

func newEpochBeforeFin(t *testing.T, persist bool) {
	ctx := context.Background()
	r, v, d := pair(t)
	if persist {
		d.cfg.Persist = keep(new([]byte), r)
	}
	devBox := relayauth.MailboxID(v.dev.PK)

	v.startRekey()
	if err := d.Poll(ctx); err != nil { // hs.init: the device answers with hs.resp
		t.Fatal(err)
	}
	v.process() // the vault activates the new epoch and sends hs.fin
	fin := r.take(devBox)
	if len(fin) != 1 {
		t.Fatalf("expected hs.fin alone in the device mailbox, got %d", len(fin))
	}
	early := v.send("test.ping", []byte(`{}`)) // the new epoch, ahead of hs.fin

	mark := len(r.entries())
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.entries()[mark:], "ack "+early) {
		t.Fatal("a new-epoch message before hs.fin was acknowledged")
	}
	if _, ok := d.st.Seen[early]; ok {
		t.Fatal("a new-epoch message before hs.fin was marked seen")
	}
	if n := pingCount(d); !slices.Contains(r.pending(devBox), early) || n != 0 {
		t.Fatal("message not kept for redelivery, or handled early")
	}

	// hs.fin arrives (behind the message, as the relay may order them).
	r.put(devBox, v.relayPK(), fin[0].Payload)
	before := v.kr.Current().ID()
	if err := d.Poll(ctx); err != nil { // the message again (still unopenable), then hs.fin
		t.Fatal(err)
	}
	if d.keyring.Current().ID() != before {
		t.Fatal("hs.fin did not activate the epoch")
	}
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := pingCount(d); n != 1 {
		t.Fatalf("redelivered message handled %d times, want 1", n)
	}
	if _, ok := d.st.Seen[early]; !ok || slices.Contains(r.pending(devBox), early) {
		t.Fatal("redelivered message not marked seen and acknowledged")
	}
}

// A message that cannot be opened for another reason stays as before:
// marked seen and acknowledged.
func TestUnopenableStillAcked(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), r)
	id := v.r.put(v.dev.Mailbox, v.relayPK(), []byte("not an envelope"))
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.st.Seen[id]; !ok || len(r.pending(relayauth.MailboxID(v.dev.PK))) != 0 {
		t.Fatal("garbage not seen and acknowledged")
	}
}

// §8.2: the vault's retransmission of one inner message is stored under
// a new msg_id; it is handled once, and both msg_ids are acknowledged.
func TestInnerIDRetransmissionHandledOnce(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	now := time.Now()
	in := &envelope.Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZZ", Type: "test.ping", TS: now, Body: []byte(`{}`)}
	var ids []string
	for range 2 {
		raw, err := v.kr.Current().Seal(in)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, r.put(v.dev.Mailbox, v.relayPK(), raw))
	}
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := pingCount(d); n != 1 {
		t.Fatalf("retransmission handled %d times, want 1", n)
	}
	for _, id := range ids {
		if _, ok := d.st.Seen[id]; !ok {
			t.Fatalf("msg_id %s not marked seen", id)
		}
	}
	if left := r.pending(relayauth.MailboxID(v.dev.PK)); len(left) != 0 {
		t.Fatalf("not acknowledged: %v", left)
	}
	if _, ok := loadState(t, saved).SeenInner[in.ID]; !ok {
		t.Fatal("inner id not saved before the acks")
	}
}

// The inner-id set survives a save and load, and entries older than 16
// days are pruned.
func TestSeenInnerRoundTripAndPrune(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	d.mu.Lock()
	d.pruned = time.Time{} // pruning runs at most once a minute
	d.st.SeenInner["old"] = time.Now().Add(-17 * 24 * time.Hour)
	d.st.SeenInner["recent"] = time.Now().Add(-15 * 24 * time.Hour)
	d.mu.Unlock()
	v.send("test.ping", []byte(`{}`))
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	st := loadState(t, saved)
	if _, ok := st.SeenInner["old"]; ok {
		t.Fatal("entry older than 16 days kept")
	}
	if _, ok := st.SeenInner["recent"]; !ok || len(st.SeenInner) != 2 {
		t.Fatalf("saved inner ids: %v", st.SeenInner)
	}
	d2 := reload(t, r, saved, nil)
	if len(d2.st.SeenInner) != 2 {
		t.Fatalf("inner ids after load: %v", d2.st.SeenInner)
	}
}

// A responder whose hs.fin does not come within the durable lifetime is
// dropped, and a message of its epoch is then acknowledged instead of
// being left in the mailbox.
func TestAwaitingExpiresAndAcks(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), r)
	devBox := relayauth.MailboxID(v.dev.PK)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	v.process()
	r.take(devBox) // hs.fin is lost
	early := v.send("test.ping", []byte(`{}`))
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.pending(devBox), early) || len(d.awaiting) != 1 {
		t.Fatal("message of a live pending epoch not left unacked")
	}
	late := time.Now().Add(17 * 24 * time.Hour)
	d.cfg.Now = func() time.Time { return late }
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(r.pending(devBox), early) || len(d.awaiting) != 0 || len(d.st.Awaiting) != 0 {
		t.Fatal("expired responder kept, or its message left unacked")
	}
}

// The awaiting times are saved and loaded with the responders.
func TestAwaitingSinceRoundTrip(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	st := loadState(t, saved)
	if len(st.Awaiting) != 1 || len(st.AwaitingSince) != 1 {
		t.Fatalf("saved %d responders, %d times", len(st.Awaiting), len(st.AwaitingSince))
	}
	d2 := reload(t, r, saved, nil)
	if len(d2.awaitingSince) != 1 || !d2.awaitingSince[0].Equal(st.AwaitingSince[0]) {
		t.Fatal("awaiting time lost on load")
	}
}

// §8.2: a retransmitted hs.init (an outbox re-deposit) under a new msg_id
// makes one hs.resp and one responder.
func TestRekeyInitRetransmissionAnsweredOnce(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), r)
	first := v.startRekey()
	second := r.put(v.dev.Mailbox, v.relayPK(), v.rekey.Envelope())
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(d.awaiting) != 1 {
		t.Fatalf("%d responders, want 1", len(d.awaiting))
	}
	if n := len(r.pending(v.mailbox())); n != 1 {
		t.Fatalf("%d hs.resp deposited, want 1", n)
	}
	for _, id := range []string{first, second} {
		if _, ok := d.st.Seen[id]; !ok {
			t.Fatalf("msg_id %s not marked seen", id)
		}
	}
	if left := r.pending(relayauth.MailboxID(v.dev.PK)); len(left) != 0 {
		t.Fatalf("not acknowledged: %v", left)
	}
}

// A message refused for the clock (here: the device clock is behind) does
// not record its inner id; delivered again with a correct clock, it is
// handled.
func TestClockRefusedInnerIDNotRecorded(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), r)
	in := &envelope.Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZY", Type: "test.ping", TS: time.Now(), Body: []byte(`{}`)}
	put := func() {
		raw, err := v.kr.Current().Seal(in)
		if err != nil {
			t.Fatal(err)
		}
		r.put(v.dev.Mailbox, v.relayPK(), raw)
	}
	put()
	behind := time.Now().Add(-time.Hour)
	d.cfg.Now = func() time.Time { return behind }
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.st.SeenInner[in.ID]; ok || pingCount(d) != 0 {
		t.Fatal("a message refused for the clock recorded its inner id or was handled")
	}
	d.cfg.Now = time.Now
	put()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := pingCount(d); n != 1 {
		t.Fatalf("re-delivery handled %d times, want 1", n)
	}
}

// A state with Awaiting and no AwaitingSince (saved before the times were
// kept) gives each responder the load time.
func TestAwaitingSinceDefaultsToLoadTime(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	st := loadState(t, saved)
	st.AwaitingSince = nil
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	load := time.Now().Add(time.Hour)
	d2, err := Load(Config{HTTP: r.srv.Client(), PollWait: time.Second, Now: func() time.Time { return load }}, b)
	if err != nil {
		t.Fatal(err)
	}
	if len(d2.awaitingSince) != 1 || !d2.awaitingSince[0].Equal(load) {
		t.Fatalf("awaiting times %v, want the load time", d2.awaitingSince)
	}
}

// A failed deposit of hs.resp does not record the hs.init's inner id: the
// vault's retransmission of it is answered.
func TestRekeyInitRetransmittedAfterFailedDeposit(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t) // no Persist: the deposit is made while handling
	v.startRekey()
	r.mu.Lock()
	r.failDeposit, r.depositStatus = 1000, 503 // the client retries a transient error
	r.mu.Unlock()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(d.awaiting) != 0 {
		t.Fatal("responder kept after a failed deposit")
	}
	r.mu.Lock()
	r.failDeposit = 0
	r.mu.Unlock()
	r.put(v.dev.Mailbox, v.relayPK(), v.rekey.Envelope())
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(d.awaiting) != 1 || len(r.pending(v.mailbox())) != 1 {
		t.Fatalf("retransmitted hs.init not answered: %d responders", len(d.awaiting))
	}
}

// An ephemeral message (one with an exp, §8.5) is kept in the inner-id set
// for 10 minutes, a durable one for 16 days.
func TestEphemeralInnerIDKeptTenMinutes(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), r)
	now := time.Now()
	for _, in := range []*envelope.Inner{
		{ID: "01HZZZZZZZZZZZZZZZZZZZZZZE", Type: "test.ping", TS: now, Exp: now.Add(30 * time.Second), Body: []byte(`{}`)},
		{ID: "01HZZZZZZZZZZZZZZZZZZZZZZD", Type: "test.ping", TS: now, Body: []byte(`{}`)},
	} {
		raw, err := v.kr.Current().Seal(in)
		if err != nil {
			t.Fatal(err)
		}
		r.put(v.dev.Mailbox, v.relayPK(), raw)
	}
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(d.st.SeenInner) != 2 {
		t.Fatalf("inner ids %v", d.st.SeenInner)
	}
	d.mu.Lock()
	d.pruneSeen(now.Add(11 * time.Minute))
	d.mu.Unlock()
	if _, ok := d.st.SeenInner["01HZZZZZZZZZZZZZZZZZZZZZZE"]; ok {
		t.Fatal("ephemeral id kept past 10 minutes")
	}
	if _, ok := d.st.SeenInner["01HZZZZZZZZZZZZZZZZZZZZZZD"]; !ok {
		t.Fatal("durable id dropped after 11 minutes")
	}
}

// A restart between the unacked new-epoch message and hs.fin: the state
// is saved and loaded, the responder restored, and the redelivery is
// handled once.
func TestNewEpochMessageAcrossRestart(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	devBox := relayauth.MailboxID(v.dev.PK)
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	v.process()
	fin := r.take(devBox)
	early := v.send("test.ping", []byte(`{}`))
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.pending(devBox), early) {
		t.Fatal("message not left unacked")
	}
	d2 := reload(t, r, saved, keep(&saved, r))
	if len(d2.awaiting) != 1 {
		t.Fatal("responder not restored")
	}
	r.put(devBox, v.relayPK(), fin[0].Payload)
	for range 2 {
		if err := d2.Poll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if n := pingCount(d2); n != 1 {
		t.Fatalf("redelivered message handled %d times, want 1", n)
	}
	if len(r.pending(devBox)) != 0 {
		t.Fatal("not acknowledged")
	}
}

// A retransmission (same inner id, new msg_id) that arrives after the
// epoch changed is handled once: the inner id does not depend on the epoch.
func TestRetransmissionAcrossEpochHandledOnce(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), r)
	in := &envelope.Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZX", Type: "test.ping", TS: time.Now(), Body: []byte(`{}`)}
	send := func() {
		raw, err := v.kr.Current().Seal(in)
		if err != nil {
			t.Fatal(err)
		}
		r.put(v.dev.Mailbox, v.relayPK(), raw)
	}
	poll := func() {
		if err := d.Poll(ctx); err != nil {
			t.Fatal(err)
		}
	}
	send()
	poll()
	v.startRekey()
	poll()
	v.process()
	poll() // hs.fin
	if d.keyring.Current().ID() != v.kr.Current().ID() {
		t.Fatal("epoch not changed")
	}
	send() // the retransmission, in the new epoch
	poll()
	if n := pingCount(d); n != 1 {
		t.Fatalf("handled %d times, want 1", n)
	}
}

// A message with a long `exp` retransmitted after the ephemeral window,
// before its exp, is handled once.
func TestLongExpInnerIDKeptUntilExp(t *testing.T) {
	ctx := context.Background()
	r, v, d := pair(t)
	d.cfg.Persist = keep(new([]byte), r)
	now := time.Now()
	in := &envelope.Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZM", Type: "test.ping", TS: now, Exp: now.Add(time.Hour), Body: []byte(`{}`)}
	send := func() {
		raw, err := v.kr.Current().Seal(in)
		if err != nil {
			t.Fatal(err)
		}
		r.put(v.dev.Mailbox, v.relayPK(), raw)
	}
	send()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	later := now.Add(15 * time.Minute)
	d.cfg.Now = func() time.Time { return later }
	send()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if n := pingCount(d); n != 1 {
		t.Fatalf("handled %d times, want 1", n)
	}
}
