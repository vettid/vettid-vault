package enclave_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// §11.3, §11.5 (0.15.0): the sealed app.api_key must equal the queue
// message's app_key (else the request is unreadable to the host: random
// bytes); the vault keeps it (app_key_seq 1) and reports it on enrolled,
// unlocked and locked.
func TestEnrollAppKey(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-ak", android(0x61))
	e, in := f.enclaveFor(a, "", true)
	_, m, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	req, err := a.dev.BuildEnroll(a.guid, pin, e, m, a.att)
	if err != nil {
		t.Fatal(err)
	}
	_, der, _ := a.dev.AppKey()
	if !bytes.Equal(req.AppKey, der) {
		t.Fatal("request does not name the app key")
	}
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	otherDER, _ := x509.MarshalPKIXPublicKey(&other.PublicKey)
	bad := *req
	bad.AppKey = otherDER
	vid := newVaultID()
	resp, err := f.w.Post(f.ctx, in, enclave.OpEnroll, vid, a.guid, &bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.dev.OpenEnrollResult(resp.Envelope, req.RequestID); err == nil {
		t.Fatal("another key's request was answered")
	}
	if r := f.enroll(a, pin); !r.OK {
		t.Fatalf("enroll: %+v", r)
	}
	f.lock(a)
	f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	seen := map[string]bool{}
	for _, ev := range f.w.Events() {
		if ev.VaultID != a.vid {
			continue
		}
		switch ev.Event {
		case "enrolled", "unlocked", "locked":
			if !bytes.Equal(ev.AppKey, der) || ev.AppKeySeq != 1 {
				t.Fatalf("%s without the app key: %+v", ev.Event, ev)
			}
			seen[ev.Event] = true
		}
	}
	if len(seen) != 3 {
		t.Fatalf("events %v", seen)
	}
}

// §11.5, §11.13 (0.15.0): the queue op account reaches the running vault
// (account.changed and account.get); without a running vault it is
// dropped; an unlock's snapshot is applied after the unlock.
func TestAccountOp(t *testing.T) {
	f := newFx(t)
	a := f.newApp("user-acct", android(0x61))
	if r := f.enroll(a, pin); !r.OK {
		t.Fatal(r.Code)
	}
	in := f.w.Instance(3)
	snap := func(at time.Time) []byte {
		return strictjson.NewBuilder().Uint("v", 1).String("as_of", envelope.FormatTS(at)).String("email", "user@example.org").
			String("first_name", "Ada").String("last_name", "Lovelace").Raw("name_change", []byte(`{"allowed_after":null,"last":null}`)).
			String("state", "member").String("account_status", "active").Raw("deletes_at", []byte("null")).
			Raw("terms", []byte(`{"needs_acceptance":false}`)).Raw("subscription", []byte("null")).Bool("voting_rights", false).
			String("future_member", "ignored").Bytes()
	}
	rid, _ := envelope.NewULID(f.clk.Now())
	q := &enclave.QueueMessage{Op: enclave.OpAccount, VaultID: a.vid, UserGUID: a.guid, RequestID: rid, EnqueuedAt: f.clk.Now(),
		Account: snap(f.clk.Now().Add(time.Millisecond))} // newer than the enrollment's (0.18.0)
	raw := q.Marshal()
	if !strings.Contains(string(raw), `"account":{"v":1`) {
		t.Fatalf("%s", raw)
	}
	resp := in.ProcessRaw(context.Background(), raw, nil)
	r, err := enclave.ParseResponse(resp)
	if err != nil || r.Status != enclave.StatusDone || r.Envelope != nil {
		t.Fatalf("%v %+v", err, r)
	}
	m := in.Manager(a.vid)
	if m == nil || m.AccountVersion() != 2 { // 1: the enrollment's (0.18.0)
		t.Fatal("snapshot not stored")
	}
	f.lock(a)
	rid2, _ := envelope.NewULID(f.clk.Now())
	q2 := &enclave.QueueMessage{Op: enclave.OpAccount, VaultID: a.vid, UserGUID: a.guid, RequestID: rid2, EnqueuedAt: f.clk.Now(),
		Account: snap(f.clk.Now().Add(time.Second))}
	if r, err := enclave.ParseResponse(in.ProcessRaw(context.Background(), q2.Marshal(), nil)); err != nil || r.Status != enclave.StatusDone {
		t.Fatal("op account on a locked vault not answered")
	}
	// The unlock's snapshot, newer: version 3. An older one: ignored.
	f.w.Account = func(string) []byte { return snap(f.clk.Now().Add(time.Minute)) }
	f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	if m := in.Manager(a.vid); m == nil || m.AccountVersion() != 3 {
		t.Fatal("unlock snapshot not applied")
	}
	f.lock(a)
	f.w.Account = func(string) []byte { return snap(f.clk.Now().Add(-time.Hour)) }
	f.mustUnlock(a, pin, client.UnlockOptions{}, "")
	if m := in.Manager(a.vid); m == nil || m.AccountVersion() != 3 {
		t.Fatal("older snapshot applied")
	}
}
