package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// device.paired's fields (§6.7, §10.3) through Paired, saved with the
// state.
func TestPairedFields(t *testing.T) {
	r, v, d := pair(t)
	if _, ok := d.Paired(); ok {
		t.Fatal("Paired before device.paired")
	}
	var saved []byte
	d.cfg.Persist = keep(&saved, r)
	exp := time.Now().Add(10 * time.Minute).UTC().Truncate(time.Millisecond)
	release := strings.Repeat("ab", 48)
	body := strictjson.NewBuilder().String("device_id", "dev-1").String("role", "agent").String("vault_id", testVaultID).
		String("release", release).Uint("release_number", 16).String("token", v.token(30*24*time.Hour)).
		String("session_expires_at", envelope.FormatTS(exp)).Bytes()
	v.send("device.paired", body)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := d.AwaitPaired(ctx); err != nil {
		t.Fatal(err)
	}
	want := Paired{DeviceID: "dev-1", Role: "agent", VaultID: testVaultID, Release: release, ReleaseNumber: 16, SessionExpiresAt: exp}
	check := func(what string, d *Device) {
		t.Helper()
		p, ok := d.Paired()
		if !ok || p.ReceivedAt.IsZero() {
			t.Fatalf("%s: no Paired", what)
		}
		p.ReceivedAt = time.Time{}
		if !p.SessionExpiresAt.Equal(want.SessionExpiresAt) {
			t.Fatalf("%s: session_expires_at %v, want %v", what, p.SessionExpiresAt, want.SessionExpiresAt)
		}
		p.SessionExpiresAt = want.SessionExpiresAt
		if p != want {
			t.Fatalf("%s: %+v, want %+v", what, p, want)
		}
	}
	check("after AwaitPaired", d)
	// A restart from what Persist saved before the ack still has them.
	check("restarted", reload(t, r, saved, nil))
}

// Without session_expires_at (no first session) it is zero; a
// transfer's fields are read; a malformed session_expires_at is ignored.
func TestPairedOptionalFields(t *testing.T) {
	_, v, d := pair(t)
	body := strictjson.NewBuilder().String("device_id", "dev-2").String("role", "app").String("vault_id", testVaultID).
		String("token", v.token(30*24*time.Hour)).Bool("transfer", true).Uint("credential_version", 7).
		String("user_guid", "user-1").String("session_expires_at", "not a time").Bytes()
	v.send("device.paired", body)
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	p, ok := d.Paired()
	if !ok || p.DeviceID != "dev-2" || !p.Transfer || p.CredentialVersion != 7 || p.UserGUID != "user-1" || !p.SessionExpiresAt.IsZero() {
		t.Fatalf("%+v", p)
	}
}
