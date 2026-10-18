package invite

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

var t0 = time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)

func seed(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

func testBundle(t testing.TB, kind string, remote bool, ttl time.Duration) *Bundle {
	t.Helper()
	kem, err := suite.NewPrivateKey(seed(5))
	if err != nil {
		t.Fatal(err)
	}
	rk := ed25519.NewKeyFromSeed(seed(0x11)).Public().(ed25519.PublicKey)
	return &Bundle{
		Kind: kind, InviteID: "01JB2Z6V9K3M4N5P6Q7R8S9T0V", Remote: remote,
		Vault: handshake.Principal{
			IK:    ed25519.NewKeyFromSeed(seed(4)).Public().(ed25519.PublicKey),
			KEM:   kem.Public(),
			Relay: handshake.RelayAddr{URL: "https://relay.vettid.org", Mailbox: handshake.MailboxID(rk), PK: rk},
		},
		Token: "v4.public.VEVTVC1PTkxZ", Exp: t0.Add(ttl), HintName: "Al",
	}
}

func publish(t testing.TB, b *Bundle, k Kind) ([]byte, *QR) {
	t.Helper()
	j, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	blob, kb, h, err := SealBundle(j)
	if err != nil {
		t.Fatal(err)
	}
	return blob, &QR{Kind: k, Relay: "https://relay.vettid.org", ClaimID: "abcdefghijklmnopqrstuvwxyz", Hash: h, Key: kb, Exp: b.Exp.Unix()}
}

func TestInviteFlow(t *testing.T) {
	for _, c := range []struct {
		kind string
		k    Kind
	}{{"connection", KindConnection}, {"app", KindApp}, {"desktop", KindDesktop}, {"agent", KindAgent}} {
		b := testBundle(t, c.kind, false, TTLInPerson)
		blob, q := publish(t, b, c.k)
		link, err := q.Link()
		if err != nil {
			t.Fatal(err)
		}
		q2, err := ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenBundle(blob, q2, t0)
		if err != nil {
			t.Fatalf("%s: %v", c.kind, err)
		}
		if got.InviteID != b.InviteID || !got.Vault.KEM.Equal(b.Vault.KEM) {
			t.Fatal("bundle changed")
		}
	}
}

// PQC-MIGRATION §6.5 / §6.4: the hash commitment keeps the relay untrusted:
// a substituted blob is rejected before decryption.
func TestBundleCommitment(t *testing.T) {
	b := testBundle(t, "connection", false, TTLInPerson)
	blob, q := publish(t, b, KindConnection)
	other, _ := publish(t, testBundle(t, "connection", true, time.Hour), KindConnection)
	if _, err := OpenBundle(other, q, t0); !errors.Is(err, ErrHash) {
		t.Fatalf("substituted blob: %v", err)
	}
	blob[40] ^= 1
	if _, err := OpenBundle(blob, q, t0); !errors.Is(err, ErrHash) {
		t.Fatal("tampered blob accepted")
	}
}

func TestBundleChecks(t *testing.T) {
	b := testBundle(t, "connection", false, TTLInPerson)
	blob, q := publish(t, b, KindConnection)
	if _, err := OpenBundle(blob, q, t0.Add(TTLInPerson)); !errors.Is(err, ErrExpired) {
		t.Fatal("expired accepted")
	}
	qk := *q
	qk.Kind = KindApp
	if _, err := OpenBundle(blob, &qk, t0); !errors.Is(err, ErrKind) {
		t.Fatal("kind mismatch accepted")
	}
	qe := *q
	qe.Exp++
	if _, err := OpenBundle(blob, &qe, t0); !errors.Is(err, ErrBundle) {
		t.Fatal("exp mismatch accepted")
	}
	qkey := *q
	qkey.Key = seed(1)
	if _, err := OpenBundle(blob, &qkey, t0); !errors.Is(err, ErrDecrypt) {
		t.Fatal("wrong key")
	}
	if _, err := testBundle(t, "app", true, time.Hour).Marshal(); err == nil {
		t.Fatal("remote pairing bundle accepted")
	}
}

func TestQRStrict(t *testing.T) {
	b := testBundle(t, "connection", false, TTLInPerson)
	_, q := publish(t, b, KindConnection)
	j, _ := q.Marshal()
	if _, err := ParseQR(j); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(j), `{"v":2,"t":"c","r":"https://relay.vettid.org","c":"abcdefghijklmnopqrstuvwxyz","h":"`) {
		t.Fatalf("layout %s", j)
	}
	rep := func(o, n string) []byte { return []byte(strings.Replace(string(j), o, n, 1)) }
	for name, bad := range map[string][]byte{
		"v 1":         rep(`"v":2`, `"v":1`),
		"t x":         rep(`"t":"c"`, `"t":"x"`),
		"http relay":  rep(`https://relay`, `http://relay`),
		"claim upper": rep(`abcdefghijklmnopqrstuvwxyz`, `ABCDEFGHIJKLMNOPQRSTUVWXYZ`),
		"claim short": rep(`abcdefghijklmnopqrstuvwxyz`, `abc`),
		"e string":    rep(`"e":`, `"e":"1",`+`"x":`),
		"padded h":    rep(`","k"`, `=","k"`),
		"dup":         rep(`{"v":2`, `{"v":2,"v":2`),
	} {
		if _, err := ParseQR(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// §6.4 TTL rules.
func TestInviteTTL(t *testing.T) {
	vettid := RelayLimits{OpenTokenMaxLifetime: 7 * 24 * time.Hour, ClaimTTL: 7 * 24 * time.Hour}
	if len(OfferableTTLs(vettid)) != 4 {
		t.Fatal("vettid.org relay offers all four")
	}
	small := RelayLimits{OpenTokenMaxLifetime: 24 * time.Hour, ClaimTTL: 2 * time.Hour}
	got := OfferableTTLs(small)
	if len(got) != 2 || got[1] != time.Hour {
		t.Fatalf("offerable %v", got)
	}
	if err := CheckTTL(24*time.Hour, small); !errors.Is(err, ErrTTL) {
		t.Fatal("TTL above claim_ttl accepted")
	}
	if err := CheckTTL(30*time.Minute, vettid); !errors.Is(err, ErrTTL) {
		t.Fatal("undefined TTL accepted")
	}
	if IsRemote(TTLInPerson) || !IsRemote(time.Hour) {
		t.Fatal("IsRemote")
	}
}

// §6.4: auto-approval MUST NOT apply to remote invites; §6.7 approval first.
func TestAutoApproval(t *testing.T) {
	if AutoApproveAllowed(true, false, true) {
		t.Fatal("remote auto-approved")
	}
	if AutoApproveAllowed(false, true, true) {
		t.Fatal("pairing auto-approved")
	}
	if !AutoApproveAllowed(false, false, true) || AutoApproveAllowed(false, false, false) {
		t.Fatal("in-person")
	}
}

func FuzzParseQR(f *testing.F) {
	_, q := publish(f, testBundle(f, "connection", false, TTLInPerson), KindConnection)
	j, _ := q.Marshal()
	f.Add(j)
	f.Fuzz(func(t *testing.T, b []byte) {
		q, err := ParseQR(b)
		if err != nil {
			return
		}
		out, err := q.Marshal()
		if err != nil {
			t.Fatal("accepted QR does not re-marshal")
		}
		if _, err := ParseQR(out); err != nil {
			t.Fatal("re-marshalled QR rejected")
		}
	})
}

func FuzzParseBundle(f *testing.F) {
	j, _ := testBundle(f, "connection", true, time.Hour).Marshal()
	f.Add(j)
	f.Fuzz(func(t *testing.T, b []byte) {
		bd, err := ParseBundle(b)
		if err != nil {
			return
		}
		out, err := bd.Marshal()
		if err != nil {
			t.Fatal("accepted bundle does not re-marshal")
		}
		if _, err := ParseBundle(out); err != nil {
			t.Fatal("re-marshalled bundle rejected")
		}
	})
}

// 0.43.0 (§11.10.9, STAGING-TIME-SCALE §5.2): a transfer's bundle
// carries the vault's time scale after its capabilities, bound by the
// QR's hash; no other kind carries it; absent is 0 (before the scale).
func TestBundleTimeScale(t *testing.T) {
	b := testBundle(t, "app", false, TTLInPerson)
	b.HintName = ""
	b.Capabilities = altchan.ReleaseCapabilities(true)
	b.TimeScale = 24
	j, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"recovery_r"],"time_scale":24`) {
		t.Fatalf("member order: %s", j)
	}
	blob, q := publish(t, b, KindApp)
	got, err := OpenBundle(blob, q, t0)
	if err != nil || got.TimeScale != 24 {
		t.Fatalf("%v %d", err, got.TimeScale)
	}
	j2 := bytes.Replace(j, []byte(`"time_scale":24`), []byte(`"time_scale":1`), 1)
	blob2, _, _, err := SealBundle(j2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(blob2, q, t0); !errors.Is(err, ErrHash) {
		t.Fatalf("a changed scale under the original QR: %v", err)
	}
	old := testBundle(t, "app", false, TTLInPerson)
	blob, q = publish(t, old, KindApp)
	if got, err := OpenBundle(blob, q, t0); err != nil || got.TimeScale != 0 {
		t.Fatalf("a bundle before the scale: %v %d", err, got.TimeScale)
	}
	for _, kind := range []string{"connection", "desktop", "agent"} {
		c := testBundle(t, kind, false, TTLInPerson)
		c.TimeScale = 1
		if _, err := c.Marshal(); err == nil {
			t.Fatalf("%s bundle with time_scale accepted", kind)
		}
	}
	for _, bad := range []string{`0`, `86401`, `"24"`} {
		if _, err := ParseBundle(bytes.Replace(j, []byte(`"time_scale":24`), []byte(`"time_scale":`+bad), 1)); err == nil {
			t.Errorf("time_scale %s parsed", bad)
		}
	}
}

// 0.34.0, release R (§6.4, §11.10.9): a transfer's bundle (kind app)
// carries the vault's capabilities, which the QR's hash binds; no other
// kind carries them; a bundle without them is a release before R.
func TestBundleCapabilities(t *testing.T) {
	b := testBundle(t, "app", false, TTLInPerson)
	b.HintName = ""
	b.Capabilities = altchan.ReleaseCapabilities(true)
	j, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(j), `"exp":"2026-10-01T12:10:00Z","capabilities":["attachments","recovery_offered","recovery_r"]`) {
		t.Fatalf("member order: %s", j)
	}
	blob, q := publish(t, b, KindApp)
	got, err := OpenBundle(blob, q, t0)
	if err != nil || !altchan.HasCapability(got.Capabilities, altchan.CapRecoveryR) || len(got.Capabilities) != 3 {
		t.Fatalf("%v %q", err, got.Capabilities)
	}
	// Removing a name changes the blob, which the QR's hash refuses.
	j2 := bytes.Replace(j, []byte(`,"recovery_r"`), nil, 1)
	blob2, _, _, err := SealBundle(j2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenBundle(blob2, q, t0); !errors.Is(err, ErrHash) {
		t.Fatalf("a bundle without recovery_r under the original QR: %v", err)
	}
	// Before R: no member, nil.
	old := testBundle(t, "app", false, TTLInPerson)
	blob, q = publish(t, old, KindApp)
	if got, err := OpenBundle(blob, q, t0); err != nil || got.Capabilities != nil {
		t.Fatalf("a bundle before R: %v %q", err, got.Capabilities)
	}
	// Only kind app; and a malformed list is refused.
	for _, kind := range []string{"connection", "desktop", "agent"} {
		c := testBundle(t, kind, false, TTLInPerson)
		c.Capabilities = altchan.ReleaseCapabilities(true)
		if _, err := c.Marshal(); err == nil {
			t.Fatalf("%s bundle with capabilities accepted", kind)
		}
	}
	bad := testBundle(t, "app", false, TTLInPerson)
	bad.Capabilities = []string{"recovery_r", "attachments"}
	if _, err := bad.Marshal(); err == nil {
		t.Fatal("unsorted capabilities accepted")
	}
	raw := strings.Replace(string(j), `["attachments","recovery_offered","recovery_r"]`, `["Recovery"]`, 1)
	if _, err := ParseBundle([]byte(raw)); err == nil {
		t.Fatal("malformed capabilities parsed")
	}
}
