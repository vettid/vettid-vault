package vault

import (
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/invite"
)

// 0.34.0, release R (§6.4, §6.7.1, §11.10.9): the bundle of a transfer
// (kind app) carries the image's capabilities, so that the new phone
// chooses release R's hs.init; the bundles of connections, desktops and
// agents do not.
func TestInviteBundleCapabilities(t *testing.T) {
	for _, off := range []bool{false, true} {
		inviteBundleCapabilities(t, off)
	}
}

func inviteBundleCapabilities(t *testing.T, notOffered bool) {
	d := newDevFixture(t)
	d.m.opt.RecoveryNotOffered = notOffered
	claims := map[string][]byte{}
	d.relay.claims = &claims
	for _, kind := range []string{KindApp, KindConnection, KindDesktop, KindAgent} {
		d.m.mu.Lock()
		_, link, err := d.m.createInvite(context.Background(), kind, 10*time.Minute, "dev1", d.m.now())
		d.m.mu.Unlock()
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		q, err := invite.ParseLink(link)
		if err != nil {
			t.Fatal(err)
		}
		b, err := invite.OpenBundle(claims[q.ClaimID], q, d.m.now())
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if kind == KindApp {
			want := 3
			if notOffered {
				want = 2
			}
			if len(b.Capabilities) != want || !altchan.HasCapability(b.Capabilities, altchan.CapRecoveryR) ||
				!altchan.HasCapability(b.Capabilities, altchan.CapAttachments) ||
				altchan.HasCapability(b.Capabilities, altchan.CapRecoveryOffered) == notOffered {
				t.Fatalf("transfer bundle: %q", b.Capabilities)
			}
		} else if b.Capabilities != nil {
			t.Fatalf("%s bundle carries %q", kind, b.Capabilities)
		}
	}
}
