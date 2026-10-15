package vault

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
)

func tokenClaims(t *testing.T, m *Manager, tok string) relayauth.Claims {
	t.Helper()
	msg, err := relayauth.VerifyToken(tok, m.keys.relay.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatal(err)
	}
	c, err := relayauth.ParseClaims(msg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// §7.1 (0.32.0, release A): every standing token the vault mints for one
// of its own devices carries owner_device; no other token does. A vault
// from before release A re-mints its devices' standing tokens once, at
// its first unlock under it (§7.2).
func TestDeviceTokensOwnerDevice(t *testing.T) {
	d := newDevFixture(t)
	conn := d.asConnection(t, "c1", 0x51)
	now := time.Now()
	d.withLock(func(m *Manager) {
		dt, _, err := m.mintStanding(d.devPeer, now, nil)
		if err != nil || !tokenClaims(t, m, dt).OwnerDevice {
			t.Fatalf("device standing token without owner_device: %v", err)
		}
		ct, _, _ := m.mintStanding(conn.peer, now, nil)
		rt, _, _ := m.mintReconnect(conn.peer, now, nil)
		qt, _, _ := m.mint(d.devPeer, TokRequest, time.Minute, nil, now, nil)
		for name, tok := range map[string]string{"connection standing": ct, "reconnect": rt, "request": qt} {
			if tokenClaims(t, m, tok).OwnerDevice {
				t.Errorf("%s token carries owner_device", name)
			}
		}
		m.st.DeviceTokensMarked = false // as a vault from before release A
	})
	d.inbox(d.self())
	d.withLock(func(m *Manager) {
		m.markDeviceTokens(now)
		m.markDeviceTokens(now)
		m.drainOutbox(context.Background())
	})
	issued := 0
	for _, in := range d.inbox(d.self())["dev1"] {
		if in.Type == tokenIssuedType {
			issued++
			d.withLock(func(m *Manager) {
				if !tokenClaims(t, m, bodyStr(t, in, "token")).OwnerDevice {
					t.Fatal("re-minted token without owner_device")
				}
			})
		}
	}
	if issued != 1 || !d.m.st.DeviceTokensMarked {
		t.Fatalf("%d re-minted tokens, marked %v", issued, d.m.st.DeviceTokensMarked)
	}
}
