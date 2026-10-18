package client

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

func pairedWith(v *fakeVault, deviceID, release string, number uint64) []byte {
	b := strictjson.NewBuilder().String("device_id", deviceID).String("role", "app").String("vault_id", testVaultID).
		String("token", v.token(30*24*time.Hour))
	if release != "" {
		b.String("release", release).Uint("release_number", number)
	}
	return b.Bytes()
}

// §6.7 "Late and duplicate": once the device has its id, a device.paired
// that no handshake of this device waits for (here: a replay under a new
// msg_id, authenticated in the session) is dropped: no new token, id,
// release or record, and no event.
func TestPairedReplayDropped(t *testing.T) {
	_, v, d := pair(t)
	r16 := strings.Repeat("16", 48)
	v.send("device.paired", pairedWith(v, "dev-1", r16, 16))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.DeviceID() != "dev-1" || d.st.PairingPending || len(d.Events()) != 1 {
		t.Fatal("first device.paired not taken")
	}
	tok, paired, alt := d.st.Vault.Token, *d.st.Paired, d.Alt()

	v.send("device.paired", pairedWith(v, "dev-other", strings.Repeat("17", 48), 17))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.DeviceID() != "dev-1" || d.st.Vault.Token != tok || *d.st.Paired != paired || d.Alt().ReleaseNumber != alt.ReleaseNumber {
		t.Fatal("a replayed device.paired changed the state")
	}
	if ev := d.Events(); len(ev) != 0 {
		t.Fatal("a replayed device.paired reached the caller")
	}
}

// A device.paired during a handshake of this device is taken even when
// the device already has an id (a recovery or a transfer on it), but it
// never lowers the release floor that unlocks use (Alt).
func TestPairedPendingNeverLowersFloor(t *testing.T) {
	_, v, d := pair(t)
	r16 := strings.Repeat("16", 48)
	v.send("device.paired", pairedWith(v, "dev-1", r16, 16))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	d.mu.Lock()
	d.st.PairingPending = true // as startInit sets it for a new handshake
	d.mu.Unlock()
	v.send("device.paired", pairedWith(v, "dev-2", strings.Repeat("15", 48), 15))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if d.DeviceID() != "dev-2" || d.st.PairingPending {
		t.Fatal("device.paired during a pending handshake not taken")
	}
	if a := d.Alt(); a.ReleaseNumber != 16 || a.Release != r16 {
		t.Fatalf("release floor lowered to %d", a.ReleaseNumber)
	}
	if p, _ := d.Paired(); p.ReleaseNumber != 15 {
		t.Fatal("Paired should record what the message named")
	}
	// A higher release raises the floor.
	d.mu.Lock()
	d.st.PairingPending = true
	d.mu.Unlock()
	v.send("device.paired", pairedWith(v, "dev-2", strings.Repeat("18", 48), 18))
	if err := d.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a := d.Alt(); a.ReleaseNumber != 18 {
		t.Fatalf("floor %d, want 18", a.ReleaseNumber)
	}
}

// startInit marks the handshake pending (pair runs it and stops before
// device.paired), and the mark is saved with the state.
func TestPairingPendingSaved(t *testing.T) {
	r, _, d := pair(t)
	b, err := d.Save()
	if err != nil {
		t.Fatal(err)
	}
	if !loadState(t, b).PairingPending {
		t.Fatal("pending handshake not in the state")
	}
	if !reload(t, r, b, nil).st.PairingPending {
		t.Fatal("pending handshake lost on load")
	}
}
