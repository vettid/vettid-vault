package client

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Activation on confirmation, the responder half (VAULT-MESSAGING 0.86.0,
// §6.3.1), for the vault's rekeys of this device: the device activates at
// a verified hs.fin and sends hs.confirm under the new epoch; its
// confirmed epoch (the newest the vault sent anything but hs.fin under)
// keeps its rk and receive keys while not current, up to 48 days, a rekey
// under it is accepted as if current, and a message under it while it is
// not current brings hs.confirm again. The device then sends
// device.features (§10.2) in the new epoch.
//
// Not here: rule E's destruction and fork evidence (a device keeps no
// epoch history and has no fork rules, §3.4.1 "Terms": nothing suspends
// between a vault and its own device), and the initiator half (a device
// starts no rekey with its vault).

// confirmedKeysFor is how long the confirmed epoch keeps its keys while
// not current (§6.3.1 table).
const confirmedKeysFor = 48 * 24 * time.Hour

// reconfirmEvery bounds hs.confirm sent again to one a minute (the spec:
// once per collected batch).
const reconfirmEvery = time.Minute

func (d *Device) confirmedID() []byte {
	if c := d.st.Vault.Confirmed; c != nil {
		return c
	}
	if cur := d.keyring.Current(); cur != nil {
		id := cur.ID()
		return id[:]
	}
	return nil
}

func (d *Device) isConfirmed(ep *handshake.Epoch) bool {
	if ep == nil || d.st.Vault == nil {
		return false
	}
	id := ep.ID()
	return bytes.Equal(id[:], d.confirmedID()) && ep.HasRK()
}

// establishRekey activates the vault's rekey epoch at its verified hs.fin
// and confirms it.
func (d *Device) establishRekey(ctx context.Context, ep *handshake.Epoch, now time.Time) {
	cur := d.keyring.Current()
	if cur != nil && bytes.Equal(d.confirmedID(), func() []byte { id := cur.ID(); return id[:] }()) {
		if d.st.Vault.Confirmed == nil {
			id := cur.ID()
			d.st.Vault.Confirmed = id[:]
		}
		d.keyring.ActivateKeeping(ep, now, now.Add(confirmedKeysFor), handshake.KeepRK)
	} else {
		d.keyring.Activate(ep, now)
	}
	d.sendConfirm(ctx)
	d.sendFeatures(ctx)
}

// noteConfirmed moves the confirmed epoch forward to ep (never back) and,
// while it is not current, confirms again.
func (d *Device) noteConfirmed(ctx context.Context, ep *handshake.Epoch, now time.Time) {
	if ep == nil || d.st.Vault == nil {
		return
	}
	id := ep.ID()
	cur := d.keyring.Current()
	if cur == ep {
		if c := d.st.Vault.Confirmed; c != nil && !bytes.Equal(c, id[:]) {
			d.keyring.Release(epochID(c), now.Add(handshake.ReceiveKeyRetention))
		}
		d.st.Vault.Confirmed = nil // the current one
		return
	}
	if bytes.Equal(id[:], d.confirmedID()) && now.Sub(d.reconfirmed) >= reconfirmEvery {
		d.reconfirmed = now
		d.sendConfirm(ctx)
	}
}

func epochID(b []byte) (id [16]byte) {
	copy(id[:], b)
	return id
}

// sendConfirm sends hs.confirm (body {}, durable, not a request).
func (d *Device) sendConfirm(ctx context.Context) {
	_, _ = d.sendFull(ctx, "", handshake.TypeConfirm, json.RawMessage(`{}`), "", "", time.Time{})
}

// sendFeatures sends device.features with this client's list (§10.2).
func (d *Device) sendFeatures(ctx context.Context) {
	arr := []byte{'['}
	for i, n := range Features() {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.MarshalString(n)...)
	}
	_, _ = d.sendFull(ctx, "", "device.features", strictjson.NewBuilder().Raw("features", append(arr, ']')).Bytes(), "", "", time.Time{})
}
