package client

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

const dropSecret = `{"secret":"s3cret-value"}`

// sealInner seals in, under the vault's current epoch, to the device.
func (v *fakeVault) sealInner(in *envelope.Inner) string {
	v.t.Helper()
	raw, err := v.kr.Current().Seal(in)
	if err != nil {
		v.t.Fatal(err)
	}
	return v.r.put(v.dev.Mailbox, v.relayPK(), raw)
}

func wiped(b []byte) bool { return len(b) > 0 && bytes.Count(b, []byte{0}) == len(b) }

// Every path on which handle drops a message it opened wipes the body,
// and a message it hands on keeps it: one test per path.
func TestDroppedBodiesAreWiped(t *testing.T) {
	ctx := context.Background()
	id := func() string { s, _ := envelope.NewULID(time.Now()); return s }
	cases := []struct {
		name string
		// send deposits the message(s); want is how many drops of a
		// message whose body is the secret the Poll must see.
		send func(v *fakeVault, d *Device)
		want int
		// pings is how many test.ping events must reach the caller intact.
		pings int
	}{
		{"duplicate inner id, no waiting request", func(v *fakeVault, _ *Device) {
			in := &envelope.Inner{ID: id(), Type: "test.ping", TS: time.Now(), Body: []byte(dropSecret)}
			v.sealInner(in)
			v.sealInner(in) // the retransmission: dropped
		}, 1, 1},
		{"refused for the clock", func(v *fakeVault, _ *Device) {
			v.sealInner(&envelope.Inner{ID: id(), Type: "test.ping", TS: time.Now().Add(time.Hour), Body: []byte(dropSecret)})
		}, 1, 0},
		{"hs.confirm", func(v *fakeVault, _ *Device) {
			v.sealInner(&envelope.Inner{ID: id(), Type: handshake.TypeConfirm, TS: time.Now(), Body: []byte(dropSecret)})
		}, 1, 0},
		{"device.pair.rejected out of place", func(v *fakeVault, _ *Device) {
			v.sealInner(&envelope.Inner{ID: id(), Type: devicePairRejected, TS: time.Now(), Re: id(), Status: envelope.StatusOK, Body: []byte(dropSecret)})
		}, 1, 0},
		{"device.paired after pairing", func(v *fakeVault, d *Device) {
			d.mu.Lock()
			d.st.DeviceID, d.st.PairingPending = "dev-1", false // paired: a late copy is dropped
			d.mu.Unlock()
			v.sealInner(&envelope.Inner{ID: id(), Type: "device.paired", TS: time.Now(), Body: []byte(dropSecret)})
		}, 1, 0},
		{"relay.token.refresh request", func(v *fakeVault, _ *Device) {
			v.sealInner(&envelope.Inner{ID: id(), Type: "relay.token.refresh", TS: time.Now(), Body: []byte(dropSecret)})
		}, 1, 0},
		{"handed on: an event", func(v *fakeVault, _ *Device) {
			v.sealInner(&envelope.Inner{ID: id(), Type: "test.ping", TS: time.Now(), Body: []byte(dropSecret)})
		}, 0, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, v, d := pair(t)
			d.Events() // what pairing left
			var drops []*envelope.Inner
			testDropHook = func(in *envelope.Inner) { drops = append(drops, in) }
			defer func() { testDropHook = nil }()
			c.send(v, d)
			if err := d.Poll(ctx); err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, in := range drops {
				if !wiped(in.Body) {
					t.Fatalf("a dropped %s kept its body: %q", in.Type, in.Body)
				}
				if len(in.Body) == len(dropSecret) {
					n++
				}
			}
			if n != c.want {
				t.Fatalf("%d drops of the secret's message, want %d", n, c.want)
			}
			pings := 0
			for _, e := range d.Events() {
				if e.Type == "test.ping" && string(e.Body) == dropSecret {
					pings++
				}
			}
			if pings != c.pings {
				t.Fatalf("%d intact test.ping events, want %d", pings, c.pings)
			}
		})
	}
}

// A rekey's hs.init is handed to the handshake, which keeps it: its body
// (public keys and links) is not wiped, and the device answers the rekey.
func TestRekeyInitNotWiped(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	var drops []*envelope.Inner
	testDropHook = func(in *envelope.Inner) { drops = append(drops, in) }
	defer func() { testDropHook = nil }()
	v.startRekey()
	if err := d.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	for _, in := range drops {
		if in.Type == handshake.TypeInit {
			t.Fatal("hs.init was dropped and wiped")
		}
	}
	if len(d.awaiting) != 1 {
		t.Fatal("the device did not answer the rekey")
	}
}

// A sealed message to the device's static key that handleEnrolled does
// not accept (another type, or a vault.enrolled without a valid bundle)
// is wiped: vault.enrolled carries the vault token.
func TestDroppedEnrolledWiped(t *testing.T) {
	ctx := context.Background()
	for _, typ := range []string{"vault.enrolled", "test.other"} {
		t.Run(typ, func(t *testing.T) {
			_, v, d := pair(t)
			var drops []*envelope.Inner
			testDropHook = func(in *envelope.Inner) { drops = append(drops, in) }
			var opened [][]byte
			testPaddedHook = func(b []byte) { opened = append(opened, b) }
			defer func() { testDropHook, testPaddedHook = nil, nil }()
			now := time.Now()
			id, _ := envelope.NewULID(now)
			padded, err := envelope.EncodeInner(&envelope.Inner{ID: id, Type: typ, TS: now, Body: []byte(dropSecret)}, envelope.ModeSealed)
			if err != nil {
				t.Fatal(err)
			}
			raw, _, err := envelope.SealSealed(d.KEMKey(), d.KEMKey().Kid(), padded)
			if err != nil {
				t.Fatal(err)
			}
			v.r.put(v.dev.Mailbox, v.relayPK(), raw)
			if err := d.Poll(ctx); err != nil {
				t.Fatal(err)
			}
			if len(drops) != 1 || drops[0].Type != typ || !wiped(drops[0].Body) {
				t.Fatalf("drops = %d, want one wiped %s", len(drops), typ)
			}
			if len(opened) != 1 || !wiped(opened[0]) {
				t.Fatal("the opened plaintext was not wiped")
			}
		})
	}
}

// The bodies that carry a token are parsed again by their handlers; those
// copies are wiped too (relay.token.issued, device.paired while pairing,
// vault.enrolled).
func TestTokenBodyCopiesWiped(t *testing.T) {
	ctx := context.Background()
	body := []byte(`{"token":"s3cret-token","kind":"standing","device_id":"dev-1"}`)
	for _, typ := range []string{"relay.token.issued", "device.paired", "vault.enrolled"} {
		t.Run(typ, func(t *testing.T) {
			_, v, d := pair(t)
			var parsed []strictjson.Object
			testParsedHook = func(o strictjson.Object) { parsed = append(parsed, o) }
			defer func() { testParsedHook = nil }()
			now := time.Now()
			id, _ := envelope.NewULID(now)
			in := &envelope.Inner{ID: id, Type: typ, TS: now, Body: body}
			if typ == "vault.enrolled" {
				padded, err := envelope.EncodeInner(in, envelope.ModeSealed)
				if err != nil {
					t.Fatal(err)
				}
				raw, _, err := envelope.SealSealed(d.KEMKey(), d.KEMKey().Kid(), padded)
				if err != nil {
					t.Fatal(err)
				}
				v.r.put(v.dev.Mailbox, v.relayPK(), raw)
			} else {
				v.sealInner(in)
			}
			if err := d.Poll(ctx); err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, o := range parsed {
				if !o.Has("token") {
					continue
				}
				n++
				for k, val := range o {
					if !wiped(val) {
						t.Fatalf("member %q of the parsed body kept its value", k)
					}
				}
			}
			if n != 1 {
				t.Fatalf("%d wiped parses of the token body, want 1", n)
			}
		})
	}
}

// The pairing's hs.resp, handed on by the initiator with the request
// token in its body, is wiped once the device has read it.
func TestPairingRespWiped(t *testing.T) {
	var drops []*envelope.Inner
	testDropHook = func(in *envelope.Inner) { drops = append(drops, in) }
	defer func() { testDropHook = nil }()
	pair(t)
	n := 0
	for _, in := range drops {
		if in.Type == handshake.TypeResp {
			n++
			if !wiped(in.Body) {
				t.Fatal("the pairing's hs.resp kept its body")
			}
		}
	}
	if n != 1 {
		t.Fatalf("%d wiped hs.resp, want 1", n)
	}
}
