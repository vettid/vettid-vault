package callwire

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/suite"
)

const callID = "01JB2Z6V9K3M4N5P6Q7R8S9T0V"

// §10.10: both devices derive the same k_call, bound to call_id; the
// vaults see only ek and enc.
func TestMediaKeyAgreement(t *testing.T) {
	sk, err := NewOfferKey()
	if err != nil {
		t.Fatal(err)
	}
	ek := sk.Public().Bytes()
	if len(ek) != EKSize {
		t.Fatalf("ek %d bytes", len(ek))
	}
	enc, k1, err := Answer(ek, callID)
	if err != nil || len(enc) != EncSize || len(k1) != KeySize {
		t.Fatalf("answer: %v", err)
	}
	k2, err := Accept(sk, enc, callID)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatal("keys differ")
	}
	// Bound to the call id: another id derives another key (or fails).
	if k3, err := Accept(sk, enc, "01JB2Z6V9K3M4N5P6Q7R8S9T0W"); err == nil && bytes.Equal(k3, k1) {
		t.Fatal("key not bound to call_id")
	}
	// Another recipient key cannot derive it.
	other, _ := NewOfferKey()
	if k4, err := Accept(other, enc, callID); err == nil && bytes.Equal(k4, k1) {
		t.Fatal("key derived by the wrong recipient")
	}
	for _, bad := range [][]byte{nil, ek[:EKSize-1], append(append([]byte(nil), ek...), 0)} {
		if _, _, err := Answer(bad, callID); err != ErrCall {
			t.Fatal("bad ek accepted")
		}
	}
	if _, err := Accept(sk, enc[:EncSize-1], callID); err != ErrCall {
		t.Fatal("short enc accepted")
	}
	if _, _, err := Answer(ek, ""); err != ErrCall {
		t.Fatal("empty call id accepted")
	}
}

func testConfig() *ICEConfig {
	return &ICEConfig{CallID: callID, Exp: time.Unix(1_800_000_000, 0).UTC(), Servers: []ICEServer{
		{URLs: []string{"stun:stun.example.org:3478"}},
		{URLs: []string{"turns:turn.example.org:5349?transport=tcp"}, Username: "1800000000:" + callID, Credential: "c2VjcmV0"},
	}}
}

// CALLING-SERVICE §6: devices accept only configurations their vault
// signed, for this call, unexpired, in canonical form.
func TestICEConfig(t *testing.T) {
	ik := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{4}, 32))
	cfg, err := testConfig().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"v":1,"call_id":"` + callID + `","exp":1800000000,"ice_servers":[{"urls":["stun:stun.example.org:3478"]},` +
		`{"urls":["turns:turn.example.org:5349?transport=tcp"],"username":"1800000000:` + callID + `","credential":"c2VjcmV0"}]}`
	if string(cfg) != want {
		t.Fatalf("canonical form:\n%s\n%s", cfg, want)
	}
	sig, err := SignICE(ik, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_799_999_000, 0)
	pub := ik.Public().(ed25519.PublicKey)
	if c, err := VerifyICE(pub, cfg, sig, callID, now); err != nil || len(c.Servers) != 2 {
		t.Fatalf("verify: %v", err)
	}
	other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{5}, 32)).Public().(ed25519.PublicKey)
	if _, err := VerifyICE(other, cfg, sig, callID, now); err != ErrICESig {
		t.Fatal("other key accepted")
	}
	if _, err := VerifyICE(pub, cfg, sig, "01JB2Z6V9K3M4N5P6Q7R8S9T0W", now); err != ErrICEStale {
		t.Fatal("other call accepted")
	}
	if _, err := VerifyICE(pub, cfg, sig, callID, time.Unix(1_800_000_000, 0)); err != ErrICEStale {
		t.Fatal("expired config accepted")
	}
	// Reordered servers or members change the bytes: the signature fails.
	reordered := bytes.Replace(cfg, []byte(`{"v":1,"call_id"`), []byte(`{"call_id"`), 1)
	reordered = bytes.Replace(reordered, []byte(`,"exp"`), []byte(`,"v":1,"exp"`), 1)
	if _, err := ParseICEConfig(reordered); err != ErrICEConfig {
		t.Fatal("non-canonical config parsed")
	}
	for _, mut := range []func(*ICEConfig){
		func(c *ICEConfig) { c.Servers[0].URLs = []string{"http://x"} },
		func(c *ICEConfig) { c.Servers[0].URLs = []string{"stun:"} },
		func(c *ICEConfig) { c.Servers[0].URLs = []string{"stun:a b"} },
		func(c *ICEConfig) { c.Servers[1].Credential = "" },
		func(c *ICEConfig) { c.Servers[0].URLs = nil },
		func(c *ICEConfig) { c.CallID = "" },
		func(c *ICEConfig) {
			for range MaxICEServers {
				c.Servers = append(c.Servers, c.Servers[0])
			}
		},
	} {
		c := testConfig()
		mut(c)
		if _, err := c.Marshal(); err != ErrICEConfig {
			t.Fatal("invalid config marshalled")
		}
	}
	if c := (&ICEConfig{CallID: callID, Exp: time.Unix(1, 0)}); true {
		b, err := c.Marshal()
		if err != nil || string(b) != `{"v":1,"call_id":"`+callID+`","exp":1,"ice_servers":[]}` {
			t.Fatalf("empty server list: %s %v", b, err)
		}
	}
}

func FuzzParseICEConfig(f *testing.F) {
	cfg, _ := testConfig().Marshal()
	f.Add(cfg)
	f.Add([]byte(`{"v":1,"call_id":"x","exp":1,"ice_servers":[]}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := ParseICEConfig(b)
		if err != nil {
			return
		}
		again, err := c.Marshal()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatal("parsed config is not canonical")
		}
	})
}

func FuzzAccept(f *testing.F) {
	sk, _ := suite.NewPrivateKey(bytes.Repeat([]byte{9}, 32))
	enc, _, _ := Answer(sk.Public().Bytes(), callID)
	f.Add(enc, callID)
	f.Fuzz(func(t *testing.T, enc []byte, id string) {
		if k, err := Accept(sk, enc, id); err == nil && len(k) != KeySize {
			t.Fatal("bad key size")
		}
	})
}
