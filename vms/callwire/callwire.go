// Package callwire is the wire crypto of call signalling (VAULT-MESSAGING
// §10.10, CALLING-SERVICE §6, §7): the per-call media key agreed between
// the two owner devices of a call through a hybrid KEM (MLKEM768X25519,
// suite 2), and the vault-signed ICE configuration.
//
// The media key never passes through a vault in the clear: the caller's
// device generates the ephemeral KEM key and keeps its private half, the
// answering device encapsulates to it, and the vaults only relay `ek` and
// `enc` inside their E2E sessions.
package callwire

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Labels and sizes (§10.10).
const (
	LabelCall    = "vettid/vms/2/call"
	LabelCallKey = "vettid/vms/2/call-key"
	LabelICE     = "vettid/vms/2/ice"
	MediaSalt    = "vettid-call-v1"
	EKSize       = 1216
	EncSize      = 1120
	KeySize      = 32
	// ICE configuration limits.
	MaxICEServers   = 8
	MaxURLs         = 4
	MaxURL          = 512
	MaxICEField     = 512
	MaxICEConfig    = 8192
	ICEConfigFormat = 1
)

// Errors.
var (
	ErrCall      = errors.New("callwire: invalid call key material")
	ErrICEConfig = errors.New("callwire: invalid ICE configuration")
	ErrICESig    = errors.New("callwire: ICE configuration signature invalid")
	ErrICEStale  = errors.New("callwire: ICE configuration expired or for another call")
)

func callInfo(callID string) string { return LabelCall + callID }

// NewOfferKey generates the caller device's ephemeral call KEM key. Its
// public half (`ek`, 1,216 bytes) goes in call.start / call.offer.
func NewOfferKey() (*suite.PrivateKey, error) { return suite.GeneratePrivateKey() }

func mediaKey(k []byte, callID string) ([]byte, error) {
	out, err := hkdf.Key(sha256.New, k, []byte(MediaSalt), callID, KeySize)
	suite.Wipe(k)
	if err != nil {
		return nil, ErrCall
	}
	return out, nil
}

// Answer is run by the answering device: it encapsulates to the caller's
// ek, bound to call_id, and returns `enc` (for call.answer) and k_call.
//
//	(enc, ctx) = SetupBaseS(ek, info = "vettid/vms/2/call" || call_id)
//	K          = ctx.Export("vettid/vms/2/call-key", 32)
//	k_call     = HKDF-SHA-256(ikm = K, salt = "vettid-call-v1", info = call_id, L = 32)
func Answer(ek []byte, callID string) (enc, kCall []byte, err error) {
	if len(ek) != EKSize || callID == "" {
		return nil, nil, ErrCall
	}
	pk, err := suite.ParsePublicKey(ek)
	if err != nil {
		return nil, nil, ErrCall
	}
	enc, ctx, err := suite.SetupSender(pk, callInfo(callID))
	if err != nil {
		return nil, nil, ErrCall
	}
	k, err := ctx.Export(LabelCallKey, KeySize)
	if err != nil {
		return nil, nil, ErrCall
	}
	kCall, err = mediaKey(k, callID)
	if err != nil {
		return nil, nil, err
	}
	return enc, kCall, nil
}

// Accept is run by the calling device on the answer's `enc`; it returns
// the same k_call.
func Accept(sk *suite.PrivateKey, enc []byte, callID string) ([]byte, error) {
	if sk == nil || len(enc) != EncSize || callID == "" {
		return nil, ErrCall
	}
	r, err := suite.SetupRecipient(enc, sk, callInfo(callID))
	if err != nil {
		return nil, ErrCall
	}
	k, err := r.Export(LabelCallKey, KeySize)
	if err != nil {
		return nil, ErrCall
	}
	return mediaKey(k, callID)
}

// ICEServer is one entry of an ICE configuration (CALLING-SERVICE §6).
type ICEServer struct {
	URLs       []string
	Username   string
	Credential string
}

// ICEConfig is the vault-signed ICE configuration of one call.
type ICEConfig struct {
	CallID  string
	Exp     time.Time // whole seconds
	Servers []ICEServer
}

func validURL(u string) bool {
	if u == "" || len(u) > MaxURL {
		return false
	}
	for i := 0; i < len(u); i++ {
		if u[i] <= 0x20 || u[i] >= 0x7f {
			return false
		}
	}
	for _, s := range []string{"stun:", "stuns:", "turn:", "turns:"} {
		if strings.HasPrefix(u, s) && len(u) > len(s) {
			return true
		}
	}
	return false
}

func validField(s string) bool {
	if len(s) > MaxICEField {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}

func (c *ICEConfig) validate() error {
	if c.CallID == "" || len(c.CallID) > 64 || c.Exp.IsZero() || len(c.Servers) > MaxICEServers {
		return ErrICEConfig
	}
	for _, s := range c.Servers {
		if len(s.URLs) == 0 || len(s.URLs) > MaxURLs || !validField(s.Username) || !validField(s.Credential) ||
			(s.Username == "") != (s.Credential == "") {
			return ErrICEConfig
		}
		for _, u := range s.URLs {
			if !validURL(u) {
				return ErrICEConfig
			}
		}
	}
	return nil
}

// Marshal returns the configuration's canonical JSON bytes:
//
//	{"v":1,"call_id":"…","exp":<unix>,"ice_servers":[{"urls":[…],"username":"…","credential":"…"}]}
//
// (username and credential only when set). These exact bytes are signed.
func (c *ICEConfig) Marshal() ([]byte, error) {
	if err := c.validate(); err != nil {
		return nil, err
	}
	arr := []byte{'['}
	for i, s := range c.Servers {
		if i > 0 {
			arr = append(arr, ',')
		}
		urls := []byte{'['}
		for j, u := range s.URLs {
			if j > 0 {
				urls = append(urls, ',')
			}
			urls = append(urls, strictjson.MarshalString(u)...)
		}
		b := strictjson.NewBuilder().Raw("urls", append(urls, ']'))
		if s.Username != "" {
			b.String("username", s.Username).String("credential", s.Credential)
		}
		arr = append(arr, b.Bytes()...)
	}
	return strictjson.NewBuilder().Uint("v", ICEConfigFormat).String("call_id", c.CallID).Uint("exp", uint64(c.Exp.Unix())).
		Raw("ice_servers", append(arr, ']')).Bytes(), nil
}

// ParseICEConfig parses configuration bytes strictly; they must be in
// canonical form (Marshal of the result returns the same bytes).
func ParseICEConfig(b []byte) (*ICEConfig, error) {
	if len(b) > MaxICEConfig {
		return nil, ErrICEConfig
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrICEConfig
	}
	if v, err := o.Uint("v", ICEConfigFormat, ICEConfigFormat); err != nil || v != ICEConfigFormat {
		return nil, ErrICEConfig
	}
	c := &ICEConfig{}
	if c.CallID, err = o.String("call_id"); err != nil {
		return nil, ErrICEConfig
	}
	exp, err := o.Uint("exp", 1, 1<<40)
	if err != nil {
		return nil, ErrICEConfig
	}
	c.Exp = time.Unix(int64(exp), 0).UTC()
	arr, err := o.Array("ice_servers")
	if err != nil || len(arr) > MaxICEServers {
		return nil, ErrICEConfig
	}
	for _, raw := range arr {
		so, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, ErrICEConfig
		}
		var s ICEServer
		urls, err := so.Array("urls")
		if err != nil || len(urls) > MaxURLs {
			return nil, ErrICEConfig
		}
		for _, u := range urls {
			us, err := strictjson.AsString(u)
			if err != nil {
				return nil, ErrICEConfig
			}
			s.URLs = append(s.URLs, us)
		}
		if s.Username, _, err = so.OptString("username"); err != nil {
			return nil, ErrICEConfig
		}
		if s.Credential, _, err = so.OptString("credential"); err != nil {
			return nil, ErrICEConfig
		}
		c.Servers = append(c.Servers, s)
	}
	canon, err := c.Marshal()
	if err != nil || !suite.Equal(canon, b) {
		return nil, ErrICEConfig
	}
	return c, nil
}

// SignICE signs configuration bytes with the vault's identity key:
// sig = Ed25519(ik, "vettid/vms/2/ice" || config).
func SignICE(ik ed25519.PrivateKey, config []byte) ([]byte, error) {
	return suite.Sign(ik, LabelICE, config)
}

// VerifyICE is run by an owner device: the signature by its vault's ik,
// the strict format, the call id and the expiry.
func VerifyICE(vaultIK ed25519.PublicKey, config, sig []byte, callID string, now time.Time) (*ICEConfig, error) {
	if err := suite.Verify(vaultIK, LabelICE, config, sig); err != nil {
		return nil, ErrICESig
	}
	c, err := ParseICEConfig(config)
	if err != nil {
		return nil, err
	}
	if c.CallID != callID || !now.Before(c.Exp) {
		return nil, ErrICEStale
	}
	return c, nil
}
