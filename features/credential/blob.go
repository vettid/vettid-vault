package credential

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Labels (§3.5).
const (
	labelSeal = "vettid/vms/2/credential"
	labelPW   = "vettid/vms/2/credential-pw"
)

// Format constants (§3.5.2).
const (
	FormatV1      = 0x01
	HeaderSize    = 17 // ver(1) || version(8) || kid(8)
	EncSize       = 1120
	lockedPrefix  = 22 // t(1) || m(4) || p(1) || salt(16)
	saltSize      = 16
	MaxInner      = 131072
	MaxSecrets    = 64
	MaxValue      = 8192
	MaxName       = 128
	MaxDesc       = 1024
	MinPassword   = 8
	MaxPassword   = 1024
	MaxBlob       = HeaderSize + EncSize + 16 + lockedPrefix + suite.XNonceSize + MaxInner + 16
	minKDFTime    = 1
	minKDFMemKiB  = 8 * 1024
	maxKDFTime    = 10
	maxKDFMemKiB  = 1024 * 1024
	maxKDFThreads = 4
)

// Categories of critical secrets (§3.5.2).
var Categories = map[string]bool{"seed_phrase": true, "private_key": true, "signing_key": true,
	"master_password": true, "recovery_key": true, "other": true}

// KDF are the password key's Argon2id parameters.
type KDF struct {
	Time      uint8
	MemoryKiB uint32
	Threads   uint8
}

// DefaultKDF is used for new seals (§3.5.1).
var DefaultKDF = KDF{Time: 3, MemoryKiB: 64 * 1024, Threads: 1}

// MinKDF is the weakest accepted (tests).
var MinKDF = KDF{Time: minKDFTime, MemoryKiB: minKDFMemKiB, Threads: 1}

func (k KDF) valid() bool {
	return k.Time >= minKDFTime && k.Time <= maxKDFTime && k.MemoryKiB >= minKDFMemKiB &&
		k.MemoryKiB <= maxKDFMemKiB && k.Threads >= 1 && k.Threads <= maxKDFThreads
}

// Errors.
var (
	ErrFormat   = errors.New("credential: malformed blob")
	ErrPassword = errors.New("credential: wrong password")
	ErrKDF      = errors.New("credential: KDF parameters refused")
)

// passwordKey derives K_pw (§3.5.1).
func passwordKey(password []byte, salt []byte, k KDF, vaultID string) ([]byte, error) {
	x := argon2.IDKey(password, salt, uint32(k.Time), k.MemoryKiB, k.Threads, 32)
	defer suite.Wipe(x)
	return hkdf.Key(sha256.New, x, []byte(labelPW), vaultID, 32)
}

// Header is a blob's clear header.
type Header struct {
	Version uint64
	Kid     suite.Kid
}

// ParseHeader parses a blob's header and checks its length bounds.
func ParseHeader(blob []byte) (Header, error) {
	var h Header
	if len(blob) < HeaderSize+EncSize+16+lockedPrefix+suite.XNonceSize+16 || len(blob) > MaxBlob || blob[0] != FormatV1 {
		return h, ErrFormat
	}
	h.Version = binary.BigEndian.Uint64(blob[1:9])
	copy(h.Kid[:], blob[9:17])
	if h.Version == 0 || h.Version > strictjson.MaxSafeInteger {
		return h, ErrFormat
	}
	return h, nil
}

// Seal seals inner under the CEK and the password (§3.5.2).
func Seal(cek *suite.PublicKey, vaultID string, version uint64, password []byte, k KDF, inner []byte) ([]byte, error) {
	if !k.valid() {
		return nil, ErrKDF
	}
	if len(inner) > MaxInner {
		return nil, ErrFormat
	}
	salt, err := suite.RandomBytes(saltSize)
	if err != nil {
		return nil, err
	}
	nonce, err := suite.NewNonce()
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, HeaderSize)
	hdr[0] = FormatV1
	binary.BigEndian.PutUint64(hdr[1:9], version)
	kid := cek.Kid()
	copy(hdr[9:17], kid[:])
	pre := make([]byte, lockedPrefix)
	pre[0] = k.Time
	binary.BigEndian.PutUint32(pre[1:5], k.MemoryKiB)
	pre[5] = k.Threads
	copy(pre[6:], salt)
	kpw, err := passwordKey(password, salt, k, vaultID)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(kpw)
	ct, err := suite.SealX(kpw, nonce, append(append([]byte(nil), hdr...), pre...), inner)
	if err != nil {
		return nil, err
	}
	locked := append(append(pre, nonce...), ct...)
	enc, sender, err := suite.SetupSender(cek, labelSeal+vaultID)
	if err != nil {
		return nil, err
	}
	outer, err := sender.Seal(hdr, locked)
	suite.Wipe(locked)
	if err != nil {
		return nil, err
	}
	return append(append(hdr, enc...), outer...), nil
}

// Open opens a blob with the CEK and the password. ErrPassword means the
// outer layer opened and the password layer did not.
func Open(cek *suite.PrivateKey, vaultID string, blob, password []byte) (uint64, []byte, error) {
	h, err := ParseHeader(blob)
	if err != nil {
		return 0, nil, err
	}
	if !h.Kid.Equal(cek.Public().Kid()) {
		return 0, nil, ErrFormat
	}
	hdr := blob[:HeaderSize]
	r, err := suite.SetupRecipient(blob[HeaderSize:HeaderSize+EncSize], cek, labelSeal+vaultID)
	if err != nil {
		return 0, nil, ErrFormat
	}
	locked, err := r.Open(hdr, blob[HeaderSize+EncSize:])
	if err != nil {
		return 0, nil, ErrFormat
	}
	defer suite.Wipe(locked)
	if len(locked) < lockedPrefix+suite.XNonceSize+16 {
		return 0, nil, ErrFormat
	}
	k := KDF{Time: locked[0], MemoryKiB: binary.BigEndian.Uint32(locked[1:5]), Threads: locked[5]}
	if !k.valid() {
		return 0, nil, ErrKDF
	}
	kpw, err := passwordKey(password, locked[6:lockedPrefix], k, vaultID)
	if err != nil {
		return 0, nil, err
	}
	defer suite.Wipe(kpw)
	nonce := locked[lockedPrefix : lockedPrefix+suite.XNonceSize]
	aad := append(append([]byte(nil), hdr...), locked[:lockedPrefix]...)
	inner, err := suite.OpenX(kpw, nonce, aad, locked[lockedPrefix+suite.XNonceSize:])
	if err != nil {
		return 0, nil, ErrPassword
	}
	return h.Version, inner, nil
}

// Secret is a critical secret inside the credential.
type Secret struct {
	ID          string
	Name        string
	Category    string
	Description string
	Value       []byte
	CreatedAt   time.Time
}

// Inner is the credential's plaintext (§3.5.2).
type Inner struct {
	VaultID           string
	Version           uint64
	CreatedAt         time.Time
	PasswordChangedAt time.Time
	Key               []byte // Ed25519 seed
	Secrets           []Secret
	CryptoKeys        json.RawMessage // reserved (wallet); "[]"
}

// Wipe zeroizes the secret parts of the plaintext.
func (in *Inner) Wipe() {
	if in == nil {
		return
	}
	suite.Wipe(in.Key)
	for i := range in.Secrets {
		suite.Wipe(in.Secrets[i].Value)
	}
}

// Marshal encodes the plaintext. The caller wipes the result.
func (in *Inner) Marshal() []byte {
	arr := []byte{'['}
	for i, s := range in.Secrets {
		if i > 0 {
			arr = append(arr, ',')
		}
		b := strictjson.NewBuilder().String("id", s.ID).String("name", s.Name).String("category", s.Category)
		if s.Description != "" {
			b.String("description", s.Description)
		}
		arr = append(arr, b.Base64("value", s.Value).String("created_at", envelope.FormatTS(s.CreatedAt)).Bytes()...)
	}
	arr = append(arr, ']')
	ck := in.CryptoKeys
	if len(ck) == 0 {
		ck = json.RawMessage(`[]`)
	}
	return strictjson.NewBuilder().Uint("v", 1).String("vault_id", in.VaultID).Uint("version", in.Version).
		String("created_at", envelope.FormatTS(in.CreatedAt)).String("password_changed_at", envelope.FormatTS(in.PasswordChangedAt)).
		Base64("key", in.Key).Raw("secrets", arr).Raw("crypto_keys", ck).Bytes()
}

// ParseInner parses the plaintext strictly (§3.5.2).
func ParseInner(b []byte) (*Inner, error) {
	if len(b) > MaxInner {
		return nil, ErrFormat
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrFormat
	}
	in := &Inner{}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrFormat
	}
	if in.VaultID, err = o.String("vault_id"); err != nil || in.VaultID == "" || len(in.VaultID) > 128 {
		return nil, ErrFormat
	}
	if in.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrFormat
	}
	if in.CreatedAt, err = ts(o, "created_at"); err != nil {
		return nil, ErrFormat
	}
	if in.PasswordChangedAt, err = ts(o, "password_changed_at"); err != nil {
		return nil, ErrFormat
	}
	if in.Key, err = o.Base64("key", 32); err != nil {
		return nil, ErrFormat
	}
	arr, err := o.Array("secrets")
	if err != nil || len(arr) > MaxSecrets {
		in.Wipe()
		return nil, ErrFormat
	}
	seen := map[string]bool{}
	for _, raw := range arr {
		so, err := strictjson.AsObject(raw)
		if err != nil {
			in.Wipe()
			return nil, ErrFormat
		}
		s, err := parseSecret(so)
		if err != nil || seen[s.ID] {
			in.Wipe()
			return nil, ErrFormat
		}
		seen[s.ID] = true
		in.Secrets = append(in.Secrets, *s)
	}
	if _, err := o.Array("crypto_keys"); err != nil {
		in.Wipe()
		return nil, ErrFormat
	}
	in.CryptoKeys = append(json.RawMessage(nil), o["crypto_keys"]...)
	return in, nil
}

func parseSecret(o strictjson.Object) (*Secret, error) {
	s := &Secret{}
	var err error
	if s.ID, err = o.String("id"); err != nil || !envelope.ValidULID(s.ID) {
		return nil, ErrFormat
	}
	if s.Name, err = o.String("name"); err != nil || s.Name == "" || len(s.Name) > MaxName {
		return nil, ErrFormat
	}
	if s.Category, err = o.String("category"); err != nil || !Categories[s.Category] {
		return nil, ErrFormat
	}
	if d, present, err := o.OptString("description"); err != nil || len(d) > MaxDesc {
		return nil, ErrFormat
	} else if present {
		s.Description = d
	}
	if s.Value, err = o.Base64("value", -1); err != nil || len(s.Value) == 0 || len(s.Value) > MaxValue {
		return nil, ErrFormat
	}
	if s.CreatedAt, err = ts(o, "created_at"); err != nil {
		return nil, ErrFormat
	}
	return s, nil
}

func ts(o strictjson.Object, k string) (time.Time, error) {
	s, err := o.String(k)
	if err != nil {
		return time.Time{}, err
	}
	return envelope.ParseTS(s)
}
