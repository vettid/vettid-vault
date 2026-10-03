package credential

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/features/itemspec"
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
	FormatV1     = 0x01
	HeaderSize   = 17 // ver(1) || version(8) || kid(8)
	EncSize      = 1120
	lockedPrefix = 22 // t(1) || m(4) || p(1) || salt(16)
	saltSize     = 16
	MaxInner     = 131072
	MaxItems     = itemspec.MaxCritItems
	// ItemKeySize is a critical item's key (§3.5.2, §10.7).
	ItemKeySize   = 32
	MinPassword   = 8
	MaxPassword   = 1024
	MaxBlob       = HeaderSize + EncSize + 16 + lockedPrefix + suite.XNonceSize + MaxInner + 16
	minKDFTime    = 1
	minKDFMemKiB  = 8 * 1024
	maxKDFTime    = 10
	maxKDFMemKiB  = 1024 * 1024
	maxKDFThreads = 4
)

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

// Item is one critical item's entry inside the credential (§3.5.2): the
// random key its values are encrypted under (in the items feature's DEK
// state) and the generation of that key, which the ciphertext's AAD
// binds. The values themselves are not in the credential.
type Item struct {
	ID  string
	Gen uint64
	Key []byte
}

// Wipe zeroizes the item key.
func (it *Item) Wipe() { suite.Wipe(it.Key) }

// Inner is the credential's plaintext (§3.5.2).
type Inner struct {
	VaultID           string
	Version           uint64
	CreatedAt         time.Time
	PasswordChangedAt time.Time
	Key               []byte // Ed25519 seed
	Items             []Item
	CryptoKeys        json.RawMessage // reserved (wallet); "[]"
}

// Wipe zeroizes the secret parts of the plaintext.
func (in *Inner) Wipe() {
	if in == nil {
		return
	}
	suite.Wipe(in.Key)
	for i := range in.Items {
		in.Items[i].Wipe()
	}
}

// FindItem returns the index of a critical item, or -1.
func (in *Inner) FindItem(id string) int {
	for i := range in.Items {
		if in.Items[i].ID == id {
			return i
		}
	}
	return -1
}

// Marshal encodes the plaintext. The caller wipes the result.
func (in *Inner) Marshal() []byte {
	arr := []byte{'['}
	for i, it := range in.Items {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, it.Marshal()...)
	}
	arr = append(arr, ']')
	ck := in.CryptoKeys
	if len(ck) == 0 {
		ck = json.RawMessage(`[]`)
	}
	return strictjson.NewBuilder().Uint("v", 1).String("vault_id", in.VaultID).Uint("version", in.Version).
		String("created_at", envelope.FormatTS(in.CreatedAt)).String("password_changed_at", envelope.FormatTS(in.PasswordChangedAt)).
		Base64("key", in.Key).Raw("items", arr).Raw("crypto_keys", ck).Bytes()
}

// Marshal encodes a critical item's entry (§3.5.2):
//
//	{"item_id","gen","key"}
//
// The caller wipes the result.
func (it *Item) Marshal() []byte {
	return strictjson.NewBuilder().String("item_id", it.ID).Uint("gen", it.Gen).Base64("key", it.Key).Bytes()
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
	arr, err := o.Array("items")
	if err != nil || len(arr) > MaxItems {
		in.Wipe()
		return nil, ErrFormat
	}
	seen := map[string]bool{}
	for _, raw := range arr {
		io, err := strictjson.AsObject(raw)
		if err != nil {
			in.Wipe()
			return nil, ErrFormat
		}
		it, err := parseItem(io)
		if err != nil || seen[it.ID] {
			in.Wipe()
			return nil, ErrFormat
		}
		seen[it.ID] = true
		in.Items = append(in.Items, *it)
	}
	if _, err := o.Array("crypto_keys"); err != nil {
		in.Wipe()
		return nil, ErrFormat
	}
	in.CryptoKeys = append(json.RawMessage(nil), o["crypto_keys"]...)
	return in, nil
}

func parseItem(o strictjson.Object) (*Item, error) {
	it := &Item{}
	var err error
	if it.ID, err = o.String("item_id"); err != nil || !envelope.ValidULID(it.ID) {
		return nil, ErrFormat
	}
	if it.Gen, err = o.Uint("gen", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, ErrFormat
	}
	if it.Key, err = o.Base64("key", ItemKeySize); err != nil {
		return nil, ErrFormat
	}
	return it, nil
}

func ts(o strictjson.Object, k string) (time.Time, error) {
	s, err := o.String(k)
	if err != nil {
		return time.Time{}, err
	}
	return envelope.ParseTS(s)
}
