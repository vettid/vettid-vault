// Package credential is the Protean Credential and its critical secrets
// (VAULT-MESSAGING §3.5, §10.6). The member's app holds the credential,
// sealed to the vault's CEK and under the member's password; every use
// carries the credential and the password, and the vault keeps no
// plaintext afterwards (the credential key only during an unlock window).
//
// Ported from vettid.dev's credential, protean-credential and
// credential-secret handlers. The UTK/LTK transport keys are gone (the §6
// session carries the request); the CEK is a suite-2 hybrid KEM key; the
// password check is the inner AEAD of the blob rather than a stored PHC
// string; the PIN verifier and the unused master secret are no longer in
// the credential (the PIN is checked by DEK derivation, §3.3.1).
package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Password backoff (§3.5.3).
const BackoffAfter = 5

var backoffDelays = []time.Duration{30 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute, 60 * time.Minute}

// Meta is a critical secret's metadata, kept in vault state so that it can
// be listed without the password (§10.6).
type Meta struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

type state struct {
	CEKSeed   []byte    `json:"cek_seed,omitempty"`
	Version   uint64    `json:"version,omitempty"`
	Hash      []byte    `json:"hash,omitempty"`
	Blob      []byte    `json:"blob,omitempty"` // the kept copy (§3.5.6)
	Key       []byte    `json:"key,omitempty"`  // the credential key's public key
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Secrets   []Meta    `json:"secrets,omitempty"`
	Failures  int       `json:"failures,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
}

// Options configure the feature.
type Options struct {
	// KDF for new seals; zero means DefaultKDF. Tests use MinKDF.
	KDF KDF
	// KeepCopy keeps the current blob in vault state (§3.5.6). The
	// reference configuration keeps it.
	KeepCopy bool
}

// Feature implements vault.Feature and vault.Zeroizer.
type Feature struct {
	mu  sync.Mutex
	opt Options
	st  state

	// The unlock window (§3.5.3): memory only, never saved.
	key    ed25519.PrivateKey
	keyExp time.Time
}

// New returns the feature.
func New(o Options) *Feature {
	if o.KDF == (KDF{}) {
		o.KDF = DefaultKDF
	}
	return &Feature{opt: o}
}

var (
	apps   = []string{vault.KindApp}
	owners = []string{vault.KindApp, vault.KindDesktop}
)

// Name implements vault.Feature.
func (f *Feature) Name() string { return "credential" }

// Types implements vault.Feature.
func (f *Feature) Types() []vault.TypeSpec {
	r := func(t string, from []string) vault.TypeSpec {
		return vault.TypeSpec{Type: t, Request: true, From: from}
	}
	return []vault.TypeSpec{
		r("credential.create", apps), r("credential.get", apps), r("credential.version", owners),
		r("credential.unlock", apps), r("credential.lock", apps), r("credential.rotate", apps),
		r("credential.password.change", apps), r("credential.delete", apps),
		r("credential.secret.add", apps), {Type: "credential.secret.get", Request: true, Volatile: true, From: apps},
		r("credential.secret.list", owners),
		r("credential.secret.delete", apps),
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(data json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	f.st = st
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.st)
}

// Zeroize implements vault.Zeroizer: it ends the unlock window and wipes
// the CEK seed held in memory.
func (f *Feature) Zeroize() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endWindow()
	suite.Wipe(f.st.CEKSeed)
	f.st = state{}
}

func (f *Feature) endWindow() {
	suite.Wipe(f.key)
	f.key, f.keyExp = nil, time.Time{}
}

// UseKey returns the credential key while the unlock window is open and
// extends the window (§3.5.3). Features that sign with the credential key
// call it; ok is false outside the window.
func (f *Feature) UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.key == nil || !now.Before(f.keyExp) {
		f.endWindow()
		return nil, false
	}
	f.keyExp = now.Add(ttl)
	return f.key, true
}

var (
	errBad       = vault.NewError("bad_request", "")
	errNotFound  = vault.NewError("not_found", "")
	errExists    = vault.NewError("exists", "")
	errPassword  = vault.NewError("bad_password", "")
	errBackoff   = vault.NewError("backoff", "")
	errStale     = vault.NewError("stale_credential", "")
	errLimit     = vault.NewError("limit", "")
	errInternal  = vault.NewError("internal", "")
	b64          = base64.StdEncoding
	activityPrio = "high"
)

// Request is a parsed request body: the credential, the passwords and the
// operation's own members.
type Request struct {
	Blob        []byte
	Password    []byte
	NewPassword []byte
	SecretID    string
	Name        string
	Category    string
	Description string
	Value       []byte
}

// Wipe zeroizes the request's secrets.
func (r *Request) Wipe() {
	if r == nil {
		return
	}
	suite.Wipe(r.Password)
	suite.Wipe(r.NewPassword)
	suite.Wipe(r.Value)
}

// What a request type carries.
const (
	needBlob = 1 << iota
	needPassword
	needNewPassword
	needSecretID
	needSecret
)

var needs = map[string]int{
	"credential.create":          needPassword,
	"credential.get":             0,
	"credential.version":         0,
	"credential.unlock":          needBlob | needPassword,
	"credential.lock":            0,
	"credential.rotate":          needBlob | needPassword,
	"credential.password.change": needBlob | needPassword | needNewPassword,
	"credential.delete":          needBlob | needPassword,
	"credential.secret.add":      needBlob | needPassword | needSecret,
	"credential.secret.get":      needBlob | needPassword | needSecretID,
	"credential.secret.list":     0,
	"credential.secret.delete":   needBlob | needPassword | needSecretID,
}

func password(o strictjson.Object, k string) ([]byte, error) {
	p, err := o.String(k)
	if err != nil || len(p) < MinPassword || len(p) > MaxPassword {
		return nil, errBad
	}
	return []byte(p), nil
}

// ParseRequest parses the body of typ strictly (§10.6).
func ParseRequest(typ string, body []byte) (*Request, error) {
	n, ok := needs[typ]
	if !ok {
		return nil, errBad
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &Request{}
	fail := func() (*Request, error) { r.Wipe(); return nil, errBad }
	if n&needBlob != 0 {
		s, err := o.String("credential")
		if err != nil || len(s) > b64.EncodedLen(MaxBlob) {
			return fail()
		}
		if r.Blob, err = strictjson.DecodeStd(s, -1); err != nil {
			return fail()
		}
		if _, err := ParseHeader(r.Blob); err != nil {
			return fail()
		}
	}
	if n&needPassword != 0 {
		if r.Password, err = password(o, "password"); err != nil {
			return fail()
		}
	}
	if n&needNewPassword != 0 {
		if r.NewPassword, err = password(o, "new_password"); err != nil {
			return fail()
		}
	}
	if n&needSecretID != 0 {
		if r.SecretID, err = o.String("secret_id"); err != nil || !envelope.ValidULID(r.SecretID) {
			return fail()
		}
	}
	if n&needSecret != 0 {
		if r.Name, err = o.String("name"); err != nil || r.Name == "" || len(r.Name) > MaxName {
			return fail()
		}
		if r.Category, err = o.String("category"); err != nil || !Categories[r.Category] {
			return fail()
		}
		if d, present, err := o.OptString("description"); err != nil || len(d) > MaxDesc {
			return fail()
		} else if present {
			r.Description = d
		}
		if r.Value, err = o.Base64("value", -1); err != nil || len(r.Value) == 0 || len(r.Value) > MaxValue {
			return fail()
		}
	}
	return r, nil
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, err := ParseRequest(in.Type, in.Body)
	if err != nil {
		return nil, err
	}
	defer r.Wipe()
	switch in.Type {
	case "credential.create":
		return f.create(s, r)
	case "credential.get":
		if f.st.CEKSeed == nil || len(f.st.Blob) == 0 {
			return nil, errNotFound
		}
		return strictjson.NewBuilder().Base64("credential", f.st.Blob).Uint("version", f.st.Version).
			String("updated_at", envelope.FormatTS(f.st.UpdatedAt)).Bytes(), nil
	case "credential.version":
		b := strictjson.NewBuilder().Bool("exists", f.st.CEKSeed != nil)
		if f.st.CEKSeed != nil {
			b.Uint("version", f.st.Version).Base64("key", f.st.Key).String("updated_at", envelope.FormatTS(f.st.UpdatedAt))
		}
		return b.Bytes(), nil
	case "credential.secret.list":
		return f.list(), nil
	case "credential.lock":
		f.endWindow()
		return nil, nil
	}
	// Everything else opens the credential with the password (§3.5.3).
	cek, inner, err := f.open(s, r)
	if err != nil {
		return nil, err
	}
	defer cek.Destroy()
	defer inner.Wipe()
	switch in.Type {
	case "credential.unlock":
		f.endWindow()
		f.key = ed25519.NewKeyFromSeed(inner.Key)
		f.keyExp = s.Now().Add(s.Settings().UnlockTTL())
		s.Record(vault.Activity{Kind: "credential.unlocked", Audit: true})
		return strictjson.NewBuilder().String("expires_at", envelope.FormatTS(f.keyExp)).Bytes(), nil
	case "credential.secret.get":
		for _, sec := range inner.Secrets {
			if sec.ID == r.SecretID {
				s.Record(vault.Activity{Kind: "credential.secret.read", Ref: sec.ID, Audit: true, Feed: true})
				b := strictjson.NewBuilder().String("secret_id", sec.ID).String("name", sec.Name).String("category", sec.Category)
				if sec.Description != "" {
					b.String("description", sec.Description)
				}
				return b.Base64("value", sec.Value).String("created_at", envelope.FormatTS(sec.CreatedAt)).Bytes(), nil
			}
		}
		return nil, errNotFound
	case "credential.delete":
		f.endWindow()
		suite.Wipe(f.st.CEKSeed)
		f.st = state{}
		s.SyncEvent("credential.deleted", nil)
		s.Record(vault.Activity{Kind: "credential.deleted", Audit: true})
		return nil, nil
	case "credential.secret.add":
		if len(inner.Secrets) >= MaxSecrets {
			return nil, errLimit
		}
		sec := Secret{ID: s.NewID(), Name: r.Name, Category: r.Category, Description: r.Description,
			Value: append([]byte(nil), r.Value...), CreatedAt: s.Now().UTC().Truncate(time.Millisecond)}
		inner.Secrets = append(inner.Secrets, sec)
		blob, err := f.reseal(s, cek.Public(), inner, r.Password)
		if err != nil {
			return nil, err
		}
		f.st.Secrets = append(f.st.Secrets, Meta{ID: sec.ID, Name: sec.Name, Category: sec.Category,
			Description: sec.Description, CreatedAt: sec.CreatedAt})
		s.Record(vault.Activity{Kind: "credential.secret.added", Ref: sec.ID, Audit: true})
		return strictjson.NewBuilder().String("secret_id", sec.ID).Base64("credential", blob).Uint("version", f.st.Version).Bytes(), nil
	case "credential.secret.delete":
		idx := -1
		for i, sec := range inner.Secrets {
			if sec.ID == r.SecretID {
				idx = i
			}
		}
		if idx < 0 {
			return nil, errNotFound
		}
		suite.Wipe(inner.Secrets[idx].Value)
		inner.Secrets = append(inner.Secrets[:idx:idx], inner.Secrets[idx+1:]...)
		blob, err := f.reseal(s, cek.Public(), inner, r.Password)
		if err != nil {
			return nil, err
		}
		for i, m := range f.st.Secrets {
			if m.ID == r.SecretID {
				f.st.Secrets = append(f.st.Secrets[:i:i], f.st.Secrets[i+1:]...)
				break
			}
		}
		s.Record(vault.Activity{Kind: "credential.secret.deleted", Ref: r.SecretID, Audit: true})
		return strictjson.NewBuilder().Base64("credential", blob).Uint("version", f.st.Version).Bytes(), nil
	case "credential.password.change":
		inner.PasswordChangedAt = s.Now().UTC().Truncate(time.Millisecond)
		blob, err := f.reseal(s, cek.Public(), inner, r.NewPassword)
		if err != nil {
			return nil, err
		}
		s.Record(vault.Activity{Kind: "credential.password_changed", Audit: true})
		return strictjson.NewBuilder().Base64("credential", blob).Uint("version", f.st.Version).Bytes(), nil
	case "credential.rotate":
		return f.rotate(s, inner, r)
	}
	return nil, vault.NewError("unsupported_type", "")
}

// open performs steps 1–3 of §3.5.3. On success the caller owns the CEK
// and the plaintext and must destroy and wipe them.
func (f *Feature) open(s *vault.Session, r *Request) (*suite.PrivateKey, *Inner, error) {
	now := s.Now()
	if f.st.CEKSeed == nil {
		return nil, nil, errNotFound
	}
	if now.Before(f.st.NotBefore) {
		return nil, nil, errBackoff
	}
	h := sha256.Sum256(r.Blob)
	if !suite.Equal(h[:], f.st.Hash) {
		return nil, nil, errStale
	}
	cek, err := suite.NewPrivateKey(f.st.CEKSeed)
	if err != nil {
		return nil, nil, errInternal
	}
	version, pt, err := Open(cek, s.VaultID(), r.Blob, r.Password)
	if err == ErrPassword {
		cek.Destroy()
		f.st.Failures++
		if n := f.st.Failures - BackoffAfter; n >= 0 {
			f.st.NotBefore = now.Add(backoffDelays[min(n, len(backoffDelays)-1)])
		}
		s.Record(vault.Activity{Kind: "credential.password_failed", Audit: true, Feed: true, Priority: activityPrio})
		return nil, nil, errPassword
	}
	if err != nil {
		cek.Destroy()
		return nil, nil, errStale
	}
	inner, err := ParseInner(pt)
	suite.Wipe(pt)
	if err != nil || inner.Version != version || version != f.st.Version || inner.VaultID != s.VaultID() {
		cek.Destroy()
		inner.Wipe()
		return nil, nil, errStale
	}
	f.st.Failures, f.st.NotBefore = 0, time.Time{}
	return cek, inner, nil
}

// reseal seals inner as the next version under cek and password, records
// it (§3.5.3 step 4) and tells the other devices.
func (f *Feature) reseal(s *vault.Session, cek *suite.PublicKey, inner *Inner, password []byte) ([]byte, error) {
	inner.Version = f.st.Version + 1
	blob, err := f.seal(s, cek, inner, password)
	if err != nil {
		return nil, err
	}
	f.commit(s, blob, inner.Version)
	return blob, nil
}

func (f *Feature) seal(s *vault.Session, cek *suite.PublicKey, inner *Inner, password []byte) ([]byte, error) {
	pt := inner.Marshal()
	defer suite.Wipe(pt)
	if len(pt) > MaxInner {
		return nil, errLimit
	}
	blob, err := Seal(cek, s.VaultID(), inner.Version, password, f.opt.KDF, pt)
	if err != nil {
		return nil, errInternal
	}
	return blob, nil
}

func (f *Feature) commit(s *vault.Session, blob []byte, version uint64) {
	h := sha256.Sum256(blob)
	f.st.Version, f.st.Hash, f.st.UpdatedAt = version, h[:], s.Now().UTC().Truncate(time.Millisecond)
	f.st.Blob = nil
	if f.opt.KeepCopy {
		f.st.Blob = blob
	}
	s.SyncEvent("credential.changed", strictjson.NewBuilder().Uint("version", version).Bytes())
}

func (f *Feature) create(s *vault.Session, r *Request) (json.RawMessage, error) {
	if f.st.CEKSeed != nil {
		return nil, errExists
	}
	cek, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, errInternal
	}
	defer cek.Destroy()
	seed, err := cek.Seed()
	if err != nil {
		return nil, errInternal
	}
	ks, err := suite.RandomBytes(32)
	if err != nil {
		return nil, errInternal
	}
	now := s.Now().UTC().Truncate(time.Millisecond)
	inner := &Inner{VaultID: s.VaultID(), Version: 1, CreatedAt: now, PasswordChangedAt: now, Key: ks}
	defer inner.Wipe()
	blob, err := f.seal(s, cek.Public(), inner, r.Password)
	if err != nil {
		suite.Wipe(seed)
		return nil, err
	}
	pub := ed25519.NewKeyFromSeed(ks).Public().(ed25519.PublicKey)
	f.st = state{CEKSeed: seed, Key: pub}
	f.commit(s, blob, 1)
	s.Record(vault.Activity{Kind: "credential.created", Audit: true})
	return strictjson.NewBuilder().Base64("credential", blob).Uint("version", 1).Base64("key", pub).Bytes(), nil
}

// rotate replaces the CEK and the credential key and rotates the vault's
// ik and kem in the same flush (§3.4, §3.5.4).
func (f *Feature) rotate(s *vault.Session, inner *Inner, r *Request) (json.RawMessage, error) {
	cek, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, errInternal
	}
	defer cek.Destroy()
	seed, err := cek.Seed()
	if err != nil {
		return nil, errInternal
	}
	ks, err := suite.RandomBytes(32)
	if err != nil {
		suite.Wipe(seed)
		return nil, errInternal
	}
	suite.Wipe(inner.Key)
	inner.Key = ks
	inner.Version = f.st.Version + 1
	blob, err := f.seal(s, cek.Public(), inner, r.Password)
	if err != nil {
		suite.Wipe(seed)
		return nil, err
	}
	if err := s.RotateIdentity(); err != nil {
		suite.Wipe(seed)
		return nil, errInternal
	}
	f.endWindow()
	suite.Wipe(f.st.CEKSeed)
	pub := ed25519.NewKeyFromSeed(ks).Public().(ed25519.PublicKey)
	f.st.CEKSeed, f.st.Key = seed, pub
	f.commit(s, blob, inner.Version)
	s.Record(vault.Activity{Kind: "credential.rotated", Audit: true, Feed: true})
	return strictjson.NewBuilder().Base64("credential", blob).Uint("version", f.st.Version).Base64("key", pub).Bytes(), nil
}

func (f *Feature) list() []byte {
	arr := []byte{'['}
	for i, m := range f.st.Secrets {
		if i > 0 {
			arr = append(arr, ',')
		}
		b := strictjson.NewBuilder().String("secret_id", m.ID).String("name", m.Name).String("category", m.Category)
		if m.Description != "" {
			b.String("description", m.Description)
		}
		arr = append(arr, b.String("created_at", envelope.FormatTS(m.CreatedAt)).Bytes()...)
	}
	return strictjson.NewBuilder().Uint("version", f.st.Version).Raw("secrets", append(arr, ']')).Bytes()
}
