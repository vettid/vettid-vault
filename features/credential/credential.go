// Package credential is the Protean Credential and its critical secrets
// (VAULT-MESSAGING §3.5, §10.6), following the owner's Protean Credential
// design: the member's app holds the credential, sealed to the vault's CEK
// and under the member's password; every use carries the credential and
// the password, sealed to a one-time transaction key (UTK) inside the
// session; every use rotates the CEK and destroys the old one, so earlier
// blobs are undecryptable by anyone; secret values return sealed to a
// one-time reply key. The vault keeps no plaintext afterwards (the
// credential key only during an unlock window). LAT is superseded by Nitro
// attestation.
//
// Ported from vettid.dev's credential, protean-credential and
// credential-secret handlers: the CEK and the UTK/LTK pairs are suite-2
// hybrid KEM keys; the password check is the inner AEAD of the blob rather
// than a stored PHC string; the PIN verifier and the unused master secret
// are no longer in the credential (the PIN is checked by DEK derivation).
package credential

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Password backoff (§3.5.3).
const BackoffAfter = 5

var backoffDelays = []time.Duration{30 * time.Second, time.Minute, 5 * time.Minute, 15 * time.Minute, 60 * time.Minute}

// UTK pool (§3.5.4).
const (
	PoolSize       = 20
	PoolLow        = 10
	PoolRefill     = 10
	UTKLifetime    = 30 * 24 * time.Hour
	maxPoolDevices = 64
)

// Meta is a critical secret's metadata, kept in vault state so that it can
// be listed without the password (§10.6).
type Meta struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Category    string    `json:"category"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	// Cataloged lists the secret in the catalog to connections, for
	// critical-secret use only (credential.secret.catalog, §10.13).
	Cataloged bool `json:"cataloged,omitempty"`
}

// LTK is the private half of an issued UTK.
type LTK struct {
	ID      string    `json:"id"`
	Seed    []byte    `json:"seed"`
	Expires time.Time `json:"expires"`
}

type state struct {
	CEKSeed   []byte    `json:"cek_seed,omitempty"`
	Version   uint64    `json:"version,omitempty"`
	Hash      []byte    `json:"hash,omitempty"`
	Blob      []byte    `json:"blob,omitempty"`  // the latest blob (§3.5.3, §3.5.6)
	Acked     bool      `json:"acked,omitempty"` // the app confirmed the latest blob
	Key       []byte    `json:"key,omitempty"`   // the credential key's public key
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	Secrets   []Meta    `json:"secrets,omitempty"`
	Failures  int       `json:"failures,omitempty"`
	NotBefore time.Time `json:"not_before,omitempty"`
	// Pools are the LTKs per app device (§3.5.4).
	Pools map[string][]LTK `json:"pools,omitempty"`
}

// Options configure the feature.
type Options struct {
	// KDF for new seals; zero means DefaultKDF. Tests use MinKDF.
	KDF KDF
}

// Feature implements vault.Feature, vault.Zeroizer, vault.SettingsObserver
// and vault.CredentialGate.
type Feature struct {
	mu  sync.Mutex
	opt Options
	st  state

	// The unlock window (§3.5.3): memory only, never saved.
	key    ed25519.PrivateKey
	keyExp time.Time

	rotObs []KeyRotationObserver
}

// KeyRotationObserver is told of every credential-key rotation statement
// (§3.5.5): member authentication delivers it to the connections that
// pinned the member's key (§10.4).
type KeyRotationObserver interface {
	CredentialKeyRotated(s *vault.Session, r *credwire.KeyRotation)
}

// AddKeyRotationObserver registers an observer (at construction).
func (f *Feature) AddKeyRotationObserver(o KeyRotationObserver) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rotObs = append(f.rotObs, o)
}

// New returns the feature.
func New(o Options) *Feature {
	if o.KDF == (KDF{}) {
		o.KDF = DefaultKDF
	}
	return &Feature{opt: o, st: state{Pools: map[string][]LTK{}}}
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
		r("credential.utk.get", apps), r("credential.create", apps), r("credential.get", apps), r("credential.ack", apps),
		r("credential.version", owners), r("credential.unlock", apps), r("credential.lock", apps), r("credential.rotate", apps),
		r("credential.password.change", apps), r("credential.delete", apps),
		r("credential.secret.add", apps), r("credential.secret.get", apps), r("credential.secret.list", owners),
		r("credential.secret.delete", apps), r("credential.recover", apps), r("credential.secret.catalog", apps),
	}
}

// CredentialReady implements vault.CredentialGate (§3.5.7).
func (f *Feature) CredentialReady() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.st.CEKSeed != nil
}

// Load implements vault.Feature.
func (f *Feature) Load(data json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var st state
	if err := json.Unmarshal(data, &st); err != nil {
		return err
	}
	if st.Pools == nil {
		st.Pools = map[string][]LTK{}
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
// the keys held in memory.
func (f *Feature) Zeroize() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.endWindow()
	f.wipeKeys()
	f.st = state{Pools: map[string][]LTK{}}
}

func (f *Feature) wipeKeys() {
	suite.Wipe(f.st.CEKSeed)
	for _, p := range f.st.Pools {
		for _, l := range p {
			suite.Wipe(l.Seed)
		}
	}
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

// SettingsChanged implements vault.SettingsObserver: turning the backup
// off drops the latest blob once the app has confirmed it (§3.5.6).
func (f *Feature) SettingsChanged(_ *vault.Session, next vault.Settings) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !next.Backup() && f.st.Acked {
		f.st.Blob = nil
	}
}

var (
	errBad          = vault.NewError("bad_request", "")
	errNotFound     = vault.NewError("not_found", "")
	errExists       = vault.NewError("exists", "")
	errPassword     = vault.NewError("bad_password", "")
	errBackoff      = vault.NewError("backoff", "")
	errStale        = vault.NewError("stale_credential", "")
	errLimit        = vault.NewError("limit", "")
	errInternal     = vault.NewError("internal", "")
	errForbidden    = vault.NewError("forbidden", "")
	errUTK          = vault.NewError("utk_invalid", "")
	errCredRequired = vault.NewError("credential_required", "")
	b64             = base64.StdEncoding
)

// What a request type carries.
const (
	needBlob = 1 << iota
	optBlob
	needSealed
	needPassword
	needNewPassword
	needSecretID
	needSecret
	needReply
	needRequest
)

var needs = map[string]int{
	"credential.utk.get":         0,
	"credential.create":          needSealed | needPassword,
	"credential.get":             0,
	"credential.ack":             0,
	"credential.version":         0,
	"credential.unlock":          needBlob | needSealed | needPassword,
	"credential.lock":            0,
	"credential.rotate":          needBlob | needSealed | needPassword,
	"credential.password.change": needBlob | needSealed | needPassword | needNewPassword,
	"credential.delete":          needBlob | needSealed | needPassword,
	"credential.secret.add":      needBlob | needSealed | needPassword | needSecret,
	"credential.secret.get":      needBlob | needSealed | needPassword | needSecretID | needReply,
	"credential.secret.list":     0,
	"credential.secret.delete":   needBlob | needSealed | needPassword | needSecretID,
	"credential.recover":         optBlob | needSealed | needPassword,
	"credential.secret.catalog":  0,
	// A critical-secret use by a connection (§10.13): the consent is bound
	// to the request and the payload.
	"critical-secret-use.approve": needBlob | needSealed | needPassword | needRequest,
}

// Envelope is a parsed request body: the blob and the sealed payload.
type Envelope struct {
	Blob   []byte
	UTKID  string
	Sealed []byte
}

// ParseEnvelope parses the outer body of typ strictly.
func ParseEnvelope(typ string, body []byte) (*Envelope, error) {
	n, ok := needs[typ]
	if !ok {
		return nil, errBad
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	e := &Envelope{}
	if n&(needBlob|optBlob) != 0 {
		s, present, err := o.OptString("credential")
		if err != nil || (!present && n&needBlob != 0) || len(s) > b64.EncodedLen(MaxBlob) {
			return nil, errBad
		}
		if present {
			if e.Blob, err = strictjson.DecodeStd(s, -1); err != nil {
				return nil, errBad
			}
			if _, err := ParseHeader(e.Blob); err != nil {
				return nil, errBad
			}
		}
	}
	if n&needSealed != 0 {
		if e.UTKID, err = o.String("utk_id"); err != nil || !ValidUTKID(e.UTKID) {
			return nil, errBad
		}
		s, err := o.String("sealed")
		if err != nil || len(s) > b64.EncodedLen(credwire.EncSize+credwire.MaxPayload+16) {
			return nil, errBad
		}
		if e.Sealed, err = strictjson.DecodeStd(s, -1); err != nil {
			return nil, errBad
		}
	}
	return e, nil
}

// ValidUTKID reports whether s is a UTK id: 16 lowercase hex characters.
func ValidUTKID(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !(s[i] >= '0' && s[i] <= '9' || s[i] >= 'a' && s[i] <= 'f') {
			return false
		}
	}
	return true
}

// Payload is a parsed UTK payload.
type Payload struct {
	Password    []byte
	NewPassword []byte
	SecretID    string
	Name        string
	Category    string
	Description string
	Value       []byte
	Reply       *suite.PublicKey
	// RequestID and PayloadHash bind a critical-secret use (§10.13).
	RequestID   string
	PayloadHash []byte
}

// Wipe zeroizes the payload's secrets.
func (p *Payload) Wipe() {
	if p == nil {
		return
	}
	suite.Wipe(p.Password)
	suite.Wipe(p.NewPassword)
	suite.Wipe(p.Value)
}

func password(o strictjson.Object, k string) ([]byte, error) {
	p, err := o.String(k)
	if err != nil || len(p) < MinPassword || len(p) > MaxPassword {
		return nil, errBad
	}
	return []byte(p), nil
}

// ParsePayload parses the opened payload of typ strictly (§10.6).
func ParsePayload(typ string, pt []byte) (*Payload, error) {
	n, ok := needs[typ]
	if !ok {
		return nil, errBad
	}
	o, err := strictjson.ParseObject(pt)
	if err != nil {
		return nil, errBad
	}
	p := &Payload{}
	fail := func() (*Payload, error) { p.Wipe(); return nil, errBad }
	if n&needPassword != 0 {
		if p.Password, err = password(o, "password"); err != nil {
			return fail()
		}
	}
	if n&needNewPassword != 0 {
		if p.NewPassword, err = password(o, "new_password"); err != nil {
			return fail()
		}
	}
	if n&needSecretID != 0 {
		if p.SecretID, err = o.String("secret_id"); err != nil || !envelope.ValidULID(p.SecretID) {
			return fail()
		}
	}
	if n&needSecret != 0 {
		if p.Name, err = o.String("name"); err != nil || p.Name == "" || len(p.Name) > MaxName {
			return fail()
		}
		if p.Category, err = o.String("category"); err != nil || !Categories[p.Category] {
			return fail()
		}
		if d, present, err := o.OptString("description"); err != nil || len(d) > MaxDesc {
			return fail()
		} else if present {
			p.Description = d
		}
		if p.Value, err = o.Base64("value", -1); err != nil || len(p.Value) == 0 || len(p.Value) > MaxValue {
			return fail()
		}
	}
	if n&needRequest != 0 {
		if p.RequestID, err = o.String("request_id"); err != nil || !envelope.ValidULID(p.RequestID) {
			return fail()
		}
		if p.PayloadHash, err = o.Base64("payload_sha256", sha256.Size); err != nil {
			return fail()
		}
	}
	if n&needReply != 0 {
		ek, err := o.Base64("reply_key", suite.EKSize)
		if err != nil {
			return fail()
		}
		if p.Reply, err = suite.ParsePublicKey(ek); err != nil {
			return fail()
		}
	}
	return p, nil
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneUTKs(s.Now())
	from := s.From()
	if from.Recovering && in.Type != "credential.recover" && in.Type != "credential.utk.get" {
		return nil, errForbidden
	}
	e, err := ParseEnvelope(in.Type, in.Body)
	if err != nil {
		return nil, err
	}
	switch in.Type {
	case "credential.utk.get":
		return strictjson.NewBuilder().Raw("utks", f.issue(s, from.ID, PoolSize-len(f.st.Pools[from.ID]))).Bytes(), nil
	case "credential.get":
		if f.st.CEKSeed == nil || len(f.st.Blob) == 0 {
			return nil, errNotFound
		}
		return strictjson.NewBuilder().Base64("credential", f.st.Blob).Uint("version", f.st.Version).
			String("updated_at", envelope.FormatTS(f.st.UpdatedAt)).Bytes(), nil
	case "credential.ack":
		o, _ := strictjson.ParseObject(in.Body)
		v, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
		if err != nil {
			return nil, errBad
		}
		if f.st.CEKSeed == nil || v != f.st.Version {
			return nil, errStale
		}
		f.acked(s)
		return nil, nil
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
	case "credential.secret.catalog":
		return f.catalog(s, in.Body)
	}
	// Everything else spends a UTK first (§3.5.4).
	p, err := f.spend(s, in, e)
	if err != nil {
		return nil, err
	}
	defer p.Wipe()
	switch in.Type {
	case "credential.create":
		return f.create(s, p)
	case "credential.recover":
		return f.recover(s, e, p)
	}
	// The rest opens the credential with the password (§3.5.3).
	cek, inner, err := f.open(s, e.Blob, p.Password)
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
		return f.respond(s, inner, p.Password, func(b *strictjson.Builder) {
			b.String("expires_at", envelope.FormatTS(f.keyExp))
		})
	case "credential.secret.get":
		for _, sec := range inner.Secrets {
			if sec.ID == p.SecretID {
				sealed, err := credwire.SealValue(p.Reply, s.VaultID(), in.ID, sec.Value)
				if err != nil {
					return nil, errInternal
				}
				sec := sec
				s.Record(vault.Activity{Kind: "credential.secret.read", Ref: sec.ID, Audit: true, Feed: true})
				return f.respond(s, inner, p.Password, func(b *strictjson.Builder) {
					b.String("secret_id", sec.ID).String("name", sec.Name).String("category", sec.Category)
					if sec.Description != "" {
						b.String("description", sec.Description)
					}
					b.Base64("value_sealed", sealed).String("created_at", envelope.FormatTS(sec.CreatedAt))
				})
			}
		}
		return nil, errNotFound
	case "credential.delete":
		f.endWindow()
		f.wipeKeys()
		f.st = state{Pools: map[string][]LTK{}}
		s.SyncEvent("credential.deleted", nil)
		s.Record(vault.Activity{Kind: "credential.deleted", Audit: true})
		return nil, nil
	case "credential.secret.add":
		if len(inner.Secrets) >= MaxSecrets {
			return nil, errLimit
		}
		sec := Secret{ID: s.NewID(), Name: p.Name, Category: p.Category, Description: p.Description,
			Value: append([]byte(nil), p.Value...), CreatedAt: s.Now().UTC().Truncate(time.Millisecond)}
		inner.Secrets = append(inner.Secrets, sec)
		out, err := f.respond(s, inner, p.Password, func(b *strictjson.Builder) { b.String("secret_id", sec.ID) })
		if err != nil {
			return nil, err
		}
		f.st.Secrets = append(f.st.Secrets, Meta{ID: sec.ID, Name: sec.Name, Category: sec.Category,
			Description: sec.Description, CreatedAt: sec.CreatedAt})
		s.Record(vault.Activity{Kind: "credential.secret.added", Ref: sec.ID, Audit: true})
		return out, nil
	case "credential.secret.delete":
		idx := -1
		for i, sec := range inner.Secrets {
			if sec.ID == p.SecretID {
				idx = i
			}
		}
		if idx < 0 {
			return nil, errNotFound
		}
		suite.Wipe(inner.Secrets[idx].Value)
		inner.Secrets = append(inner.Secrets[:idx:idx], inner.Secrets[idx+1:]...)
		out, err := f.respond(s, inner, p.Password, nil)
		if err != nil {
			return nil, err
		}
		for i, m := range f.st.Secrets {
			if m.ID == p.SecretID {
				f.st.Secrets = append(f.st.Secrets[:i:i], f.st.Secrets[i+1:]...)
				break
			}
		}
		s.Record(vault.Activity{Kind: "credential.secret.deleted", Ref: p.SecretID, Audit: true})
		return out, nil
	case "credential.password.change":
		inner.PasswordChangedAt = s.Now().UTC().Truncate(time.Millisecond)
		out, err := f.respond(s, inner, p.NewPassword, nil)
		if err != nil {
			return nil, err
		}
		s.Record(vault.Activity{Kind: "credential.password_changed", Audit: true})
		return out, nil
	case "credential.rotate":
		return f.rotate(s, inner, p)
	}
	return nil, vault.NewError("unsupported_type", "")
}

// --- UTKs (§3.5.4) ---

// issue adds n UTKs to the device's pool and returns them as JSON.
func (f *Feature) issue(s *vault.Session, device string, n int) []byte {
	arr := []byte{'['}
	if _, ok := f.st.Pools[device]; !ok && len(f.st.Pools) >= maxPoolDevices {
		n = 0
	}
	exp := s.Now().UTC().Add(UTKLifetime).Truncate(time.Millisecond)
	for i := 0; i < n; i++ {
		k, err := suite.GeneratePrivateKey()
		if err != nil {
			break
		}
		seed, err := k.Seed()
		ek := k.Public().Bytes()
		k.Destroy()
		if err != nil {
			break
		}
		idb, err := suite.RandomBytes(8)
		if err != nil {
			suite.Wipe(seed)
			break
		}
		id := hex.EncodeToString(idb)
		f.st.Pools[device] = append(f.st.Pools[device], LTK{ID: id, Seed: seed, Expires: exp})
		if len(arr) > 1 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("utk_id", id).Base64("ek", ek).String("expires_at", envelope.FormatTS(exp)).Bytes()...)
	}
	return append(arr, ']')
}

func (f *Feature) pruneUTKs(now time.Time) {
	for d, pool := range f.st.Pools {
		kept := pool[:0]
		for _, l := range pool {
			if now.Before(l.Expires) {
				kept = append(kept, l)
			} else {
				suite.Wipe(l.Seed)
			}
		}
		if len(kept) == 0 {
			delete(f.st.Pools, d)
		} else {
			f.st.Pools[d] = kept
		}
	}
}

// spend finds the UTK among those issued to the sender, removes it (it is
// spent whatever happens next) and opens the payload.
func (f *Feature) spend(s *vault.Session, in *envelope.Inner, e *Envelope) (*Payload, error) {
	device := s.From().ID
	pool := f.st.Pools[device]
	idx := -1
	for i, l := range pool {
		if l.ID == e.UTKID {
			idx = i
		}
	}
	if idx < 0 {
		return nil, errUTK
	}
	l := pool[idx]
	f.st.Pools[device] = append(pool[:idx:idx], pool[idx+1:]...)
	defer suite.Wipe(l.Seed)
	ltk, err := suite.NewPrivateKey(l.Seed)
	if err != nil {
		return nil, errUTK
	}
	defer ltk.Destroy()
	pt, err := credwire.OpenPayload(ltk, s.VaultID(), l.ID, in.Type, in.ID, e.Sealed)
	if err != nil {
		return nil, errUTK
	}
	defer suite.Wipe(pt)
	return ParsePayload(in.Type, pt)
}

// replenish returns new UTKs when the sender's pool is low.
func (f *Feature) replenish(s *vault.Session) []byte {
	device := s.From().ID
	if len(f.st.Pools[device]) >= PoolLow {
		return []byte("[]")
	}
	return f.issue(s, device, PoolRefill)
}

// --- the credential ---

// open performs steps 2–4 of §3.5.3. On success the caller owns the CEK
// and the plaintext and must destroy and wipe them.
func (f *Feature) open(s *vault.Session, blob, pw []byte) (*suite.PrivateKey, *Inner, error) {
	now := s.Now()
	if f.st.CEKSeed == nil {
		return nil, nil, errCredRequired
	}
	if now.Before(f.st.NotBefore) {
		return nil, nil, errBackoff
	}
	h := sha256.Sum256(blob)
	if !suite.Equal(h[:], f.st.Hash) {
		return nil, nil, errStale
	}
	cek, err := suite.NewPrivateKey(f.st.CEKSeed)
	if err != nil {
		return nil, nil, errInternal
	}
	version, pt, err := Open(cek, s.VaultID(), blob, pw)
	if err == ErrPassword {
		cek.Destroy()
		f.st.Failures++
		if n := f.st.Failures - BackoffAfter; n >= 0 {
			f.st.NotBefore = now.Add(backoffDelays[min(n, len(backoffDelays)-1)])
		}
		s.Record(vault.Activity{Kind: "credential.password_failed", Audit: true, Feed: true, Priority: "high"})
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

// acked records that the app holds the latest blob; without backup the
// vault then keeps only its hash (§3.5.3, §3.5.6).
func (f *Feature) acked(s *vault.Session) {
	f.st.Acked = true
	if !s.Settings().Backup() {
		f.st.Blob = nil
	}
}

// rotateCEK is step 6 of §3.5.3: a new CEK, the content sealed under it as
// the next version, the old CEK destroyed. It returns the new blob.
func (f *Feature) rotateCEK(s *vault.Session, inner *Inner, pw []byte) ([]byte, error) {
	cek, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, errInternal
	}
	defer cek.Destroy()
	seed, err := cek.Seed()
	if err != nil {
		return nil, errInternal
	}
	inner.Version = f.st.Version + 1
	blob, err := f.seal(s, cek.Public(), inner, pw)
	if err != nil {
		suite.Wipe(seed)
		return nil, err
	}
	suite.Wipe(f.st.CEKSeed) // the old CEK: every earlier blob is now dead
	f.st.CEKSeed = seed
	f.commit(s, blob, inner.Version)
	return blob, nil
}

// respond rotates the CEK and builds {extra..., credential, version, utks}.
func (f *Feature) respond(s *vault.Session, inner *Inner, pw []byte, extra func(*strictjson.Builder)) (json.RawMessage, error) {
	blob, err := f.rotateCEK(s, inner, pw)
	if err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder()
	if extra != nil {
		extra(b)
	}
	return b.Base64("credential", blob).Uint("version", f.st.Version).Raw("utks", f.replenish(s)).Bytes(), nil
}

func (f *Feature) seal(s *vault.Session, cek *suite.PublicKey, inner *Inner, pw []byte) ([]byte, error) {
	pt := inner.Marshal()
	defer suite.Wipe(pt)
	if len(pt) > MaxInner {
		return nil, errLimit
	}
	blob, err := Seal(cek, s.VaultID(), inner.Version, pw, f.opt.KDF, pt)
	if err != nil {
		return nil, errInternal
	}
	return blob, nil
}

// commit records a new latest blob: kept until the app confirms it, and
// afterwards only with backup on (§3.5.3, §3.5.6).
func (f *Feature) commit(s *vault.Session, blob []byte, version uint64) {
	h := sha256.Sum256(blob)
	f.st.Version, f.st.Hash, f.st.UpdatedAt = version, h[:], s.Now().UTC().Truncate(time.Millisecond)
	f.st.Blob, f.st.Acked = blob, false
	s.SyncEvent("credential.changed", strictjson.NewBuilder().Uint("version", version).Bytes())
}

func (f *Feature) create(s *vault.Session, p *Payload) (json.RawMessage, error) {
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
	blob, err := f.seal(s, cek.Public(), inner, p.Password)
	if err != nil {
		suite.Wipe(seed)
		return nil, err
	}
	pub := ed25519.NewKeyFromSeed(ks).Public().(ed25519.PublicKey)
	f.st.CEKSeed, f.st.Key, f.st.Secrets, f.st.Failures, f.st.NotBefore = seed, pub, nil, 0, time.Time{}
	f.commit(s, blob, 1)
	s.Record(vault.Activity{Kind: "credential.created", Audit: true})
	return strictjson.NewBuilder().Base64("credential", blob).Uint("version", 1).Base64("key", pub).
		Raw("utks", f.replenish(s)).Bytes(), nil
}

// rotate replaces the credential key and rotates the vault's ik and kem in
// the same flush (§3.4, §3.5.5); the CEK rotates as with every use.
func (f *Feature) rotate(s *vault.Session, inner *Inner, p *Payload) (json.RawMessage, error) {
	ks, err := suite.RandomBytes(32)
	if err != nil {
		return nil, errInternal
	}
	// The rotation statement: the new credential key signed by the old one
	// and by itself (§3.5.5).
	oldPriv, newPriv := ed25519.NewKeyFromSeed(inner.Key), ed25519.NewKeyFromSeed(ks)
	stmt, err := credwire.NewKeyRotation(oldPriv, newPriv)
	suite.Wipe(oldPriv)
	suite.Wipe(newPriv)
	if err != nil {
		suite.Wipe(ks)
		return nil, errInternal
	}
	if err := s.RotateIdentity(); err != nil {
		suite.Wipe(ks)
		return nil, errInternal
	}
	suite.Wipe(inner.Key)
	inner.Key = ks
	f.endWindow()
	pub := ed25519.NewKeyFromSeed(ks).Public().(ed25519.PublicKey)
	out, err := f.respond(s, inner, p.Password, func(b *strictjson.Builder) { b.Base64("key", pub) })
	if err != nil {
		return nil, err
	}
	f.st.Key = pub
	s.Record(vault.Activity{Kind: "credential.rotated", Audit: true, Feed: true})
	for _, o := range f.rotObs {
		o.CredentialKeyRotated(s, stmt)
	}
	return out, nil
}

// recover is the last step of a recovery (§11.11.5): the recovered app
// authenticates with the password against the latest blob, the vault's
// copy or, with backup off, the member's own; the CEK rotates and the new
// blob is handed over; only then does the app become an ordinary app.
func (f *Feature) recover(s *vault.Session, e *Envelope, p *Payload) (json.RawMessage, error) {
	if !s.From().Recovering {
		return nil, errForbidden
	}
	if f.st.CEKSeed == nil {
		return nil, errCredRequired // no credential, no recovery
	}
	blob := e.Blob
	if blob == nil {
		blob = f.st.Blob
	}
	if blob == nil {
		return nil, errCredRequired // backup off: the member supplies the blob
	}
	cek, inner, err := f.open(s, blob, p.Password)
	if err != nil {
		return nil, err
	}
	defer cek.Destroy()
	defer inner.Wipe()
	out, err := f.respond(s, inner, p.Password, nil)
	if err != nil {
		return nil, err
	}
	if err := s.CompleteRecovery(); err != nil {
		return nil, errInternal
	}
	s.Record(vault.Activity{Kind: "credential.recovered", Audit: true, Feed: true})
	return out, nil
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
		arr = append(arr, b.Bool("cataloged", m.Cataloged).String("created_at", envelope.FormatTS(m.CreatedAt)).Bytes()...)
	}
	return strictjson.NewBuilder().Uint("version", f.st.Version).Raw("secrets", append(arr, ']')).Bytes()
}

// PoolSizeOf returns the number of outstanding UTKs of a device (tests).
func (f *Feature) PoolSizeOf(device string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.st.Pools[device])
}

// catalog lists or unlists a critical secret in the catalog to
// connections (credential.secret.catalog, §10.13). It changes only
// vault-held metadata, so it needs no password.
func (f *Feature) catalog(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	id, err := o.String("secret_id")
	if err != nil || !envelope.ValidULID(id) {
		return nil, errBad
	}
	on, err := o.Bool("cataloged")
	if err != nil {
		return nil, errBad
	}
	if f.st.CEKSeed == nil {
		return nil, errCredRequired
	}
	for i := range f.st.Secrets {
		if f.st.Secrets[i].ID == id {
			if f.st.Secrets[i].Cataloged != on {
				f.st.Secrets[i].Cataloged = on
				s.SyncEvent("credential.secret.cataloged", strictjson.NewBuilder().String("secret_id", id).Bool("cataloged", on).Bytes())
				s.Record(vault.Activity{Kind: "credential.secret.cataloged", Ref: id, Audit: true})
			}
			return nil, nil
		}
	}
	return nil, errNotFound
}

// CatalogedSecrets returns the metadata of the critical secrets in the
// catalog (§10.12, §10.13), in the credential's order.
func (f *Feature) CatalogedSecrets() []Meta {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Meta
	for _, m := range f.st.Secrets {
		if m.Cataloged {
			out = append(out, m)
		}
	}
	return out
}

// CatalogedSecret returns a cataloged critical secret's metadata.
func (f *Feature) CatalogedSecret(id string) (Meta, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.st.Secrets {
		if m.ID == id && m.Cataloged {
			return m, true
		}
	}
	return Meta{}, false
}

// UseSecret performs one use of a critical secret for a connection
// (critical-secret-use.approve, §10.13) as a credential operation
// (§3.5.3): it spends the UTK, lets check verify the sealed payload's
// binding (request and payload hash), opens the credential with the
// password, gives use the secret's value (nil if the credential no longer
// holds it), rotates the CEK and returns the response with the members
// use added. The value and the plaintext are wiped before it returns; use
// must not keep the value.
func (f *Feature) UseSecret(s *vault.Session, in *envelope.Inner, secretID string, check func(*Payload) error,
	use func(value []byte, b *strictjson.Builder)) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pruneUTKs(s.Now())
	if s.From().Kind != vault.KindApp || s.From().Recovering {
		return nil, errForbidden
	}
	e, err := ParseEnvelope(in.Type, in.Body)
	if err != nil {
		return nil, err
	}
	p, err := f.spend(s, in, e)
	if err != nil {
		return nil, err
	}
	defer p.Wipe()
	if err := check(p); err != nil {
		return nil, err
	}
	cek, inner, err := f.open(s, e.Blob, p.Password)
	if err != nil {
		return nil, err
	}
	defer cek.Destroy()
	defer inner.Wipe()
	var value []byte
	for _, sec := range inner.Secrets {
		if sec.ID == secretID {
			value = sec.Value
		}
	}
	return f.respond(s, inner, p.Password, func(b *strictjson.Builder) { use(value, b) })
}
