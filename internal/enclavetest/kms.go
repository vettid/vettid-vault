package enclavetest

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-vault/vms/nitro"
)

// Test sealing-key namespace and host role (TEST ONLY).
const (
	KMSAccount = "111122223333"
	KMSRegion  = "us-east-1"
	HostRole   = "arn:aws:iam::111122223333:role/vettid-enclave-host"
	// RetirementRole and RetirementWindow are the test release's pinned
	// retirement principal and pending window (0.10.0; staging's 7 days).
	RetirementRole   = "arn:aws:iam::111122223333:role/vettid-org-vault-key-retirement"
	RetirementWindow = 7
)

// KeyARN returns the test sealing-key ARN of release n.
func KeyARN(n uint64) string {
	return fmt.Sprintf("arn:aws:kms:%s:%s:key/%08x-0000-4000-8000-%012x", KMSRegion, KMSAccount, n, n)
}

// Errors of the fake KMS (AccessDenied and friends).
var (
	ErrKMSAccessDenied = errors.New("enclavetest: KMS AccessDeniedException")
	ErrKMSNotFound     = errors.New("enclavetest: KMS NotFoundException")
	ErrKMSInvalid      = errors.New("enclavetest: KMS InvalidCiphertextException")
	ErrKMSAttestation  = errors.New("enclavetest: KMS invalid recipient attestation")
)

// FakeKMS is a TEST-ONLY AWS KMS: symmetric keys with key policies that it
// evaluates (Allow/Deny, actions with wildcards, StringEquals and
// StringEqualsIgnoreCase on the recipient attestation's PCRs, CallerAccount),
// and Recipient semantics: a data key or plaintext is returned only inside
// a CMS envelope to the RSA key of a valid, fresh attestation document.
type FakeKMS struct {
	Roots *x509.CertPool
	Now   func() time.Time
	// CallerAccount is the account of the calling host role.
	CallerAccount string

	mu    sync.Mutex
	keys  map[string]*FakeKey
	seed  [32]byte
	calls map[string]int
	// FailReads makes DescribeKey/GetKeyPolicy/ListGrants fail;
	// FailGenerate makes GenerateDataKey fail (fault injection).
	FailReads    bool
	FailGenerate bool
}

// FakeKey is one key.
type FakeKey struct {
	ARN      string
	Policy   string
	Describe string
	Grants   string
	master   []byte
}

// NewFakeKMS returns a fake KMS whose key material derives from seed (so
// separate test processes agree), trusting the given Nitro roots.
func NewFakeKMS(seed string, roots *x509.CertPool, now func() time.Time) *FakeKMS {
	if now == nil {
		now = time.Now
	}
	return &FakeKMS{Roots: roots, Now: now, CallerAccount: KMSAccount, keys: map[string]*FakeKey{},
		seed: sha256.Sum256([]byte("VettID TEST ONLY fake KMS\x00" + seed)), calls: map[string]int{}}
}

// GoodPolicy returns the §11.10.7 policy shape for a key whose Decrypt is
// limited to decrypt (a PCR0) and GenerateDataKey to gdk.
func GoodPolicy(decrypt string, gdk []string) string {
	vals, _ := json.Marshal(gdk)
	return `{"Version":"2012-10-17","Id":"vettid-release","Statement":[` +
		`{"Sid":"Unseal","Effect":"Allow","Principal":{"AWS":"` + HostRole + `"},"Action":"kms:Decrypt","Resource":"*",` +
		`"Condition":{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:ImageSha384":"` + decrypt + `"},"StringEquals":{"kms:CallerAccount":"` + KMSAccount + `"}}},` +
		`{"Sid":"Seal","Effect":"Allow","Principal":{"AWS":"` + HostRole + `"},"Action":"kms:GenerateDataKey","Resource":"*",` +
		`"Condition":{"StringEqualsIgnoreCase":{"kms:RecipientAttestation:ImageSha384":` + string(vals) + `},"StringEquals":{"kms:CallerAccount":"` + KMSAccount + `"}}},` +
		`{"Sid":"Verify","Effect":"Allow","Principal":{"AWS":["` + HostRole + `","` + RetirementRole + `"]},"Action":["kms:DescribeKey","kms:GetKeyPolicy","kms:ListGrants"],"Resource":"*"},` +
		`{"Sid":"RetireAfterNotice","Effect":"Allow","Principal":{"AWS":"` + RetirementRole + `"},"Action":"kms:ScheduleKeyDeletion","Resource":"*",` +
		`"Condition":{"NumericEquals":{"kms:ScheduleKeyDeletionPendingWindowInDays":"` + strconv.Itoa(RetirementWindow) + `"},"StringEquals":{"kms:CallerAccount":"` + KMSAccount + `"}}},` +
		`{"Sid":"RescueBeforeDeletion","Effect":"Allow","Principal":{"AWS":"` + RetirementRole + `"},"Action":["kms:CancelKeyDeletion","kms:EnableKey"],"Resource":"*",` +
		`"Condition":{"StringEquals":{"kms:CallerAccount":"` + KMSAccount + `"}}}]}`
}

// GoodDescribe returns a DescribeKey response for a single-region,
// enabled, symmetric customer key.
func GoodDescribe(arn string) string {
	id := arn[strings.LastIndex(arn, "/")+1:]
	return `{"KeyMetadata":{"AWSAccountId":"` + KMSAccount + `","Arn":"` + arn + `","CreationDate":1.7593344E9,` +
		`"CustomerMasterKeySpec":"SYMMETRIC_DEFAULT","Enabled":true,"EncryptionAlgorithms":["SYMMETRIC_DEFAULT"],` +
		`"KeyId":"` + id + `","KeyManager":"CUSTOMER","KeySpec":"SYMMETRIC_DEFAULT","KeyState":"Enabled",` +
		`"KeyUsage":"ENCRYPT_DECRYPT","MultiRegion":false,"Origin":"AWS_KMS"}}`
}

// AddKey creates a key with the given policy, a good DescribeKey and no
// grants.
func (f *FakeKMS) AddKey(arn, policy string) *FakeKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := sha256.Sum256(append(f.seed[:], arn...))
	k := &FakeKey{ARN: arn, Policy: policy, Describe: GoodDescribe(arn), Grants: `{"Grants":[],"Truncated":false}`, master: m[:]}
	f.keys[arn] = k
	return k
}

// Key returns a key for modification.
func (f *FakeKMS) Key(arn string) *FakeKey {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.keys[arn]
}

// Calls returns how often an operation was called.
func (f *FakeKMS) Calls(op string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[op]
}

func (f *FakeKMS) key(op, arn string) (*FakeKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[op]++
	k := f.keys[arn]
	if k == nil {
		return nil, ErrKMSNotFound
	}
	return k, nil
}

// recipient verifies a Recipient attestation document: chain, freshness,
// non-debug PCRs and an RSA public key.
func (f *FakeKMS) recipient(att []byte) (*nitro.Document, *rsa.PublicKey, error) {
	d, err := nitro.Verify(att, f.Roots)
	if err != nil {
		return nil, nil, ErrKMSAttestation
	}
	if d.CheckFresh(f.Now(), 5*time.Minute, time.Minute) != nil || d.Measurements().IsDebug() {
		return nil, nil, ErrKMSAttestation
	}
	k, err := x509.ParsePKIXPublicKey(d.PublicKey)
	if err != nil {
		return nil, nil, ErrKMSAttestation
	}
	pub, ok := k.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, nil, ErrKMSAttestation
	}
	return d, pub, nil
}

// GenerateDataKey implements the enclave's KMS interface.
func (f *FakeKMS) GenerateDataKey(_ context.Context, arn string, att []byte) ([]byte, []byte, error) {
	k, err := f.key("GenerateDataKey", arn)
	if err != nil {
		return nil, nil, err
	}
	d, pub, err := f.recipient(att)
	if err != nil {
		return nil, nil, err
	}
	f.mu.Lock()
	fail := f.FailGenerate
	f.mu.Unlock()
	if fail {
		return nil, nil, ErrKMSAccessDenied
	}
	if !f.allowed(k.Policy, "kms:GenerateDataKey", d) {
		return nil, nil, ErrKMSAccessDenied
	}
	dk := make([]byte, 32)
	_, _ = rand.Read(dk)
	aead, _ := chacha20poly1305.NewX(k.master)
	nonce := make([]byte, 24)
	_, _ = rand.Read(nonce)
	blob := binary.BigEndian.AppendUint16([]byte("FKMS"), uint16(len(arn)))
	blob = append(blob, arn...)
	blob = append(blob, nonce...)
	blob = aead.Seal(blob, nonce, dk, []byte(arn))
	return blob, WrapCMS(pub, dk, CMSOptions{}), nil
}

// Decrypt implements the enclave's KMS interface.
func (f *FakeKMS) Decrypt(_ context.Context, arn string, blob, att []byte) ([]byte, error) {
	if len(blob) < 6 || string(blob[:4]) != "FKMS" {
		return nil, ErrKMSInvalid
	}
	n := int(binary.BigEndian.Uint16(blob[4:6]))
	if len(blob) < 6+n+24+16 || string(blob[6:6+n]) != arn {
		return nil, ErrKMSInvalid // KeyId does not match the ciphertext's key
	}
	k, err := f.key("Decrypt", arn)
	if err != nil {
		return nil, err
	}
	d, pub, err := f.recipient(att)
	if err != nil {
		return nil, err
	}
	if !f.allowed(k.Policy, "kms:Decrypt", d) {
		return nil, ErrKMSAccessDenied
	}
	aead, _ := chacha20poly1305.NewX(k.master)
	nonce := blob[6+n : 6+n+24]
	dk, err := aead.Open(nil, nonce, blob[6+n+24:], []byte(arn))
	if err != nil {
		return nil, ErrKMSInvalid
	}
	return WrapCMS(pub, dk, CMSOptions{}), nil
}

func (f *FakeKMS) read(op, arn string, get func(*FakeKey) string) ([]byte, error) {
	k, err := f.key(op, arn)
	if err != nil {
		return nil, err
	}
	if f.FailReads {
		return nil, ErrKMSAccessDenied
	}
	return []byte(get(k)), nil
}

// DescribeKey implements the enclave's KMS interface.
func (f *FakeKMS) DescribeKey(_ context.Context, arn string) ([]byte, error) {
	return f.read("DescribeKey", arn, func(k *FakeKey) string { return k.Describe })
}

// GetKeyPolicy implements the enclave's KMS interface.
func (f *FakeKMS) GetKeyPolicy(_ context.Context, arn string) ([]byte, error) {
	return f.read("GetKeyPolicy", arn, func(k *FakeKey) string {
		b, _ := json.Marshal(map[string]string{"Policy": k.Policy, "PolicyName": "default"})
		return string(b)
	})
}

// ListGrants implements the enclave's KMS interface.
func (f *FakeKMS) ListGrants(_ context.Context, arn string) ([]byte, error) {
	return f.read("ListGrants", arn, func(k *FakeKey) string { return k.Grants })
}

// --- policy evaluation (the subset the tests need, as AWS evaluates it) ---

func asList(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func actionMatches(pattern, action string) bool {
	p, a := strings.ToLower(pattern), strings.ToLower(action)
	if strings.HasSuffix(p, "*") {
		return strings.HasPrefix(a, strings.TrimSuffix(p, "*"))
	}
	return p == a
}

func (f *FakeKMS) contextValue(key string, d *nitro.Document) (string, bool) {
	switch {
	case key == "kms:RecipientAttestation:ImageSha384" || key == "kms:RecipientAttestation:PCR0":
		return d.PCRHex(0), true
	case strings.HasPrefix(key, "kms:RecipientAttestation:PCR"):
		var i uint64
		if _, err := fmt.Sscanf(key[len("kms:RecipientAttestation:PCR"):], "%d", &i); err != nil {
			return "", false
		}
		v := d.PCRHex(i)
		return v, v != ""
	case key == "kms:CallerAccount":
		return f.CallerAccount, true
	case key == "aws:PrincipalArn":
		return HostRole, true
	}
	return "", false
}

func (f *FakeKMS) conditionsHold(cond map[string]any, d *nitro.Document) bool {
	for op, raw := range cond {
		entries, ok := raw.(map[string]any)
		if !ok {
			return false
		}
		ifExists := strings.HasSuffix(op, "IfExists")
		base := strings.TrimSuffix(op, "IfExists")
		for key, vals := range entries {
			v, present := f.contextValue(key, d)
			if !present {
				if ifExists {
					continue
				}
				return false
			}
			match := false
			for _, want := range asList(vals) {
				switch base {
				case "StringEquals", "ArnEquals":
					match = match || want == v
				case "StringEqualsIgnoreCase":
					match = match || strings.EqualFold(want, v)
				case "StringLike":
					match = match || want == "*" || want == v
				}
			}
			if !match {
				return false
			}
		}
	}
	return true
}

func (f *FakeKMS) allowed(policy, action string, d *nitro.Document) bool {
	var p struct {
		Statement json.RawMessage
	}
	if json.Unmarshal([]byte(policy), &p) != nil {
		return false
	}
	var stmts []map[string]any
	if json.Unmarshal(p.Statement, &stmts) != nil {
		var one map[string]any
		if json.Unmarshal(p.Statement, &one) != nil {
			return false
		}
		stmts = []map[string]any{one}
	}
	allow := false
	for _, s := range stmts {
		hit := false
		for _, a := range asList(s["Action"]) {
			hit = hit || actionMatches(a, action)
		}
		if !hit {
			continue
		}
		cond, _ := s["Condition"].(map[string]any)
		if !f.conditionsHold(cond, d) {
			continue
		}
		switch s["Effect"] {
		case "Deny":
			return false
		case "Allow":
			allow = true
		}
	}
	return allow
}

// SetFailGenerate toggles GenerateDataKey failures.
func (f *FakeKMS) SetFailGenerate(v bool) {
	f.mu.Lock()
	f.FailGenerate = v
	f.mu.Unlock()
}

// SetPolicy replaces a key's policy (tests of keys that must be refused).
func (f *FakeKMS) SetPolicy(arn, policy string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k := f.keys[arn]; k != nil {
		k.Policy = policy
	}
}

// SetDescribe replaces a key's DescribeKey response.
func (f *FakeKMS) SetDescribe(arn, describe string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k := f.keys[arn]; k != nil {
		k.Describe = describe
	}
}
