package credwire

import (
	"crypto/ed25519"
	"errors"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Credential-key rotation statements (VAULT-MESSAGING §3.5.5, §10.4): at
// credential.rotate the vault signs the new credential key with the old
// one (and the new one), so that connections which pinned the member's key
// follow the rotation.
const (
	LabelKeyRotate = "vettid/vms/2/credential-rotate"
	MaxKeyChain    = 32
)

// Errors.
var (
	ErrRotation = errors.New("credwire: invalid credential-key rotation")
	ErrChain    = errors.New("credwire: credential-key chain does not verify")
)

// KeyRotation is one statement:
//
//	{"v":1,"old_key":"<b64>","new_key":"<b64>","sig_old":"<b64>","sig_new":"<b64>"}
//	m       = old_key (32) || new_key (32)
//	sig_old = Ed25519(old key, "vettid/vms/2/credential-rotate" || m)
//	sig_new = Ed25519(new key, "vettid/vms/2/credential-rotate" || m)
type KeyRotation struct {
	Old, New       ed25519.PublicKey
	SigOld, SigNew []byte
}

func rotationMsg(old, nw []byte) []byte { return append(append([]byte(nil), old...), nw...) }

// NewKeyRotation signs a rotation from old to nw with both keys.
func NewKeyRotation(old, nw ed25519.PrivateKey) (*KeyRotation, error) {
	op, np := old.Public().(ed25519.PublicKey), nw.Public().(ed25519.PublicKey)
	if suite.EqualPublic(op, np) {
		return nil, ErrRotation
	}
	m := rotationMsg(op, np)
	so, err := suite.Sign(old, LabelKeyRotate, m)
	if err != nil {
		return nil, err
	}
	sn, err := suite.Sign(nw, LabelKeyRotate, m)
	if err != nil {
		return nil, err
	}
	return &KeyRotation{Old: op, New: np, SigOld: so, SigNew: sn}, nil
}

// Marshal returns the statement's JSON.
func (r *KeyRotation) Marshal() []byte {
	return strictjson.NewBuilder().Uint("v", 1).Base64("old_key", r.Old).Base64("new_key", r.New).
		Base64("sig_old", r.SigOld).Base64("sig_new", r.SigNew).Bytes()
}

// ParseKeyRotation parses one statement strictly (signatures unchecked).
func ParseKeyRotation(b []byte) (*KeyRotation, error) {
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return nil, ErrRotation
	}
	if v, err := o.Uint("v", 1, 1); err != nil || v != 1 {
		return nil, ErrRotation
	}
	r := &KeyRotation{}
	var e1, e2, e3, e4 error
	r.Old, e1 = o.Base64("old_key", ed25519.PublicKeySize)
	r.New, e2 = o.Base64("new_key", ed25519.PublicKeySize)
	r.SigOld, e3 = o.Base64("sig_old", ed25519.SignatureSize)
	r.SigNew, e4 = o.Base64("sig_new", ed25519.SignatureSize)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return nil, ErrRotation
	}
	return r, nil
}

// Verify checks both signatures and that the keys differ.
func (r *KeyRotation) Verify() error {
	if suite.EqualPublic(r.Old, r.New) {
		return ErrRotation
	}
	m := rotationMsg(r.Old, r.New)
	if suite.Verify(r.Old, LabelKeyRotate, m, r.SigOld) != nil || suite.Verify(r.New, LabelKeyRotate, m, r.SigNew) != nil {
		return ErrRotation
	}
	return nil
}

// FollowChain verifies a chain of statements from the pinned key: each
// link's old key is the previous link's new key (the first's is pinned),
// both signatures verify, at most MaxKeyChain links. It returns the key
// the chain leads to.
func FollowChain(pinned ed25519.PublicKey, chain []*KeyRotation) (ed25519.PublicKey, error) {
	if len(pinned) != ed25519.PublicKeySize || len(chain) == 0 || len(chain) > MaxKeyChain {
		return nil, ErrChain
	}
	cur := pinned
	for _, r := range chain {
		if !suite.EqualPublic(r.Old, cur) || r.Verify() != nil {
			return nil, ErrChain
		}
		cur = r.New
	}
	return append(ed25519.PublicKey(nil), cur...), nil
}

// ChainFrom returns the statements of chain from the one whose old key is
// from to the end (nil if from is not in the chain).
func ChainFrom(chain []*KeyRotation, from ed25519.PublicKey) []*KeyRotation {
	for i, r := range chain {
		if suite.EqualPublic(r.Old, from) {
			return chain[i:]
		}
	}
	return nil
}
