package handshake

import (
	"crypto/ed25519"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Rotation is an `identity.rotate` statement (§3.4): a link in a rotation
// chain from an old identity key to a new one, signed by both.
//
// Format (§3.4):
//
//	{"v":1,"suite":2,"old_ik":b64,"new_ik":b64,"new_kem":b64,"sig_old":b64,"sig_new":b64}
//	m       = old_ik(32) || new_ik(32) || new_kem(1216)
//	sig_old = Ed25519(old_ik, "vettid/vms/2/rotate" || m)
//	sig_new = Ed25519(new_ik, "vettid/vms/2/rotate" || m)
type Rotation struct {
	OldIK  ed25519.PublicKey
	NewIK  ed25519.PublicKey
	NewKEM *suite.PublicKey
	SigOld []byte
	SigNew []byte
}

func rotationMessage(oldIK, newIK ed25519.PublicKey, newKEM *suite.PublicKey) []byte {
	m := make([]byte, 0, 2*ed25519.PublicKeySize+suite.EKSize)
	m = append(m, oldIK...)
	m = append(m, newIK...)
	return append(m, newKEM.Bytes()...)
}

// NewRotation signs a rotation from oldKey to newKey, announcing newKEM.
func NewRotation(oldKey, newKey ed25519.PrivateKey, newKEM *suite.PublicKey) (*Rotation, error) {
	if len(oldKey) != ed25519.PrivateKeySize || len(newKey) != ed25519.PrivateKeySize || newKEM == nil {
		return nil, suite.ErrKeySize
	}
	r := &Rotation{
		OldIK:  oldKey.Public().(ed25519.PublicKey),
		NewIK:  newKey.Public().(ed25519.PublicKey),
		NewKEM: newKEM,
	}
	if suite.EqualPublic(r.OldIK, r.NewIK) {
		return nil, ErrRotation
	}
	m := rotationMessage(r.OldIK, r.NewIK, newKEM)
	var err error
	if r.SigOld, err = suite.Sign(oldKey, suite.LabelRotate, m); err != nil {
		return nil, err
	}
	if r.SigNew, err = suite.Sign(newKey, suite.LabelRotate, m); err != nil {
		return nil, err
	}
	return r, nil
}

// Verify checks both signatures.
func (r *Rotation) Verify() error {
	if r == nil || r.NewKEM == nil || len(r.OldIK) != ed25519.PublicKeySize || len(r.NewIK) != ed25519.PublicKeySize {
		return ErrRotation
	}
	if suite.EqualPublic(r.OldIK, r.NewIK) {
		return ErrRotation
	}
	m := rotationMessage(r.OldIK, r.NewIK, r.NewKEM)
	if suite.Verify(r.OldIK, suite.LabelRotate, m, r.SigOld) != nil ||
		suite.Verify(r.NewIK, suite.LabelRotate, m, r.SigNew) != nil {
		return ErrRotation
	}
	return nil
}

// Marshal encodes the statement.
func (r *Rotation) Marshal() []byte {
	return strictjson.NewBuilder().
		Uint("v", 1).
		Uint("suite", uint64(suite.Suite2)).
		Base64("old_ik", r.OldIK).
		Base64("new_ik", r.NewIK).
		Base64("new_kem", r.NewKEM.Bytes()).
		Base64("sig_old", r.SigOld).
		Base64("sig_new", r.SigNew).
		Bytes()
}

// ParseRotation parses a statement strictly. It does not verify it.
func ParseRotation(raw json.RawMessage) (*Rotation, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrRotation
	}
	if _, err := o.Uint("v", 1, 1); err != nil {
		return nil, ErrRotation
	}
	s, err := o.Uint("suite", 0, 255)
	if err != nil || suite.Check(int(s), 0) != nil {
		return nil, ErrRotation
	}
	r := &Rotation{}
	if r.OldIK, err = o.Base64("old_ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrRotation
	}
	if r.NewIK, err = o.Base64("new_ik", ed25519.PublicKeySize); err != nil {
		return nil, ErrRotation
	}
	ek, err := o.Base64("new_kem", suite.EKSize)
	if err != nil {
		return nil, ErrRotation
	}
	if r.NewKEM, err = suite.ParsePublicKey(ek); err != nil {
		return nil, ErrRotation
	}
	if r.SigOld, err = o.Base64("sig_old", ed25519.SignatureSize); err != nil {
		return nil, ErrRotation
	}
	if r.SigNew, err = o.Base64("sig_new", ed25519.SignatureSize); err != nil {
		return nil, ErrRotation
	}
	return r, nil
}

// ResolveChain follows a rotation chain from a stored identity key (§6.6):
// each link's old_ik must equal the current key, and both signatures must
// verify. It returns the final identity key and, if the chain is
// non-empty, the KEM key announced by its last link. An empty chain
// resolves to start.
func ResolveChain(start ed25519.PublicKey, chain []*Rotation) (ed25519.PublicKey, *suite.PublicKey, error) {
	if len(start) != ed25519.PublicKeySize || len(chain) > MaxRotations {
		return nil, nil, ErrRotation
	}
	cur := start
	var kem *suite.PublicKey
	for _, r := range chain {
		if err := r.Verify(); err != nil {
			return nil, nil, ErrRotation
		}
		if !suite.EqualPublic(r.OldIK, cur) {
			return nil, nil, ErrRotation
		}
		cur, kem = r.NewIK, r.NewKEM
	}
	return cur, kem, nil
}
