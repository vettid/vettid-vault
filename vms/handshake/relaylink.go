package handshake

import (
	"crypto/ed25519"
	"encoding/json"

	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// MaxRelayLinks bounds a relay link chain (§3.4.1 rule U, §6.2: 1 to 32).
const MaxRelayLinks = 32

// RelayLink is a signed relay link (VAULT-MESSAGING §3.4.1 rule U): a
// principal's relay key Old was replaced by New, and both signed it in the
// rotation's first write.
//
// Format (rule U):
//
//	{"old":b64,"new":b64,"sig_old":b64,"sig_new":b64}
//	m       = "vettid/vms/2/relay-rotate" || old (32) || new (32)
//	sig_old = Ed25519(old, m)        sig_new = Ed25519(new, m)
//
// Keys are the 32 raw Ed25519 bytes, signatures 64 bytes, all standard
// base64 with padding. As with an identity link's label, the label is
// prepended by suite.Sign, so the signed bytes are exactly m.
type RelayLink struct {
	Old    ed25519.PublicKey
	New    ed25519.PublicKey
	SigOld []byte
	SigNew []byte
}

func relayLinkMessage(old, new ed25519.PublicKey) []byte {
	m := make([]byte, 0, 2*ed25519.PublicKeySize)
	m = append(m, old...)
	return append(m, new...)
}

// RelayLinkSigned returns the exact bytes both keys sign for a link from
// old to new: "vettid/vms/2/relay-rotate" || old || new.
func RelayLinkSigned(old, new ed25519.PublicKey) []byte {
	return append([]byte(suite.LabelRelayRotate), relayLinkMessage(old, new)...)
}

// NewRelayLink signs a relay link from oldKey to newKey.
func NewRelayLink(oldKey, newKey ed25519.PrivateKey) (*RelayLink, error) {
	if len(oldKey) != ed25519.PrivateKeySize || len(newKey) != ed25519.PrivateKeySize {
		return nil, suite.ErrKeySize
	}
	l := &RelayLink{Old: oldKey.Public().(ed25519.PublicKey), New: newKey.Public().(ed25519.PublicKey)}
	if suite.EqualPublic(l.Old, l.New) {
		return nil, ErrRelayLink
	}
	m := relayLinkMessage(l.Old, l.New)
	var err error
	if l.SigOld, err = suite.Sign(oldKey, suite.LabelRelayRotate, m); err != nil {
		return nil, err
	}
	if l.SigNew, err = suite.Sign(newKey, suite.LabelRelayRotate, m); err != nil {
		return nil, err
	}
	return l, nil
}

// Verify checks both signatures. A link whose old and new keys are equal
// is refused (it moves nothing; the spec does not name the case).
func (l *RelayLink) Verify() error {
	if l == nil || len(l.Old) != ed25519.PublicKeySize || len(l.New) != ed25519.PublicKeySize {
		return ErrRelayLink
	}
	if suite.EqualPublic(l.Old, l.New) {
		return ErrRelayLink
	}
	m := relayLinkMessage(l.Old, l.New)
	if suite.Verify(l.Old, suite.LabelRelayRotate, m, l.SigOld) != nil ||
		suite.Verify(l.New, suite.LabelRelayRotate, m, l.SigNew) != nil {
		return ErrRelayLink
	}
	return nil
}

// Marshal encodes the link in rule U's member order.
func (l *RelayLink) Marshal() []byte {
	return strictjson.NewBuilder().
		Base64("old", l.Old).
		Base64("new", l.New).
		Base64("sig_old", l.SigOld).
		Base64("sig_new", l.SigNew).
		Bytes()
}

// ParseRelayLink parses a link strictly (duplicate members, non-canonical
// base64 and wrong lengths are refused; unknown members are ignored, as
// §10.1 says for every body). It does not verify it.
func ParseRelayLink(raw json.RawMessage) (*RelayLink, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrRelayLink
	}
	l := &RelayLink{}
	if l.Old, err = o.Base64("old", ed25519.PublicKeySize); err != nil {
		return nil, ErrRelayLink
	}
	if l.New, err = o.Base64("new", ed25519.PublicKeySize); err != nil {
		return nil, ErrRelayLink
	}
	if l.SigOld, err = o.Base64("sig_old", ed25519.SignatureSize); err != nil {
		return nil, ErrRelayLink
	}
	if l.SigNew, err = o.Base64("sig_new", ed25519.SignatureSize); err != nil {
		return nil, ErrRelayLink
	}
	return l, nil
}

// ParseRelayLinks parses an array of 1 to MaxRelayLinks links. It does not
// verify them.
func ParseRelayLinks(arr []json.RawMessage) ([]*RelayLink, error) {
	if len(arr) == 0 || len(arr) > MaxRelayLinks {
		return nil, ErrRelayLink
	}
	ls := make([]*RelayLink, 0, len(arr))
	for _, raw := range arr {
		l, err := ParseRelayLink(raw)
		if err != nil {
			return nil, err
		}
		ls = append(ls, l)
	}
	return ls, nil
}

// MarshalRelayLinks encodes an array of links.
func MarshalRelayLinks(ls []*RelayLink) []byte {
	out := []byte{'['}
	for i, l := range ls {
		if i > 0 {
			out = append(out, ',')
		}
		out = append(out, l.Marshal()...)
	}
	return append(out, ']')
}

// VerifyRelayChain checks a relay link chain as rule U and §6.2 require:
// 1 to MaxRelayLinks links, each verifying, each link's old equal to the
// previous link's new, the first old equal to first (the collect sender:
// the key the message was deposited with) and the last new equal to last
// (the announced key: an update's relay.pk, an hs.init's from.relay.pk,
// an hs.resp's relay.pk). Rule C and what the receiver keeps for the
// sender are the caller's.
func VerifyRelayChain(first, last ed25519.PublicKey, chain []*RelayLink) error {
	if len(chain) == 0 || len(chain) > MaxRelayLinks || len(first) != ed25519.PublicKeySize || len(last) != ed25519.PublicKeySize {
		return ErrRelayLink
	}
	cur := first
	for _, l := range chain {
		if err := l.Verify(); err != nil {
			return ErrRelayLink
		}
		if !suite.EqualPublic(l.Old, cur) {
			return ErrRelayLink
		}
		cur = l.New
	}
	if !suite.EqualPublic(cur, last) {
		return ErrRelayLink
	}
	return nil
}
