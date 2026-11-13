//go:build vmsvectors

package vectors

import (
	"crypto/ed25519"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Seed bytes of the relay-link vectors: key i is NewKeyFromSeed(32 x
// (SeedRelayLinkBase + i)).
const SeedRelayLinkBase byte = 0xb0

// relayLinkKeys is the number of keys the vectors use (0 to 33).
const relayLinkKeys = 34

func relayLinkKey(i int) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(rep(SeedRelayLinkBase+byte(i), 32))
}

func relayLinkPub(i int) ed25519.PublicKey { return relayLinkKey(i).Public().(ed25519.PublicKey) }

// rlCase is one case. The chain links keys in order (or is built by
// links); mutate changes it; v and suite override link 0's members; first
// and announced override the chain's ends.
type rlCase struct {
	name, reason     string
	valid            bool
	keys             []int
	links            func() []*handshake.RelayLink
	mutate           func([]*handshake.RelayLink) []*handshake.RelayLink
	v, suite         int  // link vAt's; 0: 1 and 2; -1: the member is absent
	vAt              int  // the link v and suite apply to (default link 0)
	first, announced *int // key indexes; nil: the chain's own ends
}

func keyIndex(i int) *int { return &i }

// relaySignedUnder signs a link from key a to key b under label.
func relaySignedUnder(label string, a, b int) *handshake.RelayLink {
	m := append(append([]byte(label), relayLinkPub(a)...), relayLinkPub(b)...)
	return &handshake.RelayLink{Old: relayLinkPub(a), New: relayLinkPub(b),
		SigOld: ed25519.Sign(relayLinkKey(a), m), SigNew: ed25519.Sign(relayLinkKey(b), m)}
}

func (c rlCase) render() (obj, error) {
	var links []*handshake.RelayLink
	if c.links != nil {
		links = c.links()
	} else {
		for i := 1; i < len(c.keys); i++ {
			l, err := handshake.NewRelayLink(relayLinkKey(c.keys[i-1]), relayLinkKey(c.keys[i]))
			if err != nil {
				return nil, err
			}
			links = append(links, l)
		}
	}
	if c.mutate != nil {
		links = c.mutate(links)
	}
	linkObjs, signed := []any{}, []any{}
	for i, l := range links {
		v, s := 1, int(suite.Suite2)
		if i == c.vAt && c.v != 0 {
			v = c.v
		}
		if i == c.vAt && c.suite != 0 {
			s = c.suite
		}
		var lo obj
		if v >= 0 {
			lo = append(lo, member{"v", v})
		}
		if s >= 0 {
			lo = append(lo, member{"suite", s})
		}
		lo = append(lo, member{"old", b64(l.Old)}, member{"new", b64(l.New)}, member{"sig_old", b64(l.SigOld)}, member{"sig_new", b64(l.SigNew)})
		linkObjs = append(linkObjs, lo)
		signed = append(signed, hx(handshake.RelayLinkSigned(l.Old, l.New)))
	}
	var first, last ed25519.PublicKey
	if len(links) > 0 {
		first, last = links[0].Old, links[len(links)-1].New
	}
	if c.first != nil {
		first = relayLinkPub(*c.first)
	}
	if c.announced != nil {
		last = relayLinkPub(*c.announced)
	}
	o := obj{{"name", c.name}}
	if c.valid {
		o = append(o, member{"description", c.reason})
	} else {
		o = append(o, member{"reason", c.reason})
	}
	return append(o,
		member{"first_b64", b64(first)},
		member{"announced_b64", b64(last)},
		member{"signed_bytes_hex", signed},
		member{"relay_links", linkObjs},
		member{"valid", c.valid},
	), nil
}

// genRelayRotate builds relay_rotate.json: signed relay links (VAULT-
// MESSAGING 0.90.3 §3.4.1 rule U, §6.2 relay_links), through vms/handshake.
func genRelayRotate() (obj, error) {
	var keys []any
	for i := 0; i < relayLinkKeys; i++ {
		keys = append(keys, obj{{"index", i}, {"seed_hex", hx(rep(SeedRelayLinkBase+byte(i), 32))}, {"pk_b64", b64(relayLinkPub(i))}})
	}
	long := make([]int, 34) // 33 links
	for i := range long {
		long[i] = i
	}
	flip := func(sig func(*handshake.RelayLink) []byte) func([]*handshake.RelayLink) []*handshake.RelayLink {
		return func(ls []*handshake.RelayLink) []*handshake.RelayLink { sig(ls[0])[0] ^= 1; return ls }
	}
	cases := []rlCase{
		{name: "single", reason: "one link, key 0 -> key 1", valid: true, keys: []int{0, 1}},
		{name: "chain", reason: "three links, key 0 -> 1 -> 2 -> 3", valid: true, keys: []int{0, 1, 2, 3}},
		{name: "wrong_signature", reason: "sig_old has its first byte XOR 0x01", keys: []int{0, 1},
			mutate: flip(func(l *handshake.RelayLink) []byte { return l.SigOld })},
		{name: "wrong_sig_new", reason: "sig_new has its first byte XOR 0x01 (sig_old is right)", keys: []int{0, 1},
			mutate: flip(func(l *handshake.RelayLink) []byte { return l.SigNew })},
		{name: "first_not_sender", reason: "first_b64 (key 2, the deposit key) is not the first link's old (key 0)", keys: []int{0, 1}, first: keyIndex(2)},
		{name: "announced_not_last", reason: "announced_b64 (key 1) is not the last link's new (key 2)", keys: []int{0, 1, 2}, announced: keyIndex(1)},
		{name: "identity_label", reason: "both signatures are over \"vettid/vms/2/rotate\" || old || new, the identity link's label",
			links: func() []*handshake.RelayLink {
				return []*handshake.RelayLink{relaySignedUnder(suite.LabelRotate, 0, 1)}
			}},
		{name: "old_equals_new", reason: "old and new are the same key (key 0), both signatures valid",
			links: func() []*handshake.RelayLink {
				return []*handshake.RelayLink{relaySignedUnder(suite.LabelRelayRotate, 0, 0)}
			}},
		{name: "repeated_key", reason: "key 0 -> 1 -> 0: a key appears twice (first equals announced)", keys: []int{0, 1, 0}},
		{name: "repeated_key_later", reason: "key 0 -> 1 -> 2 -> 1: key 1 appears twice, not at the ends", keys: []int{0, 1, 2, 1}},
		{name: "v_2", reason: "unknown v with verifying signatures: the link's v is 2; both signatures verify (v is not in m)", keys: []int{0, 1}, v: 2},
		{name: "suite_1", reason: "unknown suite with verifying signatures: the link's suite is 1; both signatures verify (the label binds suite 2)", keys: []int{0, 1}, suite: 1},
		{name: "v_2_later_link", reason: "three links, the third with v 2; every signature verifies", keys: []int{0, 1, 2, 3}, v: 2, vAt: 2},
		{name: "v_missing", reason: "the link has no v; both signatures verify", keys: []int{0, 1}, v: -1},
		{name: "suite_missing", reason: "the link has no suite; both signatures verify", keys: []int{0, 1}, suite: -1},
		{name: "no_links", reason: "an empty array: zero links (1 to 32 are required)",
			links: func() []*handshake.RelayLink { return nil }, first: keyIndex(0), announced: keyIndex(1)},
		{name: "broken_chain", reason: "key 0 -> 1, then key 2 -> 3: the second link's old is not the first link's new", keys: []int{0, 1},
			mutate: func(ls []*handshake.RelayLink) []*handshake.RelayLink {
				l, _ := handshake.NewRelayLink(relayLinkKey(2), relayLinkKey(3))
				return append(ls, l)
			}},
		{name: "too_many", reason: "33 links, key 0 -> 1 -> ... -> 33: one more than the limit of 32", keys: long},
	}
	var out []any
	for _, c := range cases {
		o, err := c.render()
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return obj{
		{"description", "VAULT-MESSAGING 0.90.3 §3.4.1 rule U and §6.2 relay_links: signed relay links. Generated by vettid-vault (vms/handshake) for the apps and service vaults to reproduce. All keys are TEST ONLY: key i is the Ed25519 key of seed 32 x (0xb0 + i). A link is {v: 1, suite: 2, old, new, sig_old, sig_new}, keys and signatures in standard base64 with padding; v and suite are not bytes of m (the label binds suite 2); m = \"vettid/vms/2/relay-rotate\" || old (32) || new (32) (signed_bytes_hex, one per link), sig_old = Ed25519(old, m), sig_new = Ed25519(new, m) (deterministic, RFC 8032). A chain is valid when it has 1 to 32 links, each with v 1 and suite 2, old different from new and both signatures verifying, each link's old is the previous link's new, no key appears twice, the first old is first_b64 (the deposit key) and the last new is announced_b64. An invalid case says why in reason."},
		{"keys", keys},
		{"cases", out},
	}, nil
}
