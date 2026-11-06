package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
)

// Capability names on every message (VAULT-MESSAGING 0.86.0, §5.3, §10.8,
// §6.3.1 "Deployment"). A vault of this release advertises hs_confirm to
// every connection (in profile.update's features and in the inner
// `features` field of every message it deposits, handshake messages
// included) and to its devices in its §11.10.9 list; it counts a peer's
// names from any message that authenticates as that peer and passes
// acceptFrom steps 1-4, and a name, once seen, stays.

// CoreFeatures are the names the runtime itself advertises to every
// connection (§10.8): today hs_confirm. relay_follow is not in this
// release (vettid.org #540's relay-key rotation is not built).
func CoreFeatures() []string { return []string{handshake.CapConfirm} }

// featureVote is the vote feature's name, which a service is also told
// (§10.8, §10.19.1).
const featureVote = "vote"

// TypeDeviceFeatures is a device's receiving-side capabilities (§10.2).
const TypeDeviceFeatures = "device.features"

// featuresFor is the inner `features` list for a message to p: to a
// connection the names advertised in its profile.update (hs_confirm, and
// to a service the optional features it can use); to a device the
// vault's §11.10.9 list.
func (m *Manager) featuresFor(p *Peer) []string {
	if p == nil {
		return nil
	}
	if p.Kind != KindConnection {
		return altchan.ReleaseCapabilities(!m.opt.RecoveryNotOffered)
	}
	names := CoreFeatures()
	if p.isService() && m.hasFeature(featureVote) {
		names = append(names, featureVote)
	}
	sort.Strings(names)
	return names
}

// sealFor seals in for p under ep, with the inner features field.
//
// Nothing is sealed under a demoted epoch (§3.4.1 "Epochs after an ik
// link": Q sends nothing to P until a new epoch is established): such a
// message is not sent (errDemoted).
func (m *Manager) sealFor(p *Peer, ep *handshake.Epoch, in *envelope.Inner) ([]byte, error) {
	if p != nil && ep != nil {
		id := ep.ID()
		if e := p.epochMeta(id[:]); e != nil && e.Demoted {
			return nil, errDemoted
		}
	}
	in.Features = m.featuresFor(p)
	return ep.Seal(in)
}

// errDemoted: the epoch was demoted by an ik link (§3.4.1).
var errDemoted = errors.New("vault: epoch demoted")

// mergeNames adds names to a sorted list; it reports whether one was new.
func mergeNames(have []string, names []string) ([]string, bool) {
	changed := false
	for _, n := range names {
		i := sort.SearchStrings(have, n)
		if i < len(have) && have[i] == n {
			continue
		}
		have = append(have, "")
		copy(have[i+1:], have[i:])
		have[i] = n
		changed = true
	}
	return have, changed
}

// noteFeatures counts a peer's advertised names (§10.8 "On every message"):
// the caller has authenticated the message as p's and it passed acceptFrom
// steps 1-4 (p not suspended, its sender p's relay key, no second
// successor). A name is only ever added. A list that is not well formed
// counts for nothing.
func (m *Manager) noteFeatures(p *Peer, names []string) {
	if p == nil || names == nil || !envelope.ValidFeatures(names) {
		return
	}
	if p.PeerFeatures == nil {
		p.PeerFeatures = []string{}
		m.dirty = true
	}
	var changed bool
	if p.PeerFeatures, changed = mergeNames(p.PeerFeatures, names); changed {
		m.dirty = true
	}
}

// advertisedFeatures reports whether p has advertised any features
// (release 29 or later); rule L applies toward a peer that has not.
func (p *Peer) advertisedFeatures() bool { return p.PeerFeatures != nil }

// hasConfirm reports whether p advertised hs_confirm (§6.3.1 "Deployment").
func (p *Peer) hasConfirm() bool {
	i := sort.SearchStrings(p.PeerFeatures, handshake.CapConfirm)
	return i < len(p.PeerFeatures) && p.PeerFeatures[i] == handshake.CapConfirm
}

// NotePeerFeatures counts the names of a connection's profile.update
// (§10.8: hs_confirm is read from any connection and kept once seen).
// Only names this release reads are kept from it.
func (s *Session) NotePeerFeatures(names []string) {
	if s.m == nil || s.peer == nil {
		return
	}
	var keep []string
	for _, n := range names {
		if n == handshake.CapConfirm {
			keep = append(keep, n)
		}
	}
	if keep != nil {
		s.m.noteFeatures(s.peer, keep)
	}
}

// hDeviceFeatures is device.features (§10.2): the device's receiving-side
// capabilities, sent after each epoch it activates. A malformed body is
// dropped and audited (drop.features_malformed); otherwise the names are
// counted as from the inner field (written only when they change).
func (m *Manager) hDeviceFeatures(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	var names []string
	if err == nil {
		var arr []json.RawMessage
		if arr, err = o.Array("features"); err == nil {
			for _, raw := range arr {
				n, e := strictjson.AsString(raw)
				if e != nil {
					err = e
					break
				}
				names = append(names, n)
			}
		}
	}
	if err != nil || !envelope.ValidFeatures(names) {
		m.audit(s.now, "features_malformed", s.peer.ID)
		return nil, nil
	}
	m.noteFeatures(s.peer, names)
	return nil, nil
}

var _ = time.Second
