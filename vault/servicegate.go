package vault

import (
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// Service connections (VAULT-MESSAGING §6.4, 0.69.0; votes 0.81.0): a
// connection whose stored peer_kind is "service" takes and gives only the
// few types of the table "What the vault allows". Three places enforce it:
//
//   - serviceInbound (dispatch): what a service may send. A type allowed
//     from a service says so in its TypeSpec (Connections), so a feature
//     that plugs in later (the votes, §10.19) declares it where it
//     registers the type.
//   - serviceDeviceRefused (dispatch): a device request naming a service
//     connection for a type §6.4 lists is forbidden.
//   - serviceMayReceive (sendWith): the one choke point of everything the
//     vault sends a connection, automatic senders included.

// auditServiceType and auditVoteNotService are the activity kinds of §10.9.
const (
	auditServiceType    = "drop.service_type"
	auditVoteNotService = "drop.vote_not_service"
)

// voteRequests are the three requests a service sends (§6.4 "Votes"): a
// vault without the vote feature answers them unsupported_type and audits
// them (the transition rule).
var voteRequests = map[string]bool{"vote.proposal": true, "vote.extended": true, "vote.closed": true}

// gateConnection applies §6.4 to a message from connection p, after the
// session checks and before the registry lookup. It reports true when the
// message is finished (dropped or answered).
func (m *Manager) gateConnection(p *Peer, in *envelope.Inner, te *typeEntry, rkey string, now time.Time) bool {
	if p.isService() {
		if te != nil && te.allows(KindConnection) && te.spec.Connections != PeersPerson && m.serviceBodyOK(in) {
			return false
		}
		m.record(Activity{Kind: auditServiceType, ConnectionID: p.ID, Ref: p.ID + " " + in.Type, Audit: true}, now)
		if voteRequests[in.Type] && te == nil {
			// Transition rule: unsupported_type, as an unknown type gets.
			m.respondError(p, in, rkey, "unsupported_type", "", now)
		}
		return true
	}
	if strings.HasPrefix(in.Type, "vote.") {
		// §6.4 0.81.0: from a person connection, whether or not the vault
		// has the feature, so that it cannot probe for it.
		m.record(Activity{Kind: auditVoteNotService, ConnectionID: p.ID, Ref: p.ID, Audit: true}, now)
		m.respondError(p, in, rkey, "unsupported_type", "", now)
		return true
	}
	if te != nil && te.spec.Connections == PeersService {
		m.respondError(p, in, rkey, "unsupported_type", "", now)
		return true
	}
	return false
}

// serviceBodyOK holds the one body rule §6.4 adds: a challenge from a
// service needs a known purpose (an unknown one reads as absent, §10.4).
func (m *Manager) serviceBodyOK(in *envelope.Inner) bool {
	if in.Type != peerwire.TypeConnAuthChallenge {
		return true
	}
	c, err := peerwire.ParseConnAuthChallenge(in.Body)
	return err == nil && peerwire.KnownPurpose(c.Purpose)
}

// serviceForbidden are the device requests that are forbidden when they
// name a service connection (§6.4 "To the service").
var serviceForbidden = map[string]bool{
	"message.send": true, "call.start": true, "call.permission.set": true, "location.share.start": true,
	"location.request": true, "presence.query": true, "grant.request": true, "grant.fetch": true,
	"grant.catalog": true, "share.rule.set": true, "critical-secret-use.request": true, "action.invoke": true,
	"action.configure": true, "intro.create": true, "connection.authenticate.request": true,
}

// serviceDeviceRefused reports whether a device request is one of
// serviceForbidden and names a service connection. The connection is
// named by connection_id, by subject.connection_id (share.rule.set) or by
// a and c (intro.create); a body that does not parse names none (the
// handler refuses it).
func (m *Manager) serviceDeviceRefused(typ string, body []byte) bool {
	if !serviceForbidden[typ] && !strings.HasPrefix(typ, "message.attachment.") {
		return false
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return false
	}
	names := []string{}
	for _, k := range []string{"connection_id", "a", "c"} {
		if v, ok, err := o.OptString(k); err == nil && ok {
			names = append(names, v)
		}
	}
	if so, err := o.Object("subject"); err == nil {
		if v, ok, err := so.OptString("connection_id"); err == nil && ok {
			names = append(names, v)
		}
	}
	for _, id := range names {
		if p := m.st.Connections[id]; p != nil && p.isService() {
			return true
		}
	}
	return false
}

// serviceOut are the types the vault sends a service connection (§6.4):
// upkeep, the reduced profile, the member-authentication answers and, with
// the vote feature, vote.cast and vote.status. Anything else is not sent,
// whatever triggers it.
var serviceOut = map[string]bool{
	"hs.init": true, "hs.resp": true, "hs.fin": true,
	connectionApprovedType: true, peerwire.TypeConnectionDeclined: true, peerwire.TypeConnectionRemoved: true,
	tokenIssuedType: true, tokenRefreshType: true, "relay.address.update": true, "identity.rotate": true,
	"profile.update":              true,
	peerwire.TypeConnAuthResponse: true,
	peerwire.TypeConnAuthRotated:  true,
	"vote.cast":                   true,
	"vote.status":                 true,
}

// serviceMayReceive reports whether the vault may send typ to p.
func serviceMayReceive(p *Peer, typ string) bool {
	return !p.isService() || serviceOut[typ]
}
