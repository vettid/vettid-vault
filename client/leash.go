package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/leashwire"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// LEASH (VAULT-MESSAGING §10.11): an app issues, revokes and lists an
// agent's grants; an agent makes LEASH requests (agent.request) and owner
// requests its grants delegate, and reads its grants.

// LeashGrantIssue issues (spec without grant_id) or replaces (spec with
// grant_id and version) a grant for an agent and returns the grant.
func (d *Device) LeashGrantIssue(ctx context.Context, agentID string, spec map[string]any) (strictjson.Object, error) {
	body := map[string]any{"agent_id": agentID}
	for k, v := range spec {
		body[k] = v
	}
	return d.Op(ctx, "leash.grant.issue", body)
}

// LeashGrantRevoke revokes a grant.
func (d *Device) LeashGrantRevoke(ctx context.Context, grantID string) error {
	_, err := d.Op(ctx, "leash.grant.revoke", map[string]any{"grant_id": grantID})
	return err
}

// LeashGrantList lists grants: an app or desktop all of them (or one
// agent's), an agent its own (agentID "").
func (d *Device) LeashGrantList(ctx context.Context, agentID string) ([]json.RawMessage, error) {
	body := map[string]any{}
	if agentID != "" {
		body["agent_id"] = agentID
	}
	o, err := d.Op(ctx, "leash.grant.list", body)
	if err != nil {
		return nil, err
	}
	return o.Array("grants")
}

// AgentRequest sends an agent.request (an agent within its access
// session). A referred request waits for an app's decision (§6.8): the
// response arrives when the app decides, so ctx should allow up to the
// approval's 5 minutes.
func (d *Device) AgentRequest(ctx context.Context, op string, members map[string]any) (*Response, error) {
	body := map[string]any{"op": op}
	for k, v := range members {
		body[k] = v
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return d.Request(ctx, "agent.request", b)
}

// newerGrantSet reports whether a leash.grant.updated body describes a newer
// set than the one kept, as §10.11 "Grant-set sequence" has an agent judge:
// a lower grant_seq (a reordered or replayed update) is ignored. An equal
// one replaces the kept body: the vault re-sends an equal number only for
// the same set with fresh status statements (a hold's end), less any grant
// that has since expired (an expiry takes no number), so taking it whole
// keeps the set and its newer statements. A body without a valid grant_seq
// (absent, 0 or invalid) is ignored ("No fallback", §10.11). d.mu is held.
func (d *Device) newerGrantSet(body []byte) bool {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return false
	}
	// The spec allows any u64; this test client caps at 2^53-1 like the
	// strict parser. A vault would need 2^53 grant-set changes to reach it.
	n, present, err := o.OptUint("grant_seq", 1, strictjson.MaxSafeInteger)
	if err != nil || !present {
		return false
	}
	if n < d.leashSeq {
		return false
	}
	d.leashSeq = n
	return true
}

// LeashGrants returns the grants in the leash.grant.updated with the highest
// grant_seq this agent received (nil if none).
func (d *Device) LeashGrants() []json.RawMessage {
	d.mu.Lock()
	body := d.leashGrants
	d.mu.Unlock()
	if body == nil {
		return nil
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil
	}
	gs, _ := o.Array("grants")
	return gs
}

// VerifyDelegation checks a grant's signed delegation (§10.11, 0.12.0):
// its sig under the delegation's iss, which must be the member's
// credential key as the verifier pinned it (e.g. through member
// authentication, §10.4), and its exp. It returns the statement. Whether
// the grant is still in force is said by a status statement
// (leashwire.VerifyPresented).
func VerifyDelegation(grant json.RawMessage, memberKey ed25519.PublicKey, now time.Time) (*leashwire.Delegation, error) {
	o, err := strictjson.ParseObject(grant)
	if err != nil {
		return nil, ErrProtocol
	}
	stmt, err := o.Base64("delegation", -1)
	if err != nil {
		return nil, ErrProtocol
	}
	sig, err := o.Base64("sig", ed25519.SignatureSize)
	if err != nil {
		return nil, ErrProtocol
	}
	return leashwire.Verify(memberKey, stmt, sig, now)
}

type cachedStatus struct {
	status, sig []byte
	chain       []*handshake.Rotation
	notAfter    time.Time
	ttl         time.Duration
}

// LeashStatus fetches a fresh status statement for one of this agent's
// grants (leash.status.get, §10.11).
func (d *Device) LeashStatus(ctx context.Context, grantID string) (status, sig []byte, chain []*handshake.Rotation, err error) {
	o, err := d.Op(ctx, "leash.status.get", map[string]any{"grant_id": grantID})
	if err != nil {
		return nil, nil, nil, err
	}
	return parseStatusMembers(o)
}

func parseStatusMembers(o strictjson.Object) (status, sig []byte, chain []*handshake.Rotation, err error) {
	if status, err = o.Base64("status", -1); err != nil {
		return nil, nil, nil, ErrProtocol
	}
	if sig, err = o.Base64("status_sig", ed25519.SignatureSize); err != nil {
		return nil, nil, nil, ErrProtocol
	}
	if raw, ok, err := o.OptArray("rotations"); err != nil {
		return nil, nil, nil, ErrProtocol
	} else if ok {
		for _, r := range raw {
			rot, err := handshake.ParseRotation(r)
			if err != nil {
				return nil, nil, nil, ErrProtocol
			}
			chain = append(chain, rot)
		}
	}
	return status, sig, chain, nil
}

// LeashPresent returns what this agent shows a relying party for one of
// its grants: the delegation, the member's signature (sig), a status
// statement and the vault's rotation chain, refreshed automatically when less than a quarter of its
// lifetime (at least a minute) remains.
func (d *Device) LeashPresent(ctx context.Context, grantID string) (*leashwire.Presented, error) {
	var grant json.RawMessage
	for _, g := range d.LeashGrants() {
		o, err := strictjson.ParseObject(g)
		if err == nil {
			if id, _ := o.String("grant_id"); id == grantID {
				grant = g
			}
		}
	}
	if grant == nil {
		gs, err := d.LeashGrantList(ctx, "")
		if err != nil {
			return nil, err
		}
		for _, g := range gs {
			o, err := strictjson.ParseObject(g)
			if err == nil {
				if id, _ := o.String("grant_id"); id == grantID {
					grant = g
				}
			}
		}
	}
	if grant == nil {
		return nil, &OpError{Type: "leash.status.get", Code: "not_found"}
	}
	o, err := strictjson.ParseObject(grant)
	if err != nil {
		return nil, ErrProtocol
	}
	del, err := o.Base64("delegation", -1)
	if err != nil {
		return nil, ErrProtocol
	}
	dsig, err := o.Base64("sig", ed25519.SignatureSize)
	if err != nil {
		return nil, ErrProtocol
	}
	now := d.cfg.Now()
	d.mu.Lock()
	c := d.leashStatus[grantID]
	d.mu.Unlock()
	margin := time.Minute
	if c != nil && c.ttl/4 > margin {
		margin = c.ttl / 4
	}
	if c == nil || !now.Add(margin).Before(c.notAfter) {
		st, sig, chain, err := d.LeashStatus(ctx, grantID)
		if err != nil {
			return nil, err
		}
		ps, err := leashwire.ParseStatus(st)
		if err != nil {
			return nil, ErrProtocol
		}
		c = &cachedStatus{status: st, sig: sig, chain: chain, notAfter: ps.NotAfter, ttl: ps.NotAfter.Sub(ps.IssuedAt)}
		d.mu.Lock()
		if d.leashStatus == nil {
			d.leashStatus = map[string]*cachedStatus{}
		}
		d.leashStatus[grantID] = c
		d.mu.Unlock()
	}
	return &leashwire.Presented{Delegation: del, Sig: dsig, Status: c.status, StatusSig: c.sig, Rotations: c.chain}, nil
}
