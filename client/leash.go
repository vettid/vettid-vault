package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/leashwire"
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

// LeashGrants returns the grants in the latest leash.grant.updated this
// agent received (nil if none).
func (d *Device) LeashGrants() []json.RawMessage {
	evs := d.Events()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == "leash.grant.updated" && evs[i].Re == "" {
			o, err := strictjson.ParseObject(evs[i].Body)
			if err != nil {
				return nil
			}
			gs, _ := o.Array("grants")
			return gs
		}
	}
	return nil
}

// VerifyDelegation checks a grant's signed delegation under the member's
// credential key (pinned by the verifier, e.g. through member
// authentication, §10.4) and returns the statement.
func VerifyDelegation(grant json.RawMessage, memberKey ed25519.PublicKey, now time.Time) (*leashwire.Delegation, error) {
	o, err := strictjson.ParseObject(grant)
	if err != nil {
		return nil, ErrProtocol
	}
	stmt, err := o.Base64("delegation", -1)
	if err != nil {
		return nil, ErrProtocol
	}
	sig, err := o.Base64("delegation_sig", ed25519.SignatureSize)
	if err != nil {
		return nil, ErrProtocol
	}
	return leashwire.Verify(memberKey, stmt, sig, now)
}
