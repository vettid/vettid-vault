package client

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Critical-item use by a connection (VAULT-MESSAGING §10.13).

// CriticalUseRequest asks a connection's member to use a field of one of
// their critical items that a share rule makes usable to this vault
// (operation "sign" or "auth") and returns the request id; the result
// arrives as critical-secret-use.result.
func (d *Device) CriticalUseRequest(ctx context.Context, connectionID, itemID, fieldID, operation string, payload []byte, note string) (string, error) {
	body := map[string]any{"connection_id": connectionID, "item_id": itemID, "field_id": fieldID, "operation": operation,
		"payload": base64.StdEncoding.EncodeToString(payload)}
	if note != "" {
		body["context"] = note
	}
	o, err := d.Op(ctx, "critical-secret-use.request", body)
	if err != nil {
		return "", err
	}
	return o.String("request_id")
}

// CriticalUseApprove consents to one pending use with the credential
// password: the UTK-sealed payload binds the password to this request and
// this payload (its SHA-256). It returns the result status. payload is the
// pending request's payload as shown to the member.
func (d *Device) CriticalUseApprove(ctx context.Context, password, requestID string, payload []byte) (string, error) {
	h := sha256.Sum256(payload)
	return d.CriticalUseApproveHash(ctx, password, requestID, h[:])
}

// CriticalUseApproveHash is CriticalUseApprove with the payload's SHA-256
// (critical-secret-use.pending carries payload_sha256).
func (d *Device) CriticalUseApproveHash(ctx context.Context, password, requestID string, payloadSHA256 []byte) (string, error) {
	o, err := d.criticalApprove(ctx, password, requestID, payloadSHA256)
	if Code(err) == "stale_credential" {
		if ferr := d.CredentialFetch(ctx); ferr == nil {
			o, err = d.criticalApprove(ctx, password, requestID, payloadSHA256)
		}
	}
	if err != nil {
		return "", err
	}
	return o.String("status")
}

func (d *Device) criticalApprove(ctx context.Context, password, requestID string, hash []byte) (strictjson.Object, error) {
	const typ = "critical-secret-use.approve"
	u, err := d.takeUTK(ctx)
	if err != nil {
		return nil, err
	}
	pt, err := json.Marshal(map[string]any{"password": password, "request_id": requestID,
		"payload_sha256": base64.StdEncoding.EncodeToString(hash)})
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(pt)
	ek, err := suite.ParsePublicKey(u.EK)
	if err != nil {
		return nil, ErrProtocol
	}
	id, err := envelope.NewULID(d.cfg.Now())
	if err != nil {
		return nil, err
	}
	sealed, err := credwire.SealPayload(ek, d.VaultID(), u.ID, typ, id, pt)
	if err != nil {
		return nil, err
	}
	blob, err := d.credential()
	if err != nil {
		return nil, err
	}
	b, _ := json.Marshal(map[string]any{"request_id": requestID, "credential": blob, "utk_id": u.ID,
		"sealed": base64.StdEncoding.EncodeToString(sealed)})
	if _, err := d.SendWithID(ctx, id, typ, b); err != nil {
		return nil, err
	}
	r, err := d.AwaitResponse(ctx, id)
	if err != nil {
		return nil, err
	}
	if !r.OK() {
		return nil, &OpError{Type: typ, Code: r.ErrorCode(), Body: r.Body()}
	}
	o, err := strictjson.ParseObject(r.Body())
	if err != nil {
		return nil, ErrProtocol
	}
	if err := d.keep(ctx, o); err != nil {
		return nil, err
	}
	return o, nil
}

// CriticalUseDeny refuses a pending use.
func (d *Device) CriticalUseDeny(ctx context.Context, requestID string) error {
	_, err := d.Op(ctx, "critical-secret-use.deny", map[string]any{"request_id": requestID})
	return err
}

// CriticalUseList lists pending incoming and recent outgoing requests.
// Incoming entries carry the field's kind (0.21.0); a request for a field
// that cannot hold a seed was answered unsuitable at once and is not
// listed (the audit log has it).
func (d *Device) CriticalUseList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "critical-secret-use.list", nil)
}

// CriticalUseGet returns an incoming request with its payload, to show it
// again (§10.13, 0.10.2). The caller MUST check SHA-256(payload) against
// payload_sha256 before offering the approval.
func (d *Device) CriticalUseGet(ctx context.Context, requestID string) (strictjson.Object, error) {
	return d.Op(ctx, "critical-secret-use.get", map[string]any{"request_id": requestID})
}
