package memberapitest

import (
	"context"
	"encoding/base64"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// Vault recovery (vault.ts "recovery", MEMBER-API.md "Vault recovery",
// VAULT-MESSAGING §11.11): the request, its status (with the sealed code
// once available), cancel and register, and the registered state (0.10.6):
// a register slot answered with the host's recovery_registered marker
// spends the code. Left out: the cancel link and its email, rate limits
// and audit.

// The code becomes usable 24 h after the request, for 24 h (§11.11.2).
const (
	recoveryDelayS    = 24 * 3600
	recoveryValidityS = 24 * 3600
)

// recoveryRow is the vault row's recovery (vault.ts RecoveryRow).
type recoveryRow struct {
	ID, State                           string // pending | registered | cancelled
	RequestedAt, AvailableAt, ExpiresAt int64
	// RegisterIDs are the register requests sent for this recovery, so
	// that their slots can be checked (vault.ts register_ids).
	RegisterIDs []string
}

// registeredCode is the host's copy of the enclave's clear marker of a
// successful register (§11.5, 0.10.6; vault.ts REGISTERED_CODE).
const registeredCode = "recovery_registered"

// maxRegisterIDs: at most this many register ids are kept on a recovery.
const maxRegisterIDs = 10

func (a *API) recoveryNowS() int64 { return a.cfg.RecoveryNow().Unix() }

func isoS(t int64) string { return time.Unix(t, 0).UTC().Format("2006-01-02T15:04:05.000Z") }

// recoveryState is vault.ts recoveryState ("" for none).
func recoveryState(r *recoveryRow, now int64) string {
	switch {
	case r == nil:
		return ""
	case r.State == "cancelled":
		return "cancelled"
	case r.State == "registered":
		// The code is spent; it stays registered after expires_at (0.10.6).
		return "registered"
	case now >= r.ExpiresAt:
		return "expired"
	case now >= r.AvailableAt:
		return "available"
	}
	return "pending"
}

// recoveryActive: pending, available or registered, before expires_at.
func recoveryActive(r *recoveryRow, now int64) bool {
	if r == nil || now >= r.ExpiresAt {
		return false
	}
	st := recoveryState(r, now)
	return st == "pending" || st == "available" || st == "registered"
}

// isRegisteredSlot: a register slot answered with the marker.
func isRegisteredSlot(it map[string]ddbtypes.AttributeValue) bool {
	return it != nil && str(it, "op") == "recovery_register" && str(it, "status") == "done" && str(it, "code") == registeredCode &&
		str(it, "recovery_id") != ""
}

// markRegistered records that the code of r is spent: pending ->
// registered, only for the same recovery and never over a cancel
// (conditional). It returns the recovery as it now is.
func (a *API) markRegistered(ctx context.Context, v *vaultRow, r *recoveryRow) (*recoveryRow, error) {
	if r.State != "pending" {
		return r, nil
	}
	_, err := a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Vaults,
		Key:                      map[string]ddbtypes.AttributeValue{"vault_id": s(v.VaultID)},
		UpdateExpression:         aws.String("SET recovery.#st = :reg, updated_at = :now"),
		ConditionExpression:      aws.String("recovery.recovery_id = :id AND recovery.#st = :pending"),
		ExpressionAttributeNames: map[string]string{"#st": "state"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":reg": s("registered"), ":pending": s("pending"),
			":id": s(r.ID), ":now": s(a.nowISO())}})
	if code(err) == "ConditionalCheckFailedException" {
		return r, nil // cancelled or replaced meanwhile
	}
	if err != nil {
		return nil, err
	}
	c := *r
	c.State = "registered"
	return &c, nil
}

// refreshRegistered: while the code is available, a slot of this
// recovery's register requests answered with the marker means the code is
// spent.
func (a *API) refreshRegistered(ctx context.Context, guid string, v *vaultRow) error {
	r := v.Recovery
	if r == nil || recoveryState(r, a.recoveryNowS()) != "available" || len(r.RegisterIDs) == 0 {
		return nil
	}
	ids := r.RegisterIDs
	if len(ids) > maxRegisterIDs {
		ids = ids[len(ids)-maxRegisterIDs:]
	}
	for _, id := range ids {
		if !ulidRE.MatchString(id) {
			continue
		}
		g, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Requests, ConsistentRead: aws.Bool(true),
			Key: map[string]ddbtypes.AttributeValue{"request_id": s(id)}})
		if err != nil {
			return err
		}
		if isRegisteredSlot(g.Item) && str(g.Item, "user_guid") == guid && str(g.Item, "recovery_id") == r.ID {
			nr, err := a.markRegistered(ctx, v, r)
			if err != nil {
				return err
			}
			v.Recovery = nr
			return nil
		}
	}
	return nil
}

// recordRegisterID remembers a register request on its recovery (best
// effort: the app's poll finds the slot anyway).
func (a *API) recordRegisterID(ctx context.Context, v *vaultRow, recoveryID, requestID string) {
	ids := append(append([]string(nil), v.Recovery.RegisterIDs...), requestID)
	if len(ids) > maxRegisterIDs {
		ids = ids[len(ids)-maxRegisterIDs:]
	}
	l := make([]ddbtypes.AttributeValue, len(ids))
	for i, id := range ids {
		l[i] = s(id)
	}
	_, _ = a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Vaults,
		Key:                 map[string]ddbtypes.AttributeValue{"vault_id": s(v.VaultID)},
		UpdateExpression:    aws.String("SET recovery.register_ids = :ids, updated_at = :now"),
		ConditionExpression: aws.String("recovery.recovery_id = :id"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":ids": &ddbtypes.AttributeValueMemberL{Value: l},
			":id": s(recoveryID), ":now": s(a.nowISO())}})
}

// recoverableVault: enrolled (not enrolling) and not deleted.
func (a *API) recoverableVault(ctx context.Context, guid string) (*vaultRow, error) {
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	if v == nil || v.State == "enrolling" {
		return nil, notFound("No enrolled vault")
	}
	return v, nil
}

// recoveryInstance: the leaseholder, else a live instance of the vault's
// sealed release (started on demand).
func (a *API) recoveryInstance(ctx context.Context, v *vaultRow, now int64) (*instanceRow, error) {
	holder, err := a.liveLease(ctx, v, now)
	if err != nil || holder != nil {
		return holder, err
	}
	if v.SealedRelease == "" {
		return nil, vaultError(409, "conflict", "The vault is not sealed to a release yet", nil)
	}
	rel, err := a.releaseRow(ctx, v.SealedRelease)
	if err != nil {
		return nil, err
	}
	if rel == nil || rel.available != nil && !*rel.available || rel.status == "removed" && rel.available == nil {
		return nil, vaultError(410, "release_unavailable", "The enclave release this vault is sealed to can no longer be started.", nil)
	}
	inst, err := a.pickInstance(ctx, v.SealedRelease, now)
	if err != nil || inst != nil {
		return inst, err
	}
	a.requestStart(v.SealedRelease)
	return nil, releaseStarting(v.SealedRelease)
}

// setRecovery writes the recovery, conditional on the one read (or none).
func (a *API) setRecovery(ctx context.Context, v *vaultRow, r *recoveryRow, expectID string) error {
	cond := "attribute_not_exists(recovery)"
	rm := map[string]ddbtypes.AttributeValue{"recovery_id": s(r.ID), "state": s(r.State),
		"requested_at": n(r.RequestedAt), "available_at": n(r.AvailableAt), "expires_at": n(r.ExpiresAt)}
	if len(r.RegisterIDs) > 0 {
		l := make([]ddbtypes.AttributeValue, len(r.RegisterIDs))
		for i, id := range r.RegisterIDs {
			l[i] = s(id)
		}
		rm["register_ids"] = &ddbtypes.AttributeValueMemberL{Value: l}
	}
	vals := map[string]ddbtypes.AttributeValue{":r": &ddbtypes.AttributeValueMemberM{Value: rm}, ":now": s(a.nowISO())}
	if expectID != "" {
		cond = "recovery.recovery_id = :id"
		vals[":id"] = s(expectID)
	}
	_, err := a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Vaults,
		Key:              map[string]ddbtypes.AttributeValue{"vault_id": s(v.VaultID)},
		UpdateExpression: aws.String("SET recovery = :r, updated_at = :now"), ConditionExpression: &cond, ExpressionAttributeValues: vals})
	if code(err) == "ConditionalCheckFailedException" {
		return vaultError(409, "conflict", "The recovery changed; try again", nil)
	}
	return err
}

func (a *API) newULID() string {
	id, err := envelope.NewULID(a.cfg.Now())
	if err != nil {
		panic(err)
	}
	return id
}

func (a *API) recoveryRequest(ctx context.Context, guid string, body map[string]any) (any, error) {
	bk, _ := body["browser_key"].(string)
	key, err := base64.StdEncoding.DecodeString(bk)
	if err != nil || len(key) != 65 || key[0] != 0x04 || base64.StdEncoding.EncodeToString(key) != bk {
		return nil, badRequest("browser_key must be base64 of an uncompressed P-256 point")
	}
	v, err := a.recoverableVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	rn := a.recoveryNowS()
	if recoveryActive(v.Recovery, rn) {
		return nil, vaultError(409, "recovery_active", "A recovery is already in progress", nil)
	}
	inst, err := a.recoveryInstance(ctx, v, a.nowS())
	if err != nil {
		return nil, err
	}
	r := &recoveryRow{ID: a.newULID(), State: "pending", RequestedAt: rn, AvailableAt: rn + recoveryDelayS, ExpiresAt: rn + recoveryDelayS + recoveryValidityS}
	expect := ""
	if v.Recovery != nil {
		expect = v.Recovery.ID
	}
	if err := a.setRecovery(ctx, v, r, expect); err != nil {
		return nil, err
	}
	// The slot keeps the sealed code until the recovery expires.
	if err := a.enqueueWith(ctx, "recovery", guid, v, r.ID, inst, "", "", "", bk, r.ExpiresAt-rn+3600, nil); err != nil {
		return nil, err
	}
	return map[string]any{"recovery_id": r.ID, "available_at": isoS(r.AvailableAt), "expires_at": isoS(r.ExpiresAt)}, nil
}

func (a *API) recoveryStatus(ctx context.Context, guid string) (any, error) {
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	rn := a.recoveryNowS()
	if v == nil || v.Recovery == nil {
		return map[string]any{"recovery": nil}, nil
	}
	if err := a.refreshRegistered(ctx, guid, v); err != nil {
		return nil, err
	}
	r := v.Recovery
	st := recoveryState(r, rn)
	out := map[string]any{"recovery_id": r.ID, "vault_id": v.VaultID, "state": st, "requested_at": isoS(r.RequestedAt),
		"available_at": isoS(r.AvailableAt), "expires_at": isoS(r.ExpiresAt)}
	if st == "available" {
		g, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Requests, ConsistentRead: aws.Bool(true),
			Key: map[string]ddbtypes.AttributeValue{"request_id": s(r.ID)}})
		if err != nil {
			return nil, err
		}
		it := g.Item
		if e := str(it, "envelope"); it != nil && str(it, "user_guid") == guid && str(it, "status") == "done" && e != "" {
			if b, err := base64.StdEncoding.DecodeString(e); err == nil && len(b) == resultEnvelope && base64.StdEncoding.EncodeToString(b) == e {
				out["sealed_code"] = e
				if _, ok := it["released"]; !ok {
					_, _ = a.cfg.DDB.UpdateItem(ctx, &dynamodb.UpdateItemInput{TableName: &a.cfg.Tables.Requests,
						Key: map[string]ddbtypes.AttributeValue{"request_id": s(r.ID)}, UpdateExpression: aws.String("SET released = :t"),
						ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":t": &ddbtypes.AttributeValueMemberBOOL{Value: true}}})
				}
			}
		}
	}
	return map[string]any{"recovery": out}, nil
}

func (a *API) recoveryCancel(ctx context.Context, guid string, body map[string]any) (any, error) {
	rid, err := field(body, "recovery_id", ulidRE, "a ULID")
	if err != nil {
		return nil, err
	}
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	if v == nil || v.Recovery == nil || v.Recovery.ID != rid {
		return nil, notFound("No such recovery")
	}
	r := v.Recovery
	if !recoveryActive(r, a.recoveryNowS()) {
		return map[string]any{"cancelled": false}, nil // nothing to cancel: a no-op
	}
	c := *r
	c.State = "cancelled"
	if err := a.setRecovery(ctx, v, &c, r.ID); err != nil {
		return nil, err
	}
	// Tell the enclave (best effort, as vault.ts).
	if inst, err := a.recoveryInstance(ctx, v, a.nowS()); err == nil {
		_ = a.enqueue(ctx, "recovery_cancel", guid, v, a.newULID(), inst, "", "", "")
	}
	return map[string]any{"cancelled": true}, nil
}

func (a *API) recoveryRegister(ctx context.Context, guid string, body map[string]any) (any, error) {
	vid, err := field(body, "vault_id", vaultIDRE, "32 lowercase hex")
	if err != nil {
		return nil, err
	}
	rid, err := field(body, "request_id", ulidRE, "a ULID")
	if err != nil {
		return nil, err
	}
	iid, err := field(body, "instance_id", instanceIDRE, "an instance id")
	if err != nil {
		return nil, err
	}
	kid, err := field(body, "etk_kid", kidRE, "16 lowercase hex")
	if err != nil {
		return nil, err
	}
	env, err := checkEnvelope(body["envelope"], envelopeLarge, kid)
	if err != nil {
		return nil, err
	}
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v := active(cur)
	if v == nil || v.VaultID != vid {
		return nil, notFound("No such vault")
	}
	if recoveryState(v.Recovery, a.recoveryNowS()) != "available" {
		return nil, vaultError(409, "recovery_not_available", "No recovery code is valid now", nil)
	}
	inst, err := a.routeCheck(ctx, v, iid, a.nowS())
	if err != nil {
		return nil, err
	}
	rel, err := a.releaseRow(ctx, inst.Release)
	if err != nil {
		return nil, err
	}
	if rel == nil || rel.available != nil && !*rel.available || rel.status == "removed" && rel.available == nil {
		return nil, vaultError(410, "release_unavailable", "The enclave release this vault is sealed to can no longer be started.", nil)
	}
	// The slot names its recovery, so its answer can retire the code
	// (0.10.6 §11.11.7).
	recID := v.Recovery.ID
	if err := a.enqueueWith(ctx, "recovery_register", guid, v, rid, inst, kid, env, "", "", requestTTLS,
		map[string]ddbtypes.AttributeValue{"recovery_id": s(recID)}); err != nil {
		return nil, err
	}
	a.recordRegisterID(ctx, v, recID, rid)
	return map[string]any{"vault_id": v.VaultID, "request_id": rid}, nil
}
