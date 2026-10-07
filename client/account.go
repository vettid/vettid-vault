package client

import (
	"context"
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// The account's names from the app's side (VAULT-MESSAGING 0.18.0,
// §10.8): account.name.set with the PIN and the credential password, as
// the owner check sends them; the request's outcome arrives in the
// account snapshot, which account.get returns with name_request.

// TypeAccountNameSet is the name change's message type.
const TypeAccountNameSet = "account.name.set"

// AccountNameSet asks the vault to change the account's first and last
// name. It returns the name request ({seq, first_name, last_name,
// requested_at, state, reason?}); too_soon's error body carries
// {allowed_after}.
func (d *Device) AccountNameSet(ctx context.Context, pin, password, first, last string) (json.RawMessage, error) {
	payload := func() map[string]any {
		return map[string]any{"pin": pin, "password": password, "first_name": first, "last_name": last}
	}
	o, _, _, err := d.credOpWith(ctx, TypeAccountNameSet, nil, payload, false)
	if err != nil {
		return nil, err
	}
	r, ok := o["request"]
	if !ok {
		return nil, ErrProtocol
	}
	if _, err := strictjson.AsObject(r); err != nil {
		return nil, ErrProtocol
	}
	return r, nil
}

// IKFingerprint is the fingerprint an app shows for a connection's
// pinned ik (§10.8): 8 groups of 4 lowercase hex digits.
func IKFingerprint(ik []byte) string { return suite.FormatIKFingerprint(ik) }
