package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// Feature operations of VAULT-MESSAGING §10.6–§10.9. Each is a request to
// the vault; errors carry the response's error code.

// OpError is an error response.
type OpError struct {
	Type string
	Code string
}

func (e *OpError) Error() string { return fmt.Sprintf("client: %s: %s", e.Type, e.Code) }

// Code returns the error code of err if it is an *OpError.
func Code(err error) string {
	var oe *OpError
	if errors.As(err, &oe) {
		return oe.Code
	}
	return ""
}

// Op sends a request whose body is v marshalled as JSON and returns the
// parsed response body.
func (d *Device) Op(ctx context.Context, typ string, v any) (strictjson.Object, error) {
	body := json.RawMessage(`{}`)
	if v != nil {
		b, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		if string(b) != "null" { // a nil map
			body = b
		}
	}
	r, err := d.Request(ctx, typ, body)
	if err != nil {
		return nil, err
	}
	if !r.OK() {
		return nil, &OpError{Type: typ, Code: r.ErrorCode()}
	}
	b := r.Body()
	if len(b) == 0 {
		b = json.RawMessage(`{}`)
	}
	return strictjson.ParseObject(b)
}

// CredentialCopy is an app's copy of the Protean Credential.
type CredentialCopy struct {
	Blob    []byte `json:"blob"`
	Version uint64 `json:"version"`
}

// ErrNoCredential: the device holds no credential.
var ErrNoCredential = errors.New("client: no credential on this device")

func (d *Device) credential() (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Credential == nil {
		return "", ErrNoCredential
	}
	return base64.StdEncoding.EncodeToString(d.st.Credential.Blob), nil
}

// storeCredential keeps a returned blob.
func (d *Device) storeCredential(o strictjson.Object) error {
	blob, err := o.Base64("credential", -1)
	if err != nil {
		return ErrProtocol
	}
	v, err := o.Uint("version", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return ErrProtocol
	}
	d.mu.Lock()
	d.st.Credential = &CredentialCopy{Blob: blob, Version: v}
	d.mu.Unlock()
	return nil
}

// credOp sends a credential operation carrying the blob and the password
// (§3.5.3) plus extra members, and stores a returned blob.
func (d *Device) credOp(ctx context.Context, typ, password string, extra map[string]any) (strictjson.Object, error) {
	c, err := d.credential()
	if err != nil {
		return nil, err
	}
	body := map[string]any{"credential": c, "password": password}
	for k, v := range extra {
		body[k] = v
	}
	o, err := d.Op(ctx, typ, body)
	if err != nil {
		return nil, err
	}
	if o.Has("credential") {
		if err := d.storeCredential(o); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// CredentialCreate creates the Protean Credential and keeps the blob.
func (d *Device) CredentialCreate(ctx context.Context, password string) error {
	o, err := d.Op(ctx, "credential.create", map[string]any{"password": password})
	if err != nil {
		return err
	}
	return d.storeCredential(o)
}

// CredentialFetch fetches the vault's copy of the blob (§3.5.6).
func (d *Device) CredentialFetch(ctx context.Context) error {
	o, err := d.Op(ctx, "credential.get", nil)
	if err != nil {
		return err
	}
	return d.storeCredential(o)
}

// CredentialVersion returns credential.version.
func (d *Device) CredentialVersion(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "credential.version", nil)
}

// CredentialUnlock opens the unlock window and returns its expiry.
func (d *Device) CredentialUnlock(ctx context.Context, password string) (string, error) {
	o, err := d.credOp(ctx, "credential.unlock", password, nil)
	if err != nil {
		return "", err
	}
	return o.String("expires_at")
}

// CredentialLock ends the unlock window.
func (d *Device) CredentialLock(ctx context.Context) error {
	_, err := d.Op(ctx, "credential.lock", nil)
	return err
}

// CredentialRotate rotates the credential (and the vault's ik and kem).
func (d *Device) CredentialRotate(ctx context.Context, password string) error {
	_, err := d.credOp(ctx, "credential.rotate", password, nil)
	return err
}

// CredentialChangePassword re-seals the credential under a new password.
func (d *Device) CredentialChangePassword(ctx context.Context, password, newPassword string) error {
	_, err := d.credOp(ctx, "credential.password.change", password, map[string]any{"new_password": newPassword})
	return err
}

// CredentialDelete deletes the credential and the local copy.
func (d *Device) CredentialDelete(ctx context.Context, password string) error {
	if _, err := d.credOp(ctx, "credential.delete", password, nil); err != nil {
		return err
	}
	d.mu.Lock()
	d.st.Credential = nil
	d.mu.Unlock()
	return nil
}

// CriticalSecretAdd adds a critical secret and returns its id.
func (d *Device) CriticalSecretAdd(ctx context.Context, password, name, category, description string, value []byte) (string, error) {
	extra := map[string]any{"name": name, "category": category, "value": base64.StdEncoding.EncodeToString(value)}
	if description != "" {
		extra["description"] = description
	}
	o, err := d.credOp(ctx, "credential.secret.add", password, extra)
	if err != nil {
		return "", err
	}
	return o.String("secret_id")
}

// CriticalSecretGet reads a critical secret's value.
func (d *Device) CriticalSecretGet(ctx context.Context, password, id string) ([]byte, error) {
	o, err := d.credOp(ctx, "credential.secret.get", password, map[string]any{"secret_id": id})
	if err != nil {
		return nil, err
	}
	return o.Base64("value", -1)
}

// CriticalSecretList lists the critical secrets' metadata.
func (d *Device) CriticalSecretList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "credential.secret.list", nil)
}

// CriticalSecretDelete deletes a critical secret.
func (d *Device) CriticalSecretDelete(ctx context.Context, password, id string) error {
	_, err := d.credOp(ctx, "credential.secret.delete", password, map[string]any{"secret_id": id})
	return err
}

// SecretPut creates (id "") or replaces a vault-held secret and returns its
// id and version (§10.7).
func (d *Device) SecretPut(ctx context.Context, id string, version uint64, name, value string, extra map[string]any) (string, uint64, error) {
	body := map[string]any{"name": name, "value": value}
	for k, v := range extra {
		body[k] = v
	}
	if id != "" {
		body["secret_id"], body["version"] = id, version
	}
	o, err := d.Op(ctx, "secret.put", body)
	if err != nil {
		return "", 0, err
	}
	sid, _ := o.String("secret_id")
	v, _ := o.Uint("version", 1, strictjson.MaxSafeInteger)
	return sid, v, nil
}

// SecretGet reads a vault-held secret.
func (d *Device) SecretGet(ctx context.Context, id string) (strictjson.Object, error) {
	return d.Op(ctx, "secret.get", map[string]any{"secret_id": id})
}

// SecretList lists the vault-held secrets (without values).
func (d *Device) SecretList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "secret.list", nil)
}

// SecretDelete deletes a vault-held secret.
func (d *Device) SecretDelete(ctx context.Context, id string) error {
	_, err := d.Op(ctx, "secret.delete", map[string]any{"secret_id": id})
	return err
}

// ProfileGet returns the owner's profile.
func (d *Device) ProfileGet(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "profile.get", nil)
}

// ProfileSet applies a profile.set body (which must name the version) and
// returns the new version.
func (d *Device) ProfileSet(ctx context.Context, body map[string]any) (uint64, error) {
	o, err := d.Op(ctx, "profile.set", body)
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// SettingsGet returns the settings.
func (d *Device) SettingsGet(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "settings.get", nil)
}

// SettingsSet sets keys at a version and returns the new version.
func (d *Device) SettingsSet(ctx context.Context, version uint64, set map[string]any) (uint64, error) {
	o, err := d.Op(ctx, "settings.set", map[string]any{"version": version, "set": set})
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// AuditList returns audit.list (or connection.audit.list when q names a
// connection_id and perConnection is set).
func (d *Device) AuditList(ctx context.Context, q map[string]any, perConnection bool) (strictjson.Object, error) {
	typ := "audit.list"
	if perConnection {
		typ = "connection.audit.list"
	}
	return d.Op(ctx, typ, q)
}

// FeedList returns feed.list.
func (d *Device) FeedList(ctx context.Context, q map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, "feed.list", q)
}

// FeedGet returns one feed item.
func (d *Device) FeedGet(ctx context.Context, id string) (strictjson.Object, error) {
	return d.Op(ctx, "feed.get", map[string]any{"item_id": id})
}

// FeedUpdate sets an item's status and/or priority ("" to leave as is).
func (d *Device) FeedUpdate(ctx context.Context, id, status, priority string) (strictjson.Object, error) {
	body := map[string]any{"item_id": id}
	if status != "" {
		body["status"] = status
	}
	if priority != "" {
		body["priority"] = priority
	}
	return d.Op(ctx, "feed.update", body)
}

// FeedDelete deletes a feed item.
func (d *Device) FeedDelete(ctx context.Context, id string) error {
	_, err := d.Op(ctx, "feed.delete", map[string]any{"item_id": id})
	return err
}

// GuideSync sends the app's guide catalog.
func (d *Device) GuideSync(ctx context.Context, guides []map[string]any) (strictjson.Object, error) {
	return d.Op(ctx, "guide.sync", map[string]any{"guides": guides})
}
