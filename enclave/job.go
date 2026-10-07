package enclave

import (
	"errors"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Job is an enroll or unlock request after the outer instance decrypted
// it with the ETK and checked its binding and freshness (§11.3, §11.6).
// The supervisor hands it to the vault's process and wipes its copy
// (VAULT-MESSAGING §12.4).
type Job struct {
	Op        string
	VaultID   string
	UserGUID  string
	RequestID string
	ETKKid    suite.Kid
	// Inner is the decrypted request (type, id, ts, body).
	Inner *envelope.Inner
	// Manifest is the served manifest document the parent supplied for
	// an enroll or unlock (0.10.0, M1), or empty. It is host input: the
	// vault verifies it against the hash in the sealed request.
	Manifest []byte
	// AppKey is the queue message's app_key (enroll, recovery_register;
	// 0.15.0), bound to the sealed app.api_key.
	AppKey []byte
	// Account is the queue message's account snapshot (unlock, 0.15.0;
	// enroll, REQUIRED since 0.18.0; §11.13), applied after a successful
	// unlock or with the enrollment's first flush.
	Account []byte
}

// ErrJob is a malformed job.
var ErrJob = errors.New("enclave: malformed job")

// MaxJobBody bounds the inner body (the 12,288-byte padded request).
const MaxJobBody = altchan.RequestPaddedSize

// Fields encodes the job for the vault channel:
// [op, vault_id, user_guid, request_id, etk_kid, type, id, ts, body,
// manifest document, app key, account snapshot].
func (j *Job) Fields() [][]byte {
	return [][]byte{[]byte(j.Op), []byte(j.VaultID), []byte(j.UserGUID), []byte(j.RequestID), []byte(j.ETKKid.String()),
		[]byte(j.Inner.Type), []byte(j.Inner.ID), []byte(envelope.FormatTS(j.Inner.TS)), j.Inner.Body, j.Manifest, j.AppKey, j.Account}
}

// MaxJobAccount bounds a job's account snapshot (§11.13: 2 KiB).
const MaxJobAccount = 2048

// ParseJob decodes Fields strictly.
func ParseJob(f [][]byte) (*Job, error) {
	if len(f) != 12 || len(f[9]) > manifest.MaxServed || len(f[10]) > altchan.MaxAppKeyB64 || len(f[11]) > MaxJobAccount {
		return nil, ErrJob
	}
	j := &Job{Op: string(f[0]), VaultID: string(f[1]), UserGUID: string(f[2]), RequestID: string(f[3])}
	want := requestType[j.Op]
	if want == "" || !validID(j.VaultID) || !validGUID(j.UserGUID) || !envelope.ValidULID(j.RequestID) {
		return nil, ErrJob
	}
	kid, err := suite.ParseKidHex(string(f[4]))
	if err != nil || kid.String() != string(f[4]) {
		return nil, ErrJob
	}
	j.ETKKid = kid
	if string(f[5]) != want || string(f[6]) != j.RequestID || len(f[8]) == 0 || len(f[8]) > MaxJobBody {
		return nil, ErrJob
	}
	ts, err := envelope.ParseTS(string(f[7]))
	if err != nil {
		return nil, ErrJob
	}
	j.Inner = &envelope.Inner{Type: want, ID: j.RequestID, TS: ts, Body: append([]byte(nil), f[8]...)}
	if len(f[9]) > 0 {
		j.Manifest = append([]byte(nil), f[9]...)
	}
	if len(f[10]) > 0 {
		j.AppKey = append([]byte(nil), f[10]...)
	}
	if len(f[11]) > 0 {
		j.Account = append([]byte(nil), f[11]...)
	}
	return j, nil
}

// Wipe zeroizes the job's decrypted body (it carries the PIN).
func (j *Job) Wipe() {
	if j != nil && j.Inner != nil {
		suite.Wipe(j.Inner.Body)
	}
}
