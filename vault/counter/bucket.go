// Package counter is the recovery attempt counter (VAULT-MESSAGING 0.33.0
// §11.14.4; VAULT-HOST-PROTOCOL 0.1.10 §8.1): Status, Spend, Confirm,
// Succeed, Close and MarkPresent over S3 objects under Object Lock in
// compliance mode. It decides only from complete versions listings and
// read-back locks, never retries a Spend by itself, and counts any outcome
// it cannot classify as an attempt used (P17). The bucket is reached
// through the Bucket interface: in the enclave over the supervisor's TLS
// to the pinned bucket (enclave/s3counter), in tests a fake.
package counter

import (
	"context"
	"errors"
	"time"
)

// Entry is one version or delete marker of a versions listing.
type Entry struct {
	Key          string
	VersionID    string
	LastModified time.Time
	DeleteMarker bool
}

// Listing is a complete versions listing of a prefix (every page
// followed): every version and delete marker, and the Date of its last
// page, the counter's time of the listing.
type Listing struct {
	Entries []Entry
	Date    time.Time
}

// Retention is an object version's lock as read back.
type Retention struct {
	Mode  string // "COMPLIANCE", "GOVERNANCE" or ""
	Until time.Time
}

// Put statuses.
const (
	PutOK           = 200
	PutPrecondition = 412
)

// ErrUnknown is any answer the bucket client cannot classify (a timeout,
// a 5xx, a malformed body): the outcome of a write is unknown.
var ErrUnknown = errors.New("counter: outcome unknown")

// Bucket is the S3 surface the counter uses (the instance role's five
// permissions, P18). Every call names a full object key under the
// counter's prefix; the client adds the bucket, the expected owner and
// the signature.
type Bucket interface {
	// List is ListObjectVersions with a prefix, every page followed.
	List(ctx context.Context, prefix string) (Listing, error)
	// PutCreate is PutObject with If-None-Match: *, the compliance lock
	// until `until`, and the body. A 200 returns its version id; a 412
	// returns status PutPrecondition and no error; anything else is
	// ErrUnknown (the object may have been stored).
	PutCreate(ctx context.Context, key string, body []byte, until time.Time) (status int, versionID string, err error)
	// Put is a plain PutObject (one request, not multipart, never a copy)
	// with the compliance lock until `until`: a new version.
	Put(ctx context.Context, key string, body []byte, until time.Time) (versionID string, err error)
	// GetRetention is GetObjectRetention by version id.
	GetRetention(ctx context.Context, key, versionID string) (Retention, error)
	// GetVersion is GetObject by version id: the body.
	GetVersion(ctx context.Context, key, versionID string) ([]byte, error)
}
