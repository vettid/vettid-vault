// Package store is the vault's object store: create-only and conditional
// (version-matched) writes of opaque blobs, which is what the split-brain
// guard (VAULT-MESSAGING §12.3) and rollback protection (§13.2) rely on.
//
// The store only ever sees ciphertext (DEK-encrypted state, sealed
// headers). Implementations: Memory and Dir here; S3 (conditional PUT with
// If-Match / If-None-Match) comes with the enclave parent in phase V3.
package store

import (
	"context"
	"errors"
	"strings"
)

// Errors.
var (
	ErrNotFound = errors.New("store: object not found")
	// ErrConflict means a conditional write found a different version: the
	// object exists (create-only) or was changed by another writer.
	ErrConflict = errors.New("store: version conflict")
	ErrKey      = errors.New("store: invalid key")
)

// Version is an opaque object version (an S3 ETag, a generation counter).
// The empty version means "absent".
type Version string

// Store is a conditional object store.
type Store interface {
	// Get returns the object and its version, or ErrNotFound.
	Get(ctx context.Context, key string) ([]byte, Version, error)
	// Put writes the object if its current version is ifMatch. ifMatch ""
	// means create-only: the write fails with ErrConflict if the object
	// exists. It returns the new version.
	Put(ctx context.Context, key string, data []byte, ifMatch Version) (Version, error)
	// Delete removes the object if its current version is ifMatch.
	Delete(ctx context.Context, key string, ifMatch Version) error
}

// ValidKey accepts keys made of path segments of [a-z0-9._-], separated by
// '/', with no empty, "." or ".." segments.
func ValidKey(k string) bool {
	if k == "" || len(k) > 256 {
		return false
	}
	for _, seg := range strings.Split(k, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return false
		}
		for i := 0; i < len(seg); i++ {
			c := seg[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Keys of a vault's objects.
func StateKey(vaultID string) string  { return "vaults/" + vaultID + "/state" }
func HeaderKey(vaultID string) string { return "vaults/" + vaultID + "/header" }
