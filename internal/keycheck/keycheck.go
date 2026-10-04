// Package keycheck runs the enclave's own §11.10.7 release-key check
// (VAULT-MESSAGING §11.10.7, package enclave/keypolicy) against a live KMS
// key from an operator's machine: `vaultctl keycheck` (VAULT-RELEASES
// §6.2, layer 2), before a release key is named in a manifest.
//
// The key's DescribeKey, GetKeyPolicy and ListGrants responses are
// fetched with the enclave's own KMS client (enclave/awskms, the same
// requests the enclave sends) using the caller's AWS credentials, or read
// from recorded fixtures, and checked with the channel's pinned constants
// (enclave/releasecfg/<channel>.json) and the draft or published
// manifest. vaultctl is not part of the enclave: this package may link
// the AWS SDK for credentials; the check itself is the enclave's code.
package keycheck

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/keypolicy"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/vms/manifest"
)

// Fixture file names (Record writes them, Fixtures reads them).
const (
	FileDescribeKey  = "describe-key.json"
	FileGetKeyPolicy = "get-key-policy.json"
	FileListGrants   = "list-grants.json"
)

// Responses are the three raw KMS response bodies.
type Responses struct {
	DescribeKey, GetKeyPolicy, ListGrants []byte
}

// Fetch reads the key's responses with the enclave's KMS client.
func Fetch(ctx context.Context, c *awskms.Client, keyARN string) (*Responses, error) {
	var r Responses
	var err error
	if r.DescribeKey, err = c.DescribeKey(ctx, keyARN); err != nil {
		return nil, fmt.Errorf("DescribeKey: %w", err)
	}
	if r.GetKeyPolicy, err = c.GetKeyPolicy(ctx, keyARN); err != nil {
		return nil, fmt.Errorf("GetKeyPolicy: %w", err)
	}
	if r.ListGrants, err = c.ListGrants(ctx, keyARN); err != nil {
		return nil, fmt.Errorf("ListGrants: %w", err)
	}
	return &r, nil
}

// Fixtures reads recorded responses from dir.
func Fixtures(dir string) (*Responses, error) {
	var r Responses
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{{FileDescribeKey, &r.DescribeKey}, {FileGetKeyPolicy, &r.GetKeyPolicy}, {FileListGrants, &r.ListGrants}} {
		b, err := os.ReadFile(filepath.Join(dir, f.name))
		if err != nil {
			return nil, err
		}
		*f.dst = b
	}
	return &r, nil
}

// Record writes the responses to dir (the release record keeps them).
func (r *Responses) Record(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for name, b := range map[string][]byte{FileDescribeKey: r.DescribeKey, FileGetKeyPolicy: r.GetKeyPolicy, FileListGrants: r.ListGrants} {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LoadManifest reads a manifest for the check: a served document, whose
// signature must verify under one of pinned (signed: true), or the bare
// manifest bytes of a draft that is not signed yet (signed: false;
// VAULT-RELEASES §10.1 step 6 checks the key against the draft).
func LoadManifest(b []byte, pinned []*ecdsa.PublicKey) (m *manifest.Manifest, signed bool, err error) {
	if s, err := manifest.ParseServed(b); err == nil {
		m, err := manifest.Verify(s, pinned)
		if err != nil {
			return nil, false, fmt.Errorf("served manifest: %w", err)
		}
		return m, true, nil
	}
	m, err = manifest.Parse(b)
	if err != nil {
		return nil, false, fmt.Errorf("manifest: %w", err)
	}
	return m, false, nil
}

// Target picks the release whose key is checked: release n if n > 0,
// otherwise the single entry whose seal_key is keyARN.
func Target(m *manifest.Manifest, keyARN string, n uint64) (uint64, error) {
	if n > 0 {
		r, ok := m.ByNumber(n)
		if !ok {
			return 0, fmt.Errorf("release %d is not in the manifest", n)
		}
		if r.SealKey != keyARN {
			return 0, fmt.Errorf("release %d's seal_key is %s, not %s", n, r.SealKey, keyARN)
		}
		return n, nil
	}
	var found []uint64
	for _, r := range m.Releases {
		if r.SealKey == keyARN {
			found = append(found, r.Number)
		}
	}
	if len(found) != 1 {
		return 0, fmt.Errorf("%d manifest entries name %s as seal_key; pass the release number", len(found), keyARN)
	}
	return found[0], nil
}

// CheckError is a refusal by one of the §11.10.7 checks.
type CheckError = keypolicy.CheckError

// Run runs the enclave's check with the channel's pinned constants.
func Run(cfg *releasecfg.Config, m *manifest.Manifest, target uint64, keyARN string, r *Responses) (*keypolicy.Result, error) {
	return keypolicy.Check(keypolicy.Input{KeyARN: keyARN, Account: cfg.SealAccount, Region: cfg.SealRegion,
		RetirementPrincipal: cfg.RetirementPrincipal, RetirementWindowDays: cfg.RetirementWindowDays,
		Manifest: m, Target: target, DescribeKey: r.DescribeKey, GetKeyPolicy: r.GetKeyPolicy, ListGrants: r.ListGrants})
}

// FailedCheck returns the §11.10.7 check number of a refusal (0 if err is
// not one).
func FailedCheck(err error) int {
	var ce *keypolicy.CheckError
	if errors.As(err, &ce) {
		return ce.Check
	}
	return 0
}
