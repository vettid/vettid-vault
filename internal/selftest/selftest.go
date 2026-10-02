// Package selftest holds the hardware smoke test's request and report
// (docs/SMOKE.md): the parent asks the enclave to run its self-test and
// prints the report. Neither carries a secret: results are booleans,
// public measurements, sizes and check numbers.
package selftest

import (
	"encoding/json"
	"errors"
	"regexp"
)

// Request is what the parent supplies (public configuration only).
type Request struct {
	// RunID names the S3 prefix smoke/<run_id>/ ([a-z0-9-]{1,32}).
	RunID string `json:"run_id"`
	// KeyARN is the test KMS key; Account and Region its namespace.
	KeyARN  string `json:"key_arn"`
	Account string `json:"account"`
	Region  string `json:"region"`
}

var (
	runIDRE   = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	accountRE = regexp.MustCompile(`^[0-9]{12}$`)
	regionRE  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]$`)
)

// ErrRequest is a malformed request.
var ErrRequest = errors.New("selftest: malformed request")

// ParseRequest decodes and validates a request.
func ParseRequest(b []byte) (*Request, error) {
	var r Request
	if len(b) > 4096 || json.Unmarshal(b, &r) != nil || !runIDRE.MatchString(r.RunID) || !accountRE.MatchString(r.Account) ||
		!regionRE.MatchString(r.Region) || len(r.KeyARN) > 256 {
		return nil, ErrRequest
	}
	return &r, nil
}

// Check is one result. OK means "as expected" (a check that expects a
// refusal is OK when refused). Required checks decide pass or fail.
type Check struct {
	Name     string `json:"name"`
	OK       bool   `json:"ok"`
	Required bool   `json:"required"`
	Detail   string `json:"detail,omitempty"`
}

// Report is the enclave's answer.
type Report struct {
	Version int     `json:"version"`
	PCR0    string  `json:"pcr0"`
	PCR1    string  `json:"pcr1"`
	PCR2    string  `json:"pcr2"`
	Checks  []Check `json:"checks"`
	// KeyPolicyCheck is the §11.10.7 check that refused the test key
	// (0: not refused).
	KeyPolicyCheck int    `json:"key_policy_check"`
	MemTotal       uint64 `json:"mem_total_bytes"`
	MemAvailable   uint64 `json:"mem_available_bytes"`
	SupervisorRSS  uint64 `json:"supervisor_rss_bytes"`
	VaultPeakRSS   uint64 `json:"vault_process_peak_rss_bytes"`
	// AttestationDocument is the self-test's own attestation document
	// (public: PCRs, the test nonce and the self-test user_data, AWS
	// certificates), included only when it did not verify, so it can be
	// examined and kept as a test fixture.
	AttestationDocument []byte `json:"attestation_document,omitempty"`
}

// Add appends a check.
func (r *Report) Add(name string, ok, required bool, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, OK: ok, Required: required, Detail: detail})
}

// Passed reports whether every required check is OK.
func (r *Report) Passed() bool {
	for _, c := range r.Checks {
		if c.Required && !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

// VaultResult is what the self-test vault process returns.
type VaultResult struct {
	Checks  []Check `json:"checks"`
	PeakRSS uint64  `json:"peak_rss_bytes"`
	UID     int     `json:"uid"`
	GID     int     `json:"gid"`
}
