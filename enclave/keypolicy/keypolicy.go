// Package keypolicy verifies a release's sealing key before the enclave
// seals a header to it for the first time (VAULT-MESSAGING §11.10.7). It is
// a pure function over the raw AWS KMS DescribeKey, GetKeyPolicy and
// ListGrants responses, which the enclave fetches over TLS it terminates
// (transport: phase V3b).
//
// It fails closed: any failure, unknown member, unexpected type, wildcard,
// operator or principal outside the allow-list, or truncated listing
// refuses the key. Each refusal names the spec's check (1-8).
//
// Since VAULT-MESSAGING 0.10.0 a release image may pin a retirement
// principal and window (VAULT-RELEASES §4.1): exactly that role may then
// schedule the key's deletion with exactly that pending window, cancel the
// deletion and re-enable the key, in statements of their own. Nothing else
// changes: no principal may change the policy, add grants or disable the
// key.
package keypolicy

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/manifest"
)

// CheckError is a refusal by one of the §11.10.7 checks.
type CheckError struct {
	Check int
}

var checkText = map[int]string{
	1: "keypolicy: check 1 (key identity) failed",
	2: "keypolicy: check 2 (key metadata) failed",
	3: "keypolicy: check 3 (grants) failed",
	4: "keypolicy: check 4 (policy shape) failed",
	6: "keypolicy: check 6 (actions) failed",
	7: "keypolicy: check 7 (attestation condition) failed",
	8: "keypolicy: check 8 (principals) failed",
}

func (e *CheckError) Error() string { return checkText[e.Check] }

// Is lets errors.Is match on the check number.
func (e *CheckError) Is(target error) bool {
	t, ok := target.(*CheckError)
	return ok && t.Check == e.Check
}

// Sentinels for errors.Is.
var (
	ErrIdentity  error = &CheckError{1}
	ErrMetadata  error = &CheckError{2}
	ErrGrants    error = &CheckError{3}
	ErrShape     error = &CheckError{4}
	ErrActions   error = &CheckError{6}
	ErrCondition error = &CheckError{7}
	ErrPrincipal error = &CheckError{8}
)

// Input is everything one check needs.
type Input struct {
	// KeyARN is the target release's seal_key from the verified manifest.
	KeyARN string
	// Account and Region are pinned in the release image.
	Account, Region string
	// Manifest is the verified manifest; Target is the release number
	// whose key this is.
	Manifest *manifest.Manifest
	Target   uint64
	// RetirementPrincipal and RetirementWindowDays are the pinned
	// retirement role (an IAM role ARN in Account) and its pending window
	// in days (7-30). Empty: the retirement actions disqualify a key, as
	// before 0.10.0.
	RetirementPrincipal  string
	RetirementWindowDays int
	// Raw KMS responses (JSON bodies).
	DescribeKey  []byte
	GetKeyPolicy []byte
	ListGrants   []byte
}

// Result records a passing check (seal_key_verified, §3.3).
type Result struct {
	KeyARN       string
	PolicySHA256 [32]byte
}

// Allowed actions (check 6).
const (
	actDecrypt = "kms:Decrypt"
	actGDK     = "kms:GenerateDataKey"
	// The retirement actions, allowed only to the pinned retirement
	// principal in statements of their own (0.10.0).
	actSchedule = "kms:ScheduleKeyDeletion"
	actCancel   = "kms:CancelKeyDeletion"
	actEnable   = "kms:EnableKey"
)

var retirement = map[string]bool{actSchedule: true, actCancel: true, actEnable: true}

// The KMS documented range of a deletion's pending window.
const (
	minWindowDays = 7
	maxWindowDays = 30
)

var readOnly = map[string]bool{
	"kms:DescribeKey": true, "kms:GetKeyPolicy": true, "kms:ListGrants": true, "kms:ListKeyPolicies": true,
	"kms:GetKeyRotationStatus": true, "kms:ListResourceTags": true,
}

const maxResponse = 64 * 1024

// Check runs the §11.10.7 checks in order.
func Check(in Input) (*Result, error) {
	if !validAccount(in.Account) || !validRegion(in.Region) || in.Manifest == nil || !validRetirement(in) {
		return nil, ErrIdentity
	}
	target, ok := in.Manifest.ByNumber(in.Target)
	if !ok {
		return nil, ErrIdentity
	}
	// 1. Key identity.
	if in.KeyARN != target.SealKey || !keyARNOK(in.KeyARN, in.Region, in.Account) {
		return nil, ErrIdentity
	}
	// 2. Key metadata.
	if err := checkMetadata(in); err != nil {
		return nil, err
	}
	// 3. No grants.
	if err := checkGrants(in.ListGrants); err != nil {
		return nil, err
	}
	// 4-8. The policy.
	if len(in.GetKeyPolicy) == 0 || len(in.GetKeyPolicy) > maxResponse {
		return nil, ErrShape
	}
	resp, err := strictjson.ParseObject(in.GetKeyPolicy)
	if err != nil {
		return nil, ErrShape
	}
	if !onlyMembers(resp, "Policy", "PolicyName") {
		return nil, ErrShape
	}
	if name, present, err := resp.OptString("PolicyName"); err != nil || present && name != "default" {
		return nil, ErrShape
	}
	doc, err := resp.String("Policy")
	if err != nil {
		return nil, ErrShape
	}
	if err := checkPolicy([]byte(doc), in, target); err != nil {
		return nil, err
	}
	return &Result{KeyARN: in.KeyARN, PolicySHA256: sha256.Sum256([]byte(doc))}, nil
}

func validAccount(a string) bool {
	if len(a) != 12 {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] < '0' || a[i] > '9' {
			return false
		}
	}
	return true
}

// validRetirement checks the pinned retirement constants: none at all, or
// an IAM role (not the account root) in the pinned account with a window
// in KMS's range.
func validRetirement(in Input) bool {
	if in.RetirementPrincipal == "" {
		return in.RetirementWindowDays == 0
	}
	acct, ok := iamARNAccount(in.RetirementPrincipal)
	return ok && acct == in.Account && !strings.HasSuffix(in.RetirementPrincipal, ":root") &&
		in.RetirementWindowDays >= minWindowDays && in.RetirementWindowDays <= maxWindowDays
}

func validRegion(r string) bool {
	if r == "" || len(r) > 32 {
		return false
	}
	for i := 0; i < len(r); i++ {
		c := r[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func isHex(s string, n int, lowerOnly bool) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || !lowerOnly && c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// keyARNOK: arn:aws:kms:<region>:<account>:key/<uuid> (a single-region key
// id; multi-region "mrk-" ids are not keys this release seals to).
func keyARNOK(arn, region, account string) bool {
	prefix := "arn:aws:kms:" + region + ":" + account + ":key/"
	if !strings.HasPrefix(arn, prefix) {
		return false
	}
	u := arn[len(prefix):]
	if len(u) != 36 {
		return false
	}
	for i, part := range strings.Split(u, "-") {
		if i > 4 || !isHex(part, []int{8, 4, 4, 4, 12}[i], true) {
			return false
		}
	}
	return strings.Count(u, "-") == 4
}

func onlyMembers(o strictjson.Object, names ...string) bool {
	for k := range o {
		ok := false
		for _, n := range names {
			if k == n {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

func checkMetadata(in Input) error {
	if len(in.DescribeKey) == 0 || len(in.DescribeKey) > maxResponse {
		return ErrMetadata
	}
	o, err := strictjson.ParseObject(in.DescribeKey)
	if err != nil {
		return ErrMetadata
	}
	md, err := o.Object("KeyMetadata")
	if err != nil {
		return ErrMetadata
	}
	want := map[string]string{
		"Arn": in.KeyARN, "AWSAccountId": in.Account, "KeyState": "Enabled", "Origin": "AWS_KMS",
		"KeySpec": "SYMMETRIC_DEFAULT", "KeyUsage": "ENCRYPT_DECRYPT", "KeyManager": "CUSTOMER",
	}
	for k, v := range want {
		s, err := md.String(k)
		if err != nil || s != v {
			return ErrMetadata
		}
	}
	if mr, err := md.Bool("MultiRegion"); err != nil || mr {
		return ErrMetadata
	}
	if md.Has("CustomKeyStoreId") || md.Has("CloudHsmClusterId") || md.Has("XksKeyConfiguration") {
		return ErrMetadata
	}
	return nil
}

func checkGrants(b []byte) error {
	if len(b) == 0 || len(b) > maxResponse {
		return ErrGrants
	}
	o, err := strictjson.ParseObject(b)
	if err != nil {
		return ErrGrants
	}
	g, err := o.Array("Grants")
	if err != nil || len(g) != 0 {
		return ErrGrants
	}
	if tr, err := o.Bool("Truncated"); err != nil || tr {
		return ErrGrants
	}
	if o.Has("NextMarker") {
		return ErrGrants
	}
	return nil
}

// stringOrArray returns a JSON string or array of strings (non-empty).
func stringOrArray(raw json.RawMessage) ([]string, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	switch raw[0] {
	case '"':
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, false
		}
		return []string{s}, true
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal(raw, &arr) != nil || len(arr) == 0 {
			return nil, false
		}
		out := make([]string, 0, len(arr))
		for _, e := range arr {
			if len(e) == 0 || e[0] != '"' {
				return nil, false
			}
			var s string
			if json.Unmarshal(e, &s) != nil {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

type statement struct {
	effect    string
	principal json.RawMessage
	actions   []string
	condition strictjson.Object
}

func checkPolicy(doc []byte, in Input, target *manifest.Release) error {
	p, err := strictjson.ParseObject(doc)
	if err != nil {
		return ErrShape // includes duplicate member names
	}
	// 4. Policy shape.
	if !onlyMembers(p, "Version", "Id", "Statement") {
		return ErrShape
	}
	if v, err := p.String("Version"); err != nil || v != "2012-10-17" {
		return ErrShape
	}
	if _, present, err := p.OptString("Id"); present && err != nil {
		return ErrShape
	}
	raw, ok := p["Statement"]
	if !ok || len(raw) == 0 {
		return ErrShape
	}
	var rawStmts []json.RawMessage
	switch raw[0] {
	case '{':
		rawStmts = []json.RawMessage{raw}
	case '[':
		if json.Unmarshal(raw, &rawStmts) != nil {
			return ErrShape
		}
	default:
		return ErrShape
	}
	var stmts []statement
	for _, r := range rawStmts {
		s, err := parseStatement(r, in.KeyARN)
		if err != nil {
			return err
		}
		stmts = append(stmts, s)
	}
	// 5. Deny statements only remove access: ignored from here on.
	for _, s := range stmts {
		if s.effect != "Allow" {
			continue
		}
		if err := checkAllow(s, in, target); err != nil {
			return err
		}
	}
	return nil
}

func parseStatement(raw json.RawMessage, keyARN string) (statement, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return statement{}, ErrShape
	}
	// NotPrincipal, NotAction and NotResource are outside the allowed
	// member set, in Allow and Deny statements alike.
	if !onlyMembers(o, "Sid", "Effect", "Principal", "Action", "Resource", "Condition") {
		return statement{}, ErrShape
	}
	var s statement
	if _, present, err := o.OptString("Sid"); present && err != nil {
		return s, ErrShape
	}
	if s.effect, err = o.String("Effect"); err != nil || s.effect != "Allow" && s.effect != "Deny" {
		return s, ErrShape
	}
	acts, ok := stringOrArray(o["Action"])
	if !ok {
		return s, ErrShape
	}
	s.actions = acts
	res, err := o.String("Resource")
	if err != nil || res != "*" && res != keyARN {
		return s, ErrShape
	}
	s.principal = o["Principal"]
	if c, present := o["Condition"]; present {
		if s.condition, err = strictjson.AsObject(c); err != nil {
			return s, ErrShape
		}
	}
	return s, nil
}

// cond is one parsed condition entry.
type cond struct {
	op, key string
	values  []string
}

const (
	keyWindow  = "kms:ScheduleKeyDeletionPendingWindowInDays"
	opNumEq    = "NumericEquals"
	keyImage   = "kms:RecipientAttestation:ImageSha384"
	keyPCR0    = "kms:RecipientAttestation:PCR0"
	keyPCRPfx  = "kms:RecipientAttestation:PCR"
	keyCaller  = "kms:CallerAccount"
	keyECPfx   = "kms:EncryptionContext:"
	keyPrinARN = "aws:PrincipalArn"
)

// parseConditions applies check 7's allow-list of operators and keys.
func parseConditions(c strictjson.Object) ([]cond, error) {
	var out []cond
	for op, raw := range c {
		switch op {
		case "StringEquals", "StringEqualsIgnoreCase", "ArnEquals":
		case opNumEq:
			// Only the deletion window (0.10.0), one value; where it may
			// appear and which value it must have is checkAllow's.
			inner, err := strictjson.AsObject(raw)
			if err != nil || len(inner) != 1 {
				return nil, ErrCondition
			}
			v, ok := windowValue(inner[keyWindow])
			if !ok {
				return nil, ErrCondition
			}
			out = append(out, cond{op: op, key: keyWindow, values: []string{v}})
			continue
		default:
			return nil, ErrCondition // …IfExists, ForAnyValue:/ForAllValues:, Null, negated, Like, …
		}
		inner, err := strictjson.AsObject(raw)
		if err != nil || len(inner) == 0 {
			return nil, ErrCondition
		}
		for key, v := range inner {
			vals, ok := stringOrArray(v)
			if !ok {
				return nil, ErrCondition
			}
			if err := allowedEntry(op, key, vals); err != nil {
				return nil, err
			}
			out = append(out, cond{op: op, key: key, values: vals})
		}
	}
	return out, nil
}

// windowValue reads the deletion window's condition value: one JSON
// string or number in canonical decimal (no array, sign, fraction,
// exponent or leading zero).
func windowValue(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	s := string(raw)
	if raw[0] == '"' {
		if json.Unmarshal(raw, &s) != nil {
			return "", false
		}
	}
	if s == "" || len(s) > 3 || s[0] == '0' {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return "", false
		}
	}
	return s, true
}

func allowedEntry(op, key string, vals []string) error {
	str := op == "StringEquals" || op == "StringEqualsIgnoreCase"
	switch {
	case key == keyImage || key == keyPCR0:
		if !str {
			return ErrCondition
		}
		for _, v := range vals {
			if !isHex(v, 96, false) {
				return ErrCondition
			}
		}
	case strings.HasPrefix(key, keyPCRPfx):
		n := key[len(keyPCRPfx):]
		if !str || len(n) != 1 || n[0] < '1' || n[0] > '8' {
			return ErrCondition
		}
		for _, v := range vals {
			if !isHex(v, 96, false) {
				return ErrCondition
			}
		}
	case strings.HasPrefix(key, keyECPfx):
		if !str || len(key) == len(keyECPfx) {
			return ErrCondition
		}
	case key == keyCaller:
		if op != "StringEquals" {
			return ErrCondition
		}
		for _, v := range vals {
			if !validAccount(v) {
				return ErrCondition
			}
		}
	case key == keyPrinARN:
		if op != "ArnEquals" {
			return ErrCondition
		}
		for _, v := range vals {
			if _, ok := iamARNAccount(v); !ok {
				return ErrCondition
			}
		}
	default:
		return ErrCondition
	}
	return nil
}

// iamARNAccount parses arn:aws:iam::<account>:root or
// arn:aws:iam::<account>:role/<path/name> and returns the account.
func iamARNAccount(s string) (string, bool) {
	const pfx = "arn:aws:iam::"
	if !strings.HasPrefix(s, pfx) || len(s) < len(pfx)+13 {
		return "", false
	}
	acct, rest := s[len(pfx):len(pfx)+12], s[len(pfx)+12:]
	if !validAccount(acct) || rest == "" || rest[0] != ':' {
		return "", false
	}
	rest = rest[1:]
	if rest == "root" {
		return acct, true
	}
	if !strings.HasPrefix(rest, "role/") {
		return "", false
	}
	name := rest[len("role/"):]
	if name == "" || len(name) > 512 || strings.HasSuffix(name, "/") || strings.HasPrefix(name, "/") || strings.Contains(name, "//") {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("+=,.@_-/", c) >= 0) {
			return "", false
		}
	}
	return acct, true
}

func checkAllow(s statement, in Input, target *manifest.Release) error {
	// 7. Conditions: operators and keys from the allow-list only.
	conds, err := parseConditions(s.condition)
	if err != nil {
		return err
	}
	// 6. Actions: explicit names from the list; Decrypt and
	// GenerateDataKey only under an attestation condition naming the
	// admitted releases; the retirement actions only with a pinned
	// retirement principal and only among themselves.
	gated := map[string]bool{}
	retire := map[string]bool{}
	readOnlyN := 0
	for _, a := range s.actions {
		if strings.ContainsAny(a, "*?") {
			return ErrActions
		}
		switch {
		case a == actDecrypt || a == actGDK:
			gated[a] = true
		case readOnly[a]:
			readOnlyN++
		case retirement[a] && in.RetirementPrincipal != "":
			retire[a] = true
		default:
			return ErrActions
		}
	}
	if len(retire) > 0 && (len(gated) > 0 || readOnlyN > 0) {
		return ErrActions // a retirement statement holds retirement actions only
	}
	for a := range gated {
		admitted := admittedFor(a, in, target)
		if err := checkAttestation(conds, admitted); err != nil {
			return err
		}
	}
	// 7. The deletion window: NumericEquals only in the statement that
	// allows ScheduleKeyDeletion, and required there, with the pinned
	// value.
	window := ""
	for _, c := range conds {
		if c.op == opNumEq {
			window = c.values[0]
		}
	}
	if window != "" && !retire[actSchedule] {
		return ErrCondition
	}
	if retire[actSchedule] && window != strconv.Itoa(in.RetirementWindowDays) {
		return ErrCondition
	}
	// 8. Principals in the pinned account; exactly the retirement
	// principal on a retirement statement and never on a gated one;
	// CallerAccount on the gated and retirement statements.
	if err := checkPrincipal(s.principal, in.Account); err != nil {
		return err
	}
	if len(retire) > 0 && !exactPrincipal(s.principal, in.RetirementPrincipal) {
		return ErrPrincipal
	}
	if len(gated) > 0 && in.RetirementPrincipal != "" && namesPrincipal(s.principal, in.RetirementPrincipal) {
		return ErrPrincipal
	}
	callerOK := false
	for _, c := range conds {
		switch c.key {
		case keyCaller:
			for _, v := range c.values {
				if v != in.Account {
					return ErrPrincipal
				}
			}
			callerOK = true
		case keyPrinARN:
			for _, v := range c.values {
				if a, _ := iamARNAccount(v); a != in.Account {
					return ErrPrincipal
				}
			}
		}
	}
	if (len(gated) > 0 || len(retire) > 0) && !callerOK {
		return ErrPrincipal
	}
	return nil
}

// exactPrincipal reports whether raw is exactly {"AWS": "<arn>"}: one
// string, not an array.
func exactPrincipal(raw json.RawMessage, arn string) bool {
	o, err := strictjson.AsObject(raw)
	if err != nil || len(o) != 1 {
		return false
	}
	v, ok := o["AWS"]
	if !ok || len(v) == 0 || v[0] != '"' {
		return false
	}
	var s string
	return json.Unmarshal(v, &s) == nil && s == arn
}

// namesPrincipal reports whether a (checked) principal lists arn.
func namesPrincipal(raw json.RawMessage, arn string) bool {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return false
	}
	arns, _ := stringOrArray(o["AWS"])
	for _, a := range arns {
		if a == arn {
			return true
		}
	}
	return false
}

// admittedFor returns the releases whose PCRs an action's attestation
// condition may name: Decrypt only the target; GenerateDataKey the target
// and the manifest releases numbered below it.
func admittedFor(action string, in Input, target *manifest.Release) []manifest.Release {
	if action == actDecrypt {
		return []manifest.Release{*target}
	}
	var out []manifest.Release
	for _, r := range in.Manifest.Releases {
		if r.Number <= target.Number {
			out = append(out, r)
		}
	}
	return out
}

func checkAttestation(conds []cond, admitted []manifest.Release) error {
	found := false
	for _, c := range conds {
		var field func(manifest.Release) string
		switch {
		case c.key == keyImage || c.key == keyPCR0:
			field = func(r manifest.Release) string { return r.PCR0 }
			found = true
		case c.key == keyPCRPfx+"1":
			field = func(r manifest.Release) string { return r.PCR1 }
		case c.key == keyPCRPfx+"2":
			field = func(r manifest.Release) string { return r.PCR2 }
		default:
			continue
		}
		for _, v := range c.values {
			lv := strings.ToLower(v)
			ok := false
			for _, r := range admitted {
				if lv == field(r) {
					ok = true
				}
			}
			if !ok {
				return ErrActions
			}
		}
	}
	if !found {
		return ErrActions // Decrypt or GenerateDataKey without an attestation condition
	}
	return nil
}

func checkPrincipal(raw json.RawMessage, account string) error {
	if len(raw) == 0 || raw[0] != '{' {
		return ErrPrincipal // "*" and anything that is not {"AWS": ...}
	}
	o, err := strictjson.AsObject(raw)
	if err != nil || len(o) != 1 {
		return ErrPrincipal
	}
	arns, ok := stringOrArray(o["AWS"])
	if !ok {
		return ErrPrincipal
	}
	for _, a := range arns {
		acct, ok := iamARNAccount(a)
		if !ok || acct != account {
			return ErrPrincipal
		}
	}
	return nil
}
