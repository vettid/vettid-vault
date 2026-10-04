package keypolicy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/manifest"
)

const (
	acct   = "111122223333"
	region = "us-east-1"
	arn4   = "arn:aws:kms:us-east-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
	arn3   = "arn:aws:kms:us-east-1:111122223333:key/0000abcd-12ab-34cd-56ef-1234567890ab"
	arn5   = "arn:aws:kms:us-east-1:111122223333:key/5555abcd-12ab-34cd-56ef-1234567890ab"
	host   = "arn:aws:iam::111122223333:role/vettid-enclave-host"
	retire = "arn:aws:iam::111122223333:role/vettid-org-vault-key-retirement"
	window = 30
)

var (
	pcr0r3 = strings.Repeat("ab", 48)
	pcr0r4 = strings.Repeat("cd", 48)
	pcr0r5 = strings.Repeat("ef", 48)
)

func testManifest(t testing.TB) *manifest.Manifest {
	at := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	b := manifest.Build(7, at, []manifest.Release{
		{Number: 3, PCR0: pcr0r3, PCR1: strings.Repeat("11", 48), PCR2: strings.Repeat("22", 48), SealKey: arn3, Status: "deprecated", PublishedAt: at, Notes: "https://vettid.org/releases/3"},
		{Number: 4, PCR0: pcr0r4, PCR1: strings.Repeat("33", 48), PCR2: strings.Repeat("44", 48), SealKey: arn4, Status: "active", PublishedAt: at, Notes: "https://vettid.org/releases/4"},
		{Number: 5, PCR0: pcr0r5, PCR1: strings.Repeat("55", 48), PCR2: strings.Repeat("66", 48), SealKey: arn5, Status: "active", PublishedAt: at, Notes: "https://vettid.org/releases/5"},
	})
	m, err := manifest.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// The §11.10.7 example policy (0.10.0, with real PCR0 values
// substituted): the attestation statements, the read-only statement for
// the host and retirement roles, and the two retirement statements.
func examplePolicy() string {
	return `{
  "Version": "2012-10-17",
  "Id": "vettid-release-4",
  "Statement": [
    { "Sid": "UnsealOnlyInRelease4", "Effect": "Allow",
      "Principal": {"AWS": "` + host + `"},
      "Action": "kms:Decrypt", "Resource": "*",
      "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "` + pcr0r4 + `"},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFromAdmittedReleases", "Effect": "Allow",
      "Principal": {"AWS": "` + host + `"},
      "Action": "kms:GenerateDataKey", "Resource": "*",
      "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": ["` + pcr0r3 + `", "` + pcr0r4 + `"]},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "EnclaveVerifiesThisPolicy", "Effect": "Allow",
      "Principal": {"AWS": ["` + host + `", "` + retire + `"]},
      "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"], "Resource": "*" },
    { "Sid": "RetireAfterNotice", "Effect": "Allow",
      "Principal": {"AWS": "` + retire + `"},
      "Action": "kms:ScheduleKeyDeletion", "Resource": "*",
      "Condition": {"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "RescueBeforeDeletion", "Effect": "Allow",
      "Principal": {"AWS": "` + retire + `"},
      "Action": ["kms:CancelKeyDeletion", "kms:EnableKey"], "Resource": "*",
      "Condition": {"StringEquals": {"kms:CallerAccount": "111122223333"}} }
  ]
}`
}

// The read-only statement's principal and first action, for variants.
const roStmt = `"Principal": {"AWS": ["` + host + `", "` + retire + `"]},
      "Action": ["kms:DescribeKey"`

// The retirement statements, for variants.
const (
	schedStmt = `"Principal": {"AWS": "` + retire + `"},
      "Action": "kms:ScheduleKeyDeletion"`
	windowCond = `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"},`
	rescueStmt = `"Principal": {"AWS": "` + retire + `"},
      "Action": ["kms:CancelKeyDeletion", "kms:EnableKey"]`
	rescueCond = `"Action": ["kms:CancelKeyDeletion", "kms:EnableKey"], "Resource": "*",
      "Condition": {"StringEquals": {"kms:CallerAccount": "111122223333"}} }`
	decryptPrin = `"Principal": {"AWS": "` + host + `"},
      "Action": "kms:Decrypt"`
)

func describe(arn string) string {
	return `{"KeyMetadata":{"AWSAccountId":"111122223333","Arn":"` + arn + `","CreationDate":1.7593344E9,` +
		`"CustomerMasterKeySpec":"SYMMETRIC_DEFAULT","Description":"vettid release 4","Enabled":true,` +
		`"EncryptionAlgorithms":["SYMMETRIC_DEFAULT"],"KeyId":"1234abcd-12ab-34cd-56ef-1234567890ab",` +
		`"KeyManager":"CUSTOMER","KeySpec":"SYMMETRIC_DEFAULT","KeyState":"Enabled","KeyUsage":"ENCRYPT_DECRYPT",` +
		`"MultiRegion":false,"Origin":"AWS_KMS"}}`
}

func policyResp(doc string) string {
	return `{"Policy":` + string(strictjson.MarshalString(doc)) + `,"PolicyName":"default"}`
}

const noGrants = `{"Grants":[],"Truncated":false}`

func input(t testing.TB, policy, desc, grants string) Input {
	return Input{KeyARN: arn4, Account: acct, Region: region, Manifest: testManifest(t), Target: 4,
		RetirementPrincipal: retire, RetirementWindowDays: window,
		DescribeKey: []byte(desc), GetKeyPolicy: []byte(policyResp(policy)), ListGrants: []byte(grants)}
}

func TestExamplePasses(t *testing.T) {
	r, err := Check(input(t, examplePolicy(), describe(arn4), noGrants))
	if err != nil {
		t.Fatal(err)
	}
	if r.KeyARN != arn4 || r.PolicySHA256 != sha256.Sum256([]byte(examplePolicy())) {
		t.Fatal("result")
	}
	// Statement as a single object, an extra read-only action, a narrowing
	// PCR1 and encryption-context condition, an aws:PrincipalArn condition
	// and a Deny statement (ignored) all still pass.
	single := `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":{"AWS":["` + host + `","arn:aws:iam::111122223333:root"]},
	  "Action":["kms:Decrypt","kms:GetKeyRotationStatus"],"Resource":"` + arn4 + `",
	  "Condition":{"StringEquals":{"kms:RecipientAttestation:PCR0":"` + strings.ToUpper(pcr0r4) + `","kms:CallerAccount":"111122223333",
	    "kms:RecipientAttestation:PCR1":"` + strings.Repeat("33", 48) + `","kms:EncryptionContext:vault":"v1"},
	    "ArnEquals":{"aws:PrincipalArn":"` + host + `"}}}}`
	if _, err := Check(input(t, single, describe(arn4), noGrants)); err != nil {
		t.Fatal(err)
	}
	deny := strings.Replace(examplePolicy(), `"Statement": [`, `"Statement": [{"Effect":"Deny","Principal":"*","Action":"kms:*","Resource":"*"},`, 1)
	if _, err := Check(input(t, deny, describe(arn4), noGrants)); err != nil {
		t.Fatalf("deny: %v", err)
	}
}

func repl(old, new string) func(string) string {
	return func(s string) string {
		if !strings.Contains(s, old) {
			panic("variant does not apply: " + old)
		}
		return strings.Replace(s, old, new, 1)
	}
}

func addStatement(st string) func(string) string {
	return repl(`"Statement": [`, `"Statement": [`+st+`,`)
}

const decryptCond = `"Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "`

// Every "MUST fail" variant of §11.10.7, each with its failing check.
func TestMustFailVariants(t *testing.T) {
	decryptStmt := `"Action": "kms:Decrypt"`
	for _, tc := range []struct {
		name   string
		policy func(string) string
		desc   func(string) string
		grants string
		want   error
	}{
		{name: "default kms:* root statement", policy: addStatement(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:*","Resource":"*"}`), want: ErrActions},
		{name: "PutKeyPolicy in an Allow", policy: repl(`"kms:ListGrants"]`, `"kms:ListGrants","kms:PutKeyPolicy"]`), want: ErrActions},
		{name: "CreateGrant in an Allow", policy: repl(`"kms:ListGrants"]`, `"kms:ListGrants","kms:CreateGrant"]`), want: ErrActions},
		{name: "IfExists on Decrypt", policy: repl(`"Condition": {"StringEqualsIgnoreCase"`, `"Condition": {"StringEqualsIgnoreCaseIfExists"`), want: ErrCondition},
		{name: "Decrypt lists pcr0-3 too", policy: repl(decryptCond+pcr0r4+`"`, `"Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": ["`+pcr0r4+`", "`+pcr0r3+`"]`), want: ErrActions},
		{name: "Decrypt without Condition", policy: repl(`"Action": "kms:Decrypt", "Resource": "*",
      "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "`+pcr0r4+`"},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },`, `"Action": "kms:Decrypt", "Resource": "*" },`), want: ErrActions},
		{name: "Decrypt + ReEncryptFrom", policy: repl(decryptStmt, `"Action": ["kms:Decrypt", "kms:ReEncryptFrom"]`), want: ErrActions},
		{name: "Encrypt", policy: repl(decryptStmt, `"Action": "kms:Encrypt"`), want: ErrActions},
		{name: "NotAction with Allow", policy: repl(`"Action": ["kms:DescribeKey"`, `"NotAction": "kms:PutKeyPolicy", "Action": ["kms:DescribeKey"`), want: ErrShape},
		{name: "StringLike * on ImageSha384", policy: repl(decryptCond+pcr0r4+`"},`, `"Condition": {"StringLike": {"kms:RecipientAttestation:ImageSha384": "*"},`), want: ErrCondition},
		{name: "GenerateDataKey value above target", policy: repl(`"`+pcr0r3+`", "`+pcr0r4+`"]`, `"`+pcr0r3+`", "`+pcr0r4+`", "`+pcr0r5+`"]`), want: ErrActions},
		{name: "GenerateDataKey value not in manifest", policy: repl(`"`+pcr0r3+`", "`+pcr0r4+`"]`, `"`+strings.Repeat("99", 48)+`", "`+pcr0r4+`"]`), want: ErrActions},
		{name: "member Condition2", policy: repl(`"Action": "kms:GenerateDataKey",`, `"Action": "kms:GenerateDataKey", "Condition2": {},`), want: ErrShape},
		{name: "duplicated Action", policy: repl(`"Action": "kms:GenerateDataKey",`, `"Action": "kms:GenerateDataKey", "Action": "kms:Decrypt",`), want: ErrShape},
		{name: "Principal * on Decrypt", policy: repl(`"Principal": {"AWS": "`+host+`"},
      "Action": "kms:Decrypt"`, `"Principal": "*",
      "Action": "kms:Decrypt"`), want: ErrPrincipal},
		{name: "Principal AWS * on Decrypt", policy: repl(`"Principal": {"AWS": "`+host+`"},
      "Action": "kms:Decrypt"`, `"Principal": {"AWS": "*"},
      "Action": "kms:Decrypt"`), want: ErrPrincipal},
		{name: "other account on GenerateDataKey", policy: repl(`"Principal": {"AWS": "`+host+`"},
      "Action": "kms:GenerateDataKey"`, `"Principal": {"AWS": "arn:aws:iam::444455556666:role/x"},
      "Action": "kms:GenerateDataKey"`), want: ErrPrincipal},
		{name: "Service principal", policy: repl(roStmt, `"Principal": {"Service": "ec2.amazonaws.com"},
      "Action": ["kms:DescribeKey"`), want: ErrPrincipal},
		{name: "Principal * on read-only", policy: repl(roStmt, `"Principal": "*",
      "Action": ["kms:DescribeKey"`), want: ErrPrincipal},
		{name: "Decrypt without CallerAccount", policy: repl(pcr0r4+`"},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFrom`, pcr0r4+`"}} },
    { "Sid": "SealFrom`), want: ErrPrincipal},
		{name: "Decrypt with another CallerAccount", policy: repl(`"StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFrom`, `"StringEquals": {"kms:CallerAccount": "444455556666"}} },
    { "Sid": "SealFrom`), want: ErrPrincipal},
		{name: "one grant", grants: `{"Grants":[{"GrantId":"x"}],"Truncated":false}`, want: ErrGrants},
		{name: "Origin EXTERNAL", desc: repl(`"Origin":"AWS_KMS"`, `"Origin":"EXTERNAL"`), want: ErrMetadata},
		{name: "MultiRegion true", desc: repl(`"MultiRegion":false`, `"MultiRegion":true`), want: ErrMetadata},
	} {
		pol, desc, grants := examplePolicy(), describe(arn4), noGrants
		if tc.policy != nil {
			pol = tc.policy(pol)
		}
		if tc.desc != nil {
			desc = tc.desc(desc)
		}
		if tc.grants != "" {
			grants = tc.grants
		}
		_, err := Check(input(t, pol, desc, grants))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// Further refusals beyond the spec's table.
func TestMoreRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy func(string) string
		desc   func(string) string
		grants string
		in     func(*Input)
		want   error
	}{
		{name: "key arn not the manifest's", in: func(i *Input) { i.KeyARN = arn3 }, want: ErrIdentity},
		{name: "other region pinned", in: func(i *Input) { i.Region = "eu-west-1" }, want: ErrIdentity},
		{name: "other account pinned", in: func(i *Input) { i.Account = "444455556666" }, want: ErrIdentity},
		{name: "target not in manifest", in: func(i *Input) { i.Target = 9 }, want: ErrIdentity},
		{name: "Arn differs", desc: repl(`"Arn":"`+arn4, `"Arn":"`+arn3), want: ErrMetadata},
		{name: "disabled", desc: repl(`"KeyState":"Enabled"`, `"KeyState":"Disabled"`), want: ErrMetadata},
		{name: "pending deletion", desc: repl(`"KeyState":"Enabled"`, `"KeyState":"PendingDeletion"`), want: ErrMetadata},
		{name: "custom key store", desc: repl(`"Origin":"AWS_KMS"`, `"Origin":"AWS_KMS","CustomKeyStoreId":"cks-1"`), want: ErrMetadata},
		{name: "asymmetric", desc: repl(`"KeySpec":"SYMMETRIC_DEFAULT"`, `"KeySpec":"RSA_2048"`), want: ErrMetadata},
		{name: "AWS managed", desc: repl(`"KeyManager":"CUSTOMER"`, `"KeyManager":"AWS"`), want: ErrMetadata},
		{name: "MultiRegion missing", desc: repl(`"MultiRegion":false,`, ``), want: ErrMetadata},
		{name: "MultiRegion string", desc: repl(`"MultiRegion":false`, `"MultiRegion":"false"`), want: ErrMetadata},
		{name: "truncated grants", grants: `{"Grants":[],"Truncated":true,"NextMarker":"x"}`, want: ErrGrants},
		{name: "marker without truncation", grants: `{"Grants":[],"Truncated":false,"NextMarker":"x"}`, want: ErrGrants},
		{name: "grants missing", grants: `{"Truncated":false}`, want: ErrGrants},
		{name: "Version 2008", policy: repl(`"2012-10-17"`, `"2008-10-17"`), want: ErrShape},
		{name: "top-level extra", policy: repl(`"Id":`, `"Extra": 1, "Id":`), want: ErrShape},
		{name: "Resource another key", policy: repl(`"Action": "kms:Decrypt", "Resource": "*"`, `"Action": "kms:Decrypt", "Resource": "`+arn3+`"`), want: ErrShape},
		{name: "NotPrincipal in Deny", policy: addStatement(`{"Effect":"Deny","NotPrincipal":{"AWS":"` + host + `"},"Action":"kms:*","Resource":"*"}`), want: ErrShape},
		{name: "lowercase action", policy: repl(`"Action": "kms:Decrypt"`, `"Action": "kms:decrypt"`), want: ErrActions},
		{name: "question mark", policy: repl(`"kms:ListGrants"]`, `"kms:ListGrant?"]`), want: ErrActions},
		{name: "GenerateDataKeyWithoutPlaintext", policy: repl(`"Action": "kms:GenerateDataKey"`, `"Action": "kms:GenerateDataKeyWithoutPlaintext"`), want: ErrActions},
		{name: "ForAnyValue", policy: repl(`"Condition": {"StringEqualsIgnoreCase"`, `"Condition": {"ForAnyValue:StringEqualsIgnoreCase"`), want: ErrCondition},
		{name: "Null operator", policy: repl(`"StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFrom`, `"StringEquals": {"kms:CallerAccount": "111122223333"}, "Null": {"kms:RecipientAttestation:ImageSha384": "false"}} },
    { "Sid": "SealFrom`), want: ErrCondition},
		{name: "unknown condition key", policy: repl(`"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFrom`, `"kms:CallerAccount": "111122223333", "aws:SourceIp": "10.0.0.1"}} },
    { "Sid": "SealFrom`), want: ErrCondition},
		{name: "case-variant condition key", policy: repl(`"kms:RecipientAttestation:ImageSha384": "`+pcr0r4, `"kms:recipientattestation:imagesha384": "`+pcr0r4), want: ErrCondition},
		{name: "CallerAccount IgnoreCase", policy: repl(`"Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "`+pcr0r4+`"},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },`, `"Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "`+pcr0r4+`", "kms:CallerAccount": "111122223333"}} },`), want: ErrCondition},
		{name: "PCR1 of another release on Decrypt", policy: repl(`"StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFrom`, `"StringEquals": {"kms:CallerAccount": "111122223333", "kms:RecipientAttestation:PCR1": "`+strings.Repeat("11", 48)+`"}} },
    { "Sid": "SealFrom`), want: ErrActions},
		{name: "PCR9", policy: repl(`"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFrom`, `"kms:CallerAccount": "111122223333", "kms:RecipientAttestation:PCR9": "`+pcr0r4+`"}} },
    { "Sid": "SealFrom`), want: ErrCondition},
		{name: "attestation value not hex", policy: repl(`"kms:RecipientAttestation:ImageSha384": "`+pcr0r4+`"`, `"kms:RecipientAttestation:ImageSha384": "`+pcr0r4[:94]+`zz"`), want: ErrCondition},
		{name: "account id principal", policy: repl(roStmt, `"Principal": {"AWS": "111122223333"},
      "Action": ["kms:DescribeKey"`), want: ErrPrincipal},
		{name: "user principal", policy: repl(roStmt, `"Principal": {"AWS": "arn:aws:iam::111122223333:user/alice"},
      "Action": ["kms:DescribeKey"`), want: ErrPrincipal},
		{name: "two principal kinds", policy: repl(roStmt, `"Principal": {"AWS": "`+host+`", "Service": "kms.amazonaws.com"},
      "Action": ["kms:DescribeKey"`), want: ErrPrincipal},
		{name: "foreign PrincipalArn condition", policy: repl(`"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFrom`, `"kms:CallerAccount": "111122223333"}, "ArnEquals": {"aws:PrincipalArn": "arn:aws:iam::444455556666:role/x"}} },
    { "Sid": "SealFrom`), want: ErrPrincipal},
		{name: "PolicyName other", in: func(i *Input) {
			i.GetKeyPolicy = []byte(strings.Replace(string(i.GetKeyPolicy), `"default"`, `"other"`, 1))
		}, want: ErrShape},
		{name: "duplicate member in DescribeKey", desc: repl(`"KeyState":"Enabled"`, `"KeyState":"Enabled","KeyState":"Enabled"`), want: ErrMetadata},
	} {
		pol, desc, grants := examplePolicy(), describe(arn4), noGrants
		if tc.policy != nil {
			pol = tc.policy(pol)
		}
		if tc.desc != nil {
			desc = tc.desc(desc)
		}
		if tc.grants != "" {
			grants = tc.grants
		}
		in := input(t, pol, desc, grants)
		if tc.in != nil {
			tc.in(&in)
		}
		_, err := Check(in)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// The retirement delta (0.10.0, VAULT-RELEASES §4.1): every must-fail
// variant of the spec's table plus further refusals, each with its check.
func TestRetirementMustFailVariants(t *testing.T) {
	for _, tc := range []struct {
		name   string
		policy func(string) string
		want   error
	}{
		{name: "ScheduleKeyDeletion without the window condition", policy: repl(windowCond, `{`), want: ErrCondition},
		{name: "NumericGreaterThanOrEquals window", policy: repl(windowCond, `{"NumericGreaterThanOrEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"},`), want: ErrCondition},
		{name: "NumericLessThanEquals window", policy: repl(windowCond, `{"NumericLessThanEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"},`), want: ErrCondition},
		{name: "NumericEqualsIfExists window", policy: repl(windowCond, `{"NumericEqualsIfExists": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"},`), want: ErrCondition},
		{name: "window 7 instead of 30", policy: repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "7"},`), want: ErrCondition},
		{name: "window as an array", policy: repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": ["30"]},`), want: ErrCondition},
		{name: "window with two values", policy: repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": ["30", "7"]},`), want: ErrCondition},
		{name: "window 030", policy: repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "030"},`), want: ErrCondition},
		{name: "window 30.0", policy: repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": 30.0},`), want: ErrCondition},
		{name: "window under StringEquals", policy: repl(windowCond+`
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} }`, `{"StringEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30", "kms:CallerAccount": "111122223333"}} }`), want: ErrCondition},
		{name: "NumericEquals on another key", policy: repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30", "kms:GrantIsForAWSResource": "1"},`), want: ErrCondition},
		{name: "ScheduleKeyDeletion for the host role", policy: repl(schedStmt, `"Principal": {"AWS": "`+host+`"},
      "Action": "kms:ScheduleKeyDeletion"`), want: ErrPrincipal},
		{name: "ScheduleKeyDeletion for the account root", policy: repl(schedStmt, `"Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "kms:ScheduleKeyDeletion"`), want: ErrPrincipal},
		{name: "ScheduleKeyDeletion for a second ARN", policy: repl(schedStmt, `"Principal": {"AWS": ["`+retire+`", "`+host+`"]},
      "Action": "kms:ScheduleKeyDeletion"`), want: ErrPrincipal},
		{name: "ScheduleKeyDeletion principal as a one-element array", policy: repl(schedStmt, `"Principal": {"AWS": ["`+retire+`"]},
      "Action": "kms:ScheduleKeyDeletion"`), want: ErrPrincipal},
		{name: "CancelKeyDeletion for the host role", policy: repl(rescueStmt, `"Principal": {"AWS": "`+host+`"},
      "Action": ["kms:CancelKeyDeletion", "kms:EnableKey"]`), want: ErrPrincipal},
		{name: "CancelKeyDeletion for the account root", policy: repl(rescueStmt, `"Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": ["kms:CancelKeyDeletion", "kms:EnableKey"]`), want: ErrPrincipal},
		{name: "CancelKeyDeletion for a second ARN", policy: repl(rescueStmt, `"Principal": {"AWS": ["`+retire+`", "`+host+`"]},
      "Action": ["kms:CancelKeyDeletion", "kms:EnableKey"]`), want: ErrPrincipal},
		{name: "retirement statement for another role", policy: repl(rescueStmt, `"Principal": {"AWS": "arn:aws:iam::111122223333:role/someone-else"},
      "Action": ["kms:CancelKeyDeletion", "kms:EnableKey"]`), want: ErrPrincipal},
		{name: "retirement statement for another account's role", policy: repl(schedStmt, `"Principal": {"AWS": "arn:aws:iam::444455556666:role/vettid-org-vault-key-retirement"},
      "Action": "kms:ScheduleKeyDeletion"`), want: ErrPrincipal},
		{name: "DisableKey for the retirement principal", policy: repl(`"kms:CancelKeyDeletion", "kms:EnableKey"], "Resource"`, `"kms:CancelKeyDeletion", "kms:EnableKey", "kms:DisableKey"], "Resource"`), want: ErrActions},
		{name: "PutKeyPolicy for the retirement principal", policy: repl(`"kms:CancelKeyDeletion", "kms:EnableKey"], "Resource"`, `"kms:CancelKeyDeletion", "kms:PutKeyPolicy"], "Resource"`), want: ErrActions},
		{name: "EnableKey in the Decrypt statement", policy: repl(`"Action": "kms:Decrypt"`, `"Action": ["kms:Decrypt", "kms:EnableKey"]`), want: ErrActions},
		{name: "ScheduleKeyDeletion in the GenerateDataKey statement", policy: repl(`"Action": "kms:GenerateDataKey"`, `"Action": ["kms:GenerateDataKey", "kms:ScheduleKeyDeletion"]`), want: ErrActions},
		{name: "retirement statement with DescribeKey", policy: repl(`"kms:CancelKeyDeletion", "kms:EnableKey"], "Resource"`, `"kms:CancelKeyDeletion", "kms:EnableKey", "kms:DescribeKey"], "Resource"`), want: ErrActions},
		{name: "NumericEquals in the Decrypt statement", policy: repl(`"Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "`+pcr0r4+`"},`, `"Condition": {"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"}, "StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "`+pcr0r4+`"},`), want: ErrCondition},
		{name: "NumericEquals in the rescue statement", policy: repl(rescueCond, `"Action": ["kms:CancelKeyDeletion", "kms:EnableKey"], "Resource": "*",
      "Condition": {"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"}, "StringEquals": {"kms:CallerAccount": "111122223333"}} }`), want: ErrCondition},
		{name: "rescue statement without CallerAccount", policy: repl(rescueCond, `"Action": ["kms:CancelKeyDeletion", "kms:EnableKey"], "Resource": "*" }`), want: ErrPrincipal},
		{name: "schedule statement without CallerAccount", policy: repl(windowCond+`
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} }`, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "30"}} }`), want: ErrPrincipal},
		{name: "retirement statement with another CallerAccount", policy: repl(rescueCond, `"Action": ["kms:CancelKeyDeletion", "kms:EnableKey"], "Resource": "*",
      "Condition": {"StringEquals": {"kms:CallerAccount": "444455556666"}} }`), want: ErrPrincipal},
		{name: "retirement principal on the Decrypt statement", policy: repl(decryptPrin, `"Principal": {"AWS": ["`+host+`", "`+retire+`"]},
      "Action": "kms:Decrypt"`), want: ErrPrincipal},
		{name: "retirement principal alone on GenerateDataKey", policy: repl(`"Principal": {"AWS": "`+host+`"},
      "Action": "kms:GenerateDataKey"`, `"Principal": {"AWS": "`+retire+`"},
      "Action": "kms:GenerateDataKey"`), want: ErrPrincipal},
		{name: "ScheduleKeyDeletion wildcard", policy: repl(`"Action": "kms:ScheduleKeyDeletion"`, `"Action": "kms:Schedule*"`), want: ErrActions},
		{name: "case variant of ScheduleKeyDeletion", policy: repl(`"Action": "kms:ScheduleKeyDeletion"`, `"Action": "kms:scheduleKeyDeletion"`), want: ErrActions},
	} {
		_, err := Check(input(t, tc.policy(examplePolicy()), describe(arn4), noGrants))
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}

// What still passes under the delta, and how the pinned constants act.
func TestRetirementPinned(t *testing.T) {
	// The window as a JSON number; the two retirement statements merged;
	// the retirement role absent from the read-only statement; a policy
	// without retirement statements at all.
	for name, f := range map[string]func(string) string{
		"window as a number": repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": 30},`),
		"no retirement role among readers": repl(roStmt, `"Principal": {"AWS": "`+host+`"},
      "Action": ["kms:DescribeKey"`),
		"no retirement statements": func(p string) string {
			return p[:strings.Index(p, `,
    { "Sid": "RetireAfterNotice"`)] + "\n  ]\n}"
		},
	} {
		pol := f(examplePolicy())
		if _, err := Check(input(t, pol, describe(arn4), noGrants)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Staging: window 7 pinned, 7 in the policy.
	in := input(t, repl(windowCond, `{"NumericEquals": {"kms:ScheduleKeyDeletionPendingWindowInDays": "7"},`)(examplePolicy()), describe(arn4), noGrants)
	in.RetirementWindowDays = 7
	if _, err := Check(in); err != nil {
		t.Errorf("staging window: %v", err)
	}
	// Without a pinned retirement principal the retirement actions
	// disqualify the key (as before 0.10.0).
	in = input(t, examplePolicy(), describe(arn4), noGrants)
	in.RetirementPrincipal, in.RetirementWindowDays = "", 0
	if _, err := Check(in); !errors.Is(err, ErrActions) {
		t.Errorf("unpinned: %v", err)
	}
	// Invalid pinned constants refuse every key.
	for name, f := range map[string]func(*Input){
		"root as retirement principal": func(i *Input) { i.RetirementPrincipal = "arn:aws:iam::111122223333:root" },
		"other account":                func(i *Input) { i.RetirementPrincipal = "arn:aws:iam::444455556666:role/r" },
		"user":                         func(i *Input) { i.RetirementPrincipal = "arn:aws:iam::111122223333:user/r" },
		"window 6":                     func(i *Input) { i.RetirementWindowDays = 6 },
		"window 31":                    func(i *Input) { i.RetirementWindowDays = 31 },
		"window without principal":     func(i *Input) { i.RetirementPrincipal = "" },
	} {
		in := input(t, examplePolicy(), describe(arn4), noGrants)
		f(&in)
		if _, err := Check(in); !errors.Is(err, ErrIdentity) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Check 2 is unchanged: a key pending deletion, or disabled after a
	// cancellation, is refused for new seals.
	for _, st := range []string{"PendingDeletion", "Disabled"} {
		if _, err := Check(input(t, examplePolicy(), repl(`"KeyState":"Enabled"`, `"KeyState":"`+st+`"`)(describe(arn4)), noGrants)); !errors.Is(err, ErrMetadata) {
			t.Errorf("%s: %v", st, err)
		}
	}
}

func TestWindowValue(t *testing.T) {
	for raw, want := range map[string]string{`"30"`: "30", `30`: "30", `"7"`: "7", `7`: "7"} {
		if v, ok := windowValue(json.RawMessage(raw)); !ok || v != want {
			t.Errorf("%s: %q %v", raw, v, ok)
		}
	}
	for _, raw := range []string{``, `""`, `"030"`, `030`, `30.0`, `3e1`, `-30`, `"+30"`, `["30"]`, `{}`, `true`, `"1000"`, `" 30"`, `null`} {
		if _, ok := windowValue(json.RawMessage(raw)); ok {
			t.Errorf("%s accepted", raw)
		}
	}
}

func TestIAMARN(t *testing.T) {
	for s, ok := range map[string]bool{
		"arn:aws:iam::111122223333:root":              true,
		"arn:aws:iam::111122223333:role/a":            true,
		"arn:aws:iam::111122223333:role/path/to/name": true,
		"arn:aws:iam::111122223333:role/":             false,
		"arn:aws:iam::111122223333:role//x":           false,
		"arn:aws:iam::111122223333:role/x*":           false,
		"arn:aws:iam::11112222333:root":               false,
		"arn:aws-cn:iam::111122223333:root":           false,
		"arn:aws:iam::111122223333:assumed-role/x/y":  false,
		"arn:aws:sts::111122223333:assumed-role/x/y":  false,
		"arn:aws:iam::111122223333:rootx":             false,
	} {
		if _, got := iamARNAccount(s); got != ok {
			t.Errorf("%s: %v", s, got)
		}
	}
}

func FuzzCheckPolicy(f *testing.F) {
	m := testManifest(f)
	f.Add([]byte(policyResp(examplePolicy())), []byte(describe(arn4)), []byte(noGrants))
	f.Fuzz(func(t *testing.T, pol, desc, grants []byte) {
		_, _ = Check(Input{KeyARN: arn4, Account: acct, Region: region, Manifest: m, Target: 4,
			RetirementPrincipal: retire, RetirementWindowDays: window,
			DescribeKey: desc, GetKeyPolicy: pol, ListGrants: grants})
	})
}

func FuzzPolicyDocument(f *testing.F) {
	m := testManifest(f)
	f.Add(examplePolicy())
	f.Add(strings.Replace(examplePolicy(), `"30"}`, `30}`, 1))
	f.Add(strings.Replace(examplePolicy(), `"vettid-release-4"`, "\"vettid-release-\xff\"", 1)) // invalid UTF-8 in Id
	f.Fuzz(func(t *testing.T, doc string) {
		r, err := Check(Input{KeyARN: arn4, Account: acct, Region: region, Manifest: m, Target: 4,
			RetirementPrincipal: retire, RetirementWindowDays: window,
			DescribeKey: []byte(describe(arn4)), GetKeyPolicy: []byte(policyResp(doc)), ListGrants: []byte(noGrants)})
		// The hash covers the policy string as KMS returned it: the JSON
		// encoding above replaces invalid UTF-8, so compare with the decoded
		// value.
		var got string
		_ = json.Unmarshal(strictjson.MarshalString(doc), &got)
		if err == nil && r.PolicySHA256 != sha256.Sum256([]byte(got)) {
			t.Fatal("hash")
		}
	})
}
