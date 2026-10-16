package releasecfg

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// Release R's members and the build rules of VAULT-MESSAGING 0.33.0
// §11.14.14 (VAULT-RELEASES 0.1.28 §5.2).
func TestRecoveryConstants(t *testing.T) {
	c, err := Check(ChannelProd, []byte(complete(t)))
	if err != nil {
		t.Fatal(err)
	}
	if c.RecoveryCounter.Host() != "vettid-org-vault-recovery-111122223333.s3.us-east-1.amazonaws.com" || len(c.RecoveryRequestKeys) != 1 ||
		c.RecoveryWaitUnitSeconds != 86400 || c.RecoveryQuietSeconds != 259200 || !c.RecoveryOffered || c.AndroidMinVersionCode != 100 {
		t.Fatalf("%+v", c)
	}
	stagingShort := staging(strings.Replace(complete(t), `"recovery_wait_unit_seconds":86400`, `"recovery_wait_unit_seconds":600`, 1))
	if c, err := Check(ChannelStaging, []byte(stagingShort)); err != nil || c.RecoveryWaitUnitSeconds != 600 {
		t.Fatalf("staging 600 s: %v", err)
	}
	refused := map[string]string{
		"production wait unit below a day": strings.Replace(complete(t), `"recovery_wait_unit_seconds":86400`, `"recovery_wait_unit_seconds":86399`, 1),
		"production quiet below 72 h":      strings.Replace(complete(t), `"recovery_quiet_seconds":259200`, `"recovery_quiet_seconds":259199`, 1),
		"another account's bucket":         strings.Replace(complete(t), `"bucket":"vettid-org-vault-recovery-111122223333"`, `"bucket":"vettid-org-vault-recovery-444455556666"`, 1),
		"another account":                  strings.Replace(complete(t), `"account":"111122223333"`, `"account":"444455556666"`, 1),
		"an unpinned bucket name":          strings.Replace(complete(t), `"bucket":"vettid-org-vault-recovery-111122223333"`, `"bucket":"other-bucket"`, 1),
		"three request keys":               strings.Replace(complete(t), `"recovery_request_keys":[`, `"recovery_request_keys":[{"key_id":"a","spki":"`+spki(t, 0x26)+`"},{"key_id":"b","spki":"`+spki(t, 0x27)+`"},`, 1),
		"a repeated key id":                strings.Replace(complete(t), `"recovery_request_keys":[`, `"recovery_request_keys":[{"key_id":"test-key-1","spki":"`+spki(t, 0x26)+`"},`, 1),
		"offered not a bool":               strings.Replace(complete(t), `"recovery_offered":true`, `"recovery_offered":"yes"`, 1),
	}
	for name, s := range refused {
		if _, err := Parse([]byte(s)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := Parse([]byte(strings.Replace(complete(t), `"recovery_quiet_seconds":259200`, `"recovery_quiet_seconds":345000`, 1))); err == nil {
		t.Error("a quiet period whose 10-minute window outlasts the present lock")
	}
	short := staging(strings.Replace(complete(t), `"recovery_quiet_seconds":259200`, `"recovery_quiet_seconds":600`, 1))
	if _, err := Parse([]byte(short)); err == nil {
		t.Error("staging quiet period shortened")
	}
	if _, err := Parse([]byte(staging(strings.Replace(complete(t), `"recovery_wait_unit_seconds":86400`, `"recovery_wait_unit_seconds":59`, 1)))); err == nil {
		t.Error("staging wait unit below a minute")
	}
}

// The committed staging file pins the member API's staging recovery
// request key (VAULT-MESSAGING 0.33.0 §11.14.8): key_id is the KMS key's
// id, spki its P-256 public key. With the first app version of release R
// (versionCode 101) as its minimum, the file passes the release gate and
// carries the key, the minimum and staging's counter.
func TestCommittedStagingRequestKey(t *testing.T) {
	const (
		keyID = "83d194b2-b474-429f-bed1-6eea4c80cede"
		spki  = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELvsvbSUL7saSkMbPRy0EIf+qcVA5eONHj0UM85ZsH46b6ImdgswcJm1WDNflDes+mDhJiInJmYCukCnxpB30fw=="
	)
	b, err := os.ReadFile("staging.json")
	if err != nil {
		t.Fatal(err)
	}
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Missing) != 0 {
		t.Fatalf("staging.json still open for %v", f.Missing)
	}
	check := func(c *Config) {
		t.Helper()
		if len(c.RecoveryRequestKeys) != 1 || c.RecoveryRequestKeys[0].KeyID != keyID {
			t.Fatalf("request keys %+v", c.RecoveryRequestKeys)
		}
		k := c.RecoveryRequestKeys[0].Key
		der, err := x509.MarshalPKIXPublicKey(k)
		if err != nil || k.Curve != elliptic.P256() || len(der) != 91 || base64.StdEncoding.EncodeToString(der) != spki {
			t.Fatalf("request key %v (%d bytes)", err, len(der))
		}
	}
	check(&f.Config)
	c, err := Check(ChannelStaging, b)
	if err != nil {
		t.Fatalf("staging.json: %v", err)
	}
	check(c)
	if c.AndroidMinVersionCode != 101 {
		t.Fatalf("staging minimum app version %d, want 101", c.AndroidMinVersionCode)
	}
	if c.RecoveryCounter.Account != "347272280361" || c.SealAccount != "347272280361" {
		t.Fatalf("staging counter %+v", c.RecoveryCounter)
	}
}
