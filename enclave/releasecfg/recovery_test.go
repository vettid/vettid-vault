package releasecfg

import (
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
	short := staging(strings.Replace(complete(t), `"recovery_quiet_seconds":259200`, `"recovery_quiet_seconds":600`, 1))
	if _, err := Parse([]byte(short)); err == nil {
		t.Error("staging quiet period shortened")
	}
	if _, err := Parse([]byte(staging(strings.Replace(complete(t), `"recovery_wait_unit_seconds":86400`, `"recovery_wait_unit_seconds":59`, 1)))); err == nil {
		t.Error("staging wait unit below a minute")
	}
}
