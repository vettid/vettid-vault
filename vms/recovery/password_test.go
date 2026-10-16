package recovery

import (
	"encoding/json"
	"os"
	"testing"
)

func TestNormalizeNFC(t *testing.T) {
	decomposed := []byte("café au lait!")
	composed := []byte("café au lait!")
	n, ok := NormalizePassword(decomposed)
	if !ok || string(n) != string(composed) {
		t.Fatalf("NFC: %q", n)
	}
	if _, ok := NormalizePassword([]byte{0xff, 0xfe}); ok {
		t.Error("invalid UTF-8 accepted")
	}
	if _, ok := NormalizePassword(make([]byte, 1025)); ok {
		t.Error("1,025 bytes accepted")
	}
}

func TestCommonListForm(t *testing.T) {
	if !CommonListSorted() {
		t.Fatal("common-passwords.txt must be lower case, sorted, unique, 12+ characters")
	}
	if len(commonWords()) == 0 || len(CommonListSHA256()) != 64 {
		t.Fatal("empty list")
	}
}

// TestPasswordVerdicts runs the shared file of passwords and expected
// verdicts that the app's estimator is tested against too (§11.14.7).
func TestPasswordVerdicts(t *testing.T) {
	b, err := os.ReadFile("../../testdata/passwords/verdicts.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		PIN   string `json:"pin"`
		Cases []struct {
			Password string `json:"password"`
			Verdict  string `json:"verdict"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	for _, c := range f.Cases {
		n, _ := NormalizePassword([]byte(c.Password))
		got := CheckNewPassword(n, f.PIN)
		if got == "" {
			got = "ok"
		}
		if got != c.Verdict {
			t.Errorf("%q: got %s want %s (guesses %.3g)", c.Password, got, c.Verdict, Guesses(string(n)))
		}
	}
}

func TestArmingRules(t *testing.T) {
	if ArmingAllowed([]byte("short")) || ArmingAllowed([]byte("aaaaaaaaaaaaaaa")) || ArmingAllowed([]byte("password1234")) {
		t.Error("armed for a weak password")
	}
	if !ArmingAllowed([]byte("violet-Kestrel-91-moss")) {
		t.Error("refused a strong password")
	}
}
