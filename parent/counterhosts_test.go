package parent

import (
	"os"
	"slices"
	"testing"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
)

func TestCounterHostsMatchChannels(t *testing.T) {
	for _, ch := range []string{"prod", "staging"} {
		b, err := os.ReadFile("../enclave/releasecfg/" + ch + ".json")
		if err != nil {
			t.Fatal(err)
		}
		f, err := releasecfg.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		if h := f.Config.RecoveryCounter.Host(); !slices.Contains(CounterHosts, h) || !slices.Contains(DefaultAllow("relay.example.org", "us-east-1"), h) {
			t.Errorf("%s counter host %s not allowed", ch, h)
		}
	}
}
