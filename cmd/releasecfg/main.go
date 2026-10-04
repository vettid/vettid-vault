// Command releasecfg is the release build's gate on a channel's release
// constants (VAULT-MESSAGING §11.10.8, VAULT-RELEASES §5.2):
//
//	releasecfg check <prod|staging> [file]
//
// It exits non-zero if the channel file (default
// enclave/releasecfg/<channel>.json) is malformed, belongs to another
// channel, or still has a placeholder ("TODO-...") or missing value, so
// that no release image is built with placeholders. scripts/build-eif.sh
// and Dockerfile.enclave run it before building a channel's image.
package main

import (
	"fmt"
	"os"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
)

func main() {
	if len(os.Args) < 3 || len(os.Args) > 4 || os.Args[1] != "check" {
		fmt.Fprintln(os.Stderr, "usage: releasecfg check <prod|staging> [file]")
		os.Exit(2)
	}
	channel := os.Args[2]
	path := "enclave/releasecfg/" + channel + ".json"
	if len(os.Args) == 4 {
		path = os.Args[3]
	}
	if channel != releasecfg.ChannelProd && channel != releasecfg.ChannelStaging {
		fmt.Fprintln(os.Stderr, "releasecfg: unknown channel", channel)
		os.Exit(2)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "releasecfg:", err)
		os.Exit(1)
	}
	c, err := releasecfg.Check(channel, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "releasecfg: %s: refusing to build a %s release image: %v\n", path, channel, err)
		os.Exit(1)
	}
	fmt.Printf("releasecfg: %s release %d complete (%d manifest key(s), sealing account %s %s, retirement window %d days)\n",
		c.Channel, c.Release, len(c.ManifestKeys), c.SealAccount, c.SealRegion, c.RetirementWindowDays)
}
