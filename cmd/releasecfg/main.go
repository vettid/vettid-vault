// Command releasecfg is the release build's gate on a channel's release
// constants (VAULT-MESSAGING §11.10.8, VAULT-RELEASES §5.2):
//
//	releasecfg check [-previous <file>] <prod|staging> [file]
//
// It exits non-zero if the channel file (default
// enclave/releasecfg/<channel>.json) is malformed, belongs to another
// channel, or still has a placeholder ("TODO-...") or missing value, so
// that no release image is built with placeholders. scripts/build-eif.sh
// and Dockerfile.enclave run it before building a channel's image.
//
// With -previous, the channel file of the channel's previous release
// (the release workflow reads it from the tag release/<channel>/<N-1>),
// it also refuses a feature list that lacks a name that file listed
// (0.26.0 §11.10.8: a channel's list only grows). A previous file from
// before 0.26.0 has no list and counts as listing every optional
// feature. A rebuild from the tag alone runs without -previous.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vettid/vettid-vault/enclave/releasecfg"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	const usage = "usage: releasecfg check [-previous <file>] <prod|staging> [file]"
	if len(args) < 1 || args[0] != "check" {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	fs := flag.NewFlagSet("releasecfg check", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	previous := fs.String("previous", "", "the channel file of the channel's previous release")
	if err := fs.Parse(args[1:]); err != nil || fs.NArg() < 1 || fs.NArg() > 2 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	channel := fs.Arg(0)
	path := "enclave/releasecfg/" + channel + ".json"
	if fs.NArg() == 2 {
		path = fs.Arg(1)
	}
	if channel != releasecfg.ChannelProd && channel != releasecfg.ChannelStaging {
		fmt.Fprintln(stderr, "releasecfg: unknown channel", channel)
		return 2
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(stderr, "releasecfg:", err)
		return 1
	}
	c, err := releasecfg.Check(channel, b)
	if err != nil {
		fmt.Fprintf(stderr, "releasecfg: %s: refusing to build a %s release image: %v\n", path, channel, err)
		return 1
	}
	grows := ""
	if *previous != "" {
		pb, err := os.ReadFile(*previous)
		if err != nil {
			fmt.Fprintln(stderr, "releasecfg:", err)
			return 1
		}
		prev, err := releasecfg.PreviousFeatures(channel, pb)
		if err != nil {
			fmt.Fprintf(stderr, "releasecfg: %s: the previous release's channel file: %v\n", *previous, err)
			return 1
		}
		if err := releasecfg.CheckGrows(c, prev); err != nil {
			fmt.Fprintf(stderr, "releasecfg: %s: refusing to build a %s release image: %v\n", path, channel, err)
			return 1
		}
		grows = fmt.Sprintf(", no feature of the previous release (%d) dropped", len(prev))
	}
	features := "none"
	if len(c.Features) > 0 {
		features = strings.Join(c.Features, " ")
	}
	fmt.Fprintf(stdout, "releasecfg: %s release %d complete (%d manifest key(s), sealing account %s %s, retirement window %d days, android package %s, optional features: %s%s)\n",
		c.Channel, c.Release, len(c.ManifestKeys), c.SealAccount, c.SealRegion, c.RetirementWindowDays, c.AndroidPackage, features, grows)
	return 0
}
