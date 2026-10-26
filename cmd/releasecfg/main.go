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
//
// It also refuses a staging-only switch past its end date
// (STAGING-DEVELOPMENT-PLAN §2.5.5; the staging file's
// automation_attestation, VAULT-RELEASES §3.1), judged at
// SOURCE_DATE_EPOCH when that is set to a positive number (an image build:
// Dockerfile.enclave and scripts/build-eif.sh set it to the commit time,
// so a rebuild of a tagged release gives the same answer on any day) and
// at the current time otherwise (the release workflow's gate, CI).
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

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
	at, atWhat := gateTime()
	if err := c.CheckEndDates(at); err != nil {
		fmt.Fprintf(stderr, "releasecfg: %s: refusing to build a %s release image (%s): %v\n", path, channel, atWhat, err)
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
	var signers []string
	for _, sg := range c.AndroidSigners {
		signers = append(signers, fmt.Sprintf("%x… %s", sg.Digest[:4], sg.Class))
	}
	unbound := ""
	if c.AcceptsUnbound() {
		unbound = "; vaults enrolled before 0.27.0 unlock unbound"
	}
	fmt.Fprintf(stdout, "releasecfg: %s release %d complete (%d manifest key(s), sealing account %s %s, retirement window %d days, android package %s, iOS App ID %s, signers: %s%s, optional features: %s%s)\n",
		c.Channel, c.Release, len(c.ManifestKeys), c.SealAccount, c.SealRegion, c.RetirementWindowDays, c.AndroidPackage, c.IOSAppID, strings.Join(signers, ", "), unbound, features, grows)
	// VAULT-RELEASES 0.1.32 §5.2: each release log entry says the scale in
	// words; this is the line to copy.
	fmt.Fprintf(stdout, "releasecfg: release log: %s\n", TimeScaleWords(c))
	if roots := c.AutomationRoots(); len(roots) > 0 {
		fmt.Fprintf(stdout, "releasecfg: staging automation attestation: %d root(s), until %s (checked %s)\n",
			len(roots), c.Automation.Until.Format(time.DateOnly), atWhat)
	}
	return 0
}

// gateTime is the time the date rule is judged at: SOURCE_DATE_EPOCH if
// it is a positive number, else now.
func gateTime() (time.Time, string) {
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			t := time.Unix(n, 0).UTC()
			return t, "at SOURCE_DATE_EPOCH " + t.Format(time.DateOnly)
		}
	}
	t := time.Now().UTC()
	return t, "on " + t.Format(time.DateOnly)
}

// TimeScaleWords is the release log's words for the image's time scale
// (VAULT-RELEASES 0.1.32 §5.2, STAGING-TIME-SCALE §4 item 3).
func TimeScaleWords(c *releasecfg.Config) string {
	switch n := c.TimeScale(); {
	case n == 1:
		return "Time scale: real time"
	case n == releasecfg.StagingTimeScale:
		return "Time scale: 1 day = 1 hour (" + c.Channel + ")"
	default:
		return fmt.Sprintf("Time scale: divided by %d (%s)", n, c.Channel)
	}
}
