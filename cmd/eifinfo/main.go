// Command eifinfo inspects Nitro Enclaves image files for the release
// build (VAULT-RELEASES §5.1, docs/RELEASING.md):
//
//	eifinfo describe FILE      print the EIF's SHA-256, measured SHA-256 and
//	                           PCR0-2 (recomputed from the sections, not
//	                           taken from nitro-cli) as JSON
//	eifinfo compare FILE FILE  exit non-zero unless the two EIFs have the
//	                           same layout and byte-identical measured
//	                           sections; prints the metadata members that
//	                           differ (build time and host details, which
//	                           nitro-cli writes and no PCR covers)
//	eifinfo pcrs FILE JSON     exit non-zero unless the PCRs nitro-cli
//	                           reported (its build-enclave JSON output)
//	                           equal the ones recomputed from FILE
//	eifinfo match A B          exit non-zero unless two measurements.json
//	                           files (scripts/build-eif.sh) describe the same
//	                           release build: same commit, channel, release,
//	                           channel file, binaries, measured EIF sections
//	                           and PCRs (the two-builder rule,
//	                           VAULT-RELEASES §5.3)
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/vettid/vettid-vault/internal/eif"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "eifinfo:", err)
		os.Exit(1)
	}
}

func usage() error {
	return fmt.Errorf("usage: eifinfo describe FILE | compare FILE FILE | pcrs FILE NITRO-CLI-JSON | match MEASUREMENTS MEASUREMENTS")
}

func run(args []string) error {
	if len(args) < 2 {
		return usage()
	}
	switch {
	case args[0] == "describe" && len(args) == 2:
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		in, _, err := eif.Describe(b)
		if err != nil {
			return err
		}
		out, _ := json.MarshalIndent(in, "", "  ")
		fmt.Println(string(out))
		return nil
	case args[0] == "compare" && len(args) == 3:
		a, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		b, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		diff, err := eif.Compare(a, b)
		if err != nil {
			return err
		}
		fmt.Printf("eifinfo: measured sections identical; unmeasured metadata differs in: %s\n", orNone(diff))
		return nil
	case args[0] == "pcrs" && len(args) == 3:
		b, err := os.ReadFile(args[1])
		if err != nil {
			return err
		}
		in, _, err := eif.Describe(b)
		if err != nil {
			return err
		}
		j, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		var rep struct {
			Measurements struct{ PCR0, PCR1, PCR2 string }
		}
		if err := json.Unmarshal(j, &rep); err != nil {
			return fmt.Errorf("nitro-cli output: %w", err)
		}
		m := rep.Measurements
		if m.PCR0 != in.PCR0 || m.PCR1 != in.PCR1 || m.PCR2 != in.PCR2 {
			return fmt.Errorf("nitro-cli reported PCRs %s/%s/%s, the EIF's sections give %s/%s/%s", m.PCR0, m.PCR1, m.PCR2, in.PCR0, in.PCR1, in.PCR2)
		}
		fmt.Println("eifinfo: PCR0-2 recomputed from the EIF equal nitro-cli's")
		return nil
	case args[0] == "match" && len(args) == 3:
		return match(args[1], args[2])
	}
	return usage()
}

// mustMatch are the measurements two builds of one release must share;
// the rest (eif_sha256: nitro-cli's unmeasured metadata; the toolchain of
// a host build) is printed for the record.
var mustMatch = []string{"source_commit", "channel", "release", "releasecfg_sha256", "binary_sha256", "parent_sha256",
	"eif_measured_sha256", "pcr0", "pcr1", "pcr2"}

func match(pa, pb string) error {
	read := func(p string) (map[string]any, error) {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		return m, nil
	}
	a, err := read(pa)
	if err != nil {
		return err
	}
	b, err := read(pb)
	if err != nil {
		return err
	}
	var bad []string
	for _, k := range mustMatch {
		va, oka := a[k]
		vb, okb := b[k]
		if !oka || !okb || fmt.Sprint(va) != fmt.Sprint(vb) {
			bad = append(bad, fmt.Sprintf("%s: %v != %v", k, va, vb))
		}
	}
	for _, k := range []string{"eif_sha256", "nitro_cli_version", "toolchain_lock_sha256"} {
		if fmt.Sprint(a[k]) != fmt.Sprint(b[k]) {
			fmt.Printf("eifinfo: %s differs (not required to match): %v / %v\n", k, a[k], b[k])
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("the builds differ:\n  %s", strings.Join(bad, "\n  "))
	}
	fmt.Printf("eifinfo: MATCH %s release %v at %v: pcr0 %v\n", a["channel"], a["release"], a["source_commit"], a["pcr0"])
	return nil
}

func orNone(s []string) string {
	if len(s) == 0 {
		return "(nothing)"
	}
	return strings.Join(s, ", ")
}
