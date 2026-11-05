package trustmodel

import (
	"fmt"
	"math/rand/v2"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil {
		return v
	}
	return def
}

// allCells: every cell of Tables A and B (and the rules' branches) the
// model can name, for the coverage report.
func allCells() []string {
	var cs []string
	for _, c := range []string{"session", "update", "token.issued", "identity.rotate", "hs.init", "hs.resp/fin"} {
		cs = append(cs, "A:suspended:"+c, "A:foreign:"+c)
	}
	for _, row := range []string{"current", "earlier-before", "earlier-after"} {
		cs = append(cs, "A:"+row+":session", "A:"+row+":token.issued")
		for _, u := range []string{"follow", "duplicate", "first-not-current", "new-is-kept", "token", "unlinked"} {
			cs = append(cs, "U("+row+"):"+u)
		}
	}
	cs = append(cs, "A:earlier-after:identity.rotate", "A:earlier-after:identity.rotate:all-followed",
		"A:earlier-after:hs.init", "A:earlier-after:hs.resp/fin:handshake-kept", "A:hs.init-sender-not-from.relay")
	for _, ik := range ikName {
		for _, k := range []string{"identity.rotate", "hs.init", "hs.resp", "hs.fin"} {
			cs = append(cs, "B:"+ik+":"+k)
		}
	}
	cs = append(cs, "C:identity", "C:relay", "C:identity-device", "C:relay-device", "E:demoted-epoch",
		"T:defer-unknown-iss", "T:defer-unknown-iss:bound-exceeded", "B:current:hs.init:fork-epoch",
		"B:ancestor:hs.fin:fork-evidence", "B:current:hs.fin:fork-evidence")
	return cs
}

// Table cells that cannot occur ("—" in the spec) or that the model
// cannot produce by construction.
var impossible = map[string]string{
	"U(current):duplicate":                "unreachable: a chain whose first old is the current key has an unfollowed first link",
	"U(current):first-not-current":        "unreachable: with no link skipped, the first old is the sender, the current key",
	"U(earlier-before):first-not-current": "unreachable after rule C: the key after the skipped prefix is current or has a followed successor (a conflict)",
	"U(earlier-after):first-not-current":  "unreachable after rule C (as above)",
	"B:reached:identity.rotate":           "spec: — (an identity.rotate's ik is the old_ik of its first unfollowed link)",
	"B:unknown:hs.fin":                    "spec: — (the pinned ik was current or reached at hs.init)",
	"U(current):unlinked":                 "model: every party builds well-formed links",
	"U(earlier-before):unlinked":          "model: every party builds well-formed links",
	"U(earlier-after):unlinked":           "model: every party builds well-formed links",
}

type agg struct {
	runs, viol int
	stats      map[string]int
	found      map[string]string // invariant -> first shrunk trace
	foundSeed  map[string]uint64
}

func TestRandom(t *testing.T) {
	runs := envInt("TRUSTMODEL_RUNS", 3000)
	seed := uint64(envInt("TRUSTMODEL_SEED", 1))
	steps := envInt("TRUSTMODEL_STEPS", 40)
	start := time.Now()
	a := agg{stats: map[string]int{}, found: map[string]string{}, foundSeed: map[string]uint64{}}
	master := rand.New(rand.NewPCG(seed, 99))
	for i := 0; i < runs; i++ {
		rs := master.Uint64()
		cfg, acts := genRun(rs, steps)
		w := runActions(cfg, rs, acts, false)
		a.runs++
		for k, v := range w.stats {
			a.stats[k] += v
		}
		if len(w.viol) == 0 {
			continue
		}
		a.viol++
		inv := w.viol[0].Inv
		sig := inv + " " + classify(w.viol[0].Detail)
		a.stats["violation "+sig]++
		if _, seen := a.found[sig]; seen || len(a.found) >= 40 {
			continue
		}
		small := shrink(cfg, rs, acts, inv)
		sw := runActions(cfg, rs, small, true)
		var b strings.Builder
		fmt.Fprintf(&b, "run seed %d, config %+v, %d actions shrunk to %d\n", rs, cfg, len(acts), len(small))
		for _, x := range small {
			fmt.Fprintf(&b, "  action %s\n", sw.describeAction(x))
		}
		for _, v := range sw.viol {
			fmt.Fprintf(&b, "  VIOLATION %s: %s\n", v.Inv, v.Detail)
		}
		b.WriteString("  trace:\n    " + strings.ReplaceAll(traceOf(sw), "\n", "\n    ") + "\n")
		a.found[sig] = b.String()
		a.foundSeed[sig] = rs
	}
	el := time.Since(start)
	report(t, &a, seed, runs, el)
	if a.viol > 0 && os.Getenv("TRUSTMODEL_STRICT") != "" {
		t.Fatalf("%d of %d runs violated an invariant", a.viol, a.runs)
	}
}

// classify groups violations by their message without the numbers.
func classify(d string) string {
	f := strings.Fields(d)
	var out []string
	for _, x := range f {
		if _, err := strconv.Atoi(strings.Trim(x, "E(),#:")); err == nil {
			continue
		}
		if x == "P" || x == "Q" || x == "R" || x == "DP" || x == "DQ" || x == "DR" || strings.Contains(x, "<->") || strings.HasSuffix(x, "'") || strings.Contains(x, "->") {
			continue
		}
		out = append(out, x)
	}
	return strings.Join(out, " ")
}

func report(t *testing.T, a *agg, seed uint64, runs int, el time.Duration) {
	t.Logf("seed %d, %d runs in %s, %d with a violation", seed, runs, el.Round(time.Millisecond), a.viol)
	keys := make([]string, 0, len(a.stats))
	for k := range a.stats {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "  %-70s %d\n", k, a.stats[k])
	}
	t.Logf("stats:\n%s", b.String())
	var never []string
	for _, c := range allCells() {
		if a.stats["cell "+c] == 0 {
			if why, ok := impossible[c]; ok {
				never = append(never, c+"  ("+why+")")
			} else {
				never = append(never, c)
			}
		}
	}
	t.Logf("cells never reached (%d):\n  %s", len(never), strings.Join(never, "\n  "))
	sigs := make([]string, 0, len(a.found))
	for s := range a.found {
		sigs = append(sigs, s)
	}
	sort.Strings(sigs)
	for _, s := range sigs {
		t.Logf("VIOLATION CLASS %q (first at run seed %d):\n%s", s, a.foundSeed[s], a.found[s])
	}
}

// genRun: the configuration and actions of one random run (from its seed;
// the environment selects the mix).
func genRun(rs uint64, steps int) (Config, []Action) {
	rng := rand.New(rand.NewPCG(rs, 3))
	cfg := Config{Vaults: 2 + rng.IntN(2), Devices: rng.IntN(2) == 0, P429: 0.05, PRefuse: 0.01,
		OldRules: os.Getenv("TRUSTMODEL_OLD") != "", Gate: os.Getenv("TRUSTMODEL_GATE") != "",
		Opt: envInt("TRUSTMODEL_OPT", optFull), Unseen: os.Getenv("TRUSTMODEL_UNSEEN") != "",
		Skew: os.Getenv("TRUSTMODEL_NOSKEW") == ""}
	if os.Getenv("TRUSTMODEL_MIXED") != "" { // release <= 28 parties, about half
		cfg.Rel28 = make([]bool, 6)
		for j := range cfg.Rel28 {
			cfg.Rel28[j] = rng.IntN(2) == 0
		}
	}
	n := 1 + rng.IntN(steps)
	acts := make([]Action, n)
	for j := range acts {
		acts[j] = randomAction(rng)
	}
	return cfg, acts
}

// TestSeedsByClass: the run seeds (as TestRandom draws them) whose first
// violation is in TRUSTMODEL_CLASS (a prefix), one per line. Attribution aid.
func TestSeedsByClass(t *testing.T) {
	cls := os.Getenv("TRUSTMODEL_CLASS")
	if v, err := strconv.ParseUint(os.Getenv("TRUSTMODEL_TRACESEED"), 10, 64); err == nil {
		cfg, acts := genRun(v, envInt("TRUSTMODEL_STEPS", 40))
		w := runActions(cfg, v, acts, false)
		small := acts
		if len(w.viol) > 0 {
			small = shrink(cfg, v, acts, w.viol[0].Inv)
		}
		sw := runActions(cfg, v, small, true)
		for _, x := range small {
			t.Logf("action %s", sw.describeAction(x))
		}
		for _, x := range sw.viol {
			t.Logf("VIOLATION %s: %s", x.Inv, x.Detail)
		}
		t.Log("trace:\n" + traceOf(sw))
		return
	}
	if cls == "" {
		t.Skip("TRUSTMODEL_CLASS not set")
	}
	runs := envInt("TRUSTMODEL_RUNS", 3000)
	master := rand.New(rand.NewPCG(uint64(envInt("TRUSTMODEL_SEED", 1)), 99))
	for i := 0; i < runs; i++ {
		rs := master.Uint64()
		cfg, acts := genRun(rs, envInt("TRUSTMODEL_STEPS", 40))
		w := runActions(cfg, rs, acts, false)
		if k := strings.TrimPrefix(cls, "stat:"); k != cls {
			if w.stats[k] > 0 {
				var vs []string
				for _, x := range w.viol {
					vs = append(vs, x.Inv)
				}
				t.Logf("SEED %d stat %d, violations %v", rs, w.stats[k], vs)
			}
			continue
		}
		if len(w.viol) > 0 && strings.HasPrefix(w.viol[0].Inv, cls) {
			t.Logf("SEED %d %s: %s", rs, w.viol[0].Inv, w.viol[0].Detail)
		}
	}
}
