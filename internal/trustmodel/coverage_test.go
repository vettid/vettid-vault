package trustmodel

import (
	"fmt"
	"math/rand/v2"
	"sort"
	"strings"
	"testing"
)

// Rule coverage (R29 rule list §9.4): N random runs of the configuration
// the environment selects (the oracle config by default); every release-29
// rule of VAULT-MESSAGING 0.87.1 §6.3.2, and every branch listed below,
// must be hit at least TRUSTMODEL_MINHITS times (default 3). The hits are
// counted by w.hit ("R29 <ID>:<branch>").

// r29Rules: the rule IDs of §6.3.2, in its order (R29-F2 was withdrawn).
// R29-U1 (0.87.1: no migration, earlier state refused) is not a two-sided
// rule: it is tested in the vault (§6.3.2).
var r29Rules = []string{"G1", "G2", "L1", "I1", "I2", "I3", "I4", "I5", "I6", "I7",
	"R1", "R2", "R3", "R4", "R5", "R6", "X1", "X2", "X3", "X4", "X5", "X6",
	"K1", "K2", "K3", "K4", "K5", "K6", "K7", "K8", "K9", "F1", "F3", "D1", "D2", "D3", "D4"}

// r29Branches: the branches that must each be hit. Branches the oracle
// config cannot reach are listed in r29Unreachable with the reason.
var r29Branches = []string{
	"G1:advertised", "G2:hs_confirm-seen",
	"L1:answer-expired-L", "L1:rekey-unanswered-16d",
	"I1:pending", "I2:confirmed", "I3:hs.confirm-held", "I3:outbox-waits",
	"I4:no-rekey-while-pending", "I4:no-rekey-while-answer-awaits-fin",
	"I5:B-reconnect-stale",
	"I6:rekey-abandoned-no-token", "I6:reconnect-kept-without-token",
	"I7:abandon", "I7:fresh-reconnect",
	"R1:hs.confirm-queued", "R2:confirmed-moves", "R3:hs.confirm-again", "R3:one-still-queued",
	"R4:rekey-names-confirmed", "R4:reconnect-names-confirmed",
	"R5:destroyed", "R5:own-abandoned-not-destroyed", "R6:fork-evidence",
	"X1:crossing-dropped", "X1:later-abandons", "X2:own-higher-abandoned", "X2:own-lower-kept", "X2:fin-first",
	"X3:undepositable-answer-destroyed", "X4:one-reconnect-at-a-time",
	"X5:current", "X5:own-pending", "X5:confirmed", "X5:abandoned-while-pending", "X5:own-reconnect-pending", "X5:refused",
	"X6:sealed-rekey-refused",
	"K1:identity.rotate-whole-chain", "K1:hs.init-whole-chain",
	"K2:S5-answer-dropped", "K2:S5-pending-abandoned", "K2:answer-dropped-H5", "K2:pending-abandoned-at-link",
	"K3:identity.rotate-resent",
	"K4:demote-audit", "K4:current-demoted", "K4:flag-suspend",
	"K5:held", "K5:released", "K5:held-ended", "K5:hs.confirm-not-sent", "K5:reconnect-after-demotion",
	"K6:try-failed", "K6:third-failure-stale", "K6:quota_exceeded-stale",
	"K7:demote", "K7:demote-several", "K7:flag-suspend", "K7:reconnect-names-E",
	"K8:link-kept-as-seen", "K8:second-successor-suspends",
	"K9:ended", "K9:flag-suspend", "K9:ended-message-suspends",
	"F1:fork-by-ctx-rekey", "F1:fork-by-ctx-reconnect",
	"F3:flag-set", "F3:flag-set-by-hs.confirm",
	"D1:B-rekey", "D2:device-starts-no-rekey", "D2:confirm-rate-limited", "D3:device-rekey-refused",
	"D4:notice message without hs_confirm", "D4:notice D3 refusal",
}

// r29Unreachable: branches counted but not required, with the reason.
var r29Unreachable = map[string]string{
	"I5:B-reconnect":                     "with the peer away its standing token (30 days) ends before B (32 days): I6 abandons first (TestF13Lifetimes, TestScenarioALostConfirmInitiatorLocked)",
	"R6:superseded_epoch":                "an earlier-ts message under a destroyed epoch needs a copy and reordering (TestR29R6SupersededEpoch)",
	"K5:no-epoch-to-name-stale":          "needs every been-current epoch demoted or destroyed",
	"K6:no-reconnect-token-stale":        "reconnect tokens last 365 days and are re-minted; runs are shorter",
	"K8:device-conflict-refused":         "devices rotate no ik; a device conflict needs a vault fork toward its own device",
	"K8:against-a-seen-link":             "a second successor against a link seen but not followed",
	"L1:handshake-expired-at-hs.resp":    "an hs.resp arriving after 16 days",
	"L1:hs.fin-after-L":                  "an hs.fin arriving after L (16 days)",
	"L1:confirmed-epoch-keys-end":        "48 days with the confirmed epoch not current",
	"D1:rekey-not-reconnect":             "token_expired toward a device with a pending rekey, exp passed on the own clock",
	"D4:notice B passed":                 "an old app that never sends under the new epoch for 32 days",
	"I6:token_expired-before-own-exp":    "token_expired while the own clock is behind",
	"I6:rekey-abandoned-token_expired":   "token_expired with a pending rekey (the parties check exp before depositing)",
	"I6:reconnect-kept-at-token_expired": "as above, with a pending reconnect",
	"K9:judged-after-cut-off":            "Table A's after-cut-off row needs relay-key rotation, off in the oracle config (TestR29K9AfterCutOffIgnoreJudged)",
	"K4:flag-suspend-already-demoted":    "a flag set on an epoch after its demotion needs a message deposited before the link in another mailbox (TestR29K4AlreadyDemotedFlagSuspends)",
	"G2:sticky":                          "a message without hs_confirm after it was seen (a copy taken before the device first advertised it)",
}

func TestR29Coverage(t *testing.T) {
	runs := envInt("TRUSTMODEL_COVRUNS", 3000)
	seed := uint64(envInt("TRUSTMODEL_SEED", 1))
	steps := envInt("TRUSTMODEL_STEPS", 40)
	min := envInt("TRUSTMODEL_MINHITS", 3)
	hits := map[string]int{}
	master := rand.New(rand.NewPCG(seed, 99))
	for i := 0; i < runs; i++ {
		rs := master.Uint64()
		cfg, acts := genRun(rs, steps)
		w := runActions(cfg, rs, acts, false)
		for k, v := range w.stats {
			if id, ok := strings.CutPrefix(k, "R29 "); ok {
				hits[id] += v
			}
		}
	}
	t.Logf("R29 rule coverage, %d runs, seed %d (minimum %d per rule and listed branch):\n%s", runs, seed, min, coverageTable(hits))
	var low []string
	for _, id := range r29Rules {
		if n := ruleTotal(hits, id); n < min {
			low = append(low, fmt.Sprintf("%s: %d", id, n))
		}
	}
	for _, b := range r29Branches {
		if hits[b] < min {
			low = append(low, fmt.Sprintf("%s: %d", b, hits[b]))
		}
	}
	if len(low) > 0 {
		t.Errorf("rules or branches hit fewer than %d times:\n  %s", min, strings.Join(low, "\n  "))
	}
}

func ruleTotal(hits map[string]int, id string) int {
	n := 0
	for k, v := range hits {
		if k == id || strings.HasPrefix(k, id+":") {
			n += v
		}
	}
	return n
}

// coverageTable: one line per rule ID with its total, then its branches.
func coverageTable(hits map[string]int) string {
	var b strings.Builder
	for _, id := range r29Rules {
		fmt.Fprintf(&b, "  R29-%-3s %9d\n", id, ruleTotal(hits, id))
		var bs []string
		for k := range hits {
			if strings.HasPrefix(k, id+":") {
				bs = append(bs, k)
			}
		}
		sort.Strings(bs)
		for _, k := range bs {
			note := ""
			if why, ok := r29Unreachable[k]; ok {
				note = "  (not required: " + why + ")"
			}
			fmt.Fprintf(&b, "      %-45s %9d%s\n", strings.TrimPrefix(k, id+":"), hits[k], note)
		}
	}
	return b.String()
}
