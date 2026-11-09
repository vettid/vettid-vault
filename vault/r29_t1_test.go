package vault

import (
	"strconv"
	"testing"
)

// R29-T1 (VAULT-MESSAGING 0.88.2 §6.3.1 "A handshake's tokens are adopted at
// confirmation"; owner decision a, GC 01M6SWPHVH6WFYJ8096KX0D5GC): seeds of
// the random pair that failed at 4a0d453 (before the rule, and before the
// harness's time jumps let an unlocked side collect, advanceLive), replayed
// from their seed (replays are exact, TestR29RandomPairReplay). Each must
// now converge, and no side may adopt a token its issuer had already
// revoked (the harness's R29-T1 assertion, watchAdoption). The scenario
// test of the class is TestR29TokenRevokedEndsTheTokenOnly.
//
//   - 16906628016574081987, 2547422016364076747, 8648490589795547312: the
//     adopt-before-confirm class (GC 01M6SWPHVH6WFYJ8096KX0D5GC): rotations
//     on both sides around crossing reconnects; at 4a0d453 deposits and
//     reconnect tries were refused token_revoked, then quota_exceeded, and
//     both sides ended stale.
//   - 3261938242456459520, 16401999147266222361: the "single 30-day lock"
//     class (lock>T:single), which ended stale the same way after one long
//     lock.
//   - 14735564589240170962: failed before and after the rule, with no lock:
//     a 30-day time jump while both sides were unlocked let handshake
//     messages expire at the relay unread, a vault that does not exist (an
//     unlocked vault collects continuously). The regression test of
//     advanceLive (the lead, GC #6449).
func TestR29T1Seeds(t *testing.T) {
	for _, seed := range []uint64{
		16906628016574081987, 2547422016364076747, 8648490589795547312,
		3261938242456459520, 16401999147266222361, 14735564589240170962,
	} {
		t.Run(strconv.FormatUint(seed, 10), func(t *testing.T) {
			if v, _ := rpRun(t, seed, 40, false, false); v != "" {
				t.Fatalf("verdict %q, want converged", v)
			}
		})
	}
}
