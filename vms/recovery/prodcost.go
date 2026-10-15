//go:build !vettid_testcost

package recovery

// TestCost is false in every build without the test-only tag: the
// specified Argon2id parameters and floors.
const TestCost = false

const (
	heavyTime, heavyMemKiB             = HeavyTime, HeavyMemoryKiB
	heavyFloorTime, heavyFloorMemKiB   = HeavyTime, HeavyMemoryKiB
	unlockTime, unlockMemKiB           = UnlockTime, UnlockMemKiB
	unlockFloorTime, unlockFloorMemKiB = 1, 8 * 1024 // as vault.MinKDF before release R
)
