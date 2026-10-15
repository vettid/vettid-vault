//go:build vettid_testcost

package recovery

// TestCost is true only in a build with the test-only tag vettid_testcost:
// the recovery wrap's derivation runs at t = 1, m = 8 MiB, and the floors
// are lowered to match. A release build never has the tag (check-tcb), and
// the enclave refuses to start if TestCost is set.
const TestCost = true

const (
	heavyTime, heavyMemKiB             = 1, 8 * 1024
	heavyFloorTime, heavyFloorMemKiB   = 1, 8 * 1024
	unlockTime, unlockMemKiB           = 1, 8 * 1024
	unlockFloorTime, unlockFloorMemKiB = 1, 8 * 1024
)
