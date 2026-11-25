//go:build vettid_testcost

package paircode

// TestCost is true only in a build with the test-only tag vettid_testcost:
// the two derivations run at t = 1, m = 8 MiB, so that the vault's handler
// tests stay fast under -race. Such a build derives tags and keys no
// other party matches. A release build never has the tag (check-tcb), and
// the enclave refuses to start if TestCost is set.
const TestCost = true

const argonTime, argonMemoryKiB = 1, 8 * 1024
