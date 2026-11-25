//go:build !vettid_testcost

package paircode

// TestCost is false in every build without the test-only tag: the
// specified Argon2id parameters.
const TestCost = false

const argonTime, argonMemoryKiB = ArgonTime, ArgonMemoryKiB
