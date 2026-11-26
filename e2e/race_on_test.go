//go:build race && devenclave && e2e

package e2e

import "time"

// entryWait is how long waitEntry waits for an attachment entry to match:
// three times as long under the race detector, whose slowdown made the
// malicious-peer rounds miss 30 s in CI.
const entryWait = 90 * time.Second
