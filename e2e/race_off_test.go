//go:build !race && devenclave && e2e

package e2e

import "time"

// entryWait is how long waitEntry waits for an attachment entry to match.
const entryWait = 30 * time.Second
