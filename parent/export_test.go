package parent

import "time"

// ParseRoutingForTest exposes parseRouting to the external tests.
func ParseRoutingForTest(b []byte) (string, bool) {
	r, ok := parseRouting(b)
	return r.Op, ok
}

// SetQueueRetryForTest shortens the wait for SQS to allow recreating the
// queue; the returned function restores the defaults.
func SetQueueRetryForTest(base, max, wait time.Duration) func() {
	b, m, w := queueRetryBase, queueRetryMax, queueRecreateWait
	queueRetryBase, queueRetryMax, queueRecreateWait = base, max, wait
	return func() { queueRetryBase, queueRetryMax, queueRecreateWait = b, m, w }
}

// QueueDeletedRecentlyForTest exposes the SQS error classification.
var QueueDeletedRecentlyForTest = queueDeletedRecently
