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

// SetRegistryWriteTimeoutForTest shortens the bound on the registry row's
// write; the returned function restores it.
func SetRegistryWriteTimeoutForTest(d time.Duration) func() {
	old := registryWriteTimeout
	registryWriteTimeout = d
	return func() { registryWriteTimeout = old }
}

// SetLeaseTimesForTest shortens the bound on a lease renewal, the wait
// after a failed pass and the margin before a lease's end at which it is
// lost; the returned function restores them.
func SetLeaseTimesForTest(timeout, retry, margin time.Duration) func() {
	a, b, c := leaseRenewTimeout, leaseRetry, leaseMargin
	leaseRenewTimeout, leaseRetry, leaseMargin = timeout, retry, margin
	return func() { leaseRenewTimeout, leaseRetry, leaseMargin = a, b, c }
}

// PeerIsEnclaveForTest exposes the rule for accepted connections.
var PeerIsEnclaveForTest = peerIsEnclave

// QueueNotFoundForTest exposes the SQS error classification of a queue
// that does not exist.
var QueueNotFoundForTest = queueNotFound

// SetQueueLostWaitForTest shortens the wait after a receive that found no
// queue; the returned function restores the defaults.
func SetQueueLostWaitForTest(first, max time.Duration) func() {
	a, b := queueLostWait, queueLostWaitMax
	queueLostWait, queueLostWaitMax = first, max
	return func() { queueLostWait, queueLostWaitMax = a, b }
}

// SetAppKeyRetryForTest shortens the backoff of the app key retry; the
// returned function restores it.
func SetAppKeyRetryForTest(first, max time.Duration) func() {
	a, b := appKeyRetryFirst, appKeyRetryCap
	appKeyRetryFirst, appKeyRetryCap = first, max
	return func() { appKeyRetryFirst, appKeyRetryCap = a, b }
}
