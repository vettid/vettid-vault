package parent

// ParseRoutingForTest exposes parseRouting to the external tests.
func ParseRoutingForTest(b []byte) (string, bool) {
	r, ok := parseRouting(b)
	return r.Op, ok
}
