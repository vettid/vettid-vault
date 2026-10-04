//go:build !vettid_channel_prod && !vettid_channel_staging

package releasecfg

// channel is empty in a build without a channel tag (dev builds, tests
// and the hardware smoke test): nothing is embedded and nothing pinned.
const channel = ""

var embedded []byte
