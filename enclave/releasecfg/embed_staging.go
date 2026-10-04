//go:build vettid_channel_staging

package releasecfg

import _ "embed"

// channel is the build's channel (build tag vettid_channel_staging).
const channel = ChannelStaging

//go:embed staging.json
var embedded []byte
