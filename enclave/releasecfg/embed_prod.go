//go:build vettid_channel_prod

package releasecfg

import _ "embed"

// channel is the build's channel (build tag vettid_channel_prod).
const channel = ChannelProd

//go:embed prod.json
var embedded []byte
