package client

import "github.com/vettid/vettid-vault/vms/suite"

// wipeKey zeroes b (a key Close wipes, or a borrowed copy of one). Under the
// race detector suite.Wipe writes byte by byte, so a read of the key while
// it is wiped is reported.
func wipeKey(b []byte) { suite.Wipe(b) }
