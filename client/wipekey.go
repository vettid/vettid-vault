//go:build !race

package client

import "github.com/vettid/vettid-vault/vms/suite"

// wipeKey zeroes b (a key Close wipes, or a borrowed copy of one).
func wipeKey(b []byte) { suite.Wipe(b) }
