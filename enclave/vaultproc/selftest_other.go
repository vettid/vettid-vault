//go:build !linux

package vaultproc

type limitResult struct {
	ok     bool
	detail string
}

func limits() map[string]limitResult { return map[string]limitResult{} }

func cpuMicros() int64 { return 0 }
