//go:build !linux

package vaultproc

type limitResult struct {
	ok     bool
	detail string
}

func limits() map[string]limitResult { return map[string]limitResult{} }

func nprocLimit() (limitResult, bool) { return limitResult{}, false }

func cpuMicros() int64 { return 0 }

// TryUserNamespace has nothing to try here.
func TryUserNamespace() string { return "not Linux" }
