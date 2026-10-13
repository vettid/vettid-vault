//go:build !linux

package vaultproc

import "errors"

var errEPERM = errors.New("EPERM")

func forbidden() map[string]error { return map[string]error{"unsupported": errors.New("not Linux")} }

type limitResult struct {
	ok     bool
	detail string
}

func limits() map[string]limitResult { return map[string]limitResult{} }

func cpuMicros() int64 { return 0 }

// TryUserNamespace has nothing to try here.
func TryUserNamespace() string { return "not Linux" }
