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
