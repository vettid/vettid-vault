//go:build !linux

package supervisor

import "errors"

func lockdownMode() (string, error)       { return "", errors.New("not Linux") }
func checkLockdown() error                { return errors.New("not Linux") }
func lockdownConfidentiality(string) bool { return false }
func modulesAbsent() error                { return errors.New("not Linux") }
func kaslrStatus() string                 { return "not Linux" }
