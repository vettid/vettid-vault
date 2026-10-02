//go:build !linux

package supervisor

import (
	"errors"
	"syscall"
)

func socketpair() ([2]int, error) {
	return [2]int{}, errors.New("supervisor: vault processes need Linux")
}

func procAttr(int, int) *syscall.SysProcAttr { return nil }

func setLimits(int, ProcConfig) {}

func hardenSelf() []string { return []string{"not Linux"} }
