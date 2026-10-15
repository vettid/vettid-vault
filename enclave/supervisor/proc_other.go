//go:build !linux

package supervisor

import (
	"errors"
	"syscall"
)

func socketpair() ([2]int, error) {
	return [2]int{}, errors.New("supervisor: vault processes need Linux")
}

func procAttr(int) *syscall.SysProcAttr { return nil }

func onSpawnerThread(f func()) { f() }

func setLimits(int, ProcConfig, bool) {}

func sweepUID(int) error { return errors.New("not Linux") }

func closeNSM() error { return errors.New("not Linux") }

func pid1() string                        { return "not Linux" }
func zombies() (all, ours int, err error) { return 0, 0, errors.New("not Linux") }
func nsmClosedCheck() error               { return errors.New("not Linux") }

func hardenSelf() []string { return []string{"not Linux"} }

func closeUserNamespaces() error     { return errors.New("not Linux") }
func userNamespacesClosed() error    { return errors.New("not Linux") }
func disableUnprivilegedBPF() error  { return errors.New("not Linux") }
func unprivilegedBPFDisabled() error { return errors.New("not Linux") }

func supervisorDumpable() (int, error) { return -1, errors.New("not Linux") }

func selfCPUMicros() int64 { return 0 }

func makeSysctls() []string { return []string{"kernel settings: not Linux"} }

type sysctlStatus struct {
	check, detail string
	ok, provable  bool
}

func sysctlStatuses() []sysctlStatus { return nil }
