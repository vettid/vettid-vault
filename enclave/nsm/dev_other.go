//go:build !linux

package nsm

func openDevice(string) (device, error) { return nil, ErrDevice }

func ioctlNumber() uint { return 0xc0200a00 }
