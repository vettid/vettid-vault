//go:build linux

package nsm

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ioctlRequest is NSM_IOCTL_REQUEST = _IOWR(0x0A, 0, struct nsm_message),
// where struct nsm_message is two struct iovec (request, response).
const ioctlRequest = 3<<30 | uint(unsafe.Sizeof(message{}))<<16 | 0x0A<<8 // number 0

type message struct {
	req, resp unix.Iovec
}

type fileDevice struct{ f *os.File }

func openDevice(path string) (device, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	return &fileDevice{f: f}, nil
}

func (d *fileDevice) close() error { return d.f.Close() }

// call passes req and a response buffer to the driver; the driver sets the
// response iovec's length to the bytes written.
func (d *fileDevice) call(req []byte) ([]byte, error) {
	if len(req) == 0 {
		return nil, ErrField
	}
	resp := make([]byte, maxResponse)
	m := message{}
	m.req.Base = &req[0]
	m.req.SetLen(len(req))
	m.resp.Base = &resp[0]
	m.resp.SetLen(len(resp))
	rc, err := d.f.SyscallConn()
	if err != nil {
		return nil, ErrDevice
	}
	var errno unix.Errno
	cerr := rc.Control(func(fd uintptr) {
		_, _, errno = unix.Syscall(unix.SYS_IOCTL, fd, uintptr(ioctlRequest), uintptr(unsafe.Pointer(&m)))
	})
	runtime.KeepAlive(req)
	runtime.KeepAlive(resp)
	if cerr != nil || errno != 0 {
		return nil, ErrDevice
	}
	n := int(m.resp.Len)
	if n <= 0 || n > len(resp) {
		return nil, ErrResponse
	}
	return resp[:n], nil
}

func ioctlNumber() uint { return ioctlRequest }
