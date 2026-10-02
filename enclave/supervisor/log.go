package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"syscall"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// logHandler sends sanitized log records to the parent (and the enclave
// console). Callers log fixed messages with ids, counts and error
// sentinels only: never keys, PINs, tokens, envelopes or plaintext
// (§13.6).
type logHandler struct {
	l     *link
	level slog.Level
	attrs []slog.Attr
}

func (h *logHandler) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }

func (h *logHandler) Handle(_ context.Context, r slog.Record) error {
	fields := [][]byte{[]byte(r.Level.String()), []byte(r.Message)}
	add := func(a slog.Attr) bool {
		if len(fields) < hostproto.MaxFields-1 {
			fields = append(fields, []byte(a.Key), []byte(a.Value.String()))
		}
		return true
	}
	for _, a := range h.attrs {
		add(a)
	}
	r.Attrs(add)
	h.l.notify(hostproto.KindLog, fields...)
	line := r.Level.String() + " " + r.Message
	for i := 2; i+1 < len(fields); i += 2 {
		line += " " + string(fields[i]) + "=" + string(fields[i+1])
	}
	fmt.Fprintln(os.Stderr, line)
	return nil
}

func (h *logHandler) WithAttrs(as []slog.Attr) slog.Handler {
	return &logHandler{l: h.l, level: h.level, attrs: append(append([]slog.Attr(nil), h.attrs...), as...)}
}

func (h *logHandler) WithGroup(string) slog.Handler { return h }

// errText reduces an error to non-secret text: sentinel errors of this
// code base carry no input data; network errors are reduced to their
// class.
func errText(err error) string {
	if err == nil {
		return ""
	}
	// File-system and system-call errors first: syscall.Errno also
	// satisfies net.Error, which made a missing file read "network error".
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Op + " " + pe.Path + ": " + pe.Err.Error()
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno.Error()
	}
	var ne net.Error
	if errors.As(err, &ne) {
		if ne.Timeout() {
			return "network timeout"
		}
		return "network error"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return "canceled"
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
