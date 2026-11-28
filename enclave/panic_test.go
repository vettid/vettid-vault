package enclave

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vault"
)

// catch runs f and describes its panic as RunRecovered does.
func catch(f func()) (pe *PanicError) {
	defer func() {
		if r := recover(); r != nil {
			pe = panicError(r)
		}
	}()
	f()
	return nil
}

// fakeRuntime implements runtime.Error without being the runtime's.
type fakeRuntime string

func (f fakeRuntime) Error() string { return string(f) }
func (fakeRuntime) RuntimeError()   {}

//go:noinline
func indexPanic(i int) int {
	var a []int
	return a[i]
}

// A panic is told by where it happened and its type, and a runtime error
// by its own text; the value of any other panic is never kept (it could
// hold vault data).
func TestPanicErrorSaysWhereNotWhat(t *testing.T) {
	pe := catch(func() { _ = indexPanic(3) })
	if pe == nil || pe.Type != "runtime.boundsError" || !strings.Contains(pe.Runtime, "index out of range [N]") {
		t.Fatalf("bounds: %+v", pe)
	}
	if len(pe.Frames) == 0 || !strings.HasPrefix(pe.Frames[0], "enclave.indexPanic panic_test.go:") {
		t.Fatalf("frames: %q", pe.Frames)
	}
	if !errors.Is(pe, ErrPanic) {
		t.Fatal("not ErrPanic")
	}
	// A runtime error's numbers may come from vault data: only its words.
	if pe.Runtime != "runtime error: index out of range [N] with length N" {
		t.Fatalf("bounds text: %q", pe.Runtime)
	}
	s := make([]byte, 7, 9)
	n := 12
	if pe := catch(func() { _ = s[:n] }); pe.Runtime != "runtime error: slice bounds out of range [:N] with capacity N" {
		t.Fatalf("slice text: %q", pe.Runtime)
	}
	// Only the runtime's own errors: a type that merely implements
	// runtime.Error keeps nothing of its text.
	if pe := catch(func() { panic(fakeRuntime("pin 424242")) }); pe.Runtime != "" || pe.Type != "enclave.fakeRuntime" {
		t.Fatalf("fake runtime error: %+v", pe)
	}
	for _, v := range []any{"pin 424242", fmt.Errorf("key %x", []byte{0xde, 0xad}), struct{ Secret string }{"424242"}} {
		pe := catch(func() { panic(v) })
		got := fmt.Sprintf("%s %s %q %s", pe.Type, pe.Runtime, pe.Frames, pe.Error())
		if pe.Runtime != "" || strings.Contains(got, "424242") || strings.Contains(got, "dead") {
			t.Fatalf("%T: the value is kept: %s", v, got)
		}
	}
	var deep func(int)
	deep = func(n int) {
		if n == 0 {
			_ = indexPanic(1)
		}
		deep(n - 1)
	}
	if pe := catch(func() { deep(20) }); len(pe.Frames) != maxPanicFrames {
		t.Fatalf("frames kept: %d", len(pe.Frames))
	}
}

// RunRecovered turns a panic in the run loop into a *PanicError, with the
// vault zeroized (a manager that was never opened panics in its start).
func TestRunRecoveredReportsWhereTheLoopPanicked(t *testing.T) {
	m := &vault.Manager{}
	err := RunRecovered(context.Background(), m)
	var pe *PanicError
	if !errors.As(err, &pe) || len(pe.Frames) == 0 || !strings.HasPrefix(pe.Frames[0], "vault.") {
		t.Fatalf("%v %+v", err, pe)
	}
	if !m.Locked() {
		t.Fatal("not zeroized")
	}
}
