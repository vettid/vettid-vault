package enclave

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vault"
)

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
