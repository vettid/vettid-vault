package wallet_test

import (
	"testing"
)

// §3.5.4 "Using a UTK", §10.18 (0.52.0): wallet.sign spends its UTK
// before any check: credential_locked outside the unlock window, and an
// unknown wallet's not_found, both leave it spent.
func TestSignRefusalsSpendTheUTK(t *testing.T) {
	e := newEnv(t, &fakeChain{})
	id, a := e.importAbandon()
	raw := psbtFor(t, a, payee, 70000, 39000)
	next := func() utk {
		if len(e.utks) == 0 {
			e.ok(e.call("app", "credential.utk.get", `{}`))
		}
		return e.utks[0]
	}
	e.ok(e.call("app", "credential.lock", `{}`))
	u := next()
	e.code(e.sign(id, raw, nil), "credential_locked")
	e.unlock()
	e.utks = append([]utk{u}, e.utks...) // the same UTK again
	e.code(e.sign(id, raw, nil), "utk_invalid")
	u = next()
	e.code(e.sign("01JB2Z6V9K3M4N5P6Q7R8S9T0V", raw, nil), "not_found")
	e.utks = append([]utk{u}, e.utks...)
	e.code(e.sign(id, raw, nil), "utk_invalid")
	e.ok(e.sign(id, raw, nil)) // a fresh UTK signs
}
