// Package trustmodel is an executable model of VAULT-MESSAGING 0.85.0
// (draft) §3.4.1, "Which keys a peer's messages may come from", at
// vettid.org f4a4d97. It is test-only: everything lives in _test.go
// files, and nothing in production imports it.
//
// The model is abstract. Keys are integers, signatures are trusted by
// construction (only a key's holder can make a link or a token with it),
// and messages are records. What it checks is the written rules: the
// receiving side (acceptFrom, Tables A and B, rules C, U, T, H5), the
// rotating side (S1-S9), and the invariants I1-I5, under random runs
// with crashes, failed writes, locks, time jumps, lease reordering and
// an old-copy actor.
//
// Run: go test ./internal/trustmodel/ -run . -v
// Env: TRUSTMODEL_RUNS (default 3000), TRUSTMODEL_SEED (default 1),
// TRUSTMODEL_STEPS (actions per run, default 40), TRUSTMODEL_STRICT (fail
// TestRandom on any violation), TRUSTMODEL_TRACE (print scenario traces),
// TRUSTMODEL_DEBUG (report malformed updates as violations).
//
// Files: relay (relay model), state (messages, state, ik and relay-key
// states), world (parties, writes, deposits, collecting), accept (the
// receiving side), rotate (the rotating side, unlock, timers), run
// (actions, quiescence, I1-I5, shrinking), random/scenario/table/findings
// (the tests).
package trustmodel
