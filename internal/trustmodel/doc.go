// Package trustmodel is an executable model of VAULT-MESSAGING 0.87.1
// (vettid.org 4734dfd8), with the 0.88.1 erratum (vettid.org #554 at
// 9839e49: hs.confirm again after 12 days; hs.resp sets no flag), §3.4.1, "Which keys a peer's messages may come
// from", and §6.3.1, "Lifetimes and activation on confirmation": release
// 29, between release-29 vaults and their devices. It is the pass/fail
// oracle for the release-29 rules of §6.3.2 (R29-G1 to R29-D4). It is
// test-only: everything lives in _test.go files, and nothing in
// production imports it.
//
// The model is abstract. Keys are integers, signatures are trusted by
// construction (only a key's holder can make a link or a token with it),
// and messages are records. What it checks is the written rules: the
// receiving side (acceptFrom, Tables A and B, rules C, U, T, H5, the
// epoch rules K4 and K7, the received flag F3), the initiator and
// responder halves of §6.3.1 (pending epochs, confirmation, rule E, the
// held queue K5, the reconnect bound K6), the rotating side (S1-S9), the
// device rules (D1-D4; 0.87.1: there is no upgrade migration, R29-U1), and the invariants
// I1-I7 of §3.4.1, under random runs with crashes, failed writes, locks,
// time jumps, lease reordering and an old-copy actor. The residuals of
// §3.4.1 are explicit exemptions, each counted with its reason, and the
// device exception (D, with finding F) likewise. A random run's device is
// the member's app (§7.2's unlock exchange); a desktop (Party.Desktop) is
// used only in scenarios.
//
// Configurations (TestRandom, TestR29Coverage; genRun):
//   - the oracle config (default): release 29 builds no relay-key
//     rotation, so Table A reduces to current/foreign. Every run starts
//     on release 29 (0.87.1: earlier state is refused and re-enrolled); a
//     quarter of the runs with devices have an app from before release 29
//     (Config.OldApp, R29-D4).
//   - the regression config (TRUSTMODEL_RELAYROT=1): the same with
//     relay-key rotation on (rule U, S1-S3, S9).
//   - TRUSTMODEL_OLD=1: the f4a4d97 rules throughout (no §6.3.1).
//
// Run: go test ./internal/trustmodel/ -run . -v
// Env: TRUSTMODEL_RUNS (default 3000), TRUSTMODEL_SEED (default 1),
// TRUSTMODEL_STEPS (actions per run, default 40), TRUSTMODEL_LENIENT (TestRandom
// reports violations without failing; by default any violation fails it), TRUSTMODEL_RELAYROT (the regression
// config), TRUSTMODEL_COVRUNS (TestR29Coverage's runs, default 3000),
// TRUSTMODEL_MINHITS (its minimum hits per rule and branch, default 3),
// TRUSTMODEL_NOSKEW (no clock skew), TRUSTMODEL_TRACE (print scenario
// traces), TRUSTMODEL_TRACESEED and TRUSTMODEL_CLASS (TestSeedsByClass:
// shrink and trace one run seed, or list the seeds of a violation class or
// of "stat:<name>"), TRUSTMODEL_RULEEFIN=keep (rule E keeps an unsent
// hs.fin, for attribution), TRUSTMODEL_EXTRA_DAY (one more rekey before
// I1), TRUSTMODEL_DEBUG (report malformed updates as violations).
//
// Files: relay (relay model), state (messages, state, ik and relay-key
// states), world (parties, writes, deposits, collecting), accept (the
// receiving side), confirm (§6.3.1: pending epochs, confirmation, rule E,
// timers), rotate (the rotating side, handshake starts, unlock, timers),
// r29 (the epoch a reconnect names, the held queue, D4, the
// residuals, hits by rule ID), reach (generators: an old copy as
// responder and as initiator, hs.fin loss around a rotation), run
// (actions, quiescence, I1-I6, shrinking), visible (splits, feed items,
// I7), coverage (TestR29Coverage: the minimum hit count per rule), and
// the tests: random, scenario, table, findings, blind, confirm_scenarios,
// f_scenarios, rotate_twice, r29_scenarios (with finding F's pinned gap),
// r29_k9_scenarios (R29-K9, K2's pending epoch at a link, K4's flag).
package trustmodel
