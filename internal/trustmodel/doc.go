// Package trustmodel is an executable model of VAULT-MESSAGING 0.90.0
// (vettid.org 6b1b4f5): §3.4.1, "Which keys a peer's messages may come
// from", §6.3.1, "Lifetimes and activation on confirmation" (release 29,
// between release-29 vaults and their devices), and §3.4.2, "Relay-key
// rotation between vaults: the rules that close its wait cycles" (RK0 to
// RK15). It is the pass/fail oracle for the release-29 rules of §6.3.2
// (R29-G1 to R29-D4) and for §3.4.2. It is test-only: everything lives in
// _test.go files, it uses the standard library only, and nothing in
// production imports it.
//
// The model is abstract. Keys are integers, signatures are trusted by
// construction (only a key's holder can make a link or a token with it),
// and messages are records. What it checks is the written rules: the
// receiving side (acceptFrom, Tables A and B, rules C, U, T, H5, the
// epoch rules K4 and K7, the received flag F3), the initiator and
// responder halves of §6.3.1 (pending epochs, confirmation, rule E, the
// held queue K5, the reconnect bound K6), the rotating side (S1-S9), the
// device rules (D1-D4; there is no upgrade migration, R29-U1), §3.4.2's
// rules (chosen_test.go) and the invariants I1-I7 of §3.4.1, under random
// runs with crashes, failed writes, locks, time jumps, lease reordering
// and an old-copy actor. The residuals of §3.4.1 are explicit exemptions,
// each counted with its reason, and the device exception (D, with finding
// F) likewise. A random run's device is the member's app (§7.2's unlock
// exchange); a desktop (Party.Desktop) is used only in scenarios.
//
// §3.4.2's rules and their switches (chosen_test.go has each one's
// detail):
//   - RK0, who advertises relay_follow: not modelled; it is an assumption.
//     Every vault in a run implements §3.4.1 and §3.4.2 (the gate is
//     always open between vaults), so no vault rotates its relay key
//     toward a peer that lacks these rules. A device's relay_follow means
//     §3.4.1 alone, and §3.4.2's switches act between vaults only.
//   - RK1, the reconnect after a demotion: release 29 as built, always on
//     (rotate_test.go startHS, r29_test.go).
//   - RK2, RK3, RK4: G2B. RK5: BINDL (the update's identity links) and RK5
//     (its ik requirement). RK6: N1. RK7: N2. RK8: L24. RK9: R25 and S9END.
//     RK10: R27 (an update Q refuses never has its links followed or its
//     tokens kept, with or without it). RK11: G4HS. RK12: RSEENSUSP. RK13:
//     S1PAUSE, and the cap on RK6, RK9, RK10 and RK11. RK14: GRACE14, HOLD
//     and TELL. RK15 is not a rule: the randomized runs check it.
//
// Model limits of §3.4.2: §8.4's ts window is applied only to RK13's
// pause (its past bound; acceptance does not judge ts, and the model's
// clocks are skewed by up to a day); a stale connection ends its held
// deposits at once (stale is final in the model); P's record of
// last_msg_id is taken when the old mailbox ends at the relay (the
// relay's msg_ids are in arrival order, so it is what P's acks give), and
// the telling is queued at P's next tick.
//
// Configurations (TestRandom, TestR29Coverage; genRun):
//   - the oracle config (default): release 29 builds no relay-key
//     rotation, so Table A reduces to current/foreign. Every run starts
//     on release 29 (earlier state is refused and re-enrolled); a
//     quarter of the runs with devices have an app from before release 29
//     (Config.OldApp, R29-D4).
//   - the regression config (TRUSTMODEL_RELAYROT=1): the same with
//     relay-key rotation on (rule U, S1-S3, S9).
//   - TRUSTMODEL_RELAYROT=1 TRUSTMODEL_CHOSEN=1: relay-key rotation with
//     every rule of §3.4.2 (the final set of 0.90.0).
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
// of "stat:<name>", or every stat starting "statprefix:<p1>|<p2>..." per run
// seed, e.g. "statprefix:wait class"), TRUSTMODEL_RULEEFIN=keep (rule E
// keeps an unsent hs.fin, for attribution), TRUSTMODEL_EXTRA_DAY (one more rekey before
// I1), TRUSTMODEL_ROTBURST (each vault rotates 4 to 6 times at the start),
// TRUSTMODEL_CHOSEN (every rule of §3.4.2, the final set; chosen_test.go),
// TRUSTMODEL_CH=a,b,-c (single rules of it on or off, for attribution),
// TRUSTMODEL_NOM1 (0.88.2's links of a refused reconnect off, for
// attribution), TRUSTMODEL_DEBUG (report malformed updates as violations).
//
// Files: relay (relay model), state (messages, state, ik and relay-key
// states), world (parties, writes, deposits, collecting), accept (the
// receiving side), confirm (§6.3.1: pending epochs, confirmation, rule E,
// timers), rotate (the rotating side, handshake starts, unlock, timers),
// r29 (the epoch a reconnect names, the held queue, D4, the
// residuals, hits by rule ID), reach (generators: an old copy as
// responder and as initiator, hs.fin loss around a rotation), run
// (actions, quiescence, I1-I6, shrinking), visible (splits, feed items,
// I7, M2), chosen (§3.4.2's rules behind switches), waitclass (with
// relay-key rotation on, the wait a stale pair or a liveness failure was
// stuck in), coverage (TestR29Coverage: the minimum hit count per rule),
// and the tests: random, scenario, table, findings, blind,
// confirm_scenarios, f_scenarios, rotate_twice, r29_scenarios (with
// finding F's pinned gap), r29_k9_scenarios (R29-K9, K2's pending epoch at
// a link, K4's flag).
package trustmodel
