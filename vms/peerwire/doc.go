// Package peerwire is the wire level of a VMS v2 connection peer
// (VAULT-MESSAGING §1.1): what a principal that connects to a member's
// vault as an ordinary `connection` sends and checks besides the
// envelope, the handshake and the invitation (vms/envelope,
// vms/handshake, vms/invite):
//
//   - member authentication between connections (§10.4,
//     connection.authenticate.*): the signed message, the challenge and
//     response bodies, the response's verification and the pinned key's
//     rotations (vms/credwire);
//   - the tokens of a connection (§7.1, §7.2): their kinds, lifetimes,
//     quotas and refresh thresholds, the check of a token a peer issued,
//     and the relay.token.issued and relay.token.refresh bodies;
//   - the lifecycle bodies of a connection (§6.4, §7.4):
//     connection.approved, connection.declined and connection.removed;
//   - the shared profile's core (§6.2, §10.8): the account names and the
//     profile.update body.
//
// The member's vault runs the same code (package vault and its features),
// so that a peer built on this package outside the vault (a service vault,
// §1.1) speaks the bytes the vault speaks. Parsers are strict and return
// fixed sentinel errors (§13.6).
package peerwire
