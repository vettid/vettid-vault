# V2 runtime notes

The V2 runtime follows VAULT-MESSAGING 0.2.3. The body schemas, error codes
and `sync.event` kinds (§10.1–§10.5), the DEK derivation and at-rest formats
(§3.3.1), the token-class rule by collect `jti` (§6.6, RELAY-PROTOCOL
0.4.0), the approval roles and 7-day pending expiry (§6.4, §6.7), the first
app's handshake (§11.3) and the unknown-type rule (§5.3) were settled during
V2 and now live in the spec; vettid.org is the source of truth.

## Not in V2

- Outgoing relay-key rotation (§3.4: dual-mailbox collect during the grace
  period). Both directions of `identity.rotate` are implemented. An
  incoming `relay.address.update` is refused (`relay_unlinked`) until
  rule U (§3.4.1) is built: release 29 rotates no relay key (A5).
  So the rotation of the vault's keys at a completed recovery (§11.14.6
  step 6), after a transfer (§11.14.10) and at `credential.rotate`
  (§3.5.5) rotates `ik`, `kem` and the wake key, but not the relay key:
  no new mailbox or tokens, no `relay.address.update`, and none of §3.4
  "Resending the new address" (the old key kept for deposits, the resends
  at each unlock). It waits for a decision on the order of the relay's
  `POST /v1/mailbox/rotate` and the state write that holds the new key.
- Broadcast spreading over 0–30 s (§9.3, SHOULD) and flush coalescing
  (§8.3, SHOULD).
- Application-level retries of the vault's own requests (§8.6).
- The alternate channel, attestation, leases and memory-pressure locks
  (phase V3).
- LEASH grants, blocks and the remaining features (phase V4).
