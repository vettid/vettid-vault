# V2 runtime notes

The V2 runtime follows VAULT-MESSAGING 0.2.3. The body schemas, error codes
and `sync.event` kinds (§10.1–§10.5), the DEK derivation and at-rest formats
(§3.3.1), the token-class rule by collect `jti` (§6.6, RELAY-PROTOCOL
0.4.0), the approval roles and 7-day pending expiry (§6.4, §6.7), the first
app's handshake (§11.3) and the unknown-type rule (§5.3) were settled during
V2 and now live in the spec; vettid.org is the source of truth.

## Not in V2

- Outgoing relay-key rotation (§3.4: dual-mailbox collect during the grace
  period). Incoming `relay.address.update` and both directions of
  `identity.rotate` are implemented.
- Broadcast spreading over 0–30 s (§9.3, SHOULD) and flush coalescing
  (§8.3, SHOULD).
- Application-level retries of the vault's own requests (§8.6).
- The alternate channel, attestation, leases and memory-pressure locks
  (phase V3).
- LEASH grants, blocks and the remaining features (phase V4).
