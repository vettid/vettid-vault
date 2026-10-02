# V2 runtime notes

Phase V2 (VAULT-PLAN §4) implements the vault runtime in dev mode. This file
records what VAULT-MESSAGING 0.2.2 does not yet specify and how the runtime
fills it in, pending spec follow-ups. vettid.org remains the source of
truth; everything here is proposed spec text.

## Body schemas used by V2

All bodies are JSON objects; unknown members are ignored; strings are
bounded (4 KiB unless stated). Timestamps use the inner `ts` format
(`YYYY-MM-DDTHH:MM:SS.mmmZ`); invite and pairing expiries in responses are
RFC 3339 whole seconds.

### Lifecycle and sessions

| Type | Dir | Request body | Response / event body |
|---|---|---|---|
| `vault.enrolled` | V→D sealed | — | `{request_id, vault_id, state_seq, vault_bundle: b64({v, suite, vault: {ik, kem, relay}}), token, attestation?}` (dev builds omit `attestation`) |
| `vault.enroll.confirm` | D→V req (app) | `{}` | `{}` |
| `vault.status` | D→V req | `{}` | `{vault_id, state_seq, header_seq, provisional, devices, connections}` |
| `vault.lock` | D→V req (app, desktop) | `{}` | `{}`; then `vault.locking` |
| `vault.locking` | V→D ephemeral | — | `{}` with `exp` = now + 60 s |
| `relay.token.issued` | any | — | `{kind: "standing"\|"reconnect", token}` |
| `relay.token.refresh` | any req | `{}` | `{kind: "standing", token}` |
| `identity.rotate` | V→D, V↔V | — | `{rotation: <identity.rotate statement, §3.4>}` |
| `relay.address.update` | any | — | `{relay: {url, mailbox, pk}, token, reconnect_token?}` |
| `sync.event` | V→D | — | `{kind, ...}`; kinds used: `message.receipt` `{connection_id, message_id, receipt}`, `message.read` `{connection_id, message_id}`, `device.paired` `{device_id, role}`, `device.unlinked` `{device_id}` |

### Devices (§6.7)

| Type | Dir | Request body | Response / event body |
|---|---|---|---|
| `device.pair.create` | D→V req (app) | `{role: "app"\|"desktop"\|"agent"}` | `{pairing_id, link, exp}` |
| `device.pair.pending` | V→D (apps) | — | `{pairing_id, pending_id, role, name, sas}` (`name` from the new device's self-asserted `profile.name`) |
| `device.pair.approve` / `.reject` | D→V req (app) | `{pairing_id}` | `{}` |
| `device.paired` | V→D (new device) | — | `{device_id, role, vault_id}` |
| `device.list` | D→V req | `{}` | `{devices: [{id, kind, state, name, ik, profile?}]}` |
| `device.unlink` | D→V req (app) | `{device_id}` | `{}` |
| `device.unlinked` | V→D (the unlinked device, best effort) | — | `{}` |

### Connections (§6.4)

| Type | Dir | Request body | Response / event body |
|---|---|---|---|
| `connection.invite.create` | D→V req | `{ttl_seconds: 600\|3600\|86400\|604800}` | `{invite_id, link, exp, remote}` |
| `connection.invite.list` | D→V req | `{}` | `{invites: [{invite_id, exp, remote}]}` |
| `connection.invite.cancel` | D→V req | `{invite_id}` | `{}` |
| `connection.invite.accept` | D→V req | `{link}` | `{connection_id, state: "pending"}` |
| `connection.request.pending` | V→D | — | `{pending_id, invite_id, sas, remote, profile?}` |
| `connection.approve` / `.decline` | D→V req | `{pending_id}` | `{}` |
| `connection.list` | D→V req | `{}` | `{connections: [{id, kind, state, name, ik, profile?}]}` |
| `connection.get` | D→V req | `{connection_id}` | `{id, kind, state, name, ik, profile?}` |
| `connection.remove` | D→V req | `{connection_id}` | `{}` |
| `connection.removed` | V↔V | — | `{}` |
| `connection.event` | V→D | — | `{connection_id, event: "added"\|"removed"\|"stale"\|"rekeyed"\|"reconnected"\|"failed"}` |

### Messaging (§10)

| Type | Dir | Request body | Response / event body |
|---|---|---|---|
| `message.send` | D→V req | `{connection_id, text}` (text 1–16 KiB; larger content uses the blob flow, §5.5) | `{message_id, sent_at}` |
| `message.deliver` | V↔V | — | `{message_id (ULID), text, sent_at}`; idempotent by `message_id` |
| `message.receipt` | V↔V | — | `{message_id, receipt: "delivered"\|"read", at}` |
| `message.new` | V→D | — | `{connection_id, message_id, direction: "in"\|"out", text, sent_at, delivered, read}` |
| `message.list` | D→V req | `{connection_id, limit? (1–500, default 100)}` | `{messages: [<message.new body>...]}` oldest first |
| `message.get` | D→V req | `{connection_id, message_id}` | `<message.new body>` |
| `message.read` | D→V req | `{connection_id, message_id}` | `{}`; sends a read receipt |
| `message.delete` | D→V req | `{connection_id, message_id}` | `{}` (local only) |

Error codes used: `bad_request`, `not_found`, `forbidden`, `unsupported_type`,
`internal`, `relay_error`, `ttl_not_allowed`, `claim_unavailable`,
`accept_failed`, `approve_failed`, `connection_unavailable`.

## At-rest formats (enclave-internal)

- **DEK.** `x = Argon2id(PIN, salt, t, m, p, 32)`;
  `DEK = HKDF-SHA-256(ikm = x, salt = pepper, info = "vettid/vms/2/dek" || vault_id, 32)`.
  `{alg: "argon2id", t, m, p, salt (16 B)}` and a random 32-byte `pepper`
  live in the sealed header, so stolen state cannot be brute-forced
  outside the enclave. Defaults t=3, m=64 MiB, p=1; minimum t=1, m=8 MiB.
- **State object.** `0x01 || state_seq (8, BE) || nonce (24) || XChaCha20-Poly1305(DEK, nonce, aad, json)`,
  `aad = "vettid/vms/2/state" || 0x00 || vault_id || 0x00 || blob[0:9]`.
- **Sealed header.** JSON sealed by the `Sealer` with
  `aad = "vettid/vms/2/header" || 0x00 || vault_id`.
- **Store.** Objects `vaults/<vault_id>/state` and `vaults/<vault_id>/header`,
  written create-only at enrollment and with version-matched conditional
  writes afterwards.

## Spec issues and proposed text

1. **§3.3, §11 — DEK derivation is unspecified.** Proposed: the text under
   "At-rest formats / DEK" above, as a new §11.4.1.
2. **§6.6 — the recipient cannot observe the token class.** Collect results
   carry `sender` but not the token used, so "the collect `sender` together
   with the envelope tells it which token class was used" holds only
   heuristically. The runtime treats a deposit from a known connection as
   made on its reconnect token when the vault holds no unexpired, unrevoked
   standing token issued to that sender. Proposed (RELAY-PROTOCOL): collect
   results include the deposit token's `jti`; VAULT-MESSAGING §6.6: "The
   vault MUST drop and audit any message other than a sealed `hs.init` with
   purpose `reconnect` whose collect `jti` is a reconnect token's."
3. **§11.3 — the first app's handshake.** `ctx` is unspecified and approval
   rules are implicit. Proposed: "The first app's `hs.init` uses purpose
   `app` and `ctx` = `vault_id`. The vault answers without approval if
   `from.ik` and the collect `sender` equal the keys bound at enrollment,
   within the 24 h provisional window."
4. **§5.3 — unknown types.** A receiver cannot tell a request from an event
   when it does not know the type. Proposed: "A message without `re` whose
   `type` is unknown is answered with `unsupported_type`; a sender that did
   not expect a response drops it (§8.1)."
5. **§6.4 — how long a remote connection request stays pending.** Proposed:
   "at most 7 days (the longest invite TTL); then it is dropped".
6. **§6.7 / §6.4 — who approves.** Proposed: "Only role `app` creates and
   approves pairings. Connection requests are approved by an app or a
   desktop. Agents do neither."
7. **§6.7 — re-pairing with an old relay key.** The vault also refuses an
   `hs.init` whose collect `sender` is a relay key it denylisted (the relay
   may not, for open tokens). Proposed: "The vault MUST refuse an `hs.init`
   from a relay key it has denylisted."
8. **§7.1 — `iat` backdating.** The spec says 60 s; `relayclient` backdates
   30 s. Either is fine for the relay; the spec and client should agree.
   Note that token lifetimes are measured from the backdated `iat`.
9. **§9.1 — device notifications.** `device.paired`/`device.unlinked` go to
   the device concerned; other owner devices learn of it through `sync.event`
   (kinds above). Proposed: list these `sync.event` kinds in §10.
10. **§12.3 — inactive epochs.** Implemented as: a message in a handshake's
    new epoch that arrives before `hs.fin` is left unacked; a bad `hs.fin`
    is acked and dropped (0.2.2 §6.3).

## Not in V2

- Outgoing relay-key rotation (§3.4: dual-mailbox collect during grace).
  Incoming `relay.address.update` and both directions of `identity.rotate`
  are implemented.
- Broadcast spreading over 0–30 s (§9.3, SHOULD) and flush coalescing
  (§8.3, SHOULD).
- Application-level retries of the vault's own requests (§8.6).
- Alternate channel, attestation, leases, memory-pressure locks (V3);
  LEASH grants, blocks and the other features (V4).
