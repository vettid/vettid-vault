# V4 notes

Batch 1 (credential, secrets, profile, audit, feed) first; batch 2
(connections polish, calls, device and agent sessions) at the end.

## Batch 1

Batch 1 of the feature port (VAULT-PLAN §4 V4): the Protean Credential and
critical secrets, vault-held secrets, profile (with personal data),
settings, audit, feed and guides. It follows VAULT-MESSAGING 0.4.0
(§3.5, §10.6–§10.9); vettid.org is the source of truth.

## Layout

- `features/credential`, `features/secrets`, `features/profile`,
  `features/audit`, `features/feed`; `features/all` builds one vault's set
  (fresh instances per vault, no package-level state).
- Settings live in the runtime (`vault/settings.go`): they are owner policy
  read by the runtime (in-person auto-approval) and by several features.
- The runtime gained a `Host` behind `Session` (so feature tests drive
  handlers through `internal/featuretest`), `Activity` with
  `ActivitySink` (audit and feed), `ConnectionObserver` (profile.update on
  activation), `HandshakeProfiler` (display name in `hs.init` and the
  invite hint) and `Zeroizer` (the credential unlock window).

## Ported, changed or dropped (from vettid.dev vault-manager)

| Old | Now | Why |
|---|---|---|
| UTK/LTK transport key pairs, `new_utks` in responses | Restored in 0.4.1 as hybrid one-time keys (see below) | Owner review: they limit a compromise of the device's session |
| CEK (X25519 ECIES) | CEK is an MLKEM768X25519 key; HPKE suite 2 | PQC Phase 1 (§1.1 item 7) |
| Password PHC hash computed by the app and compared in the vault | The password itself, inside the session; Argon2id in the enclave; the check is the blob's inner AEAD | The PHC string was a password equivalent; the inner layer also keeps the vault from opening the credential alone |
| `credential.store`, `credential.sync` (app uploads a blob) | Folded into create/rotate/change: the vault produces every version and records it | An uploaded blob could only roll the credential back |
| `credential.get`, `credential.version`, `credential.delete`, `credential.password-change`, `credential.identity-unlock` | `credential.get`, `.version`, `.delete` (now needs the password), `.password.change`, `.unlock` (+ `.lock`) | |
| `credential.secret.add/get/list/delete` | Same; `set-discoverability` deferred to grants | Discoverability only matters to the catalog (grants, batch 3) |
| `credential/sealed_blob` copy in vault storage | Kept (`KeepCopy`), OWNER DECISION §3.5.6 | Lets other apps fetch the credential; useless without the password |
| PIN hash and salt in the credential; master secret; identity key in the credential | Dropped; the credential key replaces the identity key | The PIN is checked by DEK derivation; the master secret was never used; the vault `ik` must sign handshakes without the member |
| `credential.migration.*` | Dropped | Release moves are §11.10 |
| Session TTL setting (`settings.credential`) | `credential.unlock_ttl_seconds` | |
| Derived audit key and per-entry signatures; `audit.binding` | Hash chain only | The log never leaves the E2E session and DEK state is integrity-protected and rollback-checked; no verifier needed the signatures |
| `audit.query`, `audit.export`, `connection.audit.list`, `connection.audit.search` | `audit.list`, `connection.audit.list` | Export and CSV are client concerns; full-text search had nothing to search once audit rows carry no message previews |
| Audit rows with message previews (120 characters) | No content in the audit log | Content stays in messaging |
| `feed.read/archive/set-priority/action/sync`, feed settings | `feed.update`, `feed.list{after_seq}`, `feed.retention_days` | |
| Vault-composed feed titles ("From Alice") | `kind` + references; apps render | No i18n in the vault |
| `profile.publish`, `.broadcast`, `.get-published`, `.public.*`, retained NATS profile | `shared` + `profile.update` per connection | §9.3; no retained or public profile |
| `profile.sharing-settings` (per-connection overrides) | Deferred to grants (batch 3) | Per-connection disclosure is what grants do |
| `profile.categories.*` | `app.*` settings | UI metadata the vault does not interpret |
| `personal-data.*` and its sort order | Profile fields with labels and `order` | One store |
| Registration "system" fields | Ordinary fields set by the app | The member API sends nothing to the vault |
| `settings.notifications.*`, `notifications.digest`, `notification.profile-broadcast`, `notification.revoke-notify` | Dropped | Notification settings govern push, which is deferred (§14). The digest read keys nothing wrote (`feed/_index`), so it always returned an empty list. The broadcasts are `profile.update` and `connection.removed` |
| `secrets.*` add/update/retrieve/set-discoverability | `secret.put/get/list/delete` with versions | §8.4 |

## Memory hygiene

The credential's plaintext, `x` and `K_pw` are wiped after each
operation; responses carrying a critical secret's value (`Volatile` types)
never reach vault state. The password and the value inside the request
arrive as Go strings in the decoded inner plaintext and cannot be wiped;
they live until garbage collection in the vault's own process, which
exits at lock (§12.4).

## Not in batch 1

- `pin.change`: specified as a type in §10.6. Its crash-safe write order (the
  state under the new DEK and the header with the new KDF must not be able
  to disagree) is a follow-up.
- Broadcast spreading (§9.3): still not done. A delayed deposit would hold
  back later messages to the same peer, and the spec now says so.
- Signing with the credential key: the unlock window exists (`UseKey`). The
  features that sign (connection authenticate, actions) come later.

## Recovery (0.4.1)

- `vault/recovery.go`: header-only operations (`RecoveryRequest`,
  `RecoveryCancel`, `RecoveryRegister`) that run in the vault's process
  without the PIN, and the unlock-side rules (`recovery_pending`,
  `cancel_recovery`, the recovered app's invite, restricted device,
  `completeRecovery`).
- `enclave/recovery.go`: the three queue operations; `Config.RecoveryNow`
  is the injectable clock of the delay and expiry (tests only; release
  configurations leave it nil).
- `vms/altchan/recovery.go`: the register request and result, the
  browser-sealed code (P-256 + HKDF + AES-GCM, the one non-PQ key agreement,
  §11.11.2), the QR payload.
- `Host.LockReason` carries the lock reason to the vault process over the
  channel (`KindLock` gains an optional field), so the owner's devices get
  `vault.locking{reason: "recovery"}`.
- The parent forwards the three new operations without taking the lease.

Not carried over from vettid.dev: its backup worker, the placeholder
portal upload, the three recovery flows, the route that skipped the 24 h
delay, QR rendering through Google Charts and the parent-supplied
`backup_key`. Recovery is one flow; the code never leaves the enclave
except sealed to the member's browser.

Not here: the portal pages (request, QR, cancel link) and vaultctl
commands for recovery (the e2e tests drive the client package directly).

## Protean Credential corrections (0.4.1, owner review)

The batch-1 port deviated from the owner's Protean Credential design
(vettid-dev `docs/protean_credential_system_design.md`); 0.4.1 restores it:

- **CEK rotation on every use.** Every operation that opens the blob seals
  the content under a new CEK as the next version and destroys the old CEK
  (`rotateCEK`), so earlier blobs cannot be opened by anyone. The latest
  blob is kept until the app confirms it (`credential.ack`, or the next use
  of that version); responses are cached (§8.2), so a lost response is
  recovered by retransmission or `credential.get`.
- **UTK/LTK restored** as MLKEM768X25519 one-time keys (`vms/credwire`):
  pools of 20 per app, refilled by 10 under 10, 30-day expiry, spent before
  anything else is checked, bound to the device, the type and the inner id.
  Secret values return sealed to a one-time reply key, so
  `credential.secret.get` no longer needs the volatile-response rule (the
  runtime keeps the rule for future types).
- **LAT** is superseded by Nitro attestation (decision 2026-01-08).
- **A credential is required** (§3.5.7): `vault.CredentialGate`; the runtime
  answers `credential_required` to all but the listed types and records
  `has_credential` in the sealed header; `vault.enroll.confirm` needs the
  credential, so an enrollment without one stays provisional.
- **Recovery** never completes without the credential: refused at the
  request for a vault without one (sealed `no_credential` to the browser),
  and with backup off the recovered app supplies the member's own blob.

The client keeps the UTK pool and the latest blob, confirms every new blob,
refetches on `stale_credential`, and opens reply-sealed values
(`client/credential.go`). `vaultctl credential recover -value-file` takes
the member's own blob.

## Batch 2: connections, calls, device and agent sessions (0.5.0)

Follows VAULT-MESSAGING 0.5.0 (§6.8, §10.3, §10.4, §10.10).

### Layout

- `vault/access.go`: access sessions and approvals (§6.8) in the
  runtime: the session gate in dispatch, step-up holding
  (`TypeSpec.DesktopApproval`), `approval.*`, and the LEASH hook
  (`vault.AgentPolicy`).
- `vault/connections.go`: `connection.update`, the block list, the
  listing fields, `ConnectionRemovedObserver`.
- `features/calls` + `vms/callwire`: call signalling, the ICE issuer
  interface (`calls.ICEIssuer`; `NoServers` default, `Coturn` HMAC
  implementation), the signed ICE configuration and the device-side call
  key. `Host.SignICEConfig` lets the feature get a configuration signed
  by the vault's `ik` without holding it; the runtime signs only bytes
  that parse as an ICE configuration.
- `features/connauth`: member authentication; it signs through the
  credential feature's unlock window (`credential.Feature.UseKey`, wired in
  `features/all`).
- Runtime additions for features: `Host.Send` to one principal with
  `SendOptions{Exp, MemoryOnly}` (ephemeral forwards never reach vault
  state), `NotifyDevicesWith`, `Device`, `IdentityKey`; `PeerInfo.IK`.

### Ported, changed or dropped (from vettid.dev vault-manager)

| Old | Now | Why |
|---|---|---|
| `block.add/remove` = a call-only blocklist of owner-space ids, with reason and duration | `block.add{connection_id \| pending_id, note?}`, `.remove`, `.list`: §7.4 "Peer blocked" (removal, tokens denylisted by jti) plus an entry on the peer's `ik` and relay key that refuses its handshakes | The spec's revocation already defined blocking; a timed block of a removed connection would only re-allow invitations, which `block.remove` does |
| `connection-authenticate.request/approve/deny/get/list`, signed with the identity key decrypted from the credential with a password hash | `connection.authenticate.*`, signed with the **credential key** within the unlock window (`credential.unlock` first), binary signed string over both vaults' `ik`s, nonce, request id and context; the requester pins the key | The vault `ik` (which signs handshakes) is no longer in the credential; the credential key is the member's. OWNER DECISION 2 |
| `connection.update{tags, is_favorite, is_archived, peer_alias}` | `connection.update{version, alias, note, tags, favorite, archived}`, versioned | §10.1 versioned objects |
| Connection-card extras (message preview, unread count, last call, needs-attention, credential expiry, key rotation count) | `created_at`, `last_active_at` only | Previews and counts are app concerns from `message.list`/`call.list`; rotation and expiry are runtime internals |
| `connection.rotate` (new X25519 pair) | Dropped | Rekeys (§6.5) and `identity.rotate` replace it |
| Per-call X25519 pair in the vault; `shared_secret` sent to the app in `call.accepted` | The calling device generates an MLKEM768X25519 key; the answering device encapsulates; vaults relay `ek`/`enc` and never hold `k_call` | PQC Phase 1; no media key in vault state or the response cache. OWNER DECISION 3 |
| `call.initiate/accept/reject/cancel/offer/answer/candidate/busy/blocked` peer events; `call.start/accept/reject/end/signal` app ops | `call.start` (req), `call.offer`, `call.answer`, `call.ice`, `call.ringing`, `call.end{reason}`, `call.list` | One message per signalling step; rejection, cancel, busy and blocked are `call.end` reasons (blocked peers are removed, so they cannot call) |
| `call.turn-credentials` (Cloudflare via the parent) | `ICEIssuer` in the vault, the configuration signed by the vault and delivered inside `call.start`/`call.offer` | CALLING-SERVICE §5–§6; the parent holds no TURN secret. No calling service exists yet: the default issues no servers |
| `call.history`, `call.mark-seen` | `call.list`; missed calls are feed items (read state in the feed) | |
| Caller display name resolved from the profile | Devices show the connection's `name`/`profile` | The callee already holds it |
| Event replay protection by event id and a 5-minute freshness window | Inner-id dedupe (§8.2), `exp`, `ts` window (§8.4) | Runtime rules |
| `device.request-session` / `authorize-session` / `extend-session` / `end-session` with an X25519 session key and approval token | `device.session.request/approve/deny/end`, `device.session.granted/ended`; extension is a new request | The §6 handshake already gives the E2E session; the access session is only authorization |
| `force_replace` / one active desktop session per owner | Dropped | Each desktop is paired and authorized separately |
| Desktop "independent" vs "phone-required" capability lists, phone heartbeat freshness | Desktop types per §10 roles, step-up types held for an app's approval (`approval.*`); no heartbeat | Role lists are in the registry; presence is on demand only (§9.2) |
| `agent.*` runtime (secret requests, http_request/sign actions, catalog, agent chat, approvals, rate limits), agent pairing stage 2 | Agent access sessions and the `AgentPolicy` hook; everything else waits for LEASH (batch 3) | Least privilege: without grants an agent may only ask for a session and read `vault.status` |
| `agent.approval.pending` / `.decide` (registry) | `approval.pending`, `approval.waiting`, `approval.decide` for desktops and agents | One mechanism |

### OWNER DECISIONS (decided at review)

1. **Desktops need an app-approved access session**, and their step-up
   requests need an app's approval each. Agreed.
2. **`connection.authenticate` proves the member** with the credential
   key. Kept, and credential-key rotation is followed: `credential.rotate`
   signs a statement with the old and the new key (`vms/credwire`
   `KeyRotation`), the connection that pinned the member's key gets the
   chain (`connection.authenticate.rotated`, and `rotations` in later
   responses) and moves its pin; a chain that does not verify is
   rejected and the change reported as `key_changed`.
3. **Media keys are device-held.** Kept. The shares are now signed by the
   device and vouched for by its vault (`callwire.ShareMessage`,
   `VouchCallShare`); the peer vault and the peer device check both.
   Residual: each member's own vault.
4. **One call at a time per vault.** Kept.
5. **Reconnecting after removal or block**: removal now denylists the
   peer's tokens by jti (`denyPeerTokens`), not its relay key, so a new
   invitation and approval reconnect the same peer; a fresh connection
   replaces any stale record of it. Devices keep the sub denylist (§6.7).
6. **Desktop calls**: a desktop within its session places and answers
   calls without per-call approval; first answer wins; there is no call
   handoff between devices (end the call, start a new one).

### Not in batch 2

- TURN credential issuance in production: the `ICEIssuer` interface and a
  coturn HMAC issuer exist, but no calling service or shared-secret
  delivery does; release builds issue no servers.
- LEASH (grants, `agent.request`, the agent's grant-scoped fan-out):
  batch 3, through `vault.AgentPolicy`.
- Push wakes for incoming calls (§14).
- vaultctl call commands run a whole call per invocation (the caller's
  KEM key lives only in memory); the e2e tests drive the client package.

## Batch 3: LEASH, grants, critical-secret use, shared actions (0.6.0)

Follows VAULT-MESSAGING 0.6.0 (§10.11–§10.14, with §6.7, §6.8, §9.1,
§10.1, §10.3, §10.6, §10.7, §10.9, §13.5).

### Layout

- Runtime (`vault/`): `TypeSpec.AgentPolicy` makes the `AgentPolicy`
  feature decide every agent request of that type (`agent.request`), not
  only owner types agents are not listed for; when an app approves a
  referred agent request, the policy is asked again and a request no
  grant covers any more is answered `forbidden`. `AgentGrantor`:
  `device.pair.approve{grants}` is validated at the approval, kept on the
  pending device record (`Peer.PairGrants`) and installed after
  `device.paired` when the pairing completes. `DeviceRemovedObserver`
  (unlink revokes an agent's grants). `Host.PairedDevice` (a device with
  or without an access session).
- `features/leash` + `vms/leashwire`: grants, the decision, `agent.request`,
  signed delegations (canonical JSON signed by the credential key through
  `credential.Feature.UseKey`).
- `features/grants` + `vms/sharewire`: grants between connections, values
  sealed to the fetching device's reply key; the catalog.
- `features/critical`: critical-secret use; each approval is a credential
  operation through `credential.Feature.UseSecret` (UTK spent first, the
  sealed payload bound to the request and the payload's hash, the CEK
  rotated, the plaintext wiped). `credential.secret.catalog` lists a
  critical secret's metadata in the catalog.
- `features/actions`: shared actions.
- Accessors for features: `secrets.Feature.Catalog`/`CatalogedValue`,
  `profile.Feature.FieldValue`, `credential.Feature.CatalogedSecrets`.
- Every flow between vaults is a set of events correlated by ids, like
  connection authentication and calls; the runtime still has no V↔V
  request/response routing to features (§10, 0.6.0).

### Ported, changed or dropped: LEASH (from vettid.dev `leash_handler.go`, `agent_*.go`, `capabilities.go`)

| Old | Now | Why |
|---|---|---|
| `grant.attest` / `leash.attest`: a `leash+jwt` signed by a per-user "attestation key" generated and kept in vault storage, its public key and every issuance published through the parent to a public DynamoDB table, a public revocation-status Lambda, `vettid:grant_version`, `vettid:profile_version`, `vettid:revocation_url`, a 24 h maximum | Every grant is a delegation (canonical JSON, Ed25519 by the member's **credential key**) that the agent holds and can present; the vault still enforces grants itself. Issuing needs an app within the credential's unlock window. `exp` is the grant's optional expiry (LEASH §3.2); revocation is immediate at the vault and the agent is told (LEASH §3.4) | A vault-held signing key can be used by the vault (any approved release) without the member; the credential key needs the password, so the phone must be there to give an agent power. Publishing issuances through the untrusted parent to public tables told VettID who delegates what to which agent. The 24 h cap came from vettid.dev's token, not from LEASH (owner decision 2026-10-03) |
| Connection Contract: `Scope` capability tokens (`secrets.catalog.read`, `secrets.get`, `secrets.action`, `message.send`, `message.recv`), `ApprovalMode` (`always_ask`, `auto_within_contract`, `auto_all`), `DefaultAgentCapabilities` granted on pairing | One grant per scope, `ask` or `auto`, restrictions to connections or secrets, hourly and daily limits, expiry; an agent paired without grants can do nothing | Least privilege; "automatic for all" is not offered; the contract is per grant so it can be changed and revoked piecemeal |
| `agent_secret_request`, `agent_action_request`, `agent_catalog_request` in an X25519-encrypted agent envelope | `agent.request{op: catalog \| secret.get \| secret.use}` in the §6 session, decided by the policy | One session, typed messages, decisions in one place |
| Agent actions `http_request` (returned 501) and `sign` (HMAC-SHA-256 with the secret) | `secret.use` with `hmac-sha256` | The enclave has no egress beyond the relay and KMS; HTTP execution waits for that decision |
| In-memory pending approvals (`addPendingApproval`, `agent.secret.request` / `agent.action.request` to the app, `HandleAppApprovalResponse`, cleanup loop) | Referred requests are §6.8 held requests (`approval.pending` / `approval.decide`), persisted, 5-minute expiry | One approval mechanism for desktops and agents |
| `agent_rate_limit.go` (token bucket per agent connection) | Per-grant hourly and daily windows (past a limit the grant refers requests to an app; one `leash.rate_limited` feed item per window); per agent, an exponential cooldown per scope after a refusal (1 s doubling to 5 min), at most 20 referrals an hour, and suspension after 30 refusals in an hour until an app resumes it (`leash.agent.resume`) | LEASH asks for suspension and notification; a refused agent must not be able to spam the vault or the member (owner decision 2026-10-03) |
| Audit row per agent request | Per agent and hour: the first allowed, refused, read and used event written singly, the rest counted into `<kind>.summary` (throttled requests only summarised) | An agent cannot push older entries out of the fixed-size audit log (owner decision 2026-10-03) |
| Agent chat (`agent_message`, `agent_message_response`, `message.recv`) | Dropped | Not part of LEASH; an agent can be delegated `message.*` to connections. A member ↔ agent chat would be its own feature |
| Agent-initiated leash minting (`leash_mint_request`, `agent_leash_granted` / `_denied`) | Dropped: only an app issues grants | An agent asking for its own powers is a UI flow the member can serve out of band; it is not needed for the vault's enforcement |
| Agent pairing stage 2 (X25519 connection key, NATS credentials) | §6.7 pairing with initial grants | |
| `capability.*` (capability requests between connections) | Dropped | Superseded by grants (§10.12) |

### Ported, changed or dropped: grants (from vettid.dev `grant_handler.go`, `data.*` peer flows)

| Old | Now | Why |
|---|---|---|
| `forVault.data.request`, `data.grant.created`, `.denied`, `.revoked`, `.fetch`, `.fetch-response`, with no dedupe | `data.request`, `data.decided`, `data.revoked`, `data.fetch`, `data.value` inside the connection's session, deduped by inner id and by `request_id` / `fetch_id` | §13.6 classification; idempotency |
| The fetch response carried the plaintext value to the asking vault | `value_sealed` to a one-time reply key of the fetching device | The asking vault never holds the value |
| `item_kind` `data` (profile and personal-data, alias keys) and `secret` | `field` (a profile key) and `secret` (a cataloged vault-held secret); critical secrets only in the catalog, for use (§10.13) | One profile store (batch 1); critical values never leave the credential |
| Alias-group `Items` with singular mirror fields | 1–16 `items`, one grant per approved item, `items` indices in the decision | No legacy wire to stay compatible with |
| `one-shot`, `renewable`, `agent-renewable` modes; `HandleRenew` | `uses` (1–100) and `expires_in`; a new request instead of a renewal | Simpler; agents go through LEASH |
| `deliver_to`, `requester_guid`, `owner_guid` | Dropped; the connection comes from the session | No owner-space ids |
| `HandleListOutbound`, `Inbound`, `Pending`, `MyRequests` | One `grant.list{given, received, pending, requested}` | |
| The catalog in the published profile | `grant.catalog` → `data.catalog.get` / `data.catalog`, on demand | No retained or public profile (§9.3) |
| Requester-only relinquish path | Either side's `grant.revoke`, mirrored by `data.revoked` | Symmetric rule |
| `profile.sharing-settings` (per-connection overrides, deferred in batch 1) | Field grants | Per-connection disclosure on request, counted, expiring, revocable |
| `credential.secret.set-discoverability` (deferred in batch 1) | `credential.secret.catalog` for critical secrets; `discoverability` of vault-held secrets now takes effect | The catalog is what grants, critical-secret use and LEASH read |

### Ported, changed or dropped: critical-secret use (from vettid.dev `critical_secret_handler.go`)

| Old | Now | Why |
|---|---|---|
| `CriticalSecretAllowance` (allow for a window, `max_uses`, `expires_at`) | Dropped: every use is one approval with the password | §3.5: consent per use, CEK rotation per use, no standing authority |
| Approval with `encrypted_credential`, `encrypted_password_hash`, an ephemeral key and `key_id` | `critical-secret-use.approve{request_id, credential, utk_id, sealed{password, request_id, payload_sha256}}` through `credential.UseSecret` | The UTK payload is bound to the type, inner id, request and payload hash; the old approval could be redirected to another pending request in the same session |
| Operations `sign`, `auth`, `decrypt`, `derive` (the last two "not yet implemented") | `sign` and `auth` | Never implemented; no defined semantics |
| `auth` prefix `vettid-critical-auth-v1\|<owner_guid>\|` | `vettid/vms/2/critical-auth` ‖ requester `ik` ‖ owner `ik` ‖ request id ‖ payload | Binds both vaults and the request, like §10.4 |
| The `performer` test seam that skipped the password gate | Dropped; tests drive the real credential at `MinKDF` | The seam bypassed a security check in production code |
| Any critical secret could be asked for | Only cataloged ones | Least privilege, as for grants |
| Errors sent to the peer as `err.Error()` strings | Fixed statuses (`ok`, `denied`, `expired`, `unavailable`, `unsuitable`) | No internal error text leaves the vault |
| The requester did not verify the result | The asking vault verifies the signature before forwarding it | A peer cannot pass off another key's signature |

### Ported, changed or dropped: shared actions (from vettid.dev `action_*.go`; owner decision 2026-10-03)

| Old | Now | Why |
|---|---|---|
| Built-in catalog: `profile.fields.read`, `secrets.share`, `wallet.request-address`, `wallet.request-payment`, `vote.delegate-proxy`, `connection.handoff`, `audit.recent` | Catalog v1 keeps the field, secret, wallet and audit actions, run natively in the vault's process; drops votes and handoff | Votes are removed; introductions are started by the member (§10.15) |
| `profile.fields.read` / `secrets.share` returned plaintext values in the result | One-use, 10-minute grants; values via `grant.fetch`, sealed to the fetching device | One consent and delivery model (§10.12); the invoking vault never holds values |
| Modes `default-deny`, `allowlist`, `prompt-each-time`, `default-allow` | Kept, with sensitivity rules: sensitive never `default-allow`; critical only `default-deny` or `prompt-each-time`, approved by an app in the unlock window | "The phone must be there for critical actions" |
| JSON-schema validation (`action_schema.go`) | A strict native parser per action; schema documents are listed for apps | No schema engine in the enclave |
| Ed25519 invoker and result signatures | Dropped | The E2E session authenticates both vaults |
| Offers through the published profile cache | `action.offered` per connection, `sync.event{action.offers}` | No retained or public profile |
| `forOwner.invoke-action` / `action-result` raw publishes (mis-routed) | `action.invocation` / `action.result` in the session | Fixes the mis-routing |
| `owner_params` allowlists | `fields` / `secrets` in `action.configure` | |
| `execWalletRequestAddress`, `prepareBTCSend` stubs | Defined, `unavailable` until the wallet lands (batch 4) | Defined now, executed later |
| Pending queue and sweep | Feature state, 8 pending and 60 an hour per connection, 24 h expiry | Bounded |

### Ported, changed or dropped: introductions (§10.15)

| Old | Now | Why |
|---|---|---|
| `connection.handoff`: a connection asks the member to introduce it to one of the member's connections | Dropped. Only the member starts an introduction (`intro.create`) | Owner decision 2026-10-03: connections must not see or ask for another's connections |
| Peer-mediated invitation, never specified | Both parties accept; A's vault makes a remote invitation bound to C's `ik`, relayed by B; the normal approval and SAS follow | Neither learns the other until both accept; B cannot redirect the invitation to another identity |

### Delegation status statements ("stapling", owner decision 2026-10-03)

Every delegation names its status issuer (the vault, `vault_ik`) and a
`status_ttl` (60–3,600 s, default 900). The vault signs short statements
that the delegation is in force (`leash.status.get`, and in every
`leash.grant.updated`); none for revoked, expired or suspended grants or
from a locked vault. After an `ik` rotation the statement carries the
rotation chain instead of re-signing delegations (which would need the
member's credential key). `leashwire.VerifyPresented` is the offline
verifier for relying parties; `client.Device.LeashPresent` refreshes the
statement before it expires. This replaces vettid.dev's public
revocation-status Lambda, which needed the parent and public tables.

### OWNER DECISIONS (2026-10-03)

1. **Every LEASH grant is a delegation signed by the member's credential
   key** (not optional): issuing, replacing and pairing with grants need
   an app within the credential's unlock window; lifetime and revocation
   from LEASH (§3.2 optional expiry, §3.4 immediate revocation at the
   vault); the vault still enforces grants itself. Done.
2. `auto` for `secrets.get` only with an explicit `secrets` list. Kept.
3. **Agent spam after refusal is bounded**: cooldown per agent and scope
   (1 s doubling to 5 min), at most 20 referrals per agent and hour,
   suspension after 30 refusals in an hour until an app resumes the
   agent; refusals and throttling summarised in the audit log. Done.
4–8. Kept as built: the nine delegable owner types; no HTTP action,
   member ↔ agent chat or agent self-requests; critical-secret `sign`
   and `auth`; only cataloged secrets; field grants fetch-only.
9. **Shared actions are a built-in catalog run by the vault** with
   per-action permission modes; critical actions need an app in the
   unlock window; introductions are started only by the member (§10.15).
   Done.
10. Desktops step up for `grant.decide` and `action.define`; critical
    actions are app-only. Confirmed.
11. **Auto-allowed agent activity is summarised** per agent and hour,
    like `drop.*`, so it cannot push older entries out. Done.

### Not in batch 3

- LEASH's HTTP action execution and an online status for delegations
  (VAULT-MESSAGING §15 follow-up 7).
- Location, wallet and presence (the rest of V4).
- The runtime still does not route V↔V responses to features: every
  batch-3 flow between vaults uses events (§10).

## V4 items: items, tags and share rules (0.7.0)

Follows VAULT-MESSAGING 0.7.0 (§10.7, §10.8, §10.12, with §3.5.2,
§3.5.4, §6.8, §10.1, §10.6, §10.9, §10.11, §10.13, §10.14, §13.5), which
specifies the approved design note VAULT-ITEMS (owner decisions of
2026-10-03: sensitivity per item; one tag namespace with sharing by share
rules; the profile is the `@profile` tag plus a name and photo; files
later; agents default to `ask`; share rules default to `ask`). No
production data exists, so nothing is migrated: the replaced features
are removed.

### Layout

- `features/itemspec` (new, no state): field kinds and value checks with
  canonical encodings, tag normalisation, share-rule terms and matching,
  the item's encodings (with and without values, shared content,
  metadata for connections and agents). Shared by every feature below so
  that they parse and encode items the same way; fuzzed.
- `features/items` (new): items, the tag registry, the profile and share
  rules (connection rules kept here; agent rules kept by leash), the
  inclusion state per rule and item (pending, included, declined), and
  the plan/apply machinery: every change (item, tags, sensitivity, rule,
  merge) is planned against every rule, checked against the limits
  (pending, given grants, profile), then applied (grants issued or
  revoked, `share.pending`, `data.shared` via grants), so a refused
  change has no side effects. Critical items are credential operations
  through `credential.Feature.Operate`; their metadata is here, their
  values in the credential.
- `features/credential`: `credential.secret.*` and the catalog flag are
  gone; the plaintext holds `items` (values only); `Operate` performs
  another feature's credential operation (UTK, password, check, op, CEK
  rotation) and returns `{credential, credential_version, utks}`
  members; `DeleteObserver` (a credential delete takes the critical
  items).
- `features/grants`: items instead of fields and secrets
  (`{kind: item, ref, fields?}`, requests by `category`), descriptors,
  rule grants (`IssueRuleGrants`, `RevokeRuleGrant`, `data.shared`),
  uncounted uses and no expiry for rule grants, per-connection catalogs.
- `features/leash`: the `secrets.*` scopes are replaced by `items.read`
  grants, which are the agents' share rules (`SetAgentRule`,
  `DeleteAgentRule`, `AgentRules` for the items feature); `agent.request`
  `catalog`, `item.get`, `item.use` through the items feature.
- `features/critical`: `item_id` + `field_id`; usable only through a
  rule (`items.Feature.UsableField`); each use through `Operate`.
- `features/actions`: catalog version 2, `items.share`.
- Runtime: `vault.AppOnlyForms`: a step-up type's app-only form (a
  critical item, an agent rule) is refused to a desktop at once instead
  of being held for an approval it could not pass.
- Removed: `features/secrets`, `features/profile`.
- `client` and `vaultctl`: `item`, `tag`, `share` commands; the critical
  forms through the credential (`ItemPutCritical`, `ItemRevealCritical`,
  ...); grants by item and category; agent requests by item.
- `docs/item-templates.json`: the recommended categories and templates
  the apps share (templates are not in the vault); checked by
  `itemspec.TestTemplateRegistry`.

Lock order: the items feature calls the credential, grants and leash
features with its lock held; none of them calls back from those calls.
They call into the items feature (`Readable`, `Content`, `Usable*`,
`Agent*`) only from their own handlers, and those entry points call
nothing outside. Leash passes the agent's rules to the items feature
instead of the items feature asking leash, so no call path re-enters a
feature.

### Replaced

| 0.6.0 | 0.7.0 | Why |
|---|---|---|
| `secret.put/get/list/delete` | `item.put/get/reveal/list/delete` for `data` and `secret` items; `item.list` filters by tags, category, sensitivity and is paged | One model (VAULT-ITEMS) |
| `credential.secret.add/get/list/delete` | `item.*` with `sensitivity: critical`: credential, UTK-sealed content and item id, reply-key sealing, as before | Same protections; one model |
| `credential.secret.catalog`, `discoverability` | Share rules and per-connection catalogs | Sharing by tags; each connection sees only what it is given |
| Profile fields, `shared`, `order` | Items tagged `@profile`; `profile.get/set` keep the name and photo | Owner decision 3 |
| Grant items `{kind: field \| secret}` | `{kind: item, ref, fields?}`; requests by category | One model |
| LEASH `secrets.catalog/get/use`, `secrets` restriction | Agent share rules (`items.read`), signed with the rule in the delegation | VAULT-ITEMS §6 |
| `profile.fields.read`, `secrets.share` (catalog v1) | `items.share` (catalog v2) | Both act on items now and would be the same |
| — | `tag.list/set/delete/merge`, `share.rule.set/list/delete`, `share.pending`, `share.decide`, `data.shared`, `item.tag`, `item.sensitivity`, `item.reveal` | New |

### Deviations from the design note

- `item.reveal` is a type of its own: `item.get` never returns `secret`
  or `critical` values ("values revealed on purpose"), and desktops are
  held only for the reveal, not for reading data items.
- `item.tag` and `item.sensitivity` are types of their own: tags change
  without the password for every sensitivity, and moving to or from
  critical is a credential operation the vault does without values
  crossing the session.
- Field ids are assigned by the vault from a counter and never reused, so
  a grant restricted to a field never comes to cover another one.
- `@profile` is allowed only on `data` items (a `secret` item pushed to
  every connection would not be secret).
- `access` has the one value `read`; a connection rule that matches a
  critical item makes it usable (§10.13), never readable; an agent rule
  never includes it.
- `tag.delete` of a tag a rule names, and `tag.merge` touching an agent
  rule, are refused (`in_use`): removing a tag from an `all` rule would
  widen it, and an agent rule's tags are signed.
- Critical items are envelope-encrypted (owner decision 2026-10-03,
  replacing values inside the credential): values in DEK state under a
  per-item XChaCha20-Poly1305 key; the credential holds only the keys
  (`{item_id, gen, key}`), so up to 1,000 critical items of up to 12 KiB
  fit (the old bound was about fifteen). Item keys rotate at every use of
  the item and for every item at `credential.rotate` and
  `credential.recover` (`credential.ItemRekeyer`); new ciphertexts are
  installed only after the credential is sealed, in the same flush.
- Lists that could outgrow a message are paged or bounded (`item.list`,
  `tag.list`, `share.rule.list`, previews, `share.pending`,
  `data.shared`, `data.catalog`).

### OWNER DECISIONS (2026-10-03)

1. Agent `ask`/`auto` decide inclusion (as for connections); reads of an
   included item are allowed within the rule's `per_hour`/`per_day`,
   then referred (§10.11). Agreed.
2. An agent's delegation carries its rule's tag names (§10.11). Agreed.
3. Envelope encryption for critical items (§10.7), resolving the
   capacity bound (§15 follow-up 9). Approved and done; item keys rotate
   at every use of the item (recommended: a key once obtained stops
   working at the item's next use) and for all items at
   `credential.rotate`.

### Not in this batch

- Files in items (`file` kind reserved; owner decision 4).
- Paging of `grant.list` (§15 follow-up 10).
- ANDROID-PLAN's screens (the note's step 4).
