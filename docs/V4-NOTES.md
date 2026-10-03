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
| `block.add/remove` = a call-only blocklist of owner-space ids, with reason and duration | `block.add{connection_id \| pending_id, note?}`, `.remove`, `.list`: §7.4 "Peer blocked" (removal, sub denylisted) plus an entry on the peer's `ik` and relay key that refuses its handshakes | The spec's revocation already defined blocking; a timed block of a removed connection would only re-allow invitations, which `block.remove` does |
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

### OWNER DECISIONS

1. **Desktops need an app-approved access session** (default 1 h, at most
   24 h; can be granted with the pairing approval), and their step-up
   requests (secret values, profile, settings, invitations, connection
   removal, unblock) need an app's approval each. This changes V2, where a
   paired desktop could do everything its role allowed at any time.
   Recommendation: keep (it is the old design's model); revisit the
   step-up list with app UX.
2. **`connection.authenticate` proves the member, not the vault**: the
   member's app approves and the vault signs with the credential key
   (password-gated through the unlock window). The handshake and SAS
   already authenticate the vault. Recommendation: keep; add a
   credential-key rotation statement later (§15 item 6) so a rotation is
   followed instead of reported as a key change.
3. **Media keys are device-held**: the KEM runs between the two devices;
   the registry text said "the answering vault". Recommendation: keep (no
   media key in vault state, response caches or the outbox).
4. **One call at a time per vault** (`busy`). Recommendation: keep for
   1:1 calling.
5. **Re-connecting after removal or block** needs the peer to rotate its
   relay key, because removal denylists its `sub` (existing §7.4/§6.7
   behaviour, made explicit in 0.5.0). Recommendation: denylist the
   issued `jti`s instead (§15 item 7), so `block.remove` and later
   invitations work.

### Not in batch 2

- TURN credential issuance in production: the `ICEIssuer` interface and a
  coturn HMAC issuer exist, but no calling service or shared-secret
  delivery does; release builds issue no servers.
- LEASH (grants, `agent.request`, the agent's grant-scoped fan-out):
  batch 3, through `vault.AgentPolicy`.
- Push wakes for incoming calls (§14).
- vaultctl call commands run a whole call per invocation (the caller's
  KEM key lives only in memory); the e2e tests drive the client package.
