# V4 batch 1 notes

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
| UTK/LTK transport key pairs, `new_utks` in responses | Gone | They only protected requests in transit; the §6 session does |
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
