---
title: VAULT-MESSAGING
status: draft
version: 0.4.0
date: 2026-10-02
owner: Al Liebl (Mesmer)
component: vault manager (enclave), parent forwarder, apps, desktops, agents, member API vault routes
related:
  - RELAY-PROTOCOL.md (0.4.0)
  - RELAY-PLAN.md
  - PQC-MIGRATION.md
  - CALLING-SERVICE.md
  - PUSH-GATEWAY.md
  - ACCOUNT-ADMIN-PLAN.md
  - MEMBER-API.md
changelog:
  - 0.4.0: V4 batch 1 (owner decision on the Protean Credential): the
    Protean Credential (§3.5) with a hybrid-KEM CEK, a password layer and
    per-use consent, its link to ik/kem rotation (§3.4); body schemas for
    credential, critical secrets, secrets, profile, settings, guides,
    audit and feed (§10.6–§10.9); activity, sync.event kinds and error
    codes (§10.1); the hs.init profile and profile.update (§6.2, §9.3)
  - 0.3.2: V3b implementation (vettid-vault supervisor and parent):
    lease takeover from a non-live holder, lease taken before forwarding,
    host-written expired slots, lifecycle writes only by the lease holder,
    renewal failures, parent restart and loss, KMS over HTTP/1.1, long-poll
    in the enclave, one OS process per vault (§12.4, §13.3, §13.6),
    cleanup of the member index object
  - 0.3.1: V3 implementation fixes (vettid-vault V3a, member API vault
    routes): the response slot and vault.enroll.result, result binding and
    codes, per-release header_seq, re-enrollment of an existing vault_id,
    queue, lease and liveness encodings, access and rate-limit rules, what
    the device key signs, pairing attestation, sealed-object format,
    seal_key_verified.verified_by, stricter policy-check wording, §16 sizes
  - 0.3.0: release updates (VAULT-PLAN D1): per-release sealing, the signed
    release manifest, member-approved moves at unlock, routing by
    sealed_release, enclave-side verification of sealing-key policies,
    threat-model updates; enroll and unlock requests carry the manifest and
    are padded to 12,288 bytes
  - 0.2.3: V2 runtime additions: DEK derivation; §6.6 decides the token
    class by the collect jti (RELAY-PROTOCOL 0.4.0); approval roles; 7-day
    pending connection requests; first-app handshake; refusal of revoked
    relay keys; unknown-type answers; body schemas and error codes (§10)
  - 0.2.2: V1 implementation clarifications: identity.rotate format,
    device_attest replaces app_attest, strict inner/padding rules, blob
    layout, handshake field rules per purpose, epoch and abort rules,
    bundle/QR encodings, §11 encodings, §16 vectors filled in
  - 0.2.1: enclave TLS uses pinned roots and shared connections
  - 0.2.0: suite 2 becomes HPKE with the MLKEM768X25519 hybrid KEM; remote
    invitations with selectable TTL; reconnect tokens; client-anchored rollback
    protection (state_seq); vault_id and instance leases for multiple enclave
    instances; device attestation required at enroll and unlock; shorter
    vault-to-vault epochs
  - 0.1.0: initial draft
classification: public (no secrets; safe for github.com/vettid)
---

# VettID Vault Messaging

## 1. Purpose and scope

This document defines how a VettID vault exchanges messages over the VettID
relay (RELAY-PROTOCOL.md) with its owner's devices, its paired agents and the
vaults of its connections. It covers:

- keys (§3);
- one hybrid post-quantum construction and one envelope for every payload
  (§4, §5);
- sessions, invitations, reconnects and pairing (§6);
- deposit tokens (§7);
- delivery semantics (§8, §9);
- the message-type registry (§10);
- enrollment and unlock over an alternate channel (§11);
- locked vaults (§12).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be read as
described in RFC 2119.

### 1.1 Decisions encoded here

1. **VettID core is 1:1 between identities.** Fan-out to the owner's *own*
   devices is in scope. There are no group primitives: no multi-recipient
   deposits, no group keys and no membership lists.
2. **Feature scope.**
   - In scope:
     - enrollment, PIN and credential;
     - secrets, profile and settings;
     - 1:1 connections and messaging;
     - calls, with signalling over the relay;
     - device and agent pairing;
     - LEASH;
     - audit and feed;
     - wallet and location;
     - shared actions;
     - grants and critical secrets;
     - presence, as an on-demand ping.
   - Out of scope: votes, B2C service vaults, org vaults and
     transport-credential minting.
3. **The vault relay key exists only in PIN-protected vault state.** The
   enclave generates the key at enrollment. It is stored only in vault state
   encrypted under the PIN-derived DEK; there is no KMS-sealed or otherwise
   PIN-independent copy.
   *Rationale:* no one can collect, ack or delete a user's mailbox without
   the user's PIN. That includes any future enclave release signed by VettID.
4. **A locked vault does not touch the relay.** Enrollment and unlock travel
   an *alternate channel*: member API → per-instance queue → parent →
   enclave (§11). Requests on that channel are encrypted to an
   attestation-bound enclave key. While a vault is locked, peers' messages
   wait in its mailbox, up to the relay TTL, and are collected after unlock.
5. **The parent (host) is an untrusted byte forwarder.** It never holds relay
   keys, never parses app or peer envelopes, and never decides freshness or
   dedupe. All relay requests are built and signed inside the enclave.
6. **Fresh start.** There is no compatibility with the earlier NATS-based wire
   format.
7. **PQC Phase 1 applies to all key agreement.** Every E2E key agreement uses
   a hybrid X25519 + ML-KEM-768 KEM (§4). Signatures stay Ed25519. Every
   structure carries a suite or version field, so PQC Phase 2 (Ed25519 +
   ML-DSA-65) is a suite bump.

### 1.2 Relay features used

This document uses the following RELAY-PROTOCOL 0.4.0 features:

- one-shot **open deposit tokens** (§5.6);
- **`sender`** in collect responses (§6.3, §6.4);
- **`jti`** in collect responses: the `jti` of the deposit token a message
  was accepted under (§6.3, §6.4; new in 0.4.0, used by §6.6);
- **claims** (§6.9);
- fractional-second timestamps (§4.1);
- relay **policy values** advertised at registration:
  - `max_token_lifetime_seconds`;
  - `open_token_max_lifetime_seconds`;
  - `claim_ttl_seconds`.

The policy values are relay policy, not protocol constants. Clients MUST read
them from the registration `limits` and MUST NOT exceed them. For reference,
the relay at vettid.org allows:

- open tokens and claims up to 7 days;
- token lifetimes up to 400 days, for the reconnect tokens of §6.6.

## 2. Threat model

### 2.1 Parties

| Party | Trusted for | Not trusted for |
|---|---|---|
| Enclave (attested release) | Confidentiality and integrity of the vaults sealed to it, which are only those whose members approved it (§11.10) | Anything its PCRs don't attest. Apps check the release at every enroll and unlock (§11.2, §11.10.6). |
| Parent / host | Availability | Keys, plaintext, parsing, freshness, dedupe, routing decisions |
| Relay | Availability | Content confidentiality, integrity and authorship |
| Member API, queues, tables | Member session auth, rate limits, routing, availability | PINs, keys, vault contents, relay addresses |
| Push gateway (deferred) | Delivering contentless wakes | Everything else (PUSH-GATEWAY §8) |
| Peer vault | What its owner chose to share | Anything else. It MAY be malicious. |
| Owner device / agent | What its role and grants allow | Agents get least privilege (LEASH) |
| Network | — | Everything. Every hop uses TLS, and payloads are E2E-encrypted regardless. |

### 2.2 Metadata each party learns

| Party | Learns | Does not learn |
|---|---|---|
| Relay | Mailbox ids, depositor relay keys, timing, padded sizes, blob and claim sizes | Message types, content, or which identity, device or connection a relay key belongs to |
| Parent / host | Relay host names; TLS byte counts and timing per instance (connections are shared by all vaults, §12.2); enroll, unlock and lock events; encrypted-state size; `vault_id` ↔ instance | Relay requests (TLS terminates in the enclave, §12.2), mailbox ids, PINs, keys |
| Member API | Which member enrolled, unlocked or locked, and when; `vault_id`, instance lease, `vault_version`, `state_version` (§11.5) | PINs; why an unlock failed (§11.4); mailbox ids; keys; any stable device identifier (§11.7) |
| Network | Endpoints and timing | Everything else |

VettID operates both the host and the relay, so in its own deployment it can
correlate their timing. This residual metadata is disclosed here rather than
hidden. Traffic-analysis resistance is a non-goal (as in RELAY-PROTOCOL
§8.2), and padding (§5.4) limits only size leakage.

**Out of scope:**

- compromise of the enclave platform, or side channels inside it, and AWS
  KMS or Nitro attestation not behaving as documented (§11.10.7);
- a malicious release that the member approved and moved their vault into
  (§11.10), or enrolled into, after being shown its release number, notes
  and PCR0. No other release can open the vault, and VettID cannot move it
  there (§13.5);
- recovery when every owner device is lost. Backup and recovery are a
  separate design.

## 3. Principals and keys

### 3.1 Principals

| Principal | Relay mailbox | Notes |
|---|---|---|
| Vault | yes | One per member, inside the enclave. Identified to VettID by an opaque `vault_id` (§11.5). |
| Owner device, role `app` | yes | A phone or tablet installation. The only role that may unlock (§11.7). |
| Owner device, role `desktop` | yes | Does not unlock in 0.2. |
| Owner device, role `agent` | yes | Acts under LEASH grants. Never unlocks. |
| Peer vault | yes | A connection's vault |
| Enclave instance | no | Holds the enclave transport key (ETK, §11.2) |

Devices talk only to their own vault. Peer traffic is always vault to vault.

### 3.2 Keys

A **KEM key** is an MLKEM768X25519 key pair (§4.1). The encapsulation (public)
key `ek` is 1,216 bytes. The decapsulation (private) key is stored as its
32-byte seed.

| Key | Holder | Purpose | Lifetime | Stored |
|---|---|---|---|---|
| Relay key (Ed25519) | every mailbox owner | Signing relay requests and minting tokens | Rotated per §3.4 (SHOULD be ≤ 1 year) | Vault: DEK state only. Device: platform keystore. |
| Identity key `ik` (Ed25519) | vault, each device | Signing handshakes, bundles, ICE configs and rotation statements | Vault: rotates with the Protean Credential. Device: life of the pairing. | DEK state / keystore |
| Static KEM key `kem` | vault, each device | Receiving sealed messages and handshake initiations | Same as `ik`. Retired vault keys are kept 400 days for reconnects (§6.6). | DEK state / keystore-wrapped |
| Session epoch keys | both ends | Session-mode envelopes | One epoch (§6.5) | DEK state / device storage |
| Ephemeral KEM key | handshake initiator | Forward secrecy | One handshake | Memory |
| ETK (KEM key) | enclave instance | Alternate channel | ≤ 24 h, regenerated at every start | Enclave memory only |
| DEK | vault | Encrypting vault state | While unlocked | Enclave memory only |
| Device attestation key | app (Android Keystore key, iOS App Attest key) | Device attestation (§11.7) | Life of the installation | StrongBox / TEE / Secure Enclave (platform) |
| Wake key (Ed25519) | vault | Push gateway (§14) | PUSH-GATEWAY §3 | DEK state |
| CEK (KEM key) | vault | Sealing the Protean Credential (§3.5) | Until `credential.rotate` or `credential.delete` | DEK state |
| Credential key (Ed25519; hybrid in PQC Phase 2) | the member | Signing what the member approves (later features) | Until `credential.rotate` | **Only inside the Protean Credential** held by the member's app; in vault memory only during an unlock window (§3.5) |

Rules for all keys:

- The relay key, the identity key and the KEM key MUST be distinct from each
  other and from the Protean Credential key.
- Device private keys SHOULD be non-exportable. If a platform keystore cannot
  hold them natively, they MUST be stored encrypted under a key that the
  keystore holds.
- Implementations MUST follow FIPS 203 (ML-KEM), RFC 9180 (HPKE) and the
  MLKEM768X25519 KEM definition (§4.1).

### 3.3 Vault state and the sealed header

**Vault state** is encrypted under the DEK. It holds:

- `vault_id` and `state_seq` (§13.2);
- `sealed_release` and any pending `release_move` (§11.10.4);
- the relay key, the mailbox address and the rotation state;
- the vault's current `ik` and `kem`, and its retired `kem`s;
- the vault's rotation chain;
- the wake key;
- the CEK and the credential record (§3.5): the credential's version, the
  SHA-256 of its current blob, the password backoff state, the critical
  secrets' metadata and, if kept (§3.5.6), the current blob;
- one **record per owner device and one per connection**, holding:
  - role, relay public key, mailbox address, `ik` and `kem`;
  - the peer's rotation chain;
  - session epochs;
  - the tokens it issued to the vault, and the `jti`s issued to it (standing
    and reconnect);
  - its pinned suite and its state (`pending`, `active` or `stale`);
- the issued-token registry, the dedupe store, the response cache and the
  outbox (§8);
- feature data.

The **sealed header** is a small record sealed to the enclave's attestation,
not to the DEK, so that an unlock can be checked before the DEK exists. It
contains:

- `vault_id` and `user_guid`;
- a `provisional` flag (§11.3);
- the DEK's KDF parameters, salt and pepper (§3.3.1);
- `sealed_release`, the release it is sealed to, and `manifest_serial`, the
  highest release-manifest serial the vault has seen (§11.10);
- `seal_key_verified`: the sealing key's ARN, the SHA-256 of the policy
  the enclave verified before sealing under it, and the PCR0 of the release
  that ran the check (§11.10.7);
- the **unlock keys**: for each app allowed to unlock, its `ik`, its `kem`
  and its device-attestation binding (§11.7);
- the backoff state (§11.8);
- `state_seq` and `header_seq` (§13.2).

The sealed header MUST NOT contain the relay key, session keys or feature
data.

#### 3.3.1 DEK derivation and at-rest formats

The DEK is derived from the PIN and a secret that only the sealed header
holds, so that stolen vault state cannot be brute-forced against PINs
outside the enclave:

```
x   = Argon2id(PIN, salt, t, m, p, 32)
DEK = HKDF-SHA-256(ikm = x, salt = pepper, info = "vettid/vms/2/dek" || vault_id, L = 32)
```

- The sealed header holds the KDF parameters `{alg: "argon2id", t, m, p,
  salt}` (`salt` 16 random bytes) and `pepper` (32 random bytes).
- New vaults use `t = 3`, `m = 64 MiB`, `p = 1`. The enclave MUST refuse
  parameters below `t = 1`, `m = 8 MiB`.
- A wrong PIN yields a DEK under which the state does not decrypt; that is
  the `bad_pin` outcome (§11.4), counted in the backoff state (§11.8).

The reference implementation stores vault state and the sealed header as:

```
state  = 0x01 || state_seq (8, big-endian) || nonce (24)
         || XChaCha20-Poly1305(DEK, nonce, aad, state_json)
aad    = "vettid/vms/2/state" || 0x00 || vault_id || 0x00 || state[0:9]
header = Seal_R(header_json, aad = "vettid/vms/2/header" || 0x00 || vault_id)   # sealed to release R (§11.10.2)
```

`Seal_R` encrypts under a fresh AES-256 data key from KMS `GenerateDataKey`
on release R's key (§11.10.2), with the key ARN in the object and in the
AAD, all lengths 2 bytes big-endian:

```
sealed = 0x01 || len(key_arn) || key_arn || len(blob) || blob || nonce (24)
         || XChaCha20-Poly1305(data_key, nonce, aad', plaintext)
aad'   = "vettid/vms/2/seal" || 0x00 || release_pcr0 || 0x00 || key_arn || 0x00 || aad
```

`blob` is the KMS `CiphertextBlob`. To unseal, the enclave takes `key_arn`
from the object, requires it to be in the pinned sealing-key namespace
(§11.10.2), calls `Decrypt` with it as `KeyId`, and, once the request's
manifest is verified, requires it to equal this release's `seal_key`
(else result code `manifest`). This lets the enclave open the header, and
answer sealed, before the manifest step of §11.10.4.

Both objects are written create-only at enrollment and with version-matched
conditional writes afterwards (§12.3). There is one header object per
release the vault has been sealed to (§11.10.2); a move writes the new one
create-only.

### 3.4 Rotation

- **Vault relay key** rotates per RELAY-PROTOCOL §6.7:
  1. The vault collects from both mailboxes during the grace period.
  2. It mints fresh standing and reconnect tokens for every device and peer.
  3. It sends each of them `relay.address.update`, carrying the new address,
     the new key and the new tokens.
  4. Each recipient answers with `relay.token.issued` for the new `sub`.

  The vault MUST rotate after any suspected exposure of its state.
- **Device relay key.** The device sends `relay.address.update`, and the vault
  denylists the old `sub` after the grace period.
- **Vault `ik` and `kem`** rotate with the Protean Credential (PQC-MIGRATION
  §7). A `credential.rotate` (§3.5.4) MUST rotate them, in the same flush
  as the new credential; the vault MAY also rotate them alone, after a
  suspected exposure of its state:
  1. The vault sends an `identity.rotate` statement, signed by both the old
     and the new `ik`, to every device and peer.
  2. It appends the statement to its **rotation chain**.
  3. It rekeys every session (§6.5).

  The credential rotation is the PQC migration vehicle (PQC-MIGRATION §7):
  the release that introduces suite 3 generates the hybrid credential key
  and the hybrid `ik` at the member's next `credential.rotate`.

  Peers store each other's chains (used in §6.6). PQC Phase 2 arrives this
  way, as a hybrid `ik` under suite 3.

**`identity.rotate` statement.** One link of a rotation chain is the JSON
object

```json
{ "v": 1, "suite": 2, "old_ik": "<b64>", "new_ik": "<b64>", "new_kem": "<b64 ek>",
  "sig_old": "<b64>", "sig_new": "<b64>" }
```

```
m       = old_ik (32) || new_ik (32) || new_kem (1216)
sig_old = Ed25519(old_ik, "vettid/vms/2/rotate" || m)
sig_new = Ed25519(new_ik, "vettid/vms/2/rotate" || m)
```

- Both signatures MUST verify, and `old_ik` MUST differ from `new_ik`.
- A chain is an ordered array of statements. Each link's `old_ik` MUST equal
  the previous link's `new_ik` (the first link's MUST equal the stored `ik`).
  A receiver MUST reject chains longer than 32 links.
- The chain resolves to the last link's `new_ik` and `new_kem`; an empty
  chain resolves to the stored keys.
- **ETK** rotates at least every 24 h and on every enclave start.

### 3.5 The Protean Credential

The **Protean Credential** holds the member's critical keys and secrets
(the credential key, seed phrases, private keys, recovery keys). It is
held by the member's app, sealed so that the vault alone cannot open it,
and every use of it needs the member's participation: the app supplies the
credential **and** the member's password, for that one operation. Its
contents are never part of vault state.

This replaces the earlier design's transport keys: the UTK/LTK pairs only
protected the password and the request in transit, which the §6 session
now does. The CEK-sealed blob and the per-use password, which are what
make the credential unusable without the member, are kept.

#### 3.5.1 Keys

- The **CEK** is a KEM key (MLKEM768X25519, §4.1) generated by the vault
  at `credential.create`. Its private seed is kept in DEK state; it never
  leaves the vault.
- The **password key** `K_pw` is derived from the member's password inside
  the enclave:

  ```
  x    = Argon2id(password, salt, t, m, p, 32)
  K_pw = HKDF-SHA-256(ikm = x, salt = "vettid/vms/2/credential-pw", info = vault_id, L = 32)
  ```

  New credentials use `t = 3`, `m = 64 MiB`, `p = 1`; the vault MUST refuse
  parameters below `t = 1`, `m = 8 MiB`. `salt` is 16 random bytes, fresh
  at every seal.
- The **credential key** is an Ed25519 key (a hybrid Ed25519 + ML-DSA-65
  key from PQC Phase 2). It is generated by the vault, exists only inside
  the credential, and is distinct from the relay, identity and KEM keys
  (§3.2). It signs what the member approves; the operations that use it
  are defined with the features that need it.
- The **password** is a UTF-8 string of 8–1,024 bytes. The app sends it
  inside the §6 session; the enclave sees it transiently, as it sees the
  PIN (§12.4), and MUST NOT store or log it.

#### 3.5.2 Format

```
blob   = 0x01 || version (8, big-endian) || kid(CEK) (8) || enc (1,120) || ct
hdr    = blob[0:17]
(enc, ctx) = SetupBaseS(ek_CEK, info = "vettid/vms/2/credential" || vault_id)
ct     = ctx.Seal(aad = hdr, pt = locked)
locked = t (1) || m_KiB (4, big-endian) || p (1) || salt (16) || nonce (24)
         || XChaCha20-Poly1305(K_pw, nonce, aad = hdr || locked[0:22], inner)
```

`inner` is a UTF-8 JSON object (unknown members ignored, strict as in
§5.3), at most 131,072 bytes:

```json
{ "v": 1, "vault_id": "<id>", "version": 3,
  "created_at": "<ts>", "password_changed_at": "<ts>",
  "key": "<b64 32-byte Ed25519 seed>",
  "secrets": [ { "id": "<ULID>", "name": "...", "category": "seed_phrase",
                 "description": "...", "value": "<b64>", "created_at": "<ts>" } ],
  "crypto_keys": [ ] }
```

- `category` is one of `seed_phrase`, `private_key`, `signing_key`,
  `master_password`, `recovery_key`, `other`. A `value` is 1–8,192 bytes;
  a credential holds at most 64 secrets.
- `crypto_keys` is reserved for the wallet feature and is empty until then.
- `version` in `inner` MUST equal the header's `version`; `vault_id` MUST
  equal the vault's.

Both layers are needed: the outer HPKE layer keeps a thief of the app's
copy from guessing the password offline (only the enclave holds the CEK);
the inner password layer keeps the vault, which holds the CEK, from
opening the credential without the member.

#### 3.5.3 Using the credential

Every operation that reads or changes the credential carries `credential`
(the blob) and `password`, from an owner device of role `app`. The vault:

1. refuses with `backoff` while the password backoff (below) is in effect;
2. checks that SHA-256(`credential`) equals the hash of the current blob it
   recorded, else answers `stale_credential` (an older blob, after a
   password change or a deleted secret, cannot be replayed);
3. opens the outer layer with the CEK and the inner layer with `K_pw`. If
   the inner AEAD fails, it answers `bad_password`, counts the failure and
   records `credential.password_failed` (§10.9);
4. performs the operation on the plaintext in memory, and for a change
   seals a new blob with `version + 1`, a fresh salt, nonce and HPKE
   context, records its hash and version, and returns it;
5. zeroizes the plaintext, `x` and `K_pw` before the response is sent.
   A response that carries a secret's value is never written to vault
   state (§8.2).

The vault MUST NOT keep any plaintext of the credential, `K_pw` or the
password after the operation, except the credential key during an unlock
window.

**Password backoff.** After 5 consecutive failures, the vault refuses
credential operations for 30 s, then 1 min, 5 min, 15 min and 60 min after
each further failure (capped at 60 min). A success resets the count. The
count is in DEK state and survives locks.

**Unlock window.** `credential.unlock` keeps the credential key (only that
key) in the vault process's memory for the `credential.unlock_ttl_seconds`
setting (30–3,600 s, default 300). Operations that sign with the credential
key may use it within the window; each use extends it to the full TTL.
The window ends at expiry, `credential.lock`, `credential.rotate`,
`credential.delete` and vault lock. The key is never written to state.

#### 3.5.4 Lifecycle

- **Create.** `credential.create{password}` from an app: the vault
  generates the CEK and the credential key, seals version 1 with no
  secrets, and returns the blob. A vault has at most one credential.
- **Distribution.** The app stores the blob. The vault records its hash
  and version and, if kept (§3.5.6), the blob, which other apps of the
  owner fetch with `credential.get`. Other owner devices learn of every
  change through `sync.event{kind: "credential.changed", version}`.
- **Password change.** `credential.password.change{credential, password,
  new_password}` re-seals the same content under the new password.
- **Rotate.** `credential.rotate{credential, password}` generates a new CEK
  and a new credential key, seals the content under them with `version + 1`,
  and in the same flush rotates the vault's `ik` and `kem` (§3.4). Every
  earlier blob becomes unusable, because its CEK is destroyed. Apps SHOULD
  offer a rotation at least yearly, and the vault MUST NOT rotate the
  credential without the member.
- **Delete.** `credential.delete{credential, password}` destroys the CEK,
  the recorded hash and any kept copy. Blobs held by apps can no longer be
  opened by anyone. `vault.delete` does the same.

#### 3.5.5 What VettID and the vault can do

- **VettID** (host, API, relay) never sees the CEK, the password, `K_pw`
  or the credential's plaintext. It stores, at most, the DEK-encrypted
  vault state, which contains the CEK and possibly the blob.
- **The vault** (an approved release, §11.10) holds the CEK but not the
  password. It cannot open the credential, use its keys or read its
  secrets unless the member's app sends the password for an operation.
  During that operation, and during an unlock window for the credential
  key, an approved release does see the plaintext; a malicious release the
  member approved is out of scope (§2.2), as for the PIN.
- **A thief of an app** with the blob needs the CEK, so it can only guess
  the password online, through a paired app session, under the backoff.
- **An attacker who obtains the decrypted vault state** (the DEK, which
  needs the PIN and the enclave) holds the CEK and, if kept, the blob, and
  can guess the password offline against Argon2id. The password, not the
  PIN, is what protects the credential in that case.

#### 3.5.6 Open: the vault's copy of the blob

**OWNER DECISION.** Whether the vault keeps the current blob (enabling
`credential.get` for a second app and recovery after the app loses it) or
only its hash (the credential then lives only on the member's apps, and a
lost app copy loses the critical secrets). **Recommendation:** keep the
copy. It is useless to the vault without the password, it is what lets a
member's second app or a reinstalled app get the credential back, and the
residual risk is the offline-guessing case of §3.5.5. The reference
implementation keeps it; `credential.get` answers `not_found` if a vault
does not.

## 4. Cryptographic construction

### 4.1 Suites

| Suite | Sealed mode and KEM | Session AEAD | KDF | Signatures | Status |
|---|---|---|---|---|---|
| `1` | X25519 only | XChaCha20-Poly1305 | HKDF-SHA-256 | Ed25519 | PQC-MIGRATION's classical transition suite. **MUST NOT be sent or accepted.** |
| `2` | **HPKE** (RFC 9180), base mode, KEM **MLKEM768X25519** (`0x647a`), KDF HKDF-SHA256 (`0x0001`), AEAD ChaCha20-Poly1305 (`0x0003`) | XChaCha20-Poly1305 | HKDF-SHA-256 | Ed25519 | **This document** |
| `3` | As suite 2 | As suite 2 | As suite 2 | Ed25519 + ML-DSA-65 (PQC-MIGRATION §5.2, AND policy) | Reserved for PQC Phase 2 |

MLKEM768X25519 is the X-Wing-style hybrid KEM (draft-connolly-cfrg-xwing-kem
and the HPKE PQ codepoints). Interoperable implementations exist:

- Go 1.26 `crypto/hpke` (`hpke.MLKEM768X25519()`);
- Apple CryptoKit's X-Wing HPKE suite;
- BouncyCastle.

The suite satisfies PQC-MIGRATION §5.1:

- An attacker must break **both** ML-KEM-768 and X25519 to recover the
  shared secret.
- Its combiner binds the X25519 ciphertext and public key, which is the
  transcript binding §5.1 requires. The ML-KEM ciphertext is bound by
  ML-KEM's own CCA security.

It replaces the bespoke combiner of 0.1. The KEM codepoint and all sizes are
pinned by the §16 vectors.

Notation and labels:

- All labels are ASCII strings with no terminator, and embed the suite
  number (`vettid/vms/2/...`).
- `||` is concatenation.
- `HKDF-SHA-256(ikm, salt, info, L)` is RFC 5869 extract-then-expand.
- HPKE `SetupBaseS`, `SetupBaseR`, `Seal`, `Open` and `Export` are as defined
  in RFC 9180.

### 4.2 AEADs

- **Sealed mode** uses HPKE's ChaCha20-Poly1305. Every HPKE context seals
  exactly one message, and HPKE derives the nonce.
- **Session mode** uses XChaCha20-Poly1305 with a fresh random 192-bit nonce
  per message. Restored state, device backups and retries make persisted
  nonce counters fragile, and the 96-bit nonce of ChaCha20-Poly1305 is too
  short to draw at random. XChaCha20 is also the AEAD that RELAY-PROTOCOL
  §6.8 recommends for blobs.

### 4.3 Sealing to a KEM key

```
(enc, ctx) = SetupBaseS(pk_R = ek_R, info = "vettid/vms/2/sealed")   # enc: 1120 bytes
ct         = ctx.Seal(aad = envelope header bytes[0:1140], pt = padded_inner)
```

The recipient runs `SetupBaseR(enc, sk_R, info)` and then `Open`. The same
context MAY `Export` secrets for the handshake (§6.3) and for calls (§10).
Implementations MUST NOT reuse a context for a second message.

### 4.4 Key ids

A `kid` is 8 bytes:

- for a static KEM key or the ETK, `SHA-256("vettid/vms/2/kid" || ek)[0:8]`;
- for a session, derived per direction for each epoch (§6.3);
- all-zero for an anonymous sender.

Kids are lookup hints, not authenticators. When decryption under the key a
kid indicates fails, the message is dropped. A receiver MUST NOT
trial-decrypt under other principals' keys.

## 5. The v2 envelope

### 5.1 One format

Every relay payload and every alternate-channel request (§11) is a v2
envelope, and the relay `payload` field is its base64. The message type,
request id, timestamp and sequence number are all **inside the ciphertext**.

### 5.2 Byte layout

```
offset  len    field
0       1      ver            0x02
1       1      suite          0x02
2       1      mode           0x01 session | 0x02 sealed
3       1      flags          0x00 (reserved; non-zero MUST be rejected)
4       8      sender_kid
12      8      recipient_kid
--- session mode ---
20      24     nonce          random (XChaCha20-Poly1305)
44      n+16   ciphertext     XChaCha20-Poly1305(k_epoch_dir, nonce, aad = bytes[0:44], padded_inner)
--- sealed mode ---
20      1120   enc            HPKE encapsulated key (MLKEM768X25519)
1140    n+16   ciphertext     HPKE ctx.Seal(aad = bytes[0:1140], padded_inner)   (§4.3)
```

- The header length `H` is 44 bytes in session mode and 1,140 in sealed mode.
  The AAD is the whole header.
- Overhead is 60 bytes in session mode and 1,156 bytes in sealed mode.
- Sealed mode carries:
  - `hs.init` and `hs.resp` (§6);
  - `vault.enrolled`;
  - `vault.unlock.result`;
  - alternate-channel requests.

### 5.3 Inner plaintext

The inner plaintext is a UTF-8 JSON object, followed by padding:

```json
{ "v": 1, "id": "01JB2Z6V9K3M4N5P6Q7R8S9T0V", "type": "message.send",
  "ts": "2026-10-01T12:00:00.123Z", "seq": 42,
  "re": "<id of request answered>", "exp": "<RFC 3339>",
  "status": "ok", "error": { "code": "not_found", "message": "..." },
  "body": { } }
```

| Field | Req | Meaning |
|---|---|---|
| `v` | MUST | Inner format version, `1` |
| `id` | MUST | ULID. It is both the message id and the **idempotency key**: a retransmission of the same logical message MUST reuse it, in a new envelope. |
| `type` | MUST | Registry name (§10) |
| `ts` | MUST | Sender clock, RFC 3339 UTC with milliseconds |
| `seq` | session mode | Counter per epoch and per direction, starting at 1. An ordering hint and gap detector only. |
| `re` | responses | `id` of the request being answered |
| `exp` | MAY | Discard the message if it is still unprocessed after this time. REQUIRED for ephemeral types (§8.5). |
| `status`, `error` | responses | `ok` or `error` |
| `body` | MUST | Type-specific. The schema is TBD per feature unless this document defines it. |

- Binary values are encoded as standard base64 with padding. Receivers
  MUST reject non-canonical base64 and base64 containing CR or LF.
- Unknown fields are ignored. Known fields MUST have exactly the type and
  form given here; receivers MUST reject anything else.
- Receivers MUST reject an inner plaintext (including its `body`) that is
  not valid UTF-8, that has duplicate member names at any depth, or that
  has any data after the object. Member names are case-sensitive.
- Integers are plain JSON integers (no sign, fraction or exponent) no
  larger than 2^53 − 1.
- `id` and `re` are canonical ULIDs: 26 upper-case Crockford base32
  characters, the first in `0`–`7`.
- `ts` and `exp` both use the format `YYYY-MM-DDTHH:MM:SS.mmmZ`: RFC 3339,
  UTC, exactly three fractional digits, a literal `Z`.
- `seq` MUST be present in session mode and MUST be absent in sealed
  mode. It is an integer ≥ 1.
- `re` and `status` appear together (responses) or not at all (requests and
  events). `error` is present if and only if `status` is `error`;
  `error.code` matches `[a-z_][a-z0-9_]*` (at most 64 bytes) and
  `error.message` is optional.
- `type` matches `[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*` and is at most
  64 bytes.
- `body` MUST be a JSON object (`{}` when empty).
- A receiver cannot tell a request from an event by a `type` it does not
  know. A message **without `re`** whose `type` is unknown is therefore
  answered with `error` code `unsupported_type`; a sender that did not
  expect a response drops it (§8.1). A message with `re` whose `type` is
  unknown is dropped.

### 5.4 Padding

The padded inner plaintext is `json || 0x80 || 0x00*`, padded to:

- the next multiple of 512 bytes, up to 16 KiB;
- above 16 KiB, the next multiple of 16 KiB.

The bucket is computed for `len(json) + 1` (the `0x80` marker counts). The
padded length MUST be exactly that bucket: over-padding to a larger bucket
is malformed.

Alternate-channel plaintexts are padded to exactly 4,096 bytes; a 4,096-byte
inner plaintext produces a 5,252-byte sealed envelope. The exceptions are
the `vault.enroll` and `vault.unlock` requests, which carry the signed
release manifest (§11.3, §11.4) and are padded to exactly **12,288 bytes**
(a 13,444-byte envelope), whether or not an unlock carries a release
update.

Receivers MUST reject malformed padding: a padded length that is not
exactly the bucket for the JSON it contains (or not exactly the fixed size
on the alternate channel), a last non-zero byte other than `0x80`, or no
marker at all. Senders and receivers check the ciphertext length (padded
length + 16) against the bucket sizes before decrypting.

### 5.5 Size limits and claim-check

- The decoded envelope MUST fit the relay's `max_payload_bytes` (262,144 by
  default). Senders MUST keep the padded inner plaintext at or below 245,760
  bytes, which leaves room for either mode's overhead.
- The **claim-check blob flow** (RELAY-PROTOCOL §6.8) SHOULD be used for
  content over 64 KiB, and MUST be used for content that would not otherwise
  fit:
  1. Encrypt the content under a fresh 256-bit key:

     ```
     blob = nonce (24, random) || XChaCha20-Poly1305(key, nonce, aad = "vettid/vms/2/blob", content)
     ```

  2. Upload `blob` with `PUT /v1/blob/{recipient_mailbox}`.
  3. Send a message whose body carries `{"blob": {"id", "key", "sha256",
     "size", "mime", "name"}}`, where `sha256` is SHA-256 of `blob` (the
     uploaded bytes) and `size` is the length of `content`. The receiver
     MUST check `sha256`, in constant time, before decrypting.

  Names and MIME types never leave the ciphertext.
- If the relay does not support blobs, the operation fails with
  `payload_too_large`.

## 6. Sessions, invitations, reconnects and pairing

### 6.1 One handshake

All sessions use the same three messages: vault ↔ device, vault ↔ vault,
rekeys and reconnects. Before the handshake, initiator `I` already knows the
responder's `ik_R` and `ek_R`, from one of:

- attestation (§11.3);
- a claim bundle (§6.4);
- the stored connection (rekey or reconnect).

```
I                                                         R
|--hs.init  [sealed to ek_R]------------------------------>|  K_s = Export(init ctx)
|   {purpose, ctx, from{ik,kem,relay}, eph, token,          |
|    reconnect_token, suites, ...}                          |
|<--hs.resp [sealed to eph]--------------------------------|  K_e = Export(resp ctx)
|   {token, reconnect_token, suite, sig_R, ...}            |
|--hs.fin   [session mode, new epoch]--------------------->|  epoch active
|   {sig_I}                                                |
```

### 6.2 Bodies

```json
hs.init: { "purpose": "app|desktop|agent|connection|rekey|reconnect",
           "ctx": "<invite_id | pairing_id | previous epoch_id | connection ref>",
           "from": { "ik": "<b64>", "kem": "<b64 ek>",
                     "relay": {"url": "<base>", "mailbox": "<id>", "pk": "<b64>"} },
           "eph": "<b64 ephemeral ek>",
           "token": "<standing token; sub = responder relay key>",
           "reconnect_token": "<connections only; §6.6>",
           "suites": [2],
           "profile": { },
           "rotations": [ ],
           "device_attest": { } }
hs.resp: { "token": "...", "reconnect_token": "...", "suite": 2,
           "rotations": [ ], "sig": "<b64>" }
hs.fin:  { "sig": "<b64>" }
```

Field rules:

- `profile` is self-asserted and optional (§6.4). It is allowed only for
  purposes `app`, `desktop`, `agent` and `connection`. A vault's `profile`
  (purpose `connection`) carries only `{name}`, its display name (§10.8);
  the shared profile follows in `profile.update` once the connection is
  active (§9.3), so nothing more is disclosed to a party that has not been
  approved.
- `rotations` is used only for reconnects (§6.6), in both `hs.init` and
  `hs.resp`; it MUST be absent for every other purpose.
- `device_attest` is used only for purpose `app` (§6.7, §11.7).
- `ctx`:
  - `connection`: the `invite_id`; `app`, `desktop`, `agent`: the pairing
    id (the bundle's `invite_id`, §6.4);
  - `rekey`: the standard base64 of the 16-byte `epoch_id` of the current
    epoch; the responder MUST reject any other value;
  - `reconnect`: the standard base64 of the stored `epoch_id` of the last
    epoch (§6.6).

  `ctx` is 1–128 bytes of printable ASCII (`0x21`–`0x7e`).
- Tokens, per purpose, in both `hs.init` and `hs.resp`:

  | Purpose | `token` | `reconnect_token` |
  |---|---|---|
  | `app`, `desktop`, `agent` | required | MUST be absent |
  | `connection`, `reconnect` | required | required |
  | `rekey` | optional | optional |

  Both are PASETO v4.public strings (`v4.public.` followed by base64url
  and `.` characters, at most 4,096 bytes).
- `from.relay.url` is an absolute `https` base URL without user info, query
  or fragment (`http` is allowed only for loopback hosts, in development);
  `from.relay.mailbox` MUST equal the mailbox id derived from
  `from.relay.pk` (RELAY-PROTOCOL §3.2).
- `eph` MUST differ from `from.kem`.
- `suites` is 1–8 strictly ascending integers in [2, 255]. An offer that
  contains suite 1 is rejected. Unknown suites above 2 are allowed and not
  chosen.
- `hs.init` uses `sender_kid` = anonymous or the initiator's static kid, and
  `recipient_kid` = kid of `ek_R`. A non-anonymous `sender_kid` MUST equal
  the kid of `from.kem`.
- `hs.resp` uses `sender_kid` = all-zero and `recipient_kid` = kid of
  `eph`.
- On **rekey**, `hs.init` travels in session mode under the current epoch,
  and `K_s` is the current (soon previous) epoch's `rk`. A rekey `hs.init`
  is accepted only under the current epoch.

### 6.3 Key schedule

```
K_s      = init_ctx.Export("vettid/vms/2/hs-ks", 32)       # rekey: K_s = rk of previous epoch
K_e      = resp_ctx.Export("vettid/vms/2/hs-ke", 32)
th1      = SHA-256("vettid/vms/2/th1" || env_init)         # env_init = full hs.init bytes
th       = SHA-256("vettid/vms/2/th"  || env_init || resp_header)   # hs.resp bytes[0:1140]
prk      = HKDF-Extract(salt = "vettid/vms/2/session", ikm = K_e || K_s)
k_i2r    = HKDF-Expand(prk, "vettid/vms/2/i2r"     || th, 32)
k_r2i    = HKDF-Expand(prk, "vettid/vms/2/r2i"     || th, 32)
kid_i2r  = HKDF-Expand(prk, "vettid/vms/2/kid-i2r" || th, 8)
kid_r2i  = HKDF-Expand(prk, "vettid/vms/2/kid-r2i" || th, 8)
rk       = HKDF-Expand(prk, "vettid/vms/2/rk"      || th, 32)
epoch_id = HKDF-Expand(prk, "vettid/vms/2/epoch"   || th, 16)
sig_R    = Ed25519(ik_R, "vettid/vms/2/sig-resp" || th)
sig_I    = Ed25519(ik_I, "vettid/vms/2/sig-fin"  || th)
sas      = uint32be(HKDF-SHA-256(ikm = K_s, salt = "vettid/vms/2/sas", info = th1, L = 4))
           mod 1,000,000, shown as 6 zero-padded digits
```

Session-mode envelopes use the epoch keys and kids:

- In direction `i2r`, the sender uses `k_i2r`, sets `recipient_kid` =
  `kid_i2r` and sets `sender_kid` = `kid_r2i`.
- Direction `r2i` mirrors this.

`th` covers the KEM ciphertexts of both `hs.init` and `hs.resp`, so `K_s` and
`K_e` are bound into both signatures.

Verification and activation:

- `I` MUST verify `sig_R` before using any epoch key, and MUST abort if it
  fails. For a new peer, `sig_R` is checked under the pinned `ik_R`. For a
  reconnect, it is checked under the current key that `rotations` leads to.
- The abort applies once a message has decrypted under `eph`: after that,
  any failure (body, suite, chain or `sig_R`) aborts the handshake and
  destroys its state. A message that does not decrypt under `eph`, or
  whose collect `sender` is wrong, is dropped without affecting the
  handshake.
- `R` activates the epoch only after `sig_I` verifies. Messages for an
  inactive epoch are left unacked. An `hs.fin` whose `sig_I` does not
  verify is dropped; the pending handshake is kept until it expires.
- The collect `sender` (RELAY-PROTOCOL §6.3) MUST equal `from.relay.pk` for
  `hs.init`. For every later message, `sender` MUST equal the relay key on
  record for the principal whose session decrypts it. A mismatch is acked,
  dropped and audited.
- `sas` depends only on `hs.init`, so either side can display it before
  `hs.resp` is sent.

### 6.4 Connections and invitations

An invitation combines:

- the QR claim-check of PQC-MIGRATION §6.5;
- an open token (RELAY-PROTOCOL §5.6);
- a claim (§6.9).

**Invite TTL.** The inviter chooses a TTL, which sets the invite's `exp`, the
open token's lifetime and the claim TTL together:

| TTL | Use |
|---|---|
| 10 min | Default. In person. |
| 1 h, 24 h, 7 days | **Remote invites**, for example a link sent through another channel |

The TTL MUST be at or below both of the relay's advertised
`open_token_max_lifetime_seconds` and `claim_ttl_seconds`. The app MUST NOT
offer options above them.

**Bundle**, encrypted before upload:

```json
{ "v": 1, "suite": 2, "kind": "connection", "invite_id": "<ULID>", "remote": false,
  "vault": { "ik": "<b64>", "kem": "<b64 ek>",
             "relay": {"url": "<base>", "mailbox": "<id>", "pk": "<b64>"} },
  "token": "<open token, exp = invite exp>", "exp": "<RFC 3339>",
  "hint": { "name": "<optional>" } }
```

Bundle rules:

- `hint.name`, if present, is the inviter's display name (§10.8). Anyone
  who holds the link can read it.
- `kind` is `connection`, or `app`, `desktop` or `agent` for pairing
  (§6.7); it MUST match the QR `t` (`c`, `p`, `d`, `a` respectively).
- For pairing, `invite_id` carries the pairing id, and `remote` MUST be
  `false`.
- `exp` is RFC 3339 UTC in **whole seconds** (`YYYY-MM-DDTHH:MM:SSZ`, no
  fraction) and MUST equal the QR `e`. This is the only whole-second
  timestamp in this document; inner timestamps use milliseconds (§5.3).

The bundle is protected and published as follows:

- `blob = nonce(24) || XChaCha20-Poly1305(k_b, nonce, aad = "vettid/vms/2/bundle",
  json)`, where `k_b` is a fresh random 32-byte key.
- The vault PUTs `blob` as a claim whose TTL equals the invite TTL.
- The **QR / link payload** is compact JSON (base64url-encoded in links):

  ```json
  {"v":2,"t":"c","r":"<relay base URL>","c":"<claim_id>","h":"<b64url SHA-256(blob)>","k":"<b64url k_b>","e":<unix exp>}
  ```

  `t` is `c` for a connection; `p`, `d` and `a` pair an app, desktop or agent
  (§6.7). `h`, `k` and the link encoding are base64url **without** padding
  (RFC 4648 §5). `c` is the relay's 26-character claim id.
- The scanner fetches the claim, MUST check `SHA-256(blob)` = `h` in
  constant time before decrypting, decrypts under `k`, and MUST reject a
  bundle whose `kind` does not match `t`, whose `exp` differs from `e`, or
  that has expired.

```
A app            A vault           Relay            B vault           B app
  |--invite.create{ttl}-->|           |                 |                |
  |                  |--PUT claim---->|                 |                |
  |<--QR / link------|                |                 |<--invite.accept{QR}
  |                  |                |<--GET claim-----|  check h, decrypt, exp
  |                  |                |<--hs.init (open token)-----------|
  |                  |<--collect------|                 |                |
  |<--request.pending{profile,sas,remote}               |                |
  |--approve-------->|--hs.resp------>|---------------->|                |
  |                  |<---------------|<--hs.fin--------|                |
  |<--connection.event{added}         |                 |--connection.event{added}-->|
```

Rules:

- **Single use.** Every invite is single-use. The inviting vault accepts at
  most one `hs.init` per `invite_id` and rejects invites that are expired,
  used or revoked. The claim is single-fetch.
- **In-person invites (10 min).** Approval is explicit by default; the owner
  MAY enable auto-approval for in-person invites. Apps SHOULD offer to
  compare the SAS as a safety number.
- **Remote invites.** The resulting connection stays **`pending`** until the
  inviter explicitly approves it in the app.
  - Auto-approval MUST NOT apply.
  - The app shows the invitee's presented `profile`, which is self-asserted
    and labelled as such, and the SAS. The app SHOULD suggest comparing the
    SAS over a channel the inviter trusts, such as a call.
  - The vault does not send `hs.resp` while the connection is pending.
    Anyone who saw the link could have accepted it, so approval is the
    control.
- **Pending expiry.** A connection request that the owner has neither
  approved nor declined is dropped after **7 days** (the longest invite
  TTL).
- **Who approves.** Connection requests are approved or declined by an
  owner device of role `app` or `desktop`. Agents MUST NOT create, accept,
  approve or decline invitations.
- **Revocation.** The inviter MAY revoke an outstanding invite at any time
  with `connection.invite.cancel`. The vault denylists the open token's `jti`
  and DELETEs the claim. `connection.invite.list` shows outstanding invites.

### 6.5 Epochs and rekey

**Epoch length:**

| Session | Epoch ends after |
|---|---|
| Vault ↔ vault | **24 h or 10,000 messages** in either direction |
| Vault ↔ device or agent | 7 days, and on every unlock |

Either side MAY rekey sooner. The side that hits the limit initiates. If both
sides initiate at once, the `hs.init` with the lower `th1` wins (compared as
big-endian byte strings).

Reaching the limit does not stop sending: both sides keep sending in the
old epoch until the new epoch activates, so that a locked peer does not
block delivery.

**Key retention:**

- Receive keys of previous epochs are kept for 16 days (the relay TTL plus a
  margin).
- Send keys of previous epochs, and their `rk`, are deleted when the new
  epoch activates. A rekey is therefore possible only from the current
  epoch.

**Rationale for epochs rather than a per-message ratchet:**

- The mailbox is unordered and at-least-once, so a ratchet would need
  skipped-key stores that weaken its benefit.
- The vault keeps message history in its state anyway, so per-message keys
  would protect little that a vault compromise does not already expose.

Each rekey uses a fresh ephemeral KEM. That bounds the exposure of a
compromised epoch key and restores security after compromise.

### 6.6 Reconnect tokens

Standing tokens expire after 30 days or less. Each side of a connection
therefore also holds a **reconnect token** for the peer. With it, a
connection can be restored without a new invite after a long lock or other
outage.

**Reconnect token properties:**

| Property | Value |
|---|---|
| Binding | Sender-bound: `sub` = the peer's relay key |
| Lifetime | ≤ 365 days, and ≤ the relay's `max_token_lifetime_seconds` |
| `quota` | `{"msgs": 4, "bytes": 65536}` |
| Delivered in | `hs.init`, `hs.resp`, `relay.token.issued` |
| Re-minted | After every successful reconnect and every relay-key rotation, and when less than 60 days remain |

**Permitted use.** A reconnect token MAY only be used to deposit an `hs.init`
with `purpose: reconnect`. The receiving vault records the `jti` of every
token it issues, with its kind, and decides the token class of each
collected message by the collect `jti` (RELAY-PROTOCOL 0.4.0 §6.3):

- A message from a connection whose collect `jti` is that of a reconnect
  token MUST be dropped and audited unless it is a sealed `hs.init` with
  purpose `reconnect`.
- A message from a connection that carries **no** `jti` (stored by a
  pre-0.4 relay) MUST be treated as a reconnect-token deposit.

**When to use it.** A vault uses its reconnect token automatically when it
is unlocked and either:

- a deposit to the peer fails with `token_expired`; or
- on unlock (§12.2), its standing token for the peer has already expired.

**Initiating.** The reconnect `hs.init` is sealed to the last known `ek` of
the peer. It carries:

- fresh standing and reconnect tokens;
- `ctx` = the stored `epoch_id` of the last epoch;
- `rotations`: the initiator's rotation statements since the last epoch.

**Authentication.** No SAS or approval is needed when the identities match.
The responder MUST accept the reconnect only if all of these hold:

- the collect `sender` equals the relay key on record for that connection,
  which is also the reconnect token's `sub`;
- `from.ik` equals the stored `ik`, or is reached from it through a valid
  `rotations` chain;
- `sig_I` verifies under that key.

Each link in a rotation chain is an `identity.rotate` statement (§3.4). When
`rotations` is non-empty, `from.kem` MUST equal the chain's final
`new_kem`. The responder answers with its own `rotations`, and the
initiator verifies `sig_R` the same way.

**Retired keys.** Vaults keep retired static `kem` private keys for 400 days
so that they can still open reconnect `hs.init`s sealed to an older key.

**Limits:**

- Messages older than the relay TTL are lost regardless. After a reconnect,
  the vaults exchange `sync.since` (schemas TBD) to resync shared state.
- A peer that rotated its *relay* key while the connection was unreachable
  has its old mailbox deleted after the rotation grace period. The reconnect
  then fails with `mailbox_unknown`, and the connection becomes `stale`. A new
  invite is required. Vaults SHOULD defer relay-key rotation, except after a
  suspected compromise, while any connection's standing token is expired.

### 6.7 Owner device and agent pairing

The first app is bound at enrollment (§11.3). Every other app, desktop and
agent pairs from an app that is already paired. The QR (TTL 10 min) is shown
on the paired app; the new device scans it, or the code is pasted.

```
Paired app            Vault                Relay              New device/agent
  |--device.pair.create{role}-->|              |                     |
  |             PUT claim (kind=p|d|a) ------->|                     |
  |<--QR / code-----------------|              |<--register MB(dev)--|
  |                             |              |<--GET claim---------|
  |                             |<--collect----|<--hs.init (open)----|  shows SAS
  |<--device.pair.pending{name,role,sas}       |                     |
  |   user compares SAS         |              |                     |
  |--device.pair.approve{grants}-->|--hs.resp->|-------------------->|
  |                             |<-------------|<--hs.fin------------|
  |                             |--device.paired{role,grants}------->|
```

Rules:

- **Approval first.** The vault MUST NOT send `hs.resp` before approval. If
  the owner rejects, or 10 minutes pass without approval, the vault drops the
  pairing and denylists the `jti`.
- **Who pairs.** Only an owner device of role `app` creates
  (`device.pair.create`), approves or rejects pairings. Desktops and agents
  cannot.
- **Agents.** The approval carries the agent's initial LEASH grants, and the
  agent's `ik` is the grantee.
- **Apps.** For role `app`, `hs.init` carries the device attestation in
  `device_attest` (§11.7), over the §11.7 challenge with the `hs.init`
  inner `id` as `request_id`, an empty `vault_id` (the new device does not
  know it yet) and the `hs.init` inner `ts`. The vault drops (and audits)
  an app's `hs.init` without a valid attestation.
  In the same flush as the device record, the vault adds the app's `ik`,
  `kem` and attestation binding to the sealed header's unlock keys.
- **Re-pairing.** A re-paired device MUST use a new relay key, because its
  old `sub` stays denylisted. The vault MUST refuse an `hs.init` whose
  collect `sender` is a relay key it has denylisted (§7.4), whatever token
  it arrived on.

## 7. Deposit tokens

### 7.1 Issuance

Tokens are PASETO v4.public, signed by the **recipient's** relay key
(RELAY-PROTOCOL §5). `iat` SHOULD be backdated by up to 60 s
(RELAY-PROTOCOL §5.2), and every lifetime below is measured from the
backdated `iat`. Every lifetime is also capped by the relay's advertised
policy (§1.2).

| Mailbox | `sub` | Kind | `exp − iat` | Default `quota` | Delivered in |
|---|---|---|---|---|---|
| Vault | each owner device | standing | ≤ 30 d | none | `hs.resp`, `relay.token.issued`, unlock result |
| Vault | each peer vault | standing | ≤ 30 d | 20,000 msgs / 512 MiB | handshake, `relay.token.issued` |
| Vault | each peer vault | **reconnect** (§6.6) | ≤ 365 d | 4 msgs / 64 KiB | handshake, `relay.token.issued` |
| Vault | invitee | open | = invite TTL (10 min default, up to 7 d) | one deposit | claim bundle |
| Vault | new device | open | ≤ 10 min | one deposit | claim bundle |
| Device | its vault | standing | ≤ 30 d | none | `hs.init`, `relay.token.issued`, unlock request |
| Device (app) | the vault being enrolled | open | ≤ 10 min | one deposit | enrollment request, inside the ciphertext |
| Peer vault | this vault | standing and reconnect | as above | peer's choice | handshake, `relay.token.issued` |

Devices never hold tokens for peers, and peers never hold tokens for devices.

### 7.2 Refresh

**Standing tokens:**

- An issuer SHOULD send `relay.token.issued` when an outstanding standing
  token has less than 10 days left.
- A holder MAY send `relay.token.refresh` when its token has less than
  3 days left, or after `token_expired`.

**On unlock**, the vault first:

1. re-mints every standing token it issued that has less than 10 days left;
2. re-mints every reconnect token it issued that has less than 60 days left;
3. starts a reconnect (§6.6) for each connection whose standing token it
   holds has already expired.

**Unlock exchange.** Unlock requests carry a fresh app token, and unlock
results carry a fresh vault token (§11.4). An app that has been offline for a
long time therefore recovers without going through the relay.

### 7.3 Quotas

The relay enforces each token's `quota` and its own per-sender limits. On
top of that, the vault limits each peer to:

- 60 durable messages per minute;
- 1 `presence.ping` per minute.

Excess messages are acked, dropped and audited.

### 7.4 Revocation

The actions for each event are applied in one flush, in the order listed:

| Event | Actions |
|---|---|
| Connection removed | Send `connection.removed` (best effort). Denylist `sub` = peer relay key, which also kills its reconnect token. Delete the tokens held for the peer, its session keys and its outbox entries. |
| Peer blocked | As for connection removed, plus a block entry on the peer's `ik` |
| Device unlinked | Send `device.unlinked` (best effort). Denylist `sub`. Remove the device from the unlock keys. Delete its wake reference. |
| Agent revoked | As for device unlinked, plus revoke all of the agent's LEASH grants |
| Invite or pairing cancelled or expired | Denylist the open token's `jti`. DELETE the claim. |

The relay retains denylist entries for its maximum token lifetime
(RELAY-PROTOCOL §5.5). This is why reconnect tokens raise denylist retention
at the relay.

## 8. Delivery semantics

The relay delivers at least once, in per-mailbox arrival order, with a 60 s
lease and a 14-day TTL (the defaults).

### 8.1 Requests and responses

- Types marked **req** in §10 expect a response. The response:
  - has the same `type`;
  - sets `re` to the request's `id`;
  - carries a `status`;
  - is deposited into the requester's mailbox.
- A response whose `re` matches no pending request is acked and dropped.
- Interactive requests SHOULD time out after 30 s, unless the type defines
  its own timeout.

### 8.2 Dedupe and idempotency

Both of the following layers are REQUIRED:

1. **Relay `msg_id`.** Seen ids are kept for 16 days.
2. **Inner `id`, per principal.** These are kept for 16 days in vault state.
   This layer catches sender retransmissions, which the relay stores under
   different `msg_id`s. Responses are cached for 24 h, so a duplicate request
   gets the cached response again and is not re-executed.

**Exception: responses that carry secret values** (`credential.secret.get`,
§3.5.3). They are never cached and never written to vault state, so they
are not in the outbox either. They are deposited from memory after the
batch's flush, behind any queued deposits to the same mailbox, and are
lost if that deposit fails or the vault stops first. A retransmission of
such a request is therefore executed again. This is allowed only for types
whose only side effects are audit and feed entries.

Both stores are flushed with the state changes before the ack (§8.3).

### 8.3 Ack after durable persist

For durable types, the vault processes each batch as follows:

1. Collect a batch of up to 32 messages.
2. For each message, in order:
   - dedupe;
   - decrypt;
   - authorize;
   - apply to the in-memory state;
   - record the inner `id`;
   - append any outbound messages to the **outbox**.
3. Increment `state_seq` and **flush** vault state with a conditional write
   (§12.3). The sealed header is then updated to the same `state_seq`
   (§13.2).
4. **Ack** each `msg_id`.
5. Deposit the outbox entries. An entry is removed in a later flush, once the
   relay has answered it with `201`.

If the vault crashes:

| Crash point | Recovery |
|---|---|
| Before step 3 | The batch is redelivered and re-applied cleanly. |
| Between steps 3 and 4 | The batch is redelivered and hits the inner-`id` dedupe. |
| During step 5 | The entries are re-deposited with the same inner `id`, and the recipient dedupes them. |

Flushes SHOULD be coalesced over a window of about 100 ms. Devices apply the
same rule to their local storage.

### 8.4 Ordering

- No global or causal order is provided. `seq` reveals gaps and orders one
  sender's messages for display.
- Handlers MUST tolerate reordering. State that can be edited from several
  devices carries explicit versions, defined per feature schema.
- Receivers MUST reject `ts` more than 5 minutes in the future. For durable
  types, they MUST also reject `ts` more than 16 days in the past.

### 8.5 Durability classes

| Class | Types | Ack | Dedupe | Staleness |
|---|---|---|---|---|
| durable | everything not listed below | after flush | persisted | `ts` window |
| ephemeral | `call.ice`, `presence.*`, `vault.locking` | after handling | in memory, 10 min | `exp` required |

### 8.6 Retries

**Transport retries** follow RELAY-PROTOCOL §7.2:

- full jitter, starting at 0.25 s × 2ⁿ and capped at 30 s;
- every attempt is re-signed;
- `retry_after` is honoured.

**Application retries** reuse the inner `id`, at most twice.

How each error is handled:

| Error | Handling |
|---|---|
| `token_expired` | Refresh the token, or reconnect (§6.6). |
| `token_revoked` | Terminal. Stop sending to that mailbox. |
| `token_used` | The open token is already spent. Restart first contact. |
| `mailbox_unknown` | Re-resolve the address, or mark the connection `stale`. |

## 9. Fan-out, presence and broadcasts

### 9.1 Owner devices

- The vault makes **one deposit per owner device**, each under that device's
  session. It filters by role, so an agent receives only what its grants
  cover.
- A response goes only to the device that sent the request. Side effects
  reach the owner's other devices as `sync.event`, or as feature events.
- A device that has not collected for longer than the relay TTL resyncs
  with `sync.since`.

### 9.2 Presence ping

The relay has no presence, and heartbeats sent into mailboxes that expire
would be wasteful. Presence is on demand instead:

1. The app sends `presence.query{connection_id}` to its vault.
2. The vault sends `presence.ping` to the peer vault. The ping is ephemeral,
   with `exp` = now + 30 s.
3. The peer vault replies with `presence.pong{state, last_active}`, but only
   if it is unlocked and its owner's policy allows it. `last_active` is
   rounded to 5 minutes.
4. If no pong arrives before `exp`, presence is `unknown`.

A vault answers at most one ping per peer per minute. When its policy
refuses, it answers `unknown`.

### 9.3 Broadcasts to connections

Some updates go to every connection, such as `profile.update`,
`identity.rotate` and `relay.address.update`. The vault sends them as **one
deposit per peer**, each under that peer's session. It SHOULD spread the
deposits over a random 0–30 s interval per peer. Because deposits to one
mailbox stay in order (§8.3), a delayed broadcast also delays later
messages to that peer; implementations MAY send without the spread
(the reference implementation does, for now).

When a connection becomes active (`connection.event{added}`), each vault
sends its current shared profile to the other as `profile.update`.

There are no multi-recipient primitives.

## 10. Message type registry

**Directions:**

- **D→V:** a device to its own vault.
- **V→D:** a vault to its own device(s).
- **V↔V:** between peer vaults.
- **ACh:** the alternate channel (§11).

**req** marks a request (§8.1). Body schemas for lifecycle, sessions,
devices, connections, messaging, the credential, secrets, profile,
settings, audit and feed are in §10.1–§10.9; the others are **TBD per
feature** (§15).

| Group | Type | Dir | req | Purpose |
|---|---|---|---|---|
| Lifecycle | `vault.enroll` | ACh | | Create a vault (§11.3) |
| | `vault.enrolled` | V→D sealed | | Attestation, vault bundle, `vault_id`, token |
| | `vault.enroll.confirm` | D→V | req | End the provisional state |
| | `vault.unlock` / `vault.unlock.result` | ACh | | PIN unlock (§11.4) |
| | `vault.lock`, `vault.status`, `vault.delete` | D→V | req | Lock, status, delete (§7.4 first) |
| | `vault.locking` | V→D | | Graceful lock notice (ephemeral) |
| Sessions | `hs.init`, `hs.resp`, `hs.fin` | D↔V, V↔V | | Handshake, rekey, reconnect (§6) |
| | `relay.token.issued` / `relay.token.refresh` | any | — / req | Deliver or request a token |
| | `relay.address.update`, `identity.rotate` | any | | Rotation (§3.4) |
| Credential | `credential.create`, `.get`, `.version`, `.unlock`, `.lock`, `.rotate`, `.password.change`, `.delete` | D→V | req | Protean Credential lifecycle (§3.5, §10.6) |
| | `credential.secret.add`, `.get`, `.list`, `.delete` | D→V | req | Critical secrets, inside the credential (§10.6) |
| | `pin.change` | D→V | req | Re-derive the DEK and re-seal the header (§10.6) |
| Secrets & profile | `secret.put`, `.get`, `.list`, `.delete` | D→V | req | Vault-held secrets (§10.7) |
| | `profile.get`, `profile.set`, `settings.get`, `settings.set` | D→V | req | Owner profile and policy (§10.8) |
| | `profile.update` | V↔V | | Shared profile to a connection (§9.3, §10.8) |
| | `sync.event` / `sync.since` | V→D, V↔V / D→V, V↔V | — / req | Mirror changes (kinds in §10.1); catch up |
| Connections | `connection.invite.create`, `.list`, `.cancel`, `.accept` | D→V | req | Invitations (§6.4) |
| | `connection.request.pending` | V→D | | Awaiting approval (profile, `sas`, `remote`) |
| | `connection.approve`, `.decline`, `.list`, `.get`, `.remove` | D→V | req | Manage connections |
| | `connection.removed` | V↔V | | Notify the peer |
| | `connection.event` | V→D | | Added, pending, stale, removed, rekeyed, reconnected |
| | `block.add`, `.remove`, `.list` | D→V | req | Block list |
| Messaging | `message.send` | D→V | req | Send to a connection |
| | `message.deliver`, `message.receipt` | V↔V | | Message; delivered or read receipt |
| | `message.new` | V→D | | Incoming message |
| | `message.list`, `.get`, `.read`, `.delete` | D→V | req | History and read state |
| Calls | `call.start` | D→V | req | The vault issues the ICE config (CALLING-SERVICE §6) |
| | `call.offer` / `call.answer` | V↔V, V→D / V↔V, D→V | | SDP and signed ICE config; call KEM `ek` / `enc` |
| | `call.ice` | any | | Trickle ICE (ephemeral) |
| | `call.end` | any | | Hang up, busy, decline, timeout |
| Devices & agents | `device.pair.create`, `.approve`, `.reject`, `device.list`, `device.unlink` | D→V | req | Pairing and management (§6.7) |
| | `device.pair.pending` | V→D | | Awaiting approval (`sas`) |
| | `device.paired`, `device.unlinked` | V→D | | Welcome and removal notices |
| | `agent.request` | D→V (agent) | req | Agent operation, checked against its grants |
| | `agent.approval.pending` / `.decide` | V→D / D→V | — / req | Owner approval outside standing grants |
| LEASH | `leash.grant.issue`, `.revoke`, `.list` | D→V | req | Manage agent grants |
| | `leash.grant.updated` | V→D (agent) | | The agent's current grants |
| Wallet | `wallet.*` (list, address, send, ...) | D→V | req | Owner wallet operations |
| | `wallet.address.share`, `wallet.payment.request` | V↔V | | Between connections |
| Location | `location.share.start`, `.stop`, `location.get` | D→V | req | Sharing control |
| | `location.update` | V↔V | | Sample to a connection (latest wins) |
| Actions | `action.define`, `action.list` | D→V | req | Actions offered to connections |
| | `action.invoke` | V↔V | req | Invoke an action on a connection's vault |
| Grants | `grant.request`, `critical-secret.use` | V↔V | req | Request access; use a granted secret |
| | `grant.pending` / `grant.decide` | V→D / D→V | — / req | Owner decision |
| | `grant.revoke` | V↔V | | Withdraw a grant |
| | `grant.list` | D→V | req | Grants given and received |
| Presence | `presence.query`, `presence.set` | D→V | req | Ask; set own state and policy |
| | `presence.ping` / `presence.pong` | V↔V | req / response | On demand (§9.2) |
| Audit & feed | `audit.list`, `connection.audit.list` | D→V | req | Audit log, whole or per connection (§10.9) |
| | `feed.list`, `.get`, `.update`, `.delete`, `guide.sync` | D→V | req | Activity feed; app guides as feed items (§10.9) |
| | `feed.event` | V→D | | New feed item |
| Push | `push.register`, `push.unregister` | D→V | req | Reserved (§14) |

**Calls** (CALLING-SERVICE §7, §9):

- `call.offer` carries a fresh ephemeral KEM `ek`.
- The answering vault runs
  `SetupBaseS(ek, info = "vettid/vms/2/call" || call_id)` and returns the
  resulting `enc` in `call.answer`. It derives
  `K = ctx.Export("vettid/vms/2/call-key", 32)`, and from it
  `k_call = HKDF-SHA-256(ikm = K, salt = "vettid-call-v1", info = call_id)`.
- Offers carry `exp`, 45 s by default.
- `call.offer`, `call.answer` and `call.end` are durable. `call.ice` is
  ephemeral.
- A locked callee cannot answer, so the call times out.

### 10.1 Common rules and `sync.event`

- Bodies are JSON objects (§5.3). Unknown members are ignored. Strings are
  at most 4 KiB unless stated. Timestamps in bodies use the inner `ts`
  format; invite and pairing expiries (`exp` in responses) are RFC 3339 in
  whole seconds.
- Error codes: `bad_request`, `not_found`, `forbidden` (the sender's role may
  not send this type), `unsupported_type` (§5.3), `internal`, `relay_error`,
  `ttl_not_allowed`, `claim_unavailable`, `accept_failed`, `approve_failed`,
  `connection_unavailable`, and (0.4.0):
  - `conflict`: the request's `version` is not the current one (§8.4);
  - `exists`: the object already exists (`credential.create`);
  - `limit`: a count or size limit of the feature would be exceeded;
  - `bad_password`, `backoff`, `stale_credential`: §3.5.3;
  - `bad_pin`: the current PIN given to `pin.change` is wrong.
- A request answered with an error changes no state, except the password
  backoff and the audit log and feed entries of §3.5.3. Objects that several
  owner devices can edit carry a `version` (an integer from 1, `0` before
  the first write); a change MUST name the version it was based on, and
  the vault answers `conflict` if it differs.
- Ids the vault assigns (`secret_id`, `item_id`, `entry_id`) are ULIDs.
- A type sent by a principal whose role is not listed for it is answered
  with `forbidden` (requests) or dropped and audited (other messages).
- Side effects reach the owner's other devices (§9.1) as `sync.event`
  `{kind, ...}`. Kinds:

  | `kind` | Members |
  |---|---|
  | `message.receipt` | `connection_id`, `message_id`, `receipt` (`delivered` \| `read`) |
  | `message.read` | `connection_id`, `message_id` |
  | `device.paired` | `device_id`, `role` |
  | `device.unlinked` | `device_id` |
  | `vault.release` | `release` (PCR0 hex), `release_number`; sent once after a vault first runs under a new release (§11.10.6) |
  | `credential.changed` | `version` (§3.5.4) |
  | `credential.deleted` | — |
  | `secret.changed` | `secret_id`, `version` |
  | `secret.deleted` | `secret_id` |
  | `profile.changed` | `version` |
  | `settings.changed` | `version` |
  | `feed.updated` | `item_id`, `seq` |
  | `feed.deleted` | `item_id`, `seq` |

  These go to the owner's other apps and desktops (not agents), never with
  secret values; devices fetch what changed.

### 10.2 Lifecycle and sessions

| Type | Request body | Response / event body |
|---|---|---|
| `vault.enrolled` | — | §11.3 |
| `vault.enroll.confirm` (app) | `{}` | `{}` |
| `vault.status` (app, desktop, agent) | `{}` | `{vault_id, state_seq, header_seq, provisional, devices, connections}` |
| `vault.lock` (app, desktop) | `{}` | `{}`; then `vault.locking` |
| `vault.locking` (ephemeral) | — | `{}`, with `exp` = now + 60 s |
| `relay.token.issued` | — | `{kind: "standing" \| "reconnect", token}` |
| `relay.token.refresh` (req) | `{}` | `{kind: "standing", token}` |
| `identity.rotate` | — | `{rotation: <identity.rotate statement, §3.4>}` |
| `relay.address.update` | — | `{relay: {url, mailbox, pk}, token, reconnect_token?}` |

### 10.3 Devices (§6.7)

| Type | Request body | Response / event body |
|---|---|---|
| `device.pair.create` (app) | `{role: "app" \| "desktop" \| "agent"}` | `{pairing_id, link, exp}` |
| `device.pair.pending` (to apps) | — | `{pairing_id, pending_id, role, name, sas}`; `name` is the new device's self-asserted `profile.name` |
| `device.pair.approve`, `.reject` (app) | `{pairing_id}` | `{}` |
| `device.paired` (to the new device) | — | `{device_id, role, vault_id, release, release_number}` (the release the vault runs under) |
| `device.list` (app, desktop) | `{}` | `{devices: [{id, kind, state, name, ik, profile?}]}` |
| `device.unlink` (app) | `{device_id}` | `{}` |
| `device.unlinked` (to the unlinked device, best effort) | — | `{}` |

### 10.4 Connections (§6.4)

| Type | Request body | Response / event body |
|---|---|---|
| `connection.invite.create` | `{ttl_seconds: 600 \| 3600 \| 86400 \| 604800}` | `{invite_id, link, exp, remote}` |
| `connection.invite.list` | `{}` | `{invites: [{invite_id, exp, remote}]}` |
| `connection.invite.cancel` | `{invite_id}` | `{}` |
| `connection.invite.accept` | `{link}` | `{connection_id, state: "pending"}` |
| `connection.request.pending` | — | `{pending_id, invite_id, sas, remote, profile?}` |
| `connection.approve`, `.decline` | `{pending_id}` | `{}` |
| `connection.list` | `{}` | `{connections: [{id, kind, state, name, ik, profile?}]}` |
| `connection.get` | `{connection_id}` | `{id, kind, state, name, ik, profile?}` |
| `connection.remove` | `{connection_id}` | `{}` |
| `connection.removed` (V↔V) | — | `{}` |
| `connection.event` | — | `{connection_id, event: "added" \| "removed" \| "stale" \| "rekeyed" \| "reconnected" \| "failed" \| "profile"}`; `profile`: the connection's shared profile changed (§10.8) |

The D→V types above are sent by `app` or `desktop` devices (§6.4 "Who
approves").

### 10.5 Messaging

| Type | Request body | Response / event body |
|---|---|---|
| `message.send` | `{connection_id, text}`; `text` 1 byte to 16 KiB (larger content uses the blob flow, §5.5) | `{message_id, sent_at}` |
| `message.deliver` (V↔V) | — | `{message_id (ULID), text, sent_at}`; idempotent by `message_id` |
| `message.receipt` (V↔V) | — | `{message_id, receipt: "delivered" \| "read", at}` |
| `message.new` | — | `{connection_id, message_id, direction: "in" \| "out", text, sent_at, delivered, read}` |
| `message.list` | `{connection_id, limit?}` (1–500, default 100) | `{messages: [<message.new body>, ...]}`, oldest first |
| `message.get` | `{connection_id, message_id}` | `<message.new body>` |
| `message.read` | `{connection_id, message_id}` | `{}`; the vault sends a read receipt |
| `message.delete` | `{connection_id, message_id}` | `{}`; local only |

The D→V messaging types are sent by `app` or `desktop` devices.

### 10.6 Credential and critical secrets (§3.5)

`credential` is the standard base64 of a §3.5.2 blob; `password` and
`new_password` are UTF-8 strings of 8–1,024 bytes. Every type below is
sent by an owner device of role `app`, except `credential.version` and
`credential.secret.list`, which an `app` or `desktop` may send. Types
that carry `credential` and `password` follow §3.5.3 and can answer
`backoff`, `stale_credential` and `bad_password`.

| Type | Request body | Response body |
|---|---|---|
| `credential.create` | `{password}` | `{credential, version, key}`; `exists` if the vault has a credential |
| `credential.get` | `{}` | `{credential, version, updated_at}`; `not_found` if there is none or the vault keeps no copy (§3.5.6) |
| `credential.version` | `{}` | `{exists, version?, key?, updated_at?}` |
| `credential.unlock` | `{credential, password}` | `{expires_at}` (§3.5.3 unlock window) |
| `credential.lock` | `{}` | `{}` |
| `credential.rotate` | `{credential, password}` | `{credential, version, key}`; the vault also rotates `ik` and `kem` (§3.4) |
| `credential.password.change` | `{credential, password, new_password}` | `{credential, version}` |
| `credential.delete` | `{credential, password}` | `{}` |
| `credential.secret.add` | `{credential, password, name, category, description?, value}` | `{secret_id, credential, version}` |
| `credential.secret.get` | `{credential, password, secret_id}` | `{secret_id, name, category, description?, value, created_at}` |
| `credential.secret.list` | `{}` | `{version, secrets: [{secret_id, name, category, description?, created_at}]}` |
| `credential.secret.delete` | `{credential, password, secret_id}` | `{credential, version}` |
| `pin.change` | `{pin, new_pin}` | `{}`; `bad_pin` if `pin` is wrong |

- `key` is the credential key's public key (base64). `version` is the
  credential's version (§3.5.2).
- `name` is 1–128 bytes, `description` at most 1,024 bytes, `category` and
  `value` as in §3.5.2 (`value` base64, 1–8,192 bytes decoded). A
  credential holds at most 64 secrets (`limit`).
- The secrets' metadata (`credential.secret.list`) is kept in vault state
  so that it can be listed without the password; values are only in the
  credential.
- Every change sends `sync.event{kind: "credential.changed", version}`
  (`credential.deleted` for a delete) to the owner's other devices.
- `pin.change` re-derives the DEK from `new_pin` (§3.3.1, fresh salt) and
  re-encrypts the state and the header. Its crash-safe write order is
  specified together with its implementation (§15).

### 10.7 Secrets

Secrets are vault-held values that the owner can read without the
password (the "minor" secrets; critical ones belong in the credential).
They are kept in DEK state. Sent by `app` or `desktop`.

| Type | Request body | Response body |
|---|---|---|
| `secret.put` | `{secret_id?, version?, name, value, category?, description?, discoverability?}` | `{secret_id, version, updated_at}` |
| `secret.get` | `{secret_id}` | `{secret_id, version, name, value, category, description?, discoverability, created_at, updated_at}` |
| `secret.list` | `{}` | `{secrets: [<secret.get body without value>, ...]}`, sorted by `name` |
| `secret.delete` | `{secret_id}` | `{}` |

- Without `secret_id`, `secret.put` creates a secret (version 1, and
  `version` MUST be absent). With `secret_id`, it replaces that secret and
  `version` is required (`not_found`, `conflict`).
- `name` 1–128 bytes; `value` a string of 1–16,384 bytes; `category`
  matches `[a-z][a-z0-9_]{0,31}` (default `other`); `description` at most
  1,024 bytes; `discoverability` is `private` (default) or `cataloged`.
  Only grants use `cataloged`, and until they exist it has no effect. At
  most 500 secrets (`limit`).
- Changes send `sync.event` `secret.changed` or `secret.deleted`.

### 10.8 Profile and settings

**Profile.** The owner's profile is one set of fields, which also holds
what the earlier design called personal data; `shared` selects what
connections see. Sent by `app` or `desktop`.

| Type | Request body | Response body |
|---|---|---|
| `profile.get` | `{}` | `{version, name, fields: {<key>: {value, label?, updated_at}}, shared: [<key>], order: [<key>], photo?}` |
| `profile.set` | `{version, name?, set?: {<key>: {value, label?}}, delete?: [<key>], shared?: [<key>], order?: [<key>], photo?}` | `{version}` |
| `profile.update` (V↔V) | — | `{version, name, fields: {<key>: {value, label?}}, photo?}` |

- `<key>` matches `[a-z][a-z0-9_.-]{0,63}`, for example `contact.email.work`.
  `value` is 1–4,096 bytes; `label` at most 64 bytes; at most 200 fields
  (`limit`). `name`, the display name, is at most 128 bytes.
- `photo` is base64 of a JPEG or PNG image of at most 65,536 bytes; in
  `profile.set`, `""` removes it.
- `profile.set` applies `delete`, then `set`; `shared` and `order`, if
  present, replace the lists and MUST name existing keys (a deleted key
  leaves both lists). The version rules of §10.1 apply.
- After a change the vault sends `sync.event{kind: "profile.changed"}`,
  and, if the shared view changed (`name`, `photo`, or a shared field),
  `profile.update` to every active connection (§9.3).
- `profile.update` carries only shared fields. A receiver keeps the one
  with the highest `version` per connection and ignores older ones (§8.4),
  shows it as the connection's `profile` (§10.4) and notifies its owner
  devices with `connection.event{event: "profile"}`. It is the peer's
  self-asserted data, and apps MUST present it as such.

**Settings.** Owner policy, versioned as one object. Sent by `app` or
`desktop`.

| Type | Request body | Response body |
|---|---|---|
| `settings.get` | `{}` | `{version, settings: {<key>: <value>}}`, every known key with its current or default value, plus the `app.*` keys set |
| `settings.set` | `{version, set: {<key>: <value>}}` | `{version}` |

| Key | Value | Default |
|---|---|---|
| `connections.auto_approve_in_person` | boolean (§6.4) | `false` |
| `credential.unlock_ttl_seconds` | integer 30–3,600 (§3.5.3) | 300 |
| `feed.retention_days` | integer 1–365 | 30 |
| `audit.retention_days` | integer 30–730 | 365 |
| `app.<name>` | string of at most 4,096 bytes, or `null` to remove; `<name>` matches `[a-z0-9_.-]{1,48}`; at most 64 | — |

`app.*` keys are opaque to the vault; apps use them for preferences that
follow the owner across devices. Unknown keys outside `app.*` are refused
with `bad_request`. Changes send `sync.event{kind: "settings.changed"}`.

### 10.9 Audit and feed

The vault keeps two records of what happened:

- the **audit log**, append-only and hash-chained, for security review;
- the **feed**, the owner's activity list, with read and archive state
  shared by the owner's devices.

Neither holds message text, secret values or keys. Both are DEK state.
All types are sent by `app` or `desktop`.

**Audit.**

| Type | Request body | Response body |
|---|---|---|
| `audit.list` | `{connection_id?, kinds?: [<prefix>], before_seq?, limit?}` | `{entries: [<entry>], head, next_before_seq?}`, newest first |
| `connection.audit.list` | `{connection_id, kinds?, before_seq?, limit?}` | as `audit.list`, for one connection |

```json
entry: { "entry_id": "<ULID>", "seq": 812, "at": "<ts>", "kind": "connection.added",
         "connection_id": "<id>?", "device_id": "<id>?", "ref": "<id>?",
         "direction": "in|out?", "prev": "<b64 32>", "hash": "<b64 32>" }
```

- `limit` is 1–500 (default 100). `kinds` holds 1–16 prefixes of at most
  64 bytes; an entry matches if its `kind` equals a prefix or starts with
  the prefix followed by `.`.
- `seq` starts at 1 and increases by one per entry. `hash` chains the log:

  ```
  hash = SHA-256("vettid/vms/2/audit" || prev || uint64be(seq) || uint64be(at_ms)
                 || lp(kind) || lp(connection_id) || lp(device_id) || lp(ref) || lp(direction))
  ```

  where `lp(x)` is the 2-byte big-endian length of `x` followed by its
  bytes (absent members are empty), `at_ms` is `at` in Unix milliseconds,
  and `prev` is the previous entry's `hash` (32 zero bytes for `seq` 1).
  `head` is the newest entry's `hash`. An app can check that the entries
  it receives chain, and that `head` only moves forward.
- Entries older than `audit.retention_days` are dropped, and the log keeps
  at most 10,000 entries; the oldest kept entry's `prev` is then not
  verifiable from genesis.
- Kinds: `vault.unlocked`, `vault.locked`; `device.paired`,
  `device.unlinked`; `connection.added`, `connection.removed`,
  `connection.stale`, `connection.reconnected`; `identity.rotated`;
  `credential.created`, `credential.rotated`, `credential.password_changed`,
  `credential.password_failed`, `credential.unlocked`, `credential.deleted`;
  `credential.secret.added`, `credential.secret.read`,
  `credential.secret.deleted`; `secret.added`, `secret.updated`,
  `secret.deleted`; `message.sent`, `message.received` (no content; `ref` =
  `message_id`); and `drop.<reason>` for every message the vault dropped
  or refused (§6.3, §6.6, §7.3, §8.4), with the runtime's reason, such as
  `drop.rate_limited`.

**Feed.**

| Type | Request body | Response body |
|---|---|---|
| `feed.list` | `{status?, after_seq?, limit?}` | `{items: [<item>], seq}` |
| `feed.get` | `{item_id}` | `<item>` |
| `feed.update` | `{item_id, status?, priority?}` | `<item>` |
| `feed.delete` | `{item_id}` | `{}` |
| `feed.event` (V→D) | — | `<item>`, for each new item, to apps and desktops |
| `guide.sync` | `{guides: [{guide_id, version, title, message, priority?}]}` | `{created, updated}` |

```json
item: { "item_id": "<ULID>", "seq": 41, "kind": "connection.request", "at": "<ts>",
        "status": "active|read|archived|deleted", "priority": "low|normal|high|urgent",
        "connection_id": "<id>?", "device_id": "<id>?", "ref": "<id>?",
        "title": "...?", "body": "...?" }
```

- `seq` is the vault's feed counter; an item takes a new `seq` at every
  change. `feed.list` without `after_seq` returns the items that are not
  deleted, newest first, filtered by `status` (`active`, `read`,
  `archived` or `all`, the default); with `after_seq` it returns every
  item changed after it, in `seq` order, including deleted ones (without
  `title` and `body`), so that a device can catch up. The response `seq`
  is the current counter. `limit` is 1–500 (default 100).
- `feed.update` sets `status` (`active`, `read` or `archived`) and/or
  `priority`; changes send `sync.event` `feed.updated` or `feed.deleted`.
- Kinds the vault creates: `connection.request` (`ref` = `pending_id`),
  `connection.added`, `connection.removed`, `connection.stale`,
  `device.pair.pending`, `device.paired`, `device.unlinked`,
  `message.received` (`ref` = `message_id`), `credential.password_failed`,
  `credential.secret.read`, `credential.rotated`, and `guide`. Apps render
  items from `kind` and the references; only `guide` items carry `title`
  and `body`.
- Items older than `feed.retention_days` are dropped, and the feed keeps at
  most 1,000 items.
- **Guides.** The app owns its catalog of welcome and tutorial guides.
  `guide.sync` creates a `guide` feed item for each `guide_id` the vault
  has not seen, and a new item for a higher `version` (so that read state
  is shared across devices); the same or a lower version is a no-op.
  `guide_id` matches `[a-z0-9_.-]{1,64}`, `version` is 1–2^31, `title` at
  most 256 bytes, `message` at most 4,096, `priority` as for items
  (default `normal`); at most 64 guides per request.

## 11. Enrollment and unlock (alternate channel)

### 11.1 Path and routing

```
app --HTTPS--> member API /api/vault/* --> SQS queue of the leased instance --> parent --vsock--> enclave
app <--poll--- GET /api/vault/requests/{id} <-- response slot <-------------- parent <---------- enclave
```

**Routes:**

- `GET /api/vault/enclave`
- `POST /api/vault/enroll`
- `POST /api/vault/unlock`
- `POST /api/vault/lock`
- `GET /api/vault/requests/{id}`
- `GET /api/vault/status`

The routes follow MEMBER-API conventions; errors use the MEMBER-API error
body `{error, message}` and add `code` (equal to `error`) and any fields
named here. Each request envelope is sealed to
an instance's ETK and padded to a fixed size (12,288 bytes for
`vault.enroll` and `vault.unlock`, 4,096 otherwise, §5.4), and the API, queue and parent see only opaque bytes.

**Access.** `GET /api/vault/enclave`, enroll and unlock require a member in
state `member` who has accepted the current terms (otherwise `403
terms_required`). Lock and status stay available for an existing vault
whatever the account state, because locking only reduces exposure.
Cancelling the account blocks vault access (every route but lock) at once;
after the 7-day grace period the API deletes the member's vault rows, the
stored encrypted state and headers (`vaults/<vault_id>/`), and the
enclave's member index object (`users/<hex SHA-256("vettid/vms/2/user" ||
0x00 || user_guid)>/vault`, which holds only a `vault_id`) (§11.5).

**Instances and leases:**

- Each enclave instance owns **one SQS queue**
  (`<deployment prefix>vault-control-<instance_id>`; vettid.org uses the
  prefix `vettid-org-`), which the parent creates at boot and deletes at
  shutdown. `instance_id` matches `[A-Za-z0-9_-]{1,48}`. The API sends only
  to that name in its own account. A sweeper removes queues of instances
  that have gone away.
- The instance publishes `{instance_id, release, queue_url, descriptor,
  attestation, heartbeat_at}` to an **instance registry** and heartbeats at
  least every 30 s. An instance whose `heartbeat_at` is more than 90 s old
  is **not live**.
- A per-instance queue was chosen over a shared queue with message
  attributes, because SQS cannot filter deliveries by attribute. On a shared
  queue, every instance would receive, and have to return, every other
  instance's messages.
- **A vault is held by at most one instance**, recorded as the lease
  `{instance_id, lease_expires_at}` in its vault-table row (§11.5):
  - The parent acquires the lease with a conditional write, which succeeds
    only if the lease is absent, expired, already its own, or held by an
    instance that is not live (below). Taking over a non-live holder's
    lease is conditional on the exact lease value it replaces
    (`instance_id` and `lease_expires_at`), so two instances cannot both
    take it.
  - The parent acquires the lease **before** it forwards an enroll or
    unlock to the enclave. If another instance holds the lease, the
    parent does not forward the request: it deletes the message and marks
    the response slot `expired` (§11.5, §11.9). If the request does not
    leave the vault open (a refused unlock, a failed enrollment), the
    parent releases the lease again.
  - While the vault is unlocked, the parent renews the lease every 60 s,
    with a lease length of 180 s. A renewal that finds another holder, or
    renewals that keep failing until 15 s before the lease expires, mean
    the lease is **lost**: the enclave locks the vault (§12.3).
  - The parent releases the lease on lock.
- **Routing for `GET /api/vault/enclave`:**
  - If the vault has a live lease, the API returns the descriptor of the
    leased instance.
  - Otherwise, it returns a live instance **of the vault's
    `sealed_release`** chosen by load, or starts one (§11.10.5). That
    instance takes the lease when it processes the request.
  - Enrollment goes to an instance of an `active` release.
- **Routing for posted requests.** A request names the instance whose ETK it
  was sealed to. The API forwards it only if that instance still holds the
  lease, or if there is no live lease. Otherwise it answers `409
  instance_moved`, and the app refetches the descriptor and re-seals.
- A lease is **live** only while it is unexpired and its holder is live.
  `lease_expires_at` and `heartbeat_at` are Unix seconds (numbers); the
  lease is the vault-table map attribute `lease = {instance_id,
  lease_expires_at}`, written only by the parent.
- **Leases are a routing aid.** Correctness still rests on the split-brain
  guard (§12.3). If two instances both believed they held a vault, the second
  conditional state write would fail and that instance would lock it.

### 11.2 Enclave transport key

At start, and then at least every 24 h, each instance generates an ETK and
publishes a **descriptor**:

```json
{ "v": 1, "suite": 2, "instance_id": "<id>", "kid": "<hex>", "etk": "<b64 ek>",
  "release": "<PCR0 hex>", "not_after": "<RFC 3339, ≤ issue + 24 h>" }
```

The enclave obtains a Nitro attestation document whose `user_data` is
`SHA-256("vettid/vms/2/etk" || descriptor_bytes)`. The member API serves the
exact descriptor bytes together with the attestation document.

The app MUST:

1. verify the attestation chain up to the AWS Nitro root, evaluated at the
   document's timestamp (signing certificates are short-lived; step 3
   bounds the document's age);
2. match PCR0, PCR1 and PCR2 against an entry of VettID's signed release
   manifest (§11.10.1), rejecting debug (all-zero) PCRs: an `active` entry
   to enroll, any listed entry to unlock;
3. check `user_data`, check `not_after`, and check that the attestation is
   less than 26 h old;
4. tell the user before sending a PIN if `release` differs from the release
   the app last unlocked into ("vault software was updated"), and never send
   a PIN to an older release than that one (§11.10.6).

The previous ETK stays valid for 1 h after rotation. ETK private keys never
leave enclave memory.

### 11.3 Enrollment

**The `vault.enroll` request** is sealed to the ETK of the instance named by
`GET /api/vault/enclave`:

```json
{ "user_guid": "<from /api/account/me>", "request_id": "<ULID>", "nonce": "<b64 32 B>",
  "pin": "<digits>",
  "app": { "ik": "<b64>", "kem": "<b64 ek>",
           "relay": {"url": "<base>", "mailbox": "<id>", "pk": "<b64>"},
           "open_token": "<open token for MB(app), ≤ 10 min>", "name": "<device name>",
           "device_attest": { } },
  "manifest": { "manifest": "<b64>", "sig": "<b64>", "key_id": "<hex>" } }
```

`device_attest` is REQUIRED (§11.7). `manifest` is the served manifest
document (§11.10.1), REQUIRED: the enclave verifies it, finds its own
release's entry (which must be `active`) and verifies its own sealing key
(§11.10.7) before sealing the first header. The request is padded to
exactly 12,288 bytes (§5.4).

```
App               Relay        Member API               SQS/Parent       Enclave
 | gen keys          |               |                    |                 |
 |--register MB(app)->|              |                    |                 |
 |--GET /api/vault/enclave---------->|  (instance chosen) |                 |
 |<--descriptor + attestation--------|                    |                 |
 | verify (§11.2); attest device key (§11.7, in envelope) |                 |
 |--POST /api/vault/enroll{request_id, instance_id, etk_kid, envelope}|
 |                   |      assign vault_id;              |                 |
 |                   |      row: enrolling                |                 |
 |                   |               |--enqueue{vault_id}->|--vsock bytes-->|
 |<--202{vault_id}-----------------------|                |   decrypt; bind checks; device attestation;
 |                   |               |                    |   gen keys; DEK(PIN); header
 |                   |<======== register MB(vault) (TLS from enclave) =====|
 |                   |               |                    |   persist (create-only)
 |                   |<======== deposit vault.enrolled (open token) =======|
 |                   |               |<--lifecycle{unlocked, versions}-----|
 |--collect--------->|               |                    |                 |
 |<--vault.enrolled--|  verify attestation (nonce, user_data, PCRs); pin bundle
 |--hs.init (purpose=app) ... hs.fin ===================================> vault
 |--vault.enroll.confirm, credential.create =============================> vault
```

**`vault.enrolled`** is sealed to the app's `kem`:

```json
{ "request_id": "<ULID>", "vault_id": "<id>", "state_seq": 1,
  "attestation": "<b64 COSE_Sign1: nonce = app nonce, user_data = SHA-256('vettid/vms/2/vault' || vault_bundle)>",
  "vault_bundle": "<b64 exact bytes of {v, suite, ik, kem, relay{url, mailbox, pk}}>",
  "token": "<standing token for MB(vault), sub = app relay key>" }
```

**`vault.enroll.result`.** Whatever the outcome, the enclave also answers in
the response slot (§11.5) with `vault.enroll.result`, sealed to `app.kem`
and padded to exactly 4,096 bytes, its inner `re` equal to `request_id`:

- `{"ok": true, "vault_id": "<id>"}`; `vault.enrolled` follows over the
  relay;
- `{"ok": false, "code": "vault_exists|release_key|manifest|attestation|bad_request|retry"}`.

A request the enclave cannot read or bind (wrong key, binding failure,
replay, malformed `app.kem`) is answered with random bytes of the same
size (§11.4).

**Rules:**

- **Binding.** The enclave MUST reject the request if `user_guid` or
  `request_id` in the ciphertext differ from the queue message, or if the
  inner `ts` (§5.3) is more than 5 minutes off. The inner `id` of an
  alternate-channel request equals its `request_id`, and its `sender_kid`
  is all-zero. It records the queue's `vault_id` in the sealed
  header and in vault state.
- **Provisional vaults.** A new vault stays **provisional** until
  `vault.enroll.confirm` arrives. If no confirmation arrives within 24 h, a
  new enrollment for the same member MAY replace it. A confirmed vault MUST
  NOT be replaced: the enclave answers `vault_exists`.
- **Re-enrollment.** The API assigns `vault_id` once per member: a new
  enrollment carries the member's existing `vault_id` unless the vault was
  deleted. For an enrollment whose `vault_id` already holds a vault, the
  enclave answers `vault_exists` if the vault is confirmed, provisional
  for less than 24 h, or sealed to another release (it cannot tell), and
  otherwise replaces it. The enclave also keeps its own index from a member
  to a vault and applies the same rule to a different `vault_id` of the
  same member.
- **App state.** The app stores `vault_id`, the pinned bundle, the release
  and `state_seq` (§13.2).
- **Release.** The enrolling instance's release becomes the vault's
  `sealed_release`; the header is sealed to it (§11.10.2) after the key
  check of §11.10.7. If the check fails, enrollment fails with
  `release_key`.
- **The first app's handshake.** After `vault.enrolled`, the app sends
  `hs.init` with purpose `app` and `ctx` = `vault_id`, deposited with the
  token from `vault.enrolled`. The vault answers it without approval if,
  and only if, `from.ik` and the collect `sender` equal the keys bound at
  enrollment and the 24 h provisional window has not passed.

### 11.4 Unlock

**The `vault.unlock` request** is sealed to the leased instance's ETK:

```json
{ "user_guid": "...", "vault_id": "...", "request_id": "<ULID>",
  "device_ik": "<b64>", "pin": "<digits>",
  "min_state_seq": 1234, "min_header_seq": 1301,
  "token": "<fresh standing token for MB(device), sub = vault relay key>",
  "device_assertion": { },
  "manifest": { "manifest": "<b64>", "sig": "<b64>", "key_id": "<hex>" },
  "release_update": { "to": "<pcr0 hex>", "to_release": 5, "approval": { } },
  "sig": "<b64 Ed25519 by device_ik>" }
```

`manifest` is the served manifest document (§11.10.1), REQUIRED.
`release_update` is present only when the member approved a release update
(§11.10.3). The request is padded to exactly 12,288 bytes (§5.4).

`device_assertion` is REQUIRED (§11.7). `sig` covers the following string,
where each `\n` is a literal newline:

```
"vettid/vms/2/unlock" \n user_guid \n vault_id \n request_id \n ts \n etk_kid_hex \n
min_state_seq \n min_header_seq \n hex(SHA-256(pin)) \n hex(SHA-256(token)) \n
hex(SHA-256(manifest_bytes)) \n to_pcr0_hex_or_empty
```

`ts` is the request's inner `ts` (§5.3). Integers are decimal, hex is
lowercase, and there is no trailing newline. No field may contain CR or LF.

```
App        Member API                   SQS/Parent                 Enclave
 |--POST /api/vault/unlock{vault_id, request_id, instance_id, etk_kid, envelope}
 |          check lease             |--enqueue--->|--vsock bytes--->|
 |<--202----|                       |             |  replay check; sealed header;
 |          |                       |             |  vault_id/user_guid; unlock key + sig;
 |          |                       |             |  device attestation sig; backoff; rollback
 |          |                       |             |  (§13.2); derive DEK; load state
 |          |<--response slot{request_id, envelope}----------------|
 |--GET /api/vault/requests/{id} (1 s poll)-->|                    |
 |<--{status: done, envelope}----------------|   on success: §12.2 start order
```

**`vault.unlock.result`** is sealed to the device's `kem` from the sealed
header and padded to 4,096 bytes. Its inner `re` is the request's
`request_id` and its `status` is `ok` (the outcome is in the body), so a
result cannot be presented as the answer to another request. Its body is
one of:

- `{"ok": true, "state_seq": n, "header_seq": m, "token": "<standing token for
  MB(vault)>", "release": "<PCR0 hex>", "release_number": r,
  "release_status": "active|deprecated|retired", "manifest_serial": s,
  "update": {"to": "<pcr0>", "result": "moved|refused|abandoned", "code": "<reason>"}}`
  — `update` is present only if the request carried `release_update`, or a
  pending move was completed (§11.10.4). After `moved` the vault is locked
  and sealed to the new release; `header_seq` is the new header's, and
  `token` is absent (the vault did not resume).
- `{"ok": false, "code": "bad_pin|backoff|unknown_device|attestation|state_rollback|vault_missing|manifest|wrong_release|release_key|retry",
  "header_seq": m, "retry_after": <s>}`

On `state_rollback`, the app MUST warn the user that the vault's stored state
is older than state this device has already seen (§13.2). `release_key`
means the running release's own sealing key failed its check (§11.10.7);
`retry` covers state write conflicts (§11.9) and KMS or store failures.

When no unlock key in the header matches `device_ik`, the signature does
not verify, or the release holds no header for `vault_id`, there is no key
to seal to: the enclave answers with random bytes of the result's size
(5,252 bytes), indistinguishable to the API and parent. `unknown_device`
and `vault_missing` therefore reach the app only as an unreadable result.

Every outcome has the same size and the same path, so the response reveals
neither the outcome nor the reason for a failure. VettID can still observe a
success, because the vault then starts collecting and the parent reports its
lifecycle (§11.5).

### 11.5 What the member API stores; queue shape

Nothing secret is stored:

| Store | Contents | Retention |
|---|---|---|
| Vault table | `user_guid`, **`vault_id`** (opaque, 128-bit random, 32 lowercase hex characters, assigned by the API at a member's first enrollment; the routing key for alternate-channel requests), `state` (`enrolling`, `locked`, `unlocked`, `deleted`), **lease** (`instance_id`, `lease_expires_at`), **`sealed_release`** (the PCR0 the vault is sealed to; routing aid, §11.10.5), **`vault_version`** (release that last opened the vault), **`state_version`** (vault-state format version), `created_at`, `updated_at` | account lifetime |
| Instance registry | `instance_id`, **`release`** (PCR0 from its descriptor), queue URL, descriptor, attestation, `heartbeat_at` | while the instance is live |
| Request table (response slots) | `request_id`, `vault_id`, `op`, `status` (`queued`, `done`, `expired`), opaque response `envelope` (≤ 8 KiB) and/or a host `code` | TTL 15 min |
| Audit log | enroll, unlock and lock requests: member, time, `vault_id`, request id, never PINs or envelopes | MEMBER-API audit retention |

- **Not stored:** mailbox ids, relay keys, device identifiers, and request
  envelopes beyond the queue's own retention.
- **Lifecycle reporting.** The enclave emits lifecycle events (`enrolled`,
  `unlocked`, `locked`, `deleted`, `moved` with the target release, carrying
  `vault_version` and `state_version`, a number). The parent writes them to
  the vault table only while it holds the vault's lease or no lease exists
  (a conditional write), so an instance that lost a split brain cannot
  overwrite the holder's values.
- **Lifecycle values are advisory.** `vault_version` should match the
  `release` in the attested descriptor of the reporting instance, but a
  dishonest parent could misreport any of these values. They therefore serve
  the account site and operations only, never security decisions.

**The SQS message** goes to the leased instance's queue. Retention is 5 min,
with a DLQ after 3 receives:

```json
{ "v": 1, "op": "enroll|unlock|lock|delete", "vault_id": "...", "user_guid": "...",
  "request_id": "<ULID>", "etk_kid": "<16 hex; absent for lock/delete>",
  "envelope": "<b64; absent for lock/delete>", "enqueued_at": "<RFC 3339>" }
```

The parent forwards the message to the enclave unchanged. The enclave
answers the parent with

```json
{ "v": 1, "request_id": "<ULID>", "status": "done|etk_unknown", "envelope": "<b64, 5,252 bytes>" }
```

(`envelope` absent for lock, delete and `etk_unknown`). The parent writes
the response slot: `status: "done"`, the `envelope` if any, and `code:
"etk_unknown"` when the enclave reported it; or `status: "expired"` for a
request it did not forward (lease held elsewhere, §11.1) or that the
enclave could not read (no answer). It writes only slots that are still
`queued`. `GET /api/vault/requests/{id}`
returns `{status, envelope?, code?}`; `code` matches `[a-z_][a-z0-9_]*`
and is a host code, never a sealed outcome. The parent writes the
lifecycle events to the vault table and deletes the queue message when
the enclave reports completion.

- **Lifecycle events:** `enrolled` and `unlocked` at enrollment; `moved`
  with the target release after a move, and back to the earlier release
  after an abandonment (§11.10.4).

`lock` and `delete` carry no envelope. Locking is harmless, and deletion
through the API is an operator power the host has anyway (§13.5).

### 11.6 Replay protection

- **Replayed requests.** The enclave remembers every `request_id` it has seen
  for as long as the ETK that request was sealed to is live, and rejects
  repeats. Destroying an ETK (≤ 25 h after creation, or at restart) makes
  every request sealed to it undecryptable. Requests whose `ts` is more than
  5 minutes from enclave time are rejected.
- **Redirected requests.** `user_guid`, `vault_id` and `request_id` appear
  inside the ciphertext as well as in the queue message, and a mismatch is
  rejected. A request therefore cannot be redirected to another vault.
- **Session-only attackers.** Unlock requires both a registered unlock key
  and passing device attestation (§11.7). A member session alone, which
  VettID could obtain, cannot attempt a PIN.

### 11.7 Device attestation (REQUIRED for enroll and unlock)

Enroll and unlock MUST carry platform device attestation: **Android hardware
key attestation** or **iOS App Attest**. Only role `app` can produce it,
which is why only apps unlock (§3.1). Both are verified **inside the
enclave**; the attestation data travels inside the sealed envelope, and the
member API sees none of it. The challenge is bound to the request:

```
challenge = SHA-256("vettid/vms/2/devatt" || request_id || vault_id_or_empty || ts)   # inside the envelope
```

`request_id` and `vault_id` are the ASCII strings exactly as carried in
JSON (`vault_id` is empty at enrollment), and `ts` is the request's inner
`ts` (§5.3). Both have fixed lengths, so the concatenation is unambiguous.
Android and iOS use the same challenge.

**Wire fields.** Enrollment (§11.3) and app pairing (§6.7) carry
`device_attest`; unlock (§11.4) carries `device_assertion`:

```json
device_attest:    {"platform": "android", "chain": ["<b64 DER cert, leaf first>", "..."]}
                | {"platform": "ios", "key_id": "<b64>", "attestation": "<b64 CBOR attestation object>"}
device_assertion: {"platform": "android", "sig": "<b64 DER ECDSA P-256 signature over challenge>"}
                | {"platform": "ios", "assertion": "<b64 CBOR assertion>"}
```

**What the device key signs.** Android signs with ECDSA P-256 and SHA-256
(SHA256withECDSA, DER): for `device_assertion` the message is the 32
challenge bytes; for an approval (§11.10.3) it is the approval string's
bytes. iOS asserts with `clientDataHash` = the challenge for
`device_assertion`, and SHA-256(approval string) for an approval; the
signature is checked as ECDSA P-256 with SHA-256 over `nonce` =
SHA-256(authenticatorData || clientDataHash).

`chain` has 1–10 certificates. Unknown members are ignored; a missing or
mistyped member, or another `platform`, is rejected.

Each platform has a **device attestation key**: a hardware-held signing key
that is attested once, when the app enrolls or pairs (§6.7), and then signs
the challenge at every unlock.

- **Android (hardware key attestation).**
  - At enrollment or pairing, the app generates a non-exportable EC P-256
    signing key in Android Keystore with `setAttestationChallenge(challenge)`,
    in StrongBox if the device has it and in the TEE otherwise, and sends the
    key's certificate chain.
  - The enclave verifies the chain up to a Google hardware attestation root
    pinned in the image, then checks the attestation extension: the
    challenge; attestation and key security level `TrustedEnvironment` or
    `StrongBox` (never `Software`); `RootOfTrust` with `deviceLocked` true and
    `verifiedBootState` `Verified`; the `attestationApplicationId` package
    name and signing-certificate digest of the VettID app; a signing-only,
    non-exportable key.
  - Certificate revocation uses Google's attestation status list. The
    enclave fetches it over TLS it terminates itself, like relay traffic
    (§12.2; the parent forwards only TCP bytes to an allowlisted host), and
    caches it. Enrollment and pairing need a list fetched in the last 24 h;
    unlock rechecks the stored chain against the cached list and fails if
    the list is more than 7 days old. A parent that blocks the fetch can only
    deny service, which it can do anyway. Every serial the list names counts
    as revoked, whatever its `status` (`SUSPENDED` included); freshness is
    the time the enclave fetched the list. The enclave accepts
    `attestationVersion` 3 or later, and requires the key properties to be
    hardware-enforced: purposes within {SIGN, VERIFY} and including SIGN,
    EC P-256, origin GENERATED.
  - The enclave stores the attested public key with that app's unlock key in
    the sealed header. Each unlock carries a signature over `challenge` by
    that key.
- **iOS (App Attest).**
  - At enrollment or pairing, the app sends an attestation object with
    `clientDataHash` = `challenge`. The enclave verifies it against Apple's
    App Attest root, which is pinned in the image, and checks the App ID and
    the production environment. It then stores the attested public key and
    counter with that app's unlock key in the sealed header.
  - Each unlock carries an assertion over `challenge`. The enclave checks the
    signature and that the counter increases.

**Rationale.** Both checks are local cryptography against pinned vendor
roots, so they need no VettID credentials and no third-party API call (Play
Integrity was rejected for that reason). Attestation keys and certificate
chains are stable device identifiers, so they stay inside the enclave and
never reach the API. The gate is enforced by the attested enclave, not by
VettID's servers; it is an anti-abuse control, and confidentiality never
depends on it.

Desktops and agents have no platform attestation and do not unlock.

### 11.8 Rate limits and backoff

**Member API limits:**

- enroll: 3 per member per day;
- unlock: 10 per member per 15 min; per source network, 10 per 15 min per
  IPv6 /64 and 60 per 15 min per IPv4 address (carrier NAT puts many
  members behind one address);
- polling: 2 per second.

Enroll, unlock and lock requests are audited (§11.5), without PINs or
envelopes.

**Enclave backoff**, kept in the sealed header and counted in `header_seq`:

- after 3 consecutive failures, the delays are 30 s, 1 min, 5 min, 15 min,
  60 min, then 60 min for every further failure;
- a successful unlock resets the backoff;
- failures never wipe the vault.

### 11.9 Failure handling

| Failure | Behaviour |
|---|---|
| Instance gone or lease moved | The API answers `409 instance_moved`, or the request expires (queue retention, or the parent found the lease held elsewhere and marked the slot `expired`). The app refetches `/api/vault/enclave` and re-seals. |
| Unknown or expired `etk_kid` | The enclave reports `etk_unknown`; the response slot carries `code: "etk_unknown"` and no envelope (§11.5). The app refetches and retries. |
| Decryption, binding, signature or attestation failure | Random bytes of the result's size, or the uniform sealed result (`attestation`). The API cannot tell which. |
| Bad PIN, backoff, rollback | The uniform sealed result (§11.4) |
| State write conflict | The vault locks (§12.3) and the result says `retry`. |
| The vault's release is not running | `503 release_starting` with `retry_after`; the app retries (§11.10.5). |
| Stale, invalid or unsigned manifest | Result code `manifest`; the app refetches the manifest. Not counted as a PIN failure. |
| Header or state belongs to another release | Result code `wrong_release` (§11.10.4). |

### 11.10 Release updates

A **release** is one enclave image, identified by its PCR0. The member keeps
total control over which release can open their vault (VAULT-PLAN §5.1,
decision D1):

- A vault's sealed header, which holds the pepper the DEK depends on
  (§3.3.1), is sealed to **one release**: the release the member last
  approved. No other release can open it, including any later release
  VettID ships.
- A vault moves to a newer release only during an unlock in which the member
  approves that release in the app (or back, before the newer release has
  ever run it, §11.10.4). Declining, or not answering, changes nothing.
- VettID cannot move a vault, and cannot force a member to update.

#### 11.10.1 The release manifest

VettID publishes the releases it runs in a signed **release manifest** at
`https://vettid.org/.well-known/vettid/pcr-manifest.json`.

**Manifest bytes** are a compact JSON object, parsed with the strict rules
of §5.3, at most **4,096 bytes**:

```json
{"v":1,"serial":7,"issued_at":"<RFC 3339, whole seconds>","releases":[
  {"release":4,"pcr0":"<96 hex>","pcr1":"<96 hex>","pcr2":"<96 hex>",
   "seal_key":"<sealing-key identifier, ≤ 256 bytes>","status":"active",
   "published_at":"<RFC 3339, whole seconds>","notes":"<https URL>"}]}
```

- `serial` is an integer that increases with every publication. A manifest
  with a lower `serial` than one already seen MUST be refused (by apps and
  by the enclave, §11.10.4).
- `release` is the release number: a positive integer, unique, assigned in
  publication order. **Every release image embeds its own release number**,
  so it is covered by PCR0. Entries are sorted by `release`; `release` and
  `pcr0` are unique.
- PCR values are lowercase hex SHA-384 (96 characters). Debug (all-zero)
  PCRs MUST NOT appear.
- `seal_key` names the release's sealing key (§11.10.2).
- `status`:

  | Status | Enroll into | Move into | Unlock a vault sealed to it |
  |---|---|---|---|
  | `active` | yes | yes | yes |
  | `deprecated` | no | no | yes; apps urge an update |
  | `retired` | no | no | yes; apps warn that the release is no longer maintained |

- The manifest MUST list every release that still runs for any vault, and
  every release that the sealing policy of an `active` release admits
  (§11.10.7). A release absent from the manifest is unknown: apps refuse to
  send it a PIN.
- `notes` is an `https` URL of human-readable release notes.

**The served document** wraps the exact manifest bytes:

```json
{ "manifest": "<b64 exact manifest bytes>", "sig": "<b64 64 bytes>", "key_id": "<16 hex>" }
```

```
sig    = ECDSA-P256-SHA256(manifest_key, "vettid/pcr-manifest/1" || 0x00 || manifest_bytes)
         encoded as r || s, 32 bytes each, big-endian (IEEE P1363)
key_id = hex(SHA-256(SubjectPublicKeyInfo DER of the public key)[0:8])
```

- Signatures are verified over the exact bytes, so no JSON
  canonicalization is needed.
- The **manifest key** is an ECDSA P-256 key held by VettID in a hardware
  key store and used for nothing else. Its public key is **pinned in every
  app and in every release image**. Apps and images MAY pin two keys to
  allow rotation; `key_id` selects one. Rotating to a key that an image does
  not pin requires a release.

#### 11.10.2 Sealing per release

Each release R has a **sealing key** `SK_R` with two operations:

- **unseal**: decrypt an object sealed to R. It is available **only to an
  enclave attested as release R** (its PCR0).
- **seal**: create an object sealed to R. It is available only to enclaves
  attested as a release that R's sealing policy admits: R itself, and the
  releases allowed to move vaults into R (at least every `active` and
  `deprecated` release published before R).

Neither operation gives the host any key material. A sealed object is
authenticated encryption under a fresh data key that only an attested
enclave ever holds in plaintext, so the host can neither read nor forge
sealed objects; it can only store, withhold, or replay them.

This is how release N seals for release N+1 without being able to read
what it sealed: it can seal to `SK_{N+1}`, but only N+1 can unseal.

*Deployment (VAULT-PLAN §5.1):* one AWS KMS key per release. `Decrypt` is
allowed only with a Nitro attestation whose PCR0 is R's;
`GenerateDataKey` is allowed only with a Recipient attestation whose PCR0
is in R's admitted set, so the data key reaches only that enclave. Release
images pin the account and region of the sealing keys and refuse a
`seal_key` outside them, so a manifest alone cannot redirect a vault to a
foreign key. `seal_key` is the key's full ARN. The enclave itself verifies
each key's policy before sealing to it (§11.10.7), so a key whose policy
lets anything other than the release open it, or could ever be changed, is
refused.

Storage: the sealed header is one object **per release**
(`vaults/<vault_id>/header/<pcr0>`); an enclave reads only its own release's
object. Vault state (§3.3) is encrypted under the DEK, which does not
change when a vault moves, so state is never re-encrypted.

#### 11.10.3 Approval

When the manifest lists an `active` release newer than the one the vault is
sealed to, the app MAY offer the update. It shows the release number, the
notes, and a fingerprint of PCR0 (VAULT-PLAN D3: anyone can rebuild the
image and compare). If the member approves, the next unlock carries the
approval.

The **approval signing string**, each `\n` a literal newline, no trailing
newline:

```
"vettid/vms/2/release-approval" \n vault_id \n request_id \n from_pcr0_hex \n
to_pcr0_hex \n to_release \n manifest_serial
```

- `request_id` is the unlock request's, so an approval is good for that one
  unlock only and cannot be replayed.
- `from_pcr0_hex` is the release the vault is sealed to, which is the
  release of the instance the unlock request is sealed to (§11.2); `to_pcr0_hex` and `to_release` are the
  target's manifest entry; `manifest_serial` is the serial of the manifest
  in the same request. Integers are decimal; hex is lowercase.
- It is signed with the app's **device attestation key** (§11.7), the same
  key and encoding as `device_assertion`:
  - Android: ECDSA P-256 with SHA-256 over the string's bytes, DER-encoded;
  - iOS: an App Attest assertion with `clientDataHash` =
    SHA-256(string); the counter MUST increase. With two assertions in one
    unlock (`device_assertion` and the approval), both counters MUST
    exceed the counter stored before the request and differ; the enclave
    stores the larger.

**In the unlock request** (§11.4):

```json
"release_update": { "to": "<to_pcr0_hex>", "to_release": 5,
                    "approval": { <device_assertion object over the approval string> } }
```

The unlock signing string (§11.4) also covers `to_pcr0_hex`, so the
approval is bound to the app's unlock key as well.

#### 11.10.4 The move

Every unlock request carries the current signed manifest (§11.4). An
enclave of release N processes an unlock in this order:

1. The normal checks of §11.4, in their order, up to and including the
   rollback checks (§13.2). Before deriving the DEK, it verifies the
   manifest: the signature under a pinned key, the strict format, and
   `serial` ≥ the `manifest_serial` recorded in the sealed header. A
   failure gives the result code `manifest`. A manifest failure is not a PIN
   failure and does not count toward backoff.
2. It derives the DEK and loads the state. If the state records a
   **pending move** (step 6), it never resumes the vault, with one
   exception: an **abandonment** (see "Abandoning an unconfirmed move"
   below), a `release_update` whose `to` is the enclave's own PCR0 and
   `to_release` its own number, with an approval that verifies (step 4,
   check 3). An abandonment clears the pending move and continues as an
   ordinary unlock. Otherwise the enclave skips to step 7.
3. Without `release_update`, the unlock proceeds as before. The enclave
   records the manifest `serial` at its next header write.
4. With `release_update`, it checks, and **refuses the update** (the unlock
   itself still succeeds) with the first failing reason:
   1. `to` is in the manifest with `status` `active`, and `to_release` is
      that entry's number (`target`);
   2. `to_release` is **greater than** the enclave's own release number
      (`downgrade`). Equal or lower is always refused here (abandoning a
      move is step 2's exception, not an update);
   3. the approval verifies under the attested device key bound to this
      app's unlock key (`approval`). The enclave builds the approval string
      itself, with its own PCR0 read from the NSM as `from_pcr0_hex`, so an
      approval for a different source release cannot verify;
   4. `seal_key` is within the pinned sealing-key namespace (`target`), and
      the target key passes the checks of §11.10.7 (`seal_key`);
   5. no move to a different release is pending (`pending`).
5. If an update is refused, the result reports it and the vault runs
   normally under N.
6. **Record the move.** It flushes the state (§8.3) with
   `release_move = {to, to_release, manifest_serial, approved_by: <device
   id>}`. From here on the vault does not resume under N.
7. **Seal to N+1.** It builds the new header from the current one with
   `header_seq` + 1, `sealed_release` = `to` and the manifest serial, seals
   it to `SK_to`, and writes `header/<to>` **create-only**. If that object
   already exists, it can only be a leftover of an interrupted attempt at
   this same recorded move (only admitted enclaves can seal to `SK_to`, and
   moves only go forward): the enclave replaces it with a conditional write
   on the version it read.
8. It returns the result with `update: moved` and **locks** (§12.3) without
   collecting. The parent reports the lifecycle event `moved` with the
   target release. `header/<N>` is kept until N+1 confirms the move (below).

**Failures.**

- Before step 6: nothing has changed; the result says `refused` or the
  unlock failed as usual.
- Step 6 write fails: the state is unchanged; the result says `refused`
  with code `write`, and the vault runs under N.
- Step 7 fails, or the enclave crashes after step 6: the state records the
  pending move, so the next unlock that reaches release N completes it at
  step 2 without a new approval (the member already approved), and reports
  `moved`. Until then the vault stays sealed to N, which is safe.
- A crash after step 7: `header/<to>` exists and the state records the
  move; the next unlock that reaches N reports `moved` again, and one that
  reaches N+1 confirms it.

**Re-approval and idempotency.** An approval for the target already
recorded as pending is accepted and completes the move. An approval for a
different target while a move is pending is refused (`pending`).

**Confirmation at release N+1.** When an N+1 enclave opens a vault whose
state records a pending move to N+1, it clears it, sets
`state.sealed_release` to N+1, flushes, and only then deletes `header/<N>`
(conditional delete; failure is ignored). From this flush on, the move is
**confirmed** and final. An enclave MUST refuse a vault (result code
`wrong_release`) whose state names a different `sealed_release` and no
pending move to its own release: that is a stale header served to a
release the vault has left.

**Abandoning an unconfirmed move.** If N+1 cannot unlock the vault (for
example, a defective release), the member is not stranded: while the move is
unconfirmed, `header/<N>` still exists and the state still records the
pending move. The app MAY then offer to return to release N. It sends an
unlock to an N instance (§11.10.5) with `release_update.to` = N's own PCR0
and `to_release` = N's number, approved like any update. The pending move
is necessarily unconfirmed: had N+1 confirmed it, the state would name N+1
as `sealed_release`, and N would have refused the vault as
`wrong_release`. Release N clears the pending move, deletes `header/<to>`
(conditional delete), resumes the vault, and reports `update: abandoned`;
the parent reports `moved` back to N. This is the only way back to an
earlier release, and only before the newer release has ever run the vault.

**Downgrades.** Apart from abandoning an unconfirmed move, moving to an
older or equal release is never allowed, even with an approval. A defect in
a release is fixed by publishing a newer release, if necessary a rebuild of
older code with a new number, and moving forward. *Rationale:* the member's
approval protects against releases they do not trust, not against being
talked into an old release with known vulnerabilities; forward-only moves
remove that attack, and the host cannot exploit a downgrade path that does
not exist.

#### 11.10.5 Routing and on-demand start

Several releases run at once.

- The vault table records **`sealed_release`** (the PCR0 the vault is sealed
  to), and the instance registry records each instance's **`release`**
  (from its attested descriptor, §11.2). Both are routing aids written by the
  parent from lifecycle events; a wrong value can only misroute, and a
  release that is not sealed to cannot open the vault.
- `GET /api/vault/enclave` returns a live instance of the vault's
  `sealed_release` (the leased one if there is a lease, §11.1). If none is
  running, the API requests one and answers `503` with error
  `release_starting` (MEMBER-API error body plus `code`, `release` and
  `retry_after`); the app retries after `retry_after`. A release that is
  unknown or whose image can no longer be started answers `410` with error
  `release_unavailable`. The API learns each release's status and
  availability from the signed manifest, as operations publish it
  (VAULT-PLAN §5.1); `retired` releases are still routed. VettID keeps
  each release's image and sealing key while any vault is sealed to it
  (VAULT-PLAN §5.1).
- The `moved` lifecycle event updates `sealed_release`; the next unlock is
  routed to the new release.
- An app MAY ask for a specific release with
  `GET /api/vault/enclave?release=<pcr0>`, which is answered the same way
  for any release listed in the manifest. Apps use it only to abandon an
  unconfirmed move (§11.10.4). If an instance of another release holds a
  live lease on the vault, the API answers `409` with error `vault_busy`
  and `retry_after` (lock the vault first).

#### 11.10.6 What the app shows and stores

The app stores, per vault: the **release it last unlocked into** (PCR0 and
release number), the highest manifest `serial` it has seen, `state_seq`,
and `header_seq` **per release** (§13.2): each release has its own header
object, and a move, or failures under N+1, raise only N+1's `header_seq`.
In every unlock, `min_header_seq` is the value it holds for the release
the request is sealed to; when it abandons a move it therefore sends N's
value, and keeps N's release and `header_seq` until the move is confirmed
or abandoned.

- It fetches the manifest before each unlock, refuses one with a lower
  `serial` than stored, and sends it in the unlock request.
- It MUST NOT send a PIN to a release with a **lower** release number than
  the one it last unlocked into (a rollback; it shows an error).
- If the routed release is **newer** than the stored one and listed in the
  manifest, the vault was moved from another device. The app tells the user
  ("vault software was updated") before sending the PIN, as §11.2 step 4
  requires.
- For a `deprecated` or `retired` release, it shows the status and offers
  the newest `active` release.
- After `update: moved`, it records the new release and sequence numbers
  and unlocks again, which reaches the new release. If that release
  repeatedly fails to unlock the vault, the app MAY offer to return to the
  previous release while the move is unconfirmed (§11.10.4), and records
  the previous release again after `update: abandoned`. Owner devices also
  learn the release from `device.paired` and from the `sync.event` kind
  `vault.release` that a vault sends after it first runs under a new
  release.

#### 11.10.7 Verifying a release's sealing key

"Only the approved release can open the vault" holds only if the sealing
key's policy says so and can never change. The enclave does not take that on
trust: **before it seals a header to a release key for the first time**, it
reads the key's metadata, policy and grants from AWS KMS itself and checks
them. (vettid.dev had no such check: its host role and a migration function
held `kms:PutKeyPolicy` and widened key policies during migrations, and
nothing in the enclave noticed.)

**When.** Before the first header seal under a key: at enrollment (the
enclave's own release key) and before a move (the target's key,
§11.10.4 step 4). A key whose policy passes these checks can never be
changed again (no principal may call `PutKeyPolicy` or `CreateGrant`), so
one successful check per key is enough. The enclave records it in the
sealed header it writes, as `seal_key_verified = {key_arn,
policy_sha256, verified_by}` (`verified_by` the PCR0 of the release that ran
the check); later header writes under the same key, by the same
release, rely on that record instead of re-checking. A record made by
another release (N's check of N+1's key, written with the move) is
re-checked by the release before its first header write; if that check
fails the unlock fails with `release_key`. A failed check refuses
the enrollment (result code `release_key`) or the update (`seal_key`).

**How.** The enclave calls KMS `DescribeKey`, `GetKeyPolicy` (policy name
`default`) and `ListGrants` on the key ARN from the signed manifest:

- over TLS that **the enclave terminates** (decision D5): the parent's TCP
  allowlist includes the regional endpoint `kms.<region>.amazonaws.com:443`,
  whose certificates chain to the Amazon roots already pinned in the image;
- signed with **SigV4 by the enclave**, using temporary credentials of the
  host's instance role that the parent passes in. The credentials only
  authorize the read; the host cannot forge or alter a TLS-authenticated
  KMS response about a key in the pinned account and region, so at worst it
  can withhold credentials (denial of service). The same path carries the
  enclave's `Decrypt` and `GenerateDataKey` calls.

**Checks.** The enclave fails closed: any failure, error, unknown field
shape or truncated listing refuses the seal.

1. **Key identity.** The ARN is `arn:aws:kms:<region>:<account>:key/<uuid>`
   with the pinned account and region (§11.10.2), and equals the manifest's
   `seal_key`.
2. **Key metadata** (`DescribeKey`): `KeyState` = `Enabled`; `Origin` =
   `AWS_KMS` (not imported key material, not an external or CloudHSM key
   store, and no `CustomKeyStoreId`); `KeySpec` = `SYMMETRIC_DEFAULT`;
   `KeyUsage` = `ENCRYPT_DECRYPT`; `KeyManager` = `CUSTOMER`;
   `MultiRegion` present and `false` (a replica could carry a different
   policy); `AWSAccountId` = the pinned account; no `CustomKeyStoreId`,
   `CloudHsmClusterId` or `XksKeyConfiguration`. Unknown members of the
   responses are ignored; known members with another type fail.
3. **No grants** (`ListGrants`): the list is empty and not truncated
   (`Truncated` false, no `NextMarker`). A
   grant is an authorization outside the policy, so none may exist; with
   no `CreateGrant` permission, none can be added later.
4. **Policy shape.** The policy parses with the strict JSON rules of §5.3
   (no duplicate names). Top level: only `Version` (= `"2012-10-17"`),
   `Id` and `Statement` (an object or an array). Statement members: only
   `Sid`, `Effect`, `Principal`, `Action`, `Resource` and `Condition`.
   `NotPrincipal`, `NotAction` and `NotResource` are rejected in any
   statement. `Resource` is a single string. Operators, condition keys and
   action names match case-sensitively: a case variant is refused, never
   treated as equivalent. `Resource` is `"*"` or the key's ARN.
5. **`Deny` statements** are ignored after the shape check: they can only
   remove access, so ignoring them over-approximates what is allowed.
6. **Actions in `Allow` statements** are explicit names, never wildcards
   (no `*` or `?` anywhere, so `kms:*` and `kms:Generate*` fail), from this
   list and nothing else:

   | Action | Allowed only with |
   |---|---|
   | `kms:Decrypt` | an attestation condition whose every value is the **target release's PCR0** |
   | `kms:GenerateDataKey` | an attestation condition whose every value is the PCR0 of a release in the manifest numbered **at or below** the target (the target and the releases admitted to seal for it, §11.10.2) |
   | `kms:DescribeKey`, `kms:GetKeyPolicy`, `kms:ListGrants`, `kms:ListKeyPolicies`, `kms:GetKeyRotationStatus`, `kms:ListResourceTags` | no condition required (read-only metadata) |

   Every other action disqualifies the key, among them `kms:PutKeyPolicy`,
   `kms:CreateGrant`, `kms:Encrypt` (anyone could then forge sealed
   objects), `kms:ReEncryptFrom` / `kms:ReEncryptTo` (re-encryption to a
   key the caller controls bypasses the attestation gate),
   `kms:GenerateDataKeyWithoutPlaintext`, `kms:ScheduleKeyDeletion`,
   `kms:CancelKeyDeletion`, `kms:DisableKey`, `kms:EnableKey`,
   `kms:ImportKeyMaterial`, `kms:DeleteImportedKeyMaterial`,
   `kms:UpdatePrimaryRegion`, `kms:ReplicateKey`, `kms:TagResource`,
   `kms:UntagResource`, `kms:UpdateKeyDescription`, and
   `kms:EnableKeyRotation` / `kms:DisableKeyRotation`.
7. **The attestation condition.** In the `Condition` of a `Decrypt` or
   `GenerateDataKey` statement:
   - operator `StringEquals` or `StringEqualsIgnoreCase`, never an
     `…IfExists` form (which matches when the request carries no
     attestation at all), never `ForAnyValue:` / `ForAllValues:`, `Null` or
     a negated operator;
   - key `kms:RecipientAttestation:ImageSha384` or
     `kms:RecipientAttestation:PCR0` (the same measurement on Nitro); if
     both appear, both must satisfy the rule;
   - values: one string or an array of strings, each 96 hex characters,
     compared case-insensitively to the manifest's PCR0s.

   Other condition entries in the same statement can only narrow it, but
   the enclave still accepts only these: `StringEquals` /
   `StringEqualsIgnoreCase` on `kms:RecipientAttestation:PCR1` to `PCR8`
   (PCR1 and PCR2, if present, equal the manifest's) and on
   `kms:EncryptionContext:<key>`; `StringEquals` on `kms:CallerAccount`
   (required, and equal to the pinned account, check 8); and `ArnEquals` on
   `aws:PrincipalArn` with ARNs in the pinned account. Anything else fails.
8. **Principals.** Releases are public and reproducible, so anyone can run
   a genuine release image in their own AWS account and present a valid
   attestation with its PCR0. The attestation condition alone therefore
   does not keep other accounts out; the principal must. In **every**
   `Allow` statement:
   - `Principal` is `{"AWS": <ARN or array of ARNs>}` and every ARN is in
     the pinned account: the account root `arn:aws:iam::<account>:root` or
     an IAM role `arn:aws:iam::<account>:role/<path/name>`;
   - rejected: `"*"`, `{"AWS": "*"}`, any other account, account ids
     without the ARN form, `Service`, `Federated` or `CanonicalUser`
     principals, and anything else.

   The `Decrypt` and `GenerateDataKey` statements MUST also carry
   `StringEquals` `kms:CallerAccount` = the pinned account, as defence in
   depth against a principal-shape mistake. Read-only statements are held
   to the same pinned-account rule: foreign reads of a key's metadata would
   be harmless, but there is no reason to allow them.

**Example policy that passes**, for release 4 whose sealing policy admits
release 3, in the pinned account `111122223333`. `<pcr0-4>` and `<pcr0-3>`
stand for the releases' PCR0s:

```json
{
  "Version": "2012-10-17",
  "Id": "vettid-release-4",
  "Statement": [
    { "Sid": "UnsealOnlyInRelease4", "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:role/vettid-enclave-host"},
      "Action": "kms:Decrypt", "Resource": "*",
      "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": "<pcr0-4>"},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "SealFromAdmittedReleases", "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:role/vettid-enclave-host"},
      "Action": "kms:GenerateDataKey", "Resource": "*",
      "Condition": {"StringEqualsIgnoreCase": {"kms:RecipientAttestation:ImageSha384": ["<pcr0-3>", "<pcr0-4>"]},
                    "StringEquals": {"kms:CallerAccount": "111122223333"}} },
    { "Sid": "EnclaveVerifiesThisPolicy", "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:role/vettid-enclave-host"},
      "Action": ["kms:DescribeKey", "kms:GetKeyPolicy", "kms:ListGrants"], "Resource": "*" }
  ]
}
```

There is no administrator statement, so KMS's lockout safety check rejects
the policy unless the key is created with `BypassPolicyLockoutSafetyCheck`
(VAULT-PLAN §5.1). That is intended: nobody, including the AWS account
root, can change the policy, add grants, disable or delete the key.

**Variants that MUST fail** (each changes one thing in the example):

| Change | Failing check |
|---|---|
| Add the default `{"Principal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "kms:*"}` statement | 6 (wildcard) |
| Add `"Action": "kms:PutKeyPolicy"` or `"kms:CreateGrant"` in any `Allow` | 6 |
| `StringEqualsIgnoreCaseIfExists` on the `Decrypt` condition | 7 |
| `Decrypt` condition lists `<pcr0-3>` as well | 6 (`Decrypt` values must all be the target) |
| `Decrypt` without a `Condition` | 6 |
| `"Action": ["kms:Decrypt", "kms:ReEncryptFrom"]` | 6 |
| `"Action": "kms:Encrypt"` | 6 |
| `"NotAction": "kms:PutKeyPolicy"` with `"Effect": "Allow"` | 4 |
| `StringLike` with value `"*"` on `ImageSha384` | 7 |
| A `GenerateDataKey` value that is not a manifest release numbered ≤ 4 | 6 |
| A statement member `"Condition2"`, or a duplicated `"Action"` member | 4 |
| `"Principal": "*"` or `{"AWS": "*"}` on the `Decrypt` statement | 8 |
| `Principal` `arn:aws:iam::444455556666:role/x` (another account) on `GenerateDataKey` | 8 |
| `Principal` `{"Service": "ec2.amazonaws.com"}` on any statement | 8 |
| `"Principal": "*"` on the read-only statement | 8 |
| `Decrypt` without the `kms:CallerAccount` condition, or with another account | 8 |
| `ListGrants` returns one grant | 3 |
| `DescribeKey` shows `Origin` = `EXTERNAL` or `MultiRegion` = `true` | 2 |

**What remains trusted.** The check moves the guarantee from VettID's word
to AWS's documented behaviour: that KMS enforces key policies, grants and
attestation conditions as specified, that Nitro attestation documents
cannot be forged, and that AWS itself does not bypass them. It cannot
detect a key-policy evaluation flaw in KMS or an AWS insider.

## 12. Locked vaults and the collect manager

### 12.1 Locked

A locked vault has no DEK in memory, and therefore no relay key. It does not:

- collect;
- ack;
- deposit;
- mint tokens;
- trigger wakes.

Peers' deposits still succeed and wait up to the relay TTL. When the vault
unlocks, messages that expired in the meantime show up as `seq` gaps.
Connections whose standing tokens lapsed recover through reconnect tokens
(§6.6).

### 12.2 Collect manager

- **One collect loop per unlocked vault.** The loop runs inside the enclave
  as a signed long-poll (`wait=25`, `max=32`) or a WebSocket. During a
  rotation grace period it also collects from the old mailbox.
- **Batches.** Each vault handles one batch at a time (§8.3).
- **TLS.** The enclave terminates TLS to the relay, and to AWS KMS
  (`kms.<region>.amazonaws.com`, §11.10.7). The parent forwards only TCP
  bytes to its allowlist on port 443. The enclave pins only the
  roots for the allowlisted hosts (VAULT-PLAN §5.2), so root changes are rare
  releases. Each instance carries every vault's relay requests over a few
  shared HTTP/2 connections rather than one connection per vault, so the host
  cannot attribute traffic to a vault by connection. Inside the enclave the
  collect loop therefore uses the long-poll (a WebSocket would need a
  connection of its own). AWS KMS endpoints offer only HTTP/1.1; KMS
  requests use a small pool of keep-alive connections.
- **On unlock**, in order:
  1. re-mint tokens and start reconnects (§7.2);
  2. rekey due device sessions;
  3. drain the outbox;
  4. start collecting;
  5. renew the lease while unlocked (§11.1).

### 12.3 Lock triggers

| Trigger | Behaviour |
|---|---|
| Owner request (`vault.lock`, API lock route) | Finish the batch, flush, send `vault.locking`, stop the loop, release the lease, zeroize. |
| Memory pressure (the least recently active vault is evicted) | Same as an owner request. |
| Enclave release or restart | Same if signalled. Otherwise all vaults lock through loss of memory, and their leases expire; a parent that sees the enclave restart releases the leases it held. |
| Parent restart (the enclave keeps running) | The enclave locks every vault before it serves the new parent, which holds no leases for them. |
| Parent unreachable for 120 s | Every vault is locked: its lease can no longer be renewed. |
| Lease lost (renewal failed) | Same as an owner request, without the final flush if the state write fails. |
| Split-brain guard: a conditional state write finds a newer version | Zeroize **immediately**, without flushing or acking. |
| Vault deletion | Run the §7.4 revocations, then destroy the state and the header. |
| Account cancelled | Vault routes other than lock are refused at once (§11.1); the vault is locked. After the 7-day grace period the API deletes the vault rows and the stored state and headers. |

There is no idle lock by default; the owner MAY set one. Leases left by a
lock expire within 60 s (relay) and 180 s (vault lease). Zeroizing covers the
DEK and the relay, identity, KEM and session keys; with one process per
vault (§12.4), locking ends the vault's process, which releases all of its
memory.

### 12.4 Process isolation inside the enclave

The enclave runs a **supervisor** and **one OS process per unlocked
vault**.

- **The supervisor** (the enclave's first process) keeps only shared
  duties: access to the NSM, the ETKs and the outer decryption and routing
  of alternate-channel requests (§11.2, §11.6), the egress (TLS and the
  shared connections of §12.2), the connection to the parent, and the vault
  processes' lifecycle. It holds **no per-vault long-term secret**: no DEK,
  pepper, relay key, identity or KEM key, session key, or vault state in
  plaintext.
- **The supervisor sees the PIN transiently.** As the ETK holder it
  decrypts an enroll or unlock request, hands the decrypted request to the
  vault's process, and zeroizes its copy at once. It is the enclave's
  shared trusted base, as the ETK requires.
- **A vault process** is started for an enroll or unlock and ends on lock.
  Everything else of the vault runs in it: the sealed header is unsealed
  there (it attests its own ephemeral RSA key for the KMS `Recipient`, so
  only that process can read the data key; the supervisor only obtains the
  attestation document and forwards the KMS call), the DEK is derived
  there, relay requests are built and signed there (the relay key never
  leaves it), state objects are encrypted there, and every feature handler
  runs there.
- **A vault process reaches nothing but the supervisor**, over one private
  channel. The supervisor scopes what it brokers to that vault: objects
  under `vaults/<vault_id>/` and the member's index object (reads of the
  member's previous vault at re-enrollment, §11.3), relay requests to the
  allowlisted relay signed by the vault's own relay key, KMS calls, and
  attestation documents that bind the process's own Recipient key or the
  vault bundle of §11.3, never arbitrary `user_data`.
- **Isolation of the processes from each other:** each runs under its own
  user and group id, is not dumpable and cannot be traced, inherits no
  file descriptor but its channel and no writable shared file or
  directory, and runs under resource limits (memory, file descriptors).
- **Locks:** an owner request, memory pressure, a lost lease or a lost
  parent make the supervisor ask the process to lock (flush, `vault.locking`,
  exit); a process that does not exit in time is killed. A process that
  detects a split brain (§12.3) zeroizes and exits without flushing.
  Killing one vault's process affects no other vault.

## 13. Security considerations

### 13.1 Why the relay key is PIN-only

A PIN-independent copy of the relay key would let any release that satisfies
the sealing policy collect, ack and delete a user's messages without the
user. With the relay key held only in DEK state, mailbox access requires all
of:

- the PIN;
- a registered, attested device;
- a release the app has checked.

The cost is that a locked vault is offline. Three things soften that cost:
the 14-day relay TTL, reconnect tokens, and (later) push prompts asking the
user to unlock.

### 13.2 Rollback protection

The parent stores the encrypted vault state and the sealed header, so it
could serve older versions of either. Protection is **anchored in the
client**:

- **`state_seq`** is a monotonic counter. It is incremented on every durable
  state write and recorded in two places: inside the DEK-encrypted state, and
  in the sealed header. The header is rewritten after each state flush. The
  state may lead the header by one write if a crash falls between the two
  writes.
- **`header_seq`** is incremented on every header write, including writes
  that only record backoff, which also covers the backoff counter.
- Every unlock result returns `header_seq`. A successful unlock also returns
  `state_seq`. The app stores the highest `state_seq` seen for each vault,
  and the highest `header_seq` seen for each release of the vault (each
  release has its own header, §11.10.2), and sends them as `min_state_seq`
  and `min_header_seq` (the value for the release the request is sealed
  to) in every unlock (§11.4, §11.10.6).
- The enclave refuses to unlock with `state_rollback` if any of these holds:
  - `state.state_seq < header.state_seq`;
  - `state.state_seq < min_state_seq`;
  - `header.header_seq < min_header_seq`.

  The refusal is a sealed result of uniform size, so the API cannot tell it
  apart from other outcomes.

**Residual risks:**

- An app that has never unlocked since the newer state was written cannot
  detect a rollback until it does.
- A consistent rollback of both objects, served to a device that has never
  seen the newer values, goes undetected.
- An attacker holding a registered, attested device can omit the minimums.

The split-brain guard (§12.3) separately catches stale writers.

### 13.3 Parent and host

The parent can delay, drop, reorder or replay what it forwards. Replays are
absorbed (§11.6) and rollbacks are bounded (§13.2). It can misreport the
advisory lifecycle and lease values, but those affect only routing and
availability.

Inside the enclave, a flaw in one vault's process (a feature handler, a
parser) reaches only that vault: its secrets live in its own process, and
it can read and write only its own objects and use only its own relay key
(§12.4).

### 13.4 Downgrade protection

- The suite appears in every header and AAD, in every HPKE `info`, and in
  every KDF and signature label.
- Records pin the highest suite they have negotiated. Lower suites are then
  rejected, and suite 1 is never accepted.
- `sig_R` covers `th`, which includes the initiator's `suites` list, so
  stripping suites from that list is detected.

### 13.5 Key compromise and VettID's residual powers

| Compromised | Impact | Recovery |
|---|---|---|
| Vault relay key | Collect, ack or delete the vault's mailbox (DoS); deposit as the vault; mint tokens. No plaintext, and no forged content. | Rotate (§3.4) |
| Device relay key | Deposit as the device. Its content remains unforgeable. | Unlink and re-pair |
| Reconnect token | Nothing without the holder's relay key (sender-bound), and even then only a 4-message quota of `hs.init`s that must be signed by the stored `ik` | Denylist `sub` |
| Session epoch key | Read and forge messages in that epoch and direction. Vault-to-vault epochs last at most 24 h. | Next rekey |
| Vault `ik` or `kem` | Impersonate the vault in new handshakes and read new `hs.init`s | Credential rotation, `identity.rotate`, rekey |
| ETK | PINs in requests sealed to it (≤ 25 h). Requires breaking the enclave. | Enclave restart |
| Owner app | Whatever its role allows, including unlock attempts if the PIN is known | Unlink from another device |
| PIN alone | Nothing without a registered, attested app | `pin.change` |
| An app's copy of the Protean Credential | Nothing without the CEK, which only the vault holds; password guesses only online, through a paired app, under the backoff (§3.5.3) | `credential.rotate` (destroys the CEK) |
| Credential password alone | Nothing without the blob and a paired app | `credential.password.change` |
| Decrypted vault state (DEK) | Everything in it, plus offline guessing of the credential password against the CEK and the kept blob (§3.5.5); critical secrets stay sealed under the password | Rotate the relay key and the credential; change the password |
| An old release, after members moved away | Vaults still sealed to it. A moved vault only if the host serves it a stale header and state **and** an app sends it the PIN; apps never send a PIN to an older release than they last unlocked into (§11.10.6). Residual: an owner device that never learned of the move. | Members move forward; the app warns about `deprecated` and `retired` releases |
| Manifest key | Listing a release as `active`. A vault still moves only with the member's approval, and only to a sealing key in the pinned namespace. | Rotate the key in a release; apps pin two keys |
| Sealing-key policy (VettID's AWS account) | A key whose policy let anything other than its release decrypt, or could be changed later, would expose the pepper and allow offline PIN guessing against stored state. The enclave refuses to seal to such a key: before sealing it reads the policy, metadata and grants from KMS over TLS it terminates and checks them (§11.10.7). | Nothing to recover: the check runs before any seal, and a passing policy can never change |

As operator of the host, queues and API, VettID **can**:

- deny service;
- lock vaults;
- delete stored state;
- observe the metadata in §2.2;
- publish new releases and mark old ones `deprecated` or `retired`.

It **cannot**:

- unlock a vault;
- read or forge a vault's messages;
- act on a vault's mailbox without the PIN;
- move a vault to another release, or **force an update**: only the
  member's approval at unlock moves a vault (§11.10). A vault therefore
  stays on its release, including any unfixed vulnerability, until the
  member approves an update; the app makes that visible.

These "cannot" statements do not rest on VettID's word about its key
policies: the enclave verifies each sealing key's policy before sealing to
it (§11.10.7). They rest on AWS KMS and Nitro attestation behaving as
documented.

### 13.6 Implementation requirements

- **Classification.** Inbound traffic is classified only by `sender`, by
  `recipient_kid`, and by which session decrypts it. Classification MUST NOT
  depend on payload shape or `type`.
- **Parsers.** Envelope and inner parsers MUST be fuzzed.
- **Comparisons.** Tag and key comparisons MUST be constant-time.
- **Dev mode.** Dev-mode attestation and sealing MUST be excluded at compile
  time.
- **Logging.** Keys, PINs, tokens, signatures, attestation tokens and
  plaintext MUST NOT appear in logs, metrics or errors.
- **Process isolation.** Each unlocked vault MUST run in its own process,
  and the supervisor MUST NOT hold a vault's DEK, pepper or keys (§12.4).
  The channel between them MUST be parsed strictly and fuzzed.

## 14. Push compatibility (deferred)

An app will send `push.register{platform, push_token, environment}` over its
session. The vault keeps the wake key in DEK state and stores the `wake_ref`
in the device record; `device.unlink` deletes it.

After depositing a user-visible message into an app's mailbox, an unlocked
vault triggers `POST /v1/wake/{wake_ref}` with a constant per-device
`collapse_key`.

A locked vault triggers no wakes. A "vault locked, messages waiting" prompt
would need a wake path that does not depend on the DEK. That is a separate
future decision.

## 15. Open questions and follow-ups

The owner's v0.1 review resolved every design question that v0.1 left open.
Follow-ups:

1. **Vectors.** The §16 vectors are generated (vettid-vault). Still open:
   reproduce them with CryptoKit and BouncyCastle to pin MLKEM768X25519
   interoperability (codepoint `0x647a`, `ek` 1,216 bytes, `enc` 1,120
   bytes).
2. **Schemas.** Lifecycle, sessions, devices, connections, messaging, the
   credential, secrets, profile, settings, audit and feed are in
   §10.1–§10.9. Still open: calls, the other features, the `sync.since`
   cursor, and the crash-safe write order of `pin.change` (with its
   implementation).
3. **Push.** Specify the push-gateway integration (§14) when that service is
   scheduled.
4. **Desktop unlock.** Revisit if a desktop attestation mechanism becomes
   available.
5. **Release updates.** Implementation in V3: generate the §16 release
   vectors in vettid-vault, the KMS policy shapes in VAULT-PLAN, and an
   app UX review of the approval screen.
6. **Protean Credential copy.** The vault's copy of the blob (§3.5.6) is an
   owner decision; the reference implementation keeps it.

## 16. Test vectors

These vectors use fixed seeds and are for **test use only**. The complete
vectors, with every input, are the JSON files in
[vettid-vault `testdata/vectors/`](https://github.com/vettid/vettid-vault/tree/main/testdata/vectors);
the values below are excerpts, and the files are authoritative. The Go,
Kotlin, Swift and Rust clients MUST reproduce them byte for byte.

- HPKE encapsulation randomness is 64 bytes: bytes [0:32] are the ML-KEM-768
  encapsulation randomness `m`, bytes [32:64] the X25519 ephemeral secret
  (X-Wing `EncapsulateDerand`). Implementations supply it through a
  deterministic test hook.
- A KEM key's 32-byte seed is the RFC 9180 serialized private key; it is
  expanded with SHAKE256 as in draft-ietf-hpke-pq.
- The session vector's inner plaintext is the sealed one with `"seq":1`
  after `ts`.
- Tokens, ids, PIN and claim ids in the vectors are dummy values.

```
§3.2 keys                                                       (keys.json)
  vault ik seed               : 32 x 0x04
  vault ik pk (b64)           : ypOsFwUYcHHWe4PH/w7+gQjo7EUwV113JoeTM9vavnw=
  vault MLKEM768X25519 seed   : 32 x 0x05   vault ek: 1216 B (keys.json)
  vault static kid (hex)      : 40d6c2c8471844a9

§4.3 sealing (HPKE base, suite 2)                               (hpke.json)
  encapsulation randomness    : 64 x 0x07
  enc (1120 B)                : hpke.json
  shared_secret               : 3239a1c6d8d76895e408c7e65ee38d8b43f4732c7a74c5ccfbac6bd63f743bce
  key                         : f8cfa15ec73bf1031bc50dfc462438a3d6a3d933f7edf6b28bc149fd7400e2a6
  base_nonce                  : 6666ec691911c5f6f1161207
  exporter_secret             : 1d7856a1a77eee3accf4e69fb2353f2421e3f15584739e5c6df73d487b4b66b4

§5.2 sealed envelope                                            (envelope_sealed.json)
  inner : {"v":1,"id":"01JB2Z6V9K3M4N5P6Q7R8S9T0V","type":"test.ping","ts":"2026-10-01T12:00:00.000Z","body":{}}
  padded length : 512     envelope length : 1668     sender_kid : 0000000000000000

§5.2 session envelope                                           (envelope_session.json)
  k_i2r : 32 x 0x08   nonce : 24 x 0x09   sender_kid : 8 x 0x02   recipient_kid : 8 x 0x01
  envelope length : 572

§6.3 handshake, purpose connection                              (handshake.json)
  initiator ik / kem / eph seeds 32 x 0x0a / 0x0b / 0x0c; relay seeds vault 0x10, initiator 0x11
  randomness hs.init 64 x 0x0d, hs.resp 64 x 0x0e; hs.fin nonce 24 x 0x0f
  K_s      : 3e3921cbc2a89f56741ac74c5cb2a10db0dc327c80d113ece000ecdf55eabe2d
  K_e      : 91bc195aaff1d13d0e8044800c42127df94fcf4231207adc9a84a1be29e0f866
  th1      : 2999a1fe3626e7fe57ac901c35ee2b7ba7e2e6b92f85596a6a49aa96fa888bd7
  th       : fd53f877211806d1f4fc0cfa30821d20201e44686e18fe1d222a5f2bd99c29d7
  prk      : 4cf5ffe8a9d849d312f7313365f3a1fa583e17863cda7a43f97c1b8f84b94345
  k_i2r    : cf67963c38497b503ebbcdfa8d78924395fe765f5dc37e8d18adeb472b26d379
  k_r2i    : fe388025380567d3c310943e0352a374b0d0f890f98533fb47f667ee0148fa99
  kid_i2r  : 1c14c8b40b51f614      kid_r2i : 752c20e9d8f53948
  rk       : caf3de4dd468f538464963fdbfaa4eb549558ef03cfc1220879f43c2bb41e6dd
  epoch_id : 42abe40a9588c5d779aebd3b7a3cc2b8
  sas      : 696599
  sig_R, sig_I, all three envelopes : handshake.json

§6.4 claim bundle                                               (invite.json)
  k_b : 32 x 0x14   nonce : 24 x 0x15   blob, h, QR JSON, link : invite.json

§11 alternate channel                                           (altchan.json)
  ETK seed 32 x 0x06; descriptor bytes and user_data, devatt challenges
  (enrollment and unlock), unlock signing string (0.3.0, 12 fields) and
  signature, vault.unlock padded to 12,288 B in a 13,444 B envelope
  (randomness 64 x 0x13) : altchan.json
```

**§11.10 release updates (0.3.0).** These values were computed with Go 1.26
(ECDSA P-256 with RFC 6979 deterministic nonces). vettid-vault generates
them in `testdata/vectors/release.json` (phase V3a), byte for byte equal
to the values below, together with the signing string of the unlock that
carries the approval; `altchan.json` is regenerated for 0.3.0.

```
§11.10.1 manifest signature
  manifest key (test only): P-256 private scalar 32 x 0x21
  public key SPKI (b64) : MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERi26GuT8GpaLTazyDN1tvh+uNKqXFRSmPTQFw9HP04O1i7sIwTODQoxYU8ccTIUeE0sFaCHkaP4Kl3q/QxPd4Q==
  key_id                : 1edbb48b6669decd
  manifest bytes (1,060 B, one line):
    {"v":1,"serial":7,"issued_at":"2026-10-02T12:00:00Z","releases":[{"release":3,"pcr0":"ab"x48,
    "pcr1":"11"x48,"pcr2":"22"x48,"seal_key":"arn:aws:kms:us-east-1:000000000000:key/test-release-3",
    "status":"deprecated","published_at":"2026-09-01T00:00:00Z","notes":"https://vettid.org/releases/3"},
    {"release":4,"pcr0":"cd"x48,"pcr1":"33"x48,"pcr2":"44"x48,
    "seal_key":"arn:aws:kms:us-east-1:000000000000:key/test-release-4","status":"active",
    "published_at":"2026-10-01T00:00:00Z","notes":"https://vettid.org/releases/4"}]}
    ("ab"x48 = 96 hex characters; no spaces or line breaks in the real bytes)
  SHA-256(manifest bytes)                       : d3fc1be2ce9358815863eeae15bebf5c755f168a7ab161c8e5c66500be1288f1
  SHA-256("vettid/pcr-manifest/1" 00 manifest)  : 9b086ab99783d85706fdacf3dd36f496c16e30f05468450f1efd946fae1ddfad
  sig (r||s, b64) : 3AyvBQGEjYFOYLlmp+EwyEbvd/34cnEB9jcAA5o691JRXj6eKTHcZHUZw36FgLtpEpYRLAsLlpGYYZWwQZE46w==

§11.10.3 approval (vault_id test-vault-0001, request_id 01JB2Z6V9K3M4N5P6Q7R8S9T22,
          from "ab"x48 to "cd"x48, to_release 4, manifest_serial 7)
  signing string  : "vettid/vms/2/release-approval\ntest-vault-0001\n01JB2Z6V9K3M4N5P6Q7R8S9T22\n"
                    "ab"x48 "\n" "cd"x48 "\n4\n7"
  SHA-256(string) : 1217fb681eb6a11899ff5ab2ab1a620f179bb942088dc2b79e9b0466380d10b5
  Android device attestation key (test only): P-256 private scalar 32 x 0x22
  public key SPKI (b64) : MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1lqTl3yqPRsIGFL/V6eeRl8WYFdzBLrq1QXdOkhYnPNQGF6JU3LfYiHqOhN1V+Rz/dtnVfBb1QfDxTP86ckShQ==
  approval sig (DER, b64) : MEQCIH8lw3H0EdOnkuiH6yMEMR/zIh16+kPuacXjK77FnYf+AiBGvXMyQ6vhmpA1JRJYd804f5qw9Dtyo7kXZZ/TTSMCSA==
```

Cross-implementation checks against Apple CryptoKit and BouncyCastle are
pending (§15, follow-up 1).

## 17. Changelog

- **0.4.0** (2026-10-02): V4 batch 1 (vettid-vault) and the owner's
  decision to keep the full Protean Credential.
  - §3.5 (new): the Protean Credential, held by the member's app, sealed to
    a vault-held hybrid-KEM CEK and under a password key, usable only with
    the member's password per operation; the blob format, use rules,
    password backoff, unlock window, lifecycle, and what VettID and the
    vault can and cannot do with it. The earlier UTK/LTK transport keys
    are replaced by the §6 sessions.
  - §3.2, §3.3, §3.4: the CEK and the credential key; `credential.rotate`
    rotates the vault's `ik` and `kem` in the same flush, which carries the
    PQC Phase 2 migration.
  - §6.2, §6.4, §9.3: a vault's `hs.init` profile is `{name}` only; the
    bundle hint is the display name; `profile.update` on activation; the
    broadcast spread is optional because of per-mailbox ordering.
  - §8.2: responses carrying secret values are neither cached nor written
    to state; their requests are re-executed on retransmission.
  - §10: registry entries; §10.1 error codes (`conflict`, `exists`,
    `limit`, `bad_password`, `backoff`, `stale_credential`, `bad_pin`),
    versioned objects, `sync.event` kinds; `connection.event` `profile`;
    §10.6 credential and critical secrets, §10.7 secrets, §10.8 profile
    and settings, §10.9 the hash-chained audit log, the feed and guides.
  - §13.5: the credential's compromise rows. §15: follow-ups.

- **0.3.2** (2026-10-02): from the V3b implementation (vettid-vault
  supervisor and parent) and owner decisions.
  - §11.1: a lease held by an instance that is not live may be taken over,
    conditional on the exact old lease; the parent takes the lease before
    forwarding, does not forward when another instance holds it, and gives
    it back if the vault did not open; renewal failures until 15 s before
    expiry mean a lost lease; account deletion also removes the member
    index object.
  - §11.5, §11.9: the parent writes `expired` slots for requests it did not
    forward or the enclave could not read, and only answers `queued` slots;
    lifecycle writes only by the lease holder (or with no lease);
    `state_version` is a number.
  - §12.2: long-poll collect inside the enclave; KMS over HTTP/1.1
    keep-alive (no HTTP/2 at AWS KMS).
  - §12.3: parent restart and parent loss lock every vault.
  - §12.4 (new), §13.3, §13.6: one OS process per vault; the supervisor
    holds no per-vault secrets and sees the PIN only transiently;
    per-process users, non-dumpable, resource limits, a scoped channel.

- **0.3.1** (2026-10-02): fixes from the V3 implementations (vettid-vault
  V3a, the member API vault routes).
  - §11.1, §11.5: the response slot (`status`, sealed `envelope`, host
    `code` such as `etk_unknown`) and the enclave's response to the parent;
    queue name `<prefix>vault-control-<instance_id>`, `instance_id`
    pattern; `etk_kid` and `envelope` absent for lock and delete; lease
    and heartbeat encodings (Unix seconds, `lease` map written only by the
    parent); liveness (heartbeat ≤ 30 s, live within 90 s, a lease counts
    only while unexpired and its holder is live); `vault_id` is 32
    lowercase hex; MEMBER-API error bodies plus `code`; audit of enroll,
    unlock and lock.
  - §11.1, §11.8, §12.3 (owner decisions): enroll and unlock need state
    `member` with the current terms (`403 terms_required`), lock and status
    stay available; unlock limits per IPv6 /64 (10/15 min) and per IPv4
    address (60/15 min); account cancellation blocks vault access at once
    and deletes vault rows and stored state after the 7-day grace.
  - §11.3: `vault.enroll.result` in the response slot; re-enrollment
    reuses the member's `vault_id` and the enclave replaces a provisional
    vault older than 24 h or answers `vault_exists`; the diagram no longer
    has the API write a lease.
  - §11.4: results bind `re` = `request_id`; codes `release_key` and
    `retry`; requests the enclave cannot answer get random bytes of the
    result's size; no `token` after `moved`.
  - §11.4, §11.10.6, §13.2: `header_seq` is tracked per release, so that
    abandoning a move does not trip the rollback check.
  - §6.7, §11.7, §11.10.3: the pairing challenge; what the device key signs
    on each platform; two iOS counters in one unlock; status-list and
    Android acceptance details.
  - §11.10.5: `409 vault_busy` for `?release=` while another release holds
    the lease; release status comes from the signed manifest.
  - §3.3, §3.3.1, §11.10.7: the sealed-object format with the key ARN;
    `seal_key_verified.verified_by` and re-checks by another release;
    NotX members refused in any statement, case-sensitive matching,
    `Resource` a string, `MultiRegion` present, no `NextMarker`.
  - §11.2: chains evaluated at the document's timestamp.
  - §16: the 0.3.0 altchan sizes (13,444-byte unlock envelope) and the
    release vectors as generated.

- **0.3.0** (2026-10-02): release updates (VAULT-PLAN §5.1, decision D1).
  - §11.10: the signed release manifest (format, ECDSA P-256 signature over
    exact bytes, monotonic serial, statuses, pinned key), per-release
    sealing keys (seal for another release without being able to unseal),
    the approval statement, the move at unlock with its failure handling,
    confirmation by the new release and abandonment of unconfirmed moves,
    the forward-only rule, routing by `sealed_release` with on-demand
    start, and what the app shows and stores.
  - §11.10.7: before sealing to a release key, the enclave reads its
    metadata, policy and grants from KMS over TLS it terminates and checks
    them against a strict allow-list (only that release, in the pinned
    account, can decrypt; no grants, no policy changes, no re-encryption or
    other escape hatches),
    with a passing example policy and variants that must fail.
  - §11.3, §11.4: enroll and unlock requests carry the manifest and are
    padded to 12,288 bytes (§5.4); the unlock also carries an optional
    `release_update`, and its signing string covers both; results report
    the release, its status and moves.
  - §2, §13.5: VettID cannot force updates; the sealing-key guarantee is
    verified by the enclave and rests on AWS behaving as documented;
    residual risks of old releases and the manifest key.
  - §3.3, §10, §11.1–§11.5, §11.9: `sealed_release`, `manifest_serial`,
    `release_move`, the `vault.release` sync kind, routing and failures.
  - §16: release-update vectors.
- **0.2.3** (2026-10-02): additions from the V2 runtime (vettid-vault).
  - §1.2, §6.6: RELAY-PROTOCOL 0.4.0 `jti` in collect results; the token
    class is decided by the collect `jti`, and a connection's message
    without `jti` is treated as a reconnect-token deposit.
  - §3.3.1: DEK derivation (Argon2id with a sealed-header pepper and HKDF)
    and the at-rest formats.
  - §5.3: unknown types are answered with `unsupported_type` when the
    message has no `re`.
  - §6.4: pending connection requests expire after 7 days; apps or
    desktops approve; agents never.
  - §6.7: only apps create and approve pairings; `hs.init` from a
    denylisted relay key is refused.
  - §7.1: `iat` backdated by up to 60 s; lifetimes measured from it.
  - §10.1–§10.5: body schemas, error codes and `sync.event` kinds.
  - §11.3: the first app's handshake.
- **0.2.2** (2026-10-02): clarifications from the V1 implementation
  (vettid-vault).
  - `identity.rotate` statement format and chain rules (§3.4, §6.6).
  - Strict inner-plaintext rules: types, duplicate names, ULIDs, timestamp
    format, `seq` only in session mode, `re`/`status`/`error`, `type`
    grammar, `body` an object (§5.3).
  - Exact-bucket padding; over-padding is malformed (§5.4).
  - Claim-check blob layout, AAD and `sha256` coverage (§5.5).
  - Per-purpose handshake field rules: `ctx` encoding, tokens, relay
    address, `suites`, kids; `hs.resp` `sender_kid` is all-zero (§6.2).
  - Abort scope for the initiator; a bad `sig_I` leaves the responder
    pending (§6.3).
  - Bundle `kind` for pairing, whole-second bundle `exp` equal to QR `e`,
    unpadded base64url in QR and links (§6.4).
  - Sending continues in the old epoch until the new one activates; `rk`
    is deleted with the send keys (§6.5).
  - `device_attest` (Android and iOS) replaces `app_attest`, and
    `device_assertion` replaces `app_attest_assertion` (§6.7, §11.3,
    §11.4, §11.7); encodings of the devatt challenge and the unlock
    signing string (§11).
  - §16 filled in, with the complete vectors in vettid-vault.
- **0.2.1** (2026-10-02): enclave TLS pins only the allowlisted hosts'
  roots and shares a few HTTP/2 connections per instance across vaults
  (§2.2, §12.2; VAULT-PLAN D5).
- **0.2.0** (2026-10-01): owner review of 0.1.
  - Suite 2 is now HPKE (RFC 9180) with the MLKEM768X25519 KEM, KDF
    HKDF-SHA256 and AEAD ChaCha20-Poly1305. It replaces the bespoke combiner
    for sealed mode and handshake encapsulation. The handshake uses HPKE
    `Export`.
  - Sizes changed: sealed header 1,140 bytes, sealed overhead 1,156 bytes,
    `ek` 1,216 bytes.
  - Remote invitations with a selectable TTL (10 min, 1 h, 24 h or 7 d),
    bounded by relay policy. Remote invites stay pending until the inviter
    approves them.
  - Reconnect tokens (≤ 365 d, 4 messages) restore a connection without a
    new invite.
  - Client-anchored rollback protection (`state_seq`, `header_seq`).
  - `vault_id`, per-instance queues and instance leases for multiple enclave
    instances. The vault table gains `vault_version` and `state_version`.
  - Device attestation is required at enroll and unlock: Android hardware
    key attestation and iOS App Attest, both verified in the enclave (no
    Lambda, no Google credentials). Desktops no longer unlock.
  - Vault-to-vault epochs are now 24 h or 10,000 messages.
  - The open questions from 0.1 are resolved.
- **0.1.0** (2026-10-01): initial draft.
