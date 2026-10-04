---
title: VAULT-MESSAGING
status: draft
version: 0.9.1
date: 2026-10-04
owner: Al Liebl (Mesmer)
component: vault manager (enclave), parent forwarder, apps, desktops, agents, member API vault routes
related:
  - RELAY-PROTOCOL.md (0.5.0)
  - RELAY-PLAN.md
  - PQC-MIGRATION.md
  - CALLING-SERVICE.md
  - PUSH-GATEWAY.md
  - ACCOUNT-ADMIN-PLAN.md
  - MEMBER-API.md
  - VAULT-ITEMS.md (0.1.0, approved 2026-10-03)
changelog:
  - 0.9.1: vault deletion deletes the vault's relay mailbox
    (RELAY-PROTOCOL 0.5.0 `DELETE /v1/mailbox`, owner decision of
    2026-10-04): right after the marking flush, before the drain; the
    queued revocations and claim deletions are then moot; on a relay
    before 0.5.0 they remain the fallback (§1.2, §12.5, §15 item 12)
  - 0.9.0: one app per vault (owner decisions of 2026-10-03,
    PROTEAN-CREDENTIAL §4): the member's single app is the credential's
    holder and the only app; no second app pairs (`one_app`) (§6.7);
    a credential presented by another device, or a stale copy the
    holder's own retry does not explain, is a clone: refused, an urgent
    alert to the app, audit, a content-free host alarm that the member
    API turns into an email, a freeze of credential operations until the
    app confirms, then a forced rotation (§3.5.9, §11.5); direct transfer
    to a new phone with the PIN and the password, no wait (§6.7.1);
    recovery replaces the old app and keeps desktops and agents; with
    backup off a recovery restores access only, to reset the credential
    or delete the vault (§11.11.5, §11.11.8); no off-device copy of the
    credential (§3.5.6); GrapheneOS accepted through pinned verified-boot
    keys (§11.7); vault deletion (`vault.delete`, crash-safe, the member
    emailed) (§12.5); a vault reports only to its owner (§13.7); a
    holderless vault adopts no app (§3.5.9); `one_app`,
    `credential_frozen`, `rotation_required`, `credential_lost`,
    `transfer_pending` (§10.1)
  - 0.8.0: V4 batch 4: location sharing per connection (once or
    continuous, expiring, precision and cadence enforced by the sending
    vault, positions forwarded from memory and kept by the receiver only
    while the share is active, requests) (§10.16); presence as an
    on-demand ping with a per-connection policy, refusals silent (§9.2,
    §10.17); the member's opt-in location log, owner-only, bounded, shared
    only as a snapshot through a share (§10.16); the Bitcoin wallet: BIP86
    (taproot, the default) and BIP84 accounts of a recovery phrase that is
    a critical item, addresses without the password, PSBT signing as a
    credential operation in the unlock window under a signing policy, the
    member's app as the chain source (owner decision) (§10.18); the wallet
    actions run (catalog version 3, `address` in
    wallet.request-payment) (§10.14); `invalid_psbt` and `unavailable`
    (§10.1); registry, sync.event, audit, feed and threat-model rows
  - 0.7.0: V4 items (VAULT-ITEMS, owner decisions of 2026-10-03): one item
    model (name, category, typed fields, tags, sensitivity data, secret or
    critical) replaces profile fields, vault-held secrets and critical
    secrets (§10.7); critical items' values are encrypted under per-item
    keys that only the Protean Credential holds (§3.5.2, §3.5.4, §10.7); the tag registry with rename and merge,
    and the profile as a name and photo plus `@profile` items (§10.8);
    share rules over tags for connections and agents, `ask` by default
    with remembered declines, `auto` with a preview, per-connection
    catalogs, grants of items with field restrictions, `data.shared`, and
    one-off requests by category (§10.12); agents' rules as signed
    `items.read` delegations (§10.11); critical-item use through rules
    (§10.13); `items.share` (§10.14); `in_use`; owner decisions of 2026-10-03
    on agents' rules (§10.11) and envelope encryption (§10.7)
  - 0.6.0: V4 batch 3: LEASH for the member's agents (grants with scopes,
    approval modes, rate limits and expiry; the AgentPolicy decision;
    agent.request for catalog, retrieval and use without exposure;
    initial grants at pairing; every grant a delegation signed with the
    credential key, so issuing needs the member's app in the unlock
    window; refusal cooldowns, a referral cap and suspension against
    agent spam; agent activity summarised in the audit log) (§10.11); 1:1 grants of profile fields and vault-held
    secrets between connections, values sealed to the fetching device,
    and the secrets catalog (§10.12); critical-secret use by a connection
    with the member's password per use (§10.13); shared actions offered
    to connections as a built-in catalog with permission modes (§10.14);
    introductions started by the member (§10.15); peer flows are events
    correlated by ids; registry, sync.event, audit, feed and threat-model
    rows for all of them
  - 0.5.0: V4 batch 2: access sessions and app approvals for desktops and
    agents, with the LEASH hook (§6.8); the block list, connection
    metadata and member authentication with the credential key (§10.4);
    call signalling with device-held media keys and vault-signed ICE
    configurations (§10.10); fan-out to desktops only within an access
    session (§9.1); credential-key rotation statements followed by
    authenticated connections (§3.5.5, §10.4); removal by jti so peers can
    reconnect through a new invitation (§7.4); desktop calls and signed
    key-exchange shares, no call handoff (§10.10); body schemas, error
    codes, sync.event kinds and audit and feed kinds for all of them
  - 0.4.1: the Protean Credential per the owner's design: the CEK rotates
    at every use, one-time UTK/LTK transaction keys and reply keys, LAT
    superseded by Nitro attestation, a credential required before a vault
    is used (§3.5); recovery when every owner app is lost (§11.11) and its
    member API routes, never without the credential; credential backup
    (§3.5.6); an append-only audit log with fixed retention, client
    anchors and bounded drop entries (§10.9)
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
- sessions, invitations, reconnects, pairing, and the access sessions of
  desktops and agents (§6);
- deposit tokens (§7);
- delivery semantics (§8, §9);
- the message-type registry (§10);
- enrollment, unlock and recovery over an alternate channel (§11);
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
     - items (the member's data, with tags and share rules), profile
       and settings;
     - 1:1 connections and messaging;
     - calls, with signalling over the relay;
     - device and agent pairing;
     - LEASH;
     - audit and feed;
     - wallet and location;
     - shared actions;
     - grants and critical-item use;
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
8. **One app per vault** (owner decision, 2026-10-03; 0.9.0). A vault has
   exactly one device of role `app`. That app **holds** the Protean
   Credential and is the only one that unlocks. Desktops and agents pair
   as before and never hold the credential. A second copy of the
   credential is treated as theft (§3.5.9); the app moves to a new phone
   by direct transfer (§6.7.1) or by recovery (§11.11).

### 1.2 Relay features used

This document uses the following RELAY-PROTOCOL 0.5.0 features:

- one-shot **open deposit tokens** (§5.6);
- **`sender`** in collect responses (§6.3, §6.4);
- **`jti`** in collect responses: the `jti` of the deposit token a message
  was accepted under (§6.3, §6.4; new in 0.4.0, used by §6.6);
- **claims** (§6.9);
- **mailbox deletion**, `DELETE /v1/mailbox` (§6.10; new in 0.5.0, used
  by §12.5);
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
- loss of the stored vault state itself. Recovery when the app is lost
  is §11.11; it needs the state, the PIN and, with the backup on, the
  credential password.

## 3. Principals and keys

### 3.1 Principals

| Principal | Relay mailbox | Notes |
|---|---|---|
| Vault | yes | One per member, inside the enclave. Identified to VettID by an opaque `vault_id` (§11.5). |
| Owner device, role `app` | yes | A phone or tablet installation. **Exactly one per vault** (§6.7): the holder of the Protean Credential (§3.5) and the only role that may unlock (§11.7). |
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
| Credential key (Ed25519; hybrid in PQC Phase 2) | the member | Signing what the member approves: member authentication (§10.4), LEASH delegations (§10.11) | Until `credential.rotate` | **Only inside the Protean Credential** held by the member's app; in vault memory only during an unlock window (§3.5) |

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
  SHA-256 of its current blob, the password backoff state, the latest
  blob while kept (§3.5.3, §3.5.6), and the LTKs of each app's UTK pool
  (§3.5.4);
- the items (§10.7): `data` and `secret` items whole; `critical` items'
  metadata and their values encrypted under item keys that only the
  credential holds (§3.5.2); the tag registry, the profile object and the
  share rules (§10.8, §10.12);
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
- `has_credential`, whether the vault has a Protean Credential (§3.5.7);
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
  §7). A `credential.rotate` (§3.5.5) MUST rotate them, in the same flush
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

The **Protean Credential** holds the member's critical keys: the
credential key and the **item keys** of the member's critical items
(§10.7), such as seed phrases, private keys and recovery keys, whose
values the vault keeps encrypted under those keys.

- It is held by the member's one app, the **holder** (§1.1 item 8). The
  vault records which device that is; a direct transfer (§6.7.1) or a
  recovery (§11.11.5) moves it.
- It is sealed so that the vault alone cannot open it.
- Every use needs the member's participation: the app supplies the
  credential **and** the member's password, for that one operation.
- Its contents are never part of vault state.

This section follows the owner's Protean Credential design
([PROTEAN-CREDENTIAL.md](PROTEAN-CREDENTIAL.md)) on the new
transport. Its three rotating mechanisms map as follows:

- **CEK** (credential encryption key): a new CEK after **every** use of
  the credential (§3.5.3). Old blobs become undecryptable by anyone,
  including the vault.
- **UTK/LTK** (one-time transaction keys): every operation's critical
  payload is sealed, inside the §6 session, to a single-use key of the
  vault (§3.5.4).
- **LAT** (ledger authentication token): **superseded**, by decision of
  2026-01-08. The app authenticates the enclave by its Nitro attestation
  (§11.2, §11.3) and the vault's pinned identity (§6.3), which is the
  mutual authentication the LAT provided.

#### 3.5.1 Keys

- **CEK.** A KEM key (MLKEM768X25519, §4.1) generated by the vault. Its
  private seed is kept in DEK state and never leaves the vault. There is
  exactly one live CEK per credential; it is replaced, and the old one
  destroyed, at every use (§3.5.3).
- **Password key** `K_pw`. It is derived from the member's password inside
  the enclave:

  ```
  x    = Argon2id(password, salt, t, m, p, 32)
  K_pw = HKDF-SHA-256(ikm = x, salt = "vettid/vms/2/credential-pw", info = vault_id, L = 32)
  ```

  New seals use `t = 3`, `m = 64 MiB`, `p = 1`; the vault MUST refuse
  parameters below `t = 1`, `m = 8 MiB`. `salt` is 16 random bytes, fresh
  at every seal.
- **Credential key.** An Ed25519 key (a hybrid Ed25519 + ML-DSA-65 key
  from PQC Phase 2).
  - It is generated by the vault, exists only inside the credential, and
    is distinct from the relay, identity and KEM keys (§3.2).
  - It signs what the member approves; the operations that use it are
    defined with the features that need it: member authentication
    (§10.4) and signed LEASH delegations (§10.11).
- **UTK/LTK pairs.** One-time transaction keys, each an MLKEM768X25519 key pair.
  - The vault keeps the private halves (LTKs) in DEK state.
  - It gives the public halves (UTKs) to one app (§3.5.4).
- **Password.** A UTF-8 string of 8–1,024 bytes. It travels only inside a
  UTK-sealed payload. The enclave sees it transiently, as it sees the PIN
  (§12.4), and MUST NOT store or log it.

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
  "items": [ { "item_id": "<ULID>", "gen": 4, "key": "<b64 32 bytes>" } ],
  "crypto_keys": [ ] }
```

- `items` holds one entry per critical item (§10.7): its `item_id`, the
  random 32-byte **item key** its values are encrypted under, and that
  key's generation `gen` (≥ 1), which the ciphertext's AAD binds. The
  values (and notes) themselves are not in the credential: the vault
  keeps them in DEK state as ciphertext under the item key (envelope
  encryption, §10.7), with the items' metadata (name, category, tags,
  labels and kinds), so that apps can list them without the password and
  the credential stays small. A credential holds at most 1,000 entries
  (about 90 bytes each; `limit`) (0.7.0 replaced 0.6.0's `secrets` by
  `items`; no blob of an earlier draft exists).
- `crypto_keys` is reserved and empty: wallets keep their recovery
  phrase as a critical item (§10.18, 0.8.0).
- `version` in `inner` MUST equal the header's `version`; `vault_id` MUST
  equal the vault's.

Both layers are needed:

- The outer HPKE layer keeps a thief of the app's copy from guessing the
  password offline: only the enclave holds the CEK.
- The inner password layer keeps the vault, which holds the CEK, from
  opening the credential without the member.

#### 3.5.3 Using the credential: every use rotates the CEK

Every operation that opens the credential comes from the **holder**
(§3.5.9) and carries:

- `credential`: the blob;
- `utk_id` and `sealed`: the operation's critical payload, sealed to a UTK
  (§3.5.4).

The vault:

1. refuses with `credential_frozen` or `rotation_required` while a clone
   alarm is open (§3.5.9), before anything else (the UTK is not spent),
   and with `transfer_pending` from an old app whose transfer it approved
   (§6.7.1);
2. **opens `sealed`** with the LTK for `utk_id` and destroys the LTK
   (§3.5.4). A missing, used, expired or foreign UTK is refused with
   `utk_invalid`;
3. **checks the blob.** SHA-256(`credential`) must equal the hash of the
   current blob, and the presenter must be the holder. If not, the vault
   applies the clone rule of §3.5.9: the holder's own retry with the
   previous, unconfirmed version is answered `stale_credential`; anything
   else is a clone, answered `credential_frozen`. The check comes before
   the backoff, so a clone is detected even while the backoff runs;
4. refuses with `backoff` while the password backoff (below) is in effect;
5. **opens it.** The outer layer opens with the current CEK and the inner
   layer with `K_pw`. If the inner AEAD fails, the answer is
   `bad_password`; the failure is counted and recorded as
   `credential.password_failed` (§10.9);
6. **performs the operation** on the plaintext in memory;
7. **rotates the CEK**, after every successful opening, whether or not
   the content changed:
   - it generates a new CEK;
   - it seals the (possibly changed) content under it as `version + 1`,
     with a fresh salt, nonce and HPKE context;
   - it records the new hash, version and blob (the **latest blob**,
     below);
   - it **destroys the old CEK**;
   - every earlier blob is then undecryptable by anyone, the vault
     included;
8. returns the new blob and version, with new UTKs when the app's pool is
   low (§3.5.4);
9. zeroizes the plaintext, `x` and `K_pw` before the response is sent.

The vault MUST NOT keep any plaintext of the credential, `K_pw` or the
password after the operation, except the credential key during an unlock
window.

**Atomicity of a rotation.** The new CEK, the latest blob and the response
are written in the batch's flush, before the request is acked (§8.3). A
lost response therefore never loses the credential:

- **Retransmission.** The response is cached (§8.2). It holds the new blob
  but no secret value in the clear (§3.5.4), so a retransmission of the
  request within 24 h gets the same answer.
- **The latest blob is always kept until the app confirms it.** Even with
  `credential.backup` off (§3.5.6), the vault keeps the latest blob until
  the app either presents that version in a later operation or sends
  `credential.ack{version}`. The holder, answered `stale_credential` for
  its previous version (§3.5.9), fetches it with `credential.get` and
  retries with a fresh UTK. This is the only stale copy that is not a
  clone.
- **A crash.** A crash before the flush leaves the old CEK and blob in
  force: the request is redelivered and re-executed. A crash after the
  flush is covered by the outbox and the two rules above.

**Password backoff.** After 5 consecutive failures, the vault refuses
credential operations:

- for 30 s, then 1 min, 5 min, 15 min and 60 min after each further
  failure (capped at 60 min);
- a success resets the count;
- the count is in DEK state and survives locks.

**Unlock window.** `credential.unlock` keeps the credential key, and only
that key, in the vault process's memory for the
`credential.unlock_ttl_seconds` setting (30–3,600 s, default 300).

- Operations that sign with the credential key may use it within the
  window; each use extends the window to the full TTL.
- The window ends at expiry, `credential.lock`, `credential.rotate`,
  `credential.delete` and vault lock.
- The key is never written to state.

#### 3.5.4 One-time transaction keys (UTK/LTK)

The critical payload of every credential operation is sealed to a
single-use vault key, **inside** the session envelope. Its purpose is to
limit what a compromise of the device's session, or its session keys,
can do:

- Someone who reads or alters session traffic still cannot read a
  password or a secret.
- They cannot replay an operation: every UTK works once.
- They cannot move a payload to another operation or request: it is bound
  to both.

**Pool.** The vault keeps a pool of UTKs for each app:

- `credential.utk.get` tops the app's outstanding UTKs up to 20.
- Every credential response adds 10 new UTKs when fewer than 10 remain.
- UTKs are bound to the app they were issued to: another device's
  request naming them is refused.
- A UTK expires 30 days after issue; the vault deletes expired LTKs.
- An app whose pool is empty calls `credential.utk.get` first. It is
  allowed even on a restricted vault (§3.5.7) and for a recovering app
  (§11.11.5).

```
utk    = {"utk_id": "<16 lowercase hex>", "ek": "<b64 1,216 bytes>", "expires_at": "<ts>"}
sealed = enc (1,120) || ct                     (standard base64 in the body)
(enc, ctx) = SetupBaseS(ek_UTK, info = "vettid/vms/2/utk" || 0x00 || vault_id || 0x00 || utk_id)
ct     = ctx.Seal(aad = type || 0x00 || inner id, pt = payload JSON)
```

**Payload.** The payload is a JSON object, strict as in §5.3, of at most
16 KiB. It holds the operation's critical members (§10.6, §10.7):
`password`, `new_password`, `item_id` (which item an operation acts on),
`item` (a critical item's content) and `reply_key`, and, for a
critical-item use (§10.13), `request_id` and `payload_sha256`, which bind
the member's consent to one request and one payload. A wallet spend
(§10.18) binds it with `item_id` (the wallet) and `payload_sha256` (the
PSBT's hash), and `wallet.create` may carry an imported phrase as `item`.
A transfer's approval (§6.7.1) carries the `pin` (4–32 ASCII digits, as
at unlock) with the password.

**Using a UTK.** The vault looks the UTK up among those issued to the
sending app and removes it from the pool before anything else is checked.
The removal is part of the batch's flush, so the UTK is spent even if the
operation then fails, for example with `bad_password`.

**Critical values in responses.** A response that would carry a critical
item's values seals them to a **one-time reply key** instead:

- The app generates an MLKEM768X25519 key pair for that request and puts
  its `ek` in the UTK-sealed payload as `reply_key`, so a session-level
  attacker can neither read nor replace it.
- The vault seals the value:

  ```
  (enc, ctx) = SetupBaseS(reply_key, info = "vettid/vms/2/reply" || 0x00 || vault_id || 0x00 || inner id)
  value_sealed = enc || ctx.Seal(aad = "", pt = value)
  ```

- Such a response holds no secret in the clear, so it is cached like any
  other (§8.2). A lost response is therefore recovered by retransmission;
  this replaces the volatile-response rule for revealing critical values
  (`item.reveal`, §10.7).
- The reply key's private half lives only in the app's memory for that
  request. The session alone, or a cached response, reveals nothing.

#### 3.5.5 Lifecycle

- **Create.** `credential.create` comes from an app, with
  `{utk_id, sealed{password}}`.
  - The vault generates the CEK and the credential key, seals version 1
    with no items, and returns the blob.
  - A vault has at most one credential.
  - Until a credential exists the vault is restricted (§3.5.7).
- **Distribution.** The app that sent `credential.create` becomes the
  holder. It stores the blob and confirms it (§3.5.3).
  - There are no other apps to distribute it to (§6.7). Only the holder
    may fetch the latest blob (`credential.get`), and only to recover
    from its own lost response (§3.5.9).
  - Desktops learn of each new version through
    `sync.event{kind: "credential.changed", version}`; they never hold
    the blob.
  - The holder changes only by a direct transfer (§6.7.1) or a recovery
    (§11.11.5); both rotate the CEK, so the old holder's copy is dead.
- **Password change.** `credential.password.change` re-seals the content
  under the new password (and, like every use, under a new CEK).
- **Rotate.** `credential.rotate` generates a new credential key.
  - It rotates the vault's `ik` and `kem` in the same flush (§3.4).
  - The vault signs a **credential-key rotation statement** with the old
    and the new credential key, while it holds both, and delivers it to
    the connections that pinned the member's key (§10.4):

    ```json
    { "v": 1, "old_key": "<b64>", "new_key": "<b64>", "sig_old": "<b64>", "sig_new": "<b64>" }
    ```

    ```
    m       = old_key (32) || new_key (32)
    sig_old = Ed25519(old credential key, "vettid/vms/2/credential-rotate" || m)
    sig_new = Ed25519(new credential key, "vettid/vms/2/credential-rotate" || m)
    ```

    Both signatures MUST verify and `old_key` MUST differ from `new_key`.
    A vault keeps its latest 32 statements. A new credential after
    `credential.delete` has no statement.
  - It is the PQC Phase 2 vehicle; the CEK rotates as with every use.
  - Apps SHOULD offer it at least yearly.
  - The vault MUST NOT rotate the credential key without the member.
- **Delete.** `credential.delete` destroys the CEK, the recorded hash, the
  latest blob and the UTKs.
  - Blobs held by apps can no longer be opened by anyone.
  - The vault becomes restricted again (§3.5.7) until a new
    `credential.create`.
  - `vault.delete` does the same, as the first step of the vault's
    deletion (§12.5).

#### 3.5.6 Backup: the vault's copy of the blob

The vault keeps the latest blob in DEK state while the `credential.backup`
setting (§10.8) is on, which is the default.

- That copy is what `credential.get` returns to the holder after a lost
  response (§3.5.9), and what a recovery hands to the new app after the
  password (§11.11.5).
- It is sealed to the vault's current CEK outside and to the password
  inside. It is therefore useless anywhere but in the vault, and to anyone
  but the member: no copy that could be guessed offline leaves the vault.
- If the vault keeps its stored state in several versions for durability,
  every version holds the same vault-sealed object. The copies under
  destroyed CEKs are useless.
- The critical items' values are not in the blob but in DEK state,
  encrypted under the item keys the blob holds (§10.7): whichever copy
  of the latest blob a recovery uses (§11.11.5), it opens them, and
  `credential.recover` re-keys every item.

With `credential.backup` off, the vault keeps the latest blob only until
the holder confirms it (§3.5.3), then only its hash and version.

- The credential then lives **only on the holder's phone**. There is no
  off-device copy and no export (owner decision, 2026-10-03): the app
  MUST NOT write the blob anywhere but its own protected storage (no
  cloud or device backup, no file, no QR, no copy to another device).
  A member-supplied blob is never accepted (0.9.0 removed it from
  `credential.recover`).
- **Losing the phone with the backup off loses the credential and every
  critical item permanently.** A recovery can then only reset the
  credential, destroying the critical items, or delete the vault
  (§11.11.5).
- The app MUST warn clearly before turning the backup off, saying exactly
  that, and MUST ask the member to confirm. An app approving a desktop's
  `settings.set` that turns it off (§6.8) shows the same warning.
- Moving to a new phone while holding the old one is a direct transfer
  (§6.7.1), which works with the backup off.
- Turning the backup on again stores the copy at the next use of the
  credential.

#### 3.5.7 A vault without a credential is restricted

A vault MUST have a credential before it is used.

- From enrollment until `credential.create` completes, and again after
  `credential.delete`, the vault answers every request with
  `credential_required` and drops every other message (audited).
- The exceptions are the types needed to create the credential and keep
  the session alive: `vault.status`, `vault.lock`, `credential.utk.get`,
  `credential.create`, `credential.version`, `relay.token.issued`,
  `relay.token.refresh` and `relay.address.update`.
- In particular there is no pairing, no connection or invitation and no
  feature use, and `vault.enroll.confirm` is refused. The vault therefore
  stays **provisional** (§11.3) until it has a credential.
- The sealed header records whether a credential exists (`has_credential`)
  so that a recovery of a vault without one is refused (§11.11.1).

#### 3.5.8 What VettID and the vault can do

- **VettID** (host, API, relay) never sees the CEK, the LTKs, the
  password, `K_pw` or the credential's plaintext. It stores, at most, the
  DEK-encrypted vault state, which contains the current CEK, the LTKs and
  possibly the latest blob.
- **The vault** (an approved release, §11.10) holds the current CEK but
  not the password. It cannot open the credential, use its keys or read
  its critical items unless the member's app sends the password for an
  operation. During that operation, and during an unlock window for the
  credential key, an approved release does see the plaintext. A malicious
  release the member approved is out of scope (§2.2), as for the PIN.
- **A thief of an app's stored blob** needs the current CEK, which
  rotates at every use. The thief can therefore only guess the password
  online, through a paired app session, with a UTK, under the backoff.
  The blob is useless once the member uses the credential again.
- **An attacker reading or altering an app's session** cannot see the
  password or critical values (UTK and reply-key sealing), replay an
  operation (single-use UTKs), or redirect a payload (bound to type and
  request id).
- **An attacker who obtains the decrypted vault state** (the DEK, which
  needs the PIN and the enclave) holds the current CEK and, if kept, the
  latest blob, and can guess the password offline against Argon2id. The
  password, not the PIN, is what protects the credential in that case,
  and with it the critical items: their ciphertext in DEK state opens
  only with the item keys inside the credential (§10.7).
- **A thief who copies the blob and presents it** (through the holder's
  session, or as any other device) is detected unless the copy is
  byte-identical to the current blob and used before the member uses it
  again: every other presentation is a clone (§3.5.9). The vault refuses
  it, alerts the app and the member, and forces a rotation that kills
  every copy.

#### 3.5.9 One holder; clone alarm, freeze and forced rotation

The credential is useful only while exactly one copy circulates, on the
holder (owner decision, 2026-10-03; PROTEAN-CREDENTIAL §4). A second
copy is the signal of theft, so the vault treats it as an alarm, not as a
routine refresh.

**The holder.** The credential state records the holder's device id.
`credential.create` sets it to the sender; a completed transfer
(§6.7.1) or recovery (§11.11.5) moves it. Only the holder may send the
types that carry or return a blob: `credential.get`, `.ack`, `.unlock`,
`.rotate`, `.password.change`, `.delete`, the critical-item, critical-use
and wallet operations (§10.7, §10.13, §10.18) and `device.transfer.*`
(§6.7.1). **A vault with a credential but no holder** (a state of an
earlier draft) never adopts an app that presents a blob: it refuses
every request with `credential_required` (§3.5.7) except the recovery
path (§11.11.5: a recovering app's `credential.utk.get`,
`credential.recover`, `credential.reset` and `vault.delete`) and the
types a restricted vault always accepts. Vaults with several apps from
earlier drafts are not migrated; none exist outside tests.

**Detection.** Whenever a request presents a blob whose SHA-256 differs
from the current hash:

- **The holder's own retry is not a clone.** If the presenter is the
  holder, the blob's header `version` is exactly the current version − 1,
  and the holder has not yet confirmed the current version (by
  `credential.ack`, or by presenting it), the answer is
  `stale_credential`. This is the app re-fetching after a lost response
  or a crash; it fetches the latest blob with `credential.get`.
- **Everything else is a clone:** a presenter other than the holder; an
  older version; the previous version after the holder confirmed the
  current one; the current version with different bytes; a version above
  the current one. (Only the vault can make a valid blob, so the last two
  are tampering. OWNER DECISION, recommended: count them as clones.)

**On a clone,** in the request's flush (the UTK is spent):

1. the vault **refuses** with `credential_frozen`. It does not open the
   blob and returns nothing;
2. it **opens an alarm** `{alarm_id (ULID), kind: "clone", at, state:
   "frozen", presenter, version}` in DEK state, so it survives locks. The
   unlock window ends at once, and an open transfer is aborted (§6.7.1);
3. it sends the holder an **urgent alert**: `credential.alarm{alarm_id,
   kind: "clone", state: "frozen", at, presenter: "holder" | "other",
   version}` (durable), a feed item `credential.alarm` with priority
   `urgent` (`ref` = `alarm_id`), and `sync.event{kind:
   "credential.alarm", alarm_id, state}` to the owner's apps and
   desktops (§9.1);
4. it records `credential.clone_detected` in the audit log (`ref` =
   `alarm_id`, `device_id` = the presenter);
5. it reports the **host alarm** `alarm.credential_clone` (§11.5): a
   content-free event that the parent records on the vault row and the
   member API turns into an **email to the member** (MEMBER-API). The
   vault has no email egress; the event carries no data beyond its kind
   and the vault id. OWNER DECISION (recommended: this path).

Nothing of the alarm reaches a connection (§13.7).

A clone presented while an alarm is open is refused with the current
freeze code and audited (`credential.clone_detected`), but opens no new
alarm and reports nothing to the host.

**Freeze.** While an alarm is open, credential operations wait for the
member:

- In state `frozen`, every credential operation is refused with
  `credential_frozen`; in state `rotation_required`, with
  `rotation_required`. This covers critical items (§10.7), critical-item
  use (§10.13), wallet signing (§10.18), `credential.unlock` (so signed
  LEASH grants and member authentication answer `credential_locked`) and
  `device.transfer.create` and `.approve`.
- These refusals come before the UTK is spent (§3.5.3, step 1).
- Still allowed: `credential.utk.get`, `credential.version` (which shows
  the alarm), `credential.lock`, `credential.alarm.confirm`; in state
  `rotation_required` the holder's `credential.get`, `credential.ack` and
  `credential.rotate`; and a recovering app's `credential.recover` and
  `credential.reset` (§11.11.5).
- **Everything else keeps working**: messaging, connections, calls,
  `data` and `secret` items, desktops and agents.

**Confirm.** The holder answers `credential.alarm.confirm{alarm_id,
mine}`: `true` for "that was me" (for example a restored phone backup),
`false` for "not me". Both move the alarm to `rotation_required`
(OWNER DECISION, recommended: a "that was me" that skipped the rotation
would keep a known second copy alive). On "not me" the app SHOULD also
suggest changing the password and the PIN. The vault audits
`credential.alarm.confirmed` (`ref` = `<alarm_id>:mine` or
`<alarm_id>:not_mine`) and sends `sync.event{kind:
"credential.alarm", alarm_id, state: "rotation_required"}`.

**Forced rotation.** In state `rotation_required` the only credential
operation is `credential.rotate` (§3.5.5) by the holder, with the current
blob and the password: a new credential key (with its rotation statement
to the connections that pinned it, §10.4), a new CEK, every critical item
re-keyed (§10.7), and the vault's `ik` and `kem` rotated (§3.4). On
success the alarm closes (`state: "resolved"`, audit
`credential.alarm.resolved`, `sync.event`) and credential operations
resume. Every older blob, the clone included, is dead; presenting it later
opens a new alarm.

- If the holder's own blob is stale, because the clone was used first,
  the holder fetches the latest with `credential.get`, allowed in
  `rotation_required`.
- **Residual.** With the backup off and the latest blob already confirmed
  by whoever used the clone, no copy of the latest version exists: the
  credential is lost, and only a recovery (§11.11.5) helps.
- A recovery completed during an alarm (`credential.recover`) moves the
  alarm to `rotation_required`: the recovered app is the new holder and
  must rotate.

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
  Since 0.9.0, `app` (`p`) is used only by a direct transfer (§6.7.1).
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

  `t` is `c` for a connection; `p` transfers the app to a new phone
  (§6.7.1); `d` and `a` pair a desktop or agent (§6.7). `h`, `k` and the link encoding are base64url **without** padding
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

**One app per vault** (owner decision, 2026-10-03). A vault has exactly
one device of role `app`, the holder of the Protean Credential (§3.5.9).
An app is bound only:

- at enrollment (§11.3), the first and only app;
- by a direct transfer, which replaces it (§6.7.1);
- by a recovery, which replaces it (§11.11.5).

No second app pairs: `device.pair.create{role: "app"}` is answered
`one_app`; the app cannot be unlinked (`device.unlink` of the app is
answered `forbidden`: it leaves only by a transfer or a recovery); and an `hs.init` of purpose `app` that is not one of these
three handshakes is dropped and audited (`drop.one_app`). Desktops and
agents pair from the app as below; they never hold the credential. The QR
(TTL 10 min) is shown on the app; the new device scans it, or the code is
pasted.

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
- **Agents.** The approval MAY carry the agent's initial LEASH grants
  (`device.pair.approve{grants}`, §10.3, §10.11). The member's credential
  key signs them at the approval, so the app opens the unlock window
  first; they take effect in the flush that completes the pairing, and
  the agent learns them in `leash.grant.updated`. The agent's `ik` is the
  grantee.
- **Apps.** An app pairs only by a direct transfer (§6.7.1). Its
  `hs.init` carries the device attestation in `device_attest` (§11.7),
  over the §11.7 challenge with the `hs.init` inner `id` as `request_id`,
  an empty `vault_id` (the new device does not know it yet) and the
  `hs.init` inner `ts`. The vault drops (and audits) an app's `hs.init`
  without a valid attestation.
  In the same flush as the device record, the vault adds the app's `ik`,
  `kem` and attestation binding to the sealed header's unlock keys, and
  removes the old app's.
- **Re-pairing.** A re-paired device MUST use a new relay key, because its
  old `sub` stays denylisted. The vault MUST refuse an `hs.init` whose
  collect `sender` is a relay key it has denylisted as a whole (an unlinked
  device, §7.4), whatever token it arrived on. Removed connections are
  denylisted by `jti` instead and may connect again (§7.4).

#### 6.7.1 Direct transfer to a new phone

A member who still holds the old phone moves the app, and with it the
credential, to a new phone without the 24 h wait of a recovery (owner
decision, 2026-10-03). The old app's session, the PIN and the credential
password are the proof. The QR is the pairing QR with `t: "p"` and bundle
`kind: "app"` (§6.4), TTL 10 minutes; nothing else uses it.

```
Old app (holder)           Vault                  Relay             New app
  |--device.transfer.create-->|                     |                   |
  |<--{transfer_id, link, exp}|--PUT claim (p)----->|                   |
  |   shows QR                |                     |<--GET claim-------|
  |                           |<--collect-----------|<--hs.init (app,   |
  |                           |  device_attest ok   |   device_attest)  |
  |<--device.transfer.pending{name, sas}            |                   | shows SAS
  |   compare SAS; PIN + password                   |                   |
  |--device.transfer.approve{credential, utk_id, sealed{password, pin}}->|
  |                           |  PIN; open; CEK rotates (v+1, kept)     |
  |<--{exp}-------------------|--hs.resp----------->|------------------>|
  |                           |<--------------------|<--hs.fin----------|
  |                           |  one flush: new app record + unlock key,|
  |                           |  holder := new app, old app removed     |
  |<--device.unlinked{transferred} (best effort)    |                   |
  |                           |--device.paired{transfer, credential_version}->|
  |                           |<--credential.get, credential.ack, credential.utk.get--|
```

1. The holder sends `device.transfer.create`. It is refused with
   `credential_frozen` or `rotation_required` during a clone alarm
   (§3.5.9), and `exists` while another transfer is open: one at a time.
   The vault creates the invitation and answers `{transfer_id, link,
   exp}`; audit `device.transfer.started`.
2. The new app scans the QR and sends `hs.init` (purpose `app`) with
   `device_attest`, which is REQUIRED (§11.7). An invalid attestation drops
   the `hs.init` (audit `device.transfer.attestation_failed`); the holder
   sees no pending transfer. Otherwise the vault sends the holder
   `device.transfer.pending{transfer_id, name, sas}`.
3. The holder compares the SAS and sends `device.transfer.approve` with
   its current blob and, sealed to a UTK (§3.5.4), the `password` and the
   `pin`. The vault:
   - spends the UTK;
   - checks the PIN against the vault's DEK derivation (§3.3.1): `bad_pin`
     on a mismatch, counted in the unlock backoff of §11.8 (and audited
     `vault.pin_failed`), and `backoff` while that backoff runs;
   - opens the credential with the password (§3.5.3: `bad_password`,
     `backoff`, and the clone rule of §3.5.9);
   - **rotates the CEK** (version + 1). Nobody receives the new blob yet:
     the vault keeps it as the latest blob, unconfirmed, whatever
     `credential.backup` says (§3.5.3). The old app's copy is dead;
   - records the transfer as approved with `exp` = now + 10 minutes,
     sends `hs.resp`, answers `{exp}` and audits
     `device.transfer.approved`. From now on the old app's credential
     operations are refused with `transfer_pending`.
4. The new app's `hs.fin` completes the transfer in **one flush**: the new
   device record (role `app`, attestation binding, unlock key); the
   holder becomes the new app; the old app is **removed** as by
   `device.unlink` (§7.4: `device.unlinked{reason: "transferred"}` best
   effort, relay key denylisted, unlock key and UTK pool removed). The new
   app receives `device.paired{…, transfer: true, credential_version}`;
   the vault audits `device.transferred` (`device_id` = the new app, `ref`
   = `transfer_id`), creates the feed item `device.transferred` and sends
   desktops `sync.event{kind: "device.transferred", device_id,
   old_device_id}`.
5. The new app fetches the blob with `credential.get`, confirms it with
   `credential.ack` and fills its UTK pool with `credential.utk.get`.
   It unlocks later with the PIN, like any app (§11.4).

**Failures and aborts.** An aborted transfer is audited
`device.transfer.aborted` (`ref` = `transfer_id`) and announced as
`sync.event{kind: "device.transfer", transfer_id, state: "aborted",
reason}` (`reason`: `rejected`, `expired`, `alarm`, `replaced` or
`failed`); the pairing's `jti` is denylisted, and a pending `hs.init` or
an answered handshake of the new app is dropped.

| Case | What happens |
|---|---|
| The holder rejects (`device.transfer.reject`), before or after the scan, or after its own approval while the new app has not finished | Aborted. Nothing else changes (after an approval the old app fetches the rotated blob, as in the offline row below). |
| No scan, or no approval, within 10 minutes | Aborted. Nothing else changes. |
| The new app's attestation fails | Its `hs.init` is dropped; the transfer stays open until its 10 minutes run out. |
| Wrong PIN or password at approval | `bad_pin` / `bad_password`, counted in their backoffs. The transfer stays pending until its 10 minutes run out; the member may retry. |
| The new app goes offline after the approval (no `hs.fin` by `exp`) | Aborted. The old app was never removed and stays the holder. Its blob is now the previous, unconfirmed version, so it is answered `stale_credential` (not a clone, §3.5.9) and fetches the rotated blob with `credential.get`. |
| The old app goes offline before approving | The transfer times out; nothing changes. |
| The old app goes offline after approving | Nothing is needed from it: the transfer completes at `hs.fin`. The old app learns of its removal from `device.unlinked` (best effort) or from its relay key being refused. |
| A clone alarm opens (§3.5.9) | An open transfer is aborted. |
| The vault locks | The transfer and its pending handshake are kept in vault state; its 10 minutes still run and are checked at the next unlock, which aborts an expired one. |
| A recovery completes (§11.11.5) | An open transfer is aborted (`replaced`). |

OWNER DECISION (recommended: as specified): the transfer does not
re-check the old app's device attestation; its session, the PIN and the
password prove it.

### 6.8 Access sessions and approvals for desktops and agents

Pairing (§6.7) gives a desktop or an agent an E2E session with the vault.
It does not, by itself, let the device act. A desktop or agent acts only
within an **access session**: a time-limited authorization that an owner
app grants. (An access session is unrelated to the E2E session of §6.1;
its end does not end the E2E session or the pairing.) Apps need none.

**Requesting and granting:**

1. The desktop or agent sends `device.session.request{seconds?}` (60 s to
   24 h, default 1 h).
2. The vault asks the owner's apps with `device.session.pending`. A newer
   request from the same device replaces an older one; a request no app
   decides within 10 minutes is dropped.
3. An app answers `device.session.approve{request_id, seconds?}` (the app
   may change the length) or `device.session.deny`. The device is told
   with `device.session.granted{session_id, expires_at}` or
   `device.session.ended{reason: "denied"}`.

`device.pair.approve` MAY carry `session_seconds` to grant the first access
session together with the pairing (§10.3). A grant replaces the device's
current access session, so a request made within a session renews it.

**What a desktop or agent may do:**

- Without an access session, the vault answers every request of a type
  the device's role may send with `session_required` (other types remain
  `forbidden`) and drops every other message (audited), except
  `vault.status`, `device.session.request`, `device.session.end`,
  `relay.token.issued`, `relay.token.refresh`, `relay.address.update` and
  the handshake. Feature messages the vault addresses to one device (such
  as a call's answer) also reach a desktop or agent only within its
  session; responses and the messages of this section always do.
- Within it, a **desktop** may send the types listed for it in §10. Some
  of them are **step-up types**: the vault holds each such request until
  an app approves it (below). They are the types that reveal a secret
  item's values, change items, tags that sharing may depend on, the
  profile or the settings, create or accept an invitation, remove a
  connection or lift a block, or disclose data to a connection or change
  what connections can obtain: `item.put`, `item.reveal`, `item.tag`,
  `item.sensitivity`, `item.delete`, `tag.delete`, `tag.merge`,
  `profile.set`, `settings.set`, `share.rule.set`, `share.decide`,
  `connection.invite.create`, `connection.invite.accept`,
  `connection.remove`, `block.remove`, `grant.decide`,
  `action.configure`, `intro.create`, `intro.accept`,
  `location.share.start`, `location.history.list`, `.delete` and
  `.share`, and `presence.set`. Apps are never held. (Types that use the credential,
  such as `critical-secret-use.approve`, signed `leash.grant.issue`,
  `wallet.create` and `wallet.sign`, are app-only. A step-up type's app-only form, such as a critical
  item's `item.put` or an agent's `share.rule.set`, is answered
  `forbidden` to a desktop at once, never held, §10.7, §10.12.)
- An **agent** may send only the types listed for agents in §10, unless
  its LEASH grants (§10.11) allow more. For an agent's `agent.request`,
  and for its request of a type that a desktop may send but agents are
  not listed for, the vault asks its LEASH policy whether to **allow**
  it, **refer** it to an app (held like a step-up request, below) or
  **refuse** it (`forbidden`). Without a grant that covers it, a request
  is refused. Types only apps may send are never delegated. A referred
  request is executed on approval only if a grant still covers it then
  (otherwise `forbidden`): revoking a grant also stops what it had
  referred.
- Fan-out reaches a desktop only within its access session (§9.1).

**Approvals.** A held request is kept for at most 5 minutes, at most 8 per
device (`limit` beyond that):

1. The vault sends the owner's apps `approval.pending{approval_id,
   device_id, role, name, type, body, exp}` and the requester
   `approval.waiting{approval_id, request_id, exp}`; a requester that
   receives it waits up to `exp` for the response instead of the usual
   30 s (§8.1).
2. An app answers `approval.decide{approval_id, approve}`. On approval the
   vault executes the request then, as the requester's (its access
   session must still be valid), and answers the requester as usual; on
   denial it answers `denied`; at expiry `approval_timeout`.
3. The held request keeps its inner `id`: a retransmission while it is
   held is absorbed by the dedupe of §8.2, and once answered gets the
   cached response.

**Ending.** An app ends a device's access session with
`device.session.end{device_id}`; a desktop or agent ends its own with
`device.session.end{}`. Held requests of the device are answered
`denied`, its pending request is dropped, and the device is told
`device.session.ended{reason: "ended"}` when an app ended it. Unlinking
(§7.4) ends everything of the device. Access sessions also simply expire;
the device knows `expires_at`.

Every grant, end and decision is audited (§10.9), and the owner's other
devices learn of it as `sync.event` (§10.1).

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
- 1 `presence.ping` answered per minute (§10.17).

Excess messages are acked, dropped and audited.

### 7.4 Revocation

The actions for each event are applied in one flush, in the order listed:

| Event | Actions |
|---|---|
| Connection removed | Send `connection.removed` (best effort). Denylist the `jti` of every token the vault issued to the peer (standing and reconnect, including those minted in handshakes still in flight), so that none of them is accepted again. Delete the tokens held for the peer, its session keys and its outbox entries. |
| Peer blocked | As for connection removed, plus a block entry on the peer's `ik` and relay key (§10.4) |
| Device unlinked | End its access session and drop its held and pending requests (§6.8). Send `device.unlinked` (best effort). Denylist `sub`. Remove the device from the unlock keys. Delete its wake reference. |
| Agent revoked | As for device unlinked, plus revoke all of the agent's LEASH grants |
| Invite or pairing cancelled or expired | Denylist the open token's `jti`. DELETE the claim. |

The relay retains denylist entries for its maximum token lifetime
(RELAY-PROTOCOL §5.5). This is why reconnect tokens raise denylist retention
at the relay.

**Connecting again after a removal.** A removed connection's tokens are
denylisted by `jti`, not by `sub`, so its relay key itself is not refused:

- The removed peer cannot deposit with any token it held: each is
  denylisted at the relay, and messages that still arrive find no session
  and are dropped and audited.
- A fresh connection with the same peer (the same relay key) is made only
  through the normal flow: a new invitation from one owner and, on the
  inviter's side, the usual pending request and approval (§6.4). The
  removed peer gets no shortcut: reconnect tokens are denylisted, and an
  `hs.init` with purpose `reconnect` from a peer without a record is
  dropped.
- A blocked peer is refused by its block entry (§10.4) until the owner
  lifts it with `block.remove`; then the same applies.
- When the new connection activates, the vault deletes any older record of
  the same peer (same `ik` or relay key), such as a `stale` one left
  after the peer removed it or after refused deposits, without a notice;
  owner devices get `connection.event{removed}` for the old id. An
  `hs.init` of purpose `connection` from a peer whose record is `stale`
  is accepted as a new connection request for that reason.

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

**Exception: responses that carry secret values in the clear.** A type
may mark its responses volatile: they are never cached and never written to
vault state, so they are not in the outbox either. They are deposited from memory after the
batch's flush, behind any queued deposits to the same mailbox, and are
lost if that deposit fails or the vault stops first. A retransmission of
such a request is therefore executed again. This is allowed only for types
whose only side effects are audit and feed entries. No type of this
document needs it today: `item.reveal` of a critical item seals the
values to a one-time reply key instead (§3.5.4), so its response is
cached normally.

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
| ephemeral | `call.ice`, `call.ringing`, `location.update`, `presence.ping`, `presence.pong`, `presence.result`, `vault.locking` | after handling | in memory, 10 min | `exp` required |

A vault forwards ephemeral messages from memory: they are deposited after
the batch's flush, behind any queued deposits to the same mailbox, once
and best effort, and never written to vault state (they are lost if the
deposit fails or the vault stops first).

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
  session. It filters by role: apps receive fan-out; desktops only within
  their access session (§6.8); agents none. An agent receives only
  responses, the messages of §6.8 and its own `leash.grant.updated`
  (§10.11), within its access session.
- A response goes only to the device that sent the request. Side effects
  reach the owner's other devices as `sync.event`, or as feature events.
- A device that has not collected for longer than the relay TTL resyncs
  with `sync.since`.

### 9.2 Presence ping

The relay has no presence, and heartbeats sent into mailboxes that expire
would be wasteful. Presence is on demand instead (§10.17):

1. The app sends `presence.query{connection_id}` to its vault, which
   answers `{ping_id, exp}`.
2. The vault sends `presence.ping{ping_id}` to the peer vault. The ping is
   ephemeral, with `exp` = now + 30 s.
3. The peer vault replies with `presence.pong{ping_id, state,
   last_active?}`, but only if it is unlocked and its owner's policy
   allows it. `last_active` is rounded to 5 minutes. The asking vault
   passes the answer to the asking device as `presence.result`.
4. If no pong arrives before `exp`, presence is `unknown`.

A vault pings each connection, and answers each peer, at most once per
minute. When its policy refuses, it **does not answer** (0.8.0; 0.7.0
answered `unknown`, which told the peer that the vault was unlocked): a
refusal looks like a locked or offline vault.

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
devices and access sessions, connections (with blocks and member
authentication), messaging, the credential, items, tags, profile,
settings, audit, feed, calls, LEASH, share rules and grants,
critical-item use, shared actions, introductions, location, presence and
the wallet are in §10.1–§10.18; push is reserved (§14).

Every flow between vaults is a set of **events** correlated by ids in
their bodies (`request_id`, `fetch_id`, `invocation_id`), never a V↔V
request (§8.1): its answer usually waits for a member's decision, far
longer than §8.1's timeout, and must survive a lock of either vault.
Each vault records what it sent and received in its state: an event that
repeats a known id is ignored (beyond the inner-`id` dedupe of §8.2), and
an answer to an unknown or expired id is dropped.

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
| Credential | `credential.create`, `.get`, `.version`, `.unlock`, `.lock`, `.rotate`, `.password.change`, `.delete`, `.recover`, `.reset` | D→V | req | Protean Credential lifecycle (§3.5, §10.6) |
| | `credential.alarm` / `credential.alarm.confirm` | V→D / D→V | — / req | Clone alarm to the holder; its confirmation (§3.5.9) |
| | `pin.change` | D→V | req | Re-derive the DEK and re-seal the header (§10.6) |
| Items & profile | `item.put`, `.get`, `.reveal`, `.list`, `.tag`, `.sensitivity`, `.delete` | D→V | req | The member's items: `data`, `secret` and `critical` (§10.7) |
| | `tag.list`, `.set`, `.delete`, `.merge` | D→V | req | The tag registry; rename and merge (§10.8) |
| | `profile.get`, `profile.set`, `settings.get`, `settings.set` | D→V | req | Display name and photo; owner policy (§10.8) |
| | `profile.update` | V↔V | | Shared profile (name, photo, `@profile` items) to a connection (§9.3, §10.8) |
| | `sync.event` / `sync.since` | V→D, V↔V / D→V, V↔V | — / req | Mirror changes (kinds in §10.1); catch up |
| Connections | `connection.invite.create`, `.list`, `.cancel`, `.accept` | D→V | req | Invitations (§6.4) |
| | `connection.request.pending` | V→D | | Awaiting approval (profile, `sas`, `remote`) |
| | `connection.approve`, `.decline`, `.list`, `.get`, `.remove`, `.update` | D→V | req | Manage connections; the owner's own metadata |
| | `connection.removed` | V↔V | | Notify the peer |
| | `connection.event` | V→D | | Added, pending, stale, removed, rekeyed, reconnected |
| | `block.add`, `.remove`, `.list` | D→V | req | Block list (§7.4) |
| | `connection.authenticate.request`, `.approve`, `.deny`, `.list` | D→V | req | Member authentication (§10.4) |
| | `connection.authenticate.challenge`, `.response`, `.rotated` | V↔V | | Challenge; the member's signature or refusal; credential-key rotation statements |
| | `connection.authenticate.pending` / `.result` / `.key` | V→D | | Asked to authenticate; the verdict; the pinned key followed a rotation |
| Messaging | `message.send` | D→V | req | Send to a connection |
| | `message.deliver`, `message.receipt` | V↔V | | Message; delivered or read receipt |
| | `message.new` | V→D | | Incoming message |
| | `message.list`, `.get`, `.read`, `.delete` | D→V | req | History and read state |
| Calls | `call.start`, `call.list` | D→V | req | Place a call (the vault issues its signed ICE config, CALLING-SERVICE §6); call history (§10.10) |
| | `call.offer` | V↔V, V→D | | SDP and the caller device's KEM `ek`; to devices with their vault's signed ICE config |
| | `call.answer` | D→V, V↔V, V→D | | SDP and the answering device's KEM `enc` |
| | `call.ice`, `call.ringing` | any | | Trickle ICE; the callee rings (ephemeral) |
| | `call.end` | any | | Hang up, decline, busy, timeout, answered elsewhere |
| Devices & agents | `device.pair.create`, `.approve`, `.reject`, `device.list`, `device.unlink` | D→V | req | Pairing and management (§6.7) |
| | `device.pair.pending` | V→D | | Awaiting approval (`sas`) |
| | `device.transfer.create`, `.approve`, `.reject` | D→V | req | Direct transfer of the app to a new phone (§6.7.1) |
| | `device.transfer.pending` | V→D | | The new phone scanned: name and `sas` |
| | `device.paired`, `device.unlinked` | V→D | | Welcome and removal notices |
| | `device.session.request`, `.approve`, `.deny`, `.end` | D→V | req | Access sessions of desktops and agents (§6.8) |
| | `device.session.pending`, `.granted`, `.ended` | V→D | | Asked; granted; ended or denied |
| | `approval.pending`, `approval.waiting` / `approval.decide` | V→D / D→V | — / req | A desktop's step-up request or an agent's referred request, held for an app (§6.8) |
| | `agent.request` | D→V (agent) | req | LEASH: the catalog, an item its share rules include, a use of a field without exposure (§10.11) |
| LEASH | `leash.grant.issue`, `.revoke`, `.list` | D→V | req | Manage agent grants (§10.11) |
| | `leash.grant.updated` | V→D (agent) | | The agent's current grants |
| Wallet | `wallet.create`, `.list`, `.get`, `.update`, `.address.new`, `.address.list`, `.address.used`, `.psbt.inspect`, `.sign`, `.history`, `.balance` | D→V | req | BIP86 and BIP84 accounts of a phrase that is a critical item; PSBT signing (§10.18). Between connections: the wallet actions (§10.14) |
| Location | `location.share.start`, `.stop`, `.list`, `location.get`, `location.request` | D→V | req | Share with one connection; ask a connection to share (§10.16) |
| | `location.update` | D→V, V↔V, V→D | | A position: from the source device; reduced, to the connection (ephemeral) |
| | `location.history.list`, `.delete`, `.share` | D→V | req | The member's own location log; a snapshot through a share (§10.16) |
| | `location.shared`, `location.stopped`, `location.requested`, `location.snapshot` | V↔V | | A share started or stopped; a request; a log snapshot |
| | `location.event`, `location.request.pending` | V→D | | Started or stopped; asked to share |
| Actions | `action.list`, `.configure`, `.invoke`, `.respond` | D→V | req | The built-in catalog and its permission modes; invoke an action on a connection's vault; approve one (§10.14) |
| | `action.offered`, `action.invocation`, `action.result` | V↔V | | The actions offered to that connection; an invocation; its result |
| | `action.pending`, `action.result` | V→D | | Invoked and waiting for the owner; a result |
| Introductions | `intro.create`, `.cancel`, `.list`, `.accept`, `.decline` | D→V | req | Introduce two connections; answer an introduction (§10.15) |
| | `intro.offer`, `.answer`, `.connect`, `.invite`, `.link`, `.closed` | V↔V | | Between the introducer and each party |
| | `intro.pending`, `intro.event` | V→D | | Offered; answered, connecting or closed |
| Sharing | `share.rule.set`, `.list`, `.delete`, `share.decide` | D→V | req | Share rules for connections and agents; decide the items they ask about (§10.12) |
| | `share.pending` | V→D | | Items waiting for the member's decision (§10.12) |
| Grants | `grant.request`, `.decide`, `.revoke`, `.list`, `.fetch`, `.catalog` | D→V | req | 1:1 grants of items; a connection's catalog (§10.12) |
| | `data.request`, `data.decided`, `data.shared`, `data.revoked`, `data.fetch`, `data.value`, `data.catalog.get`, `data.catalog` | V↔V | | Between the two vaults |
| | `grant.pending`, `grant.event`, `grant.value`, `grant.catalog.result` | V→D | | Asked; granted, denied or revoked; a value sealed to the fetching device; a connection's catalog |
| Critical items | `critical-secret-use.request`, `.approve`, `.deny`, `.list` | D→V | req | Ask a connection's member to use a critical item; consent with the password (§10.13) |
| | `critical-secret.use`, `critical-secret.result` | V↔V | | The request; the result or refusal |
| | `critical-secret-use.pending`, `critical-secret-use.result` | V→D | | Asked (apps and desktops); the result |
| Presence | `presence.query`, `presence.get`, `presence.set` | D→V | req | Ask; read and set own state and policy (§10.17) |
| | `presence.ping`, `presence.pong` | V↔V | | On demand (§9.2; ephemeral events) |
| | `presence.result` | V→D | | The answer, to the asking device (ephemeral) |
| Audit & feed | `audit.list`, `connection.audit.list` | D→V | req | Audit log, whole or per connection (§10.9) |
| | `feed.list`, `.get`, `.update`, `.delete`, `guide.sync` | D→V | req | Activity feed; app guides as feed items (§10.9) |
| | `feed.event` | V→D | | New feed item |
| Push | `push.register`, `push.unregister` | D→V | req | Reserved (§14) |

**Calls** (CALLING-SERVICE §7, §9; §10.10):

- `call.offer` carries a fresh ephemeral KEM `ek`, generated by the
  calling device, which keeps its private half.
- The answering **device** runs
  `SetupBaseS(ek, info = "vettid/vms/2/call" || call_id)` and returns the
  resulting `enc` in `call.answer`. Both devices derive
  `K = ctx.Export("vettid/vms/2/call-key", 32)`, and from it
  `k_call = HKDF-SHA-256(ikm = K, salt = "vettid-call-v1", info = call_id)`.
  The vaults relay `ek` and `enc` and never hold `k_call`.
- Offers carry `exp`, 45 s by default.
- `call.offer`, `call.answer` and `call.end` are durable. `call.ice` and
  `call.ringing` are ephemeral.
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
  - `bad_password`, `backoff`, `stale_credential`, `utk_invalid`: §3.5.3,
    §3.5.4;
  - `credential_required`: the vault has no credential (§3.5.7), or a
    recovery needs one (§11.11.5);
  - `bad_pin`: the current PIN given to `pin.change` is wrong;
  - and (0.5.0):
    - `session_required`: a desktop or agent has no access session
      (§6.8);
    - `denied`: an app denied a held request, or the device's access
      session ended while it was held (§6.8);
    - `approval_timeout`: no app decided a held request in time (§6.8);
    - `busy`: `call.start` while a call is ringing or active (§10.10);
    - `credential_locked`: the operation signs with the credential key
      and the unlock window is closed (§3.5.3, §10.4);
    - `blocked`: `connection.invite.accept` of an invitation from a
      blocked identity (§10.4);
  - and (0.6.0) no new codes: `forbidden` also answers an agent's request
    that no LEASH grant covers (§6.8, §10.11), and `credential_locked` a
    signed LEASH grant outside the unlock window. Refusals between vaults
    are not error responses but `status` or `error` members of the
    answering event (§10.12–§10.14);
  - and (0.7.0) `in_use`: `tag.delete` of a tag a share rule names
    (§10.8), and (0.8.0) `item.put` or `item.sensitivity` of a wallet's
    item (§10.18);
  - and (0.8.0):
    - `invalid_psbt`: a PSBT the wallet refuses to sign; `message` holds a
      short reason (§10.18);
    - `unavailable`: the operation needs something this release does not
      have, such as a vault-side chain source (§10.18);
  - and (0.9.0):
    - `one_app`: `device.pair.create{role: "app"}`; the vault already has
      its app (§6.7);
    - `credential_frozen`: a clone alarm is open and awaits the holder's
      confirmation, or the request presented a clone (§3.5.9);
    - `rotation_required`: the alarm is confirmed; only
      `credential.rotate` runs until the forced rotation (§3.5.9);
    - `credential_lost`: `credential.recover` when the vault keeps no copy
      of the latest blob (backup off, §11.11.5);
    - `transfer_pending`: a credential operation of the old app after it
      approved a transfer (§6.7.1).
- A request answered with an error changes no state, except the password
  backoff, the spent UTK and the audit log and feed entries of §3.5.3.
  Objects that several
  owner devices can edit carry a `version` (an integer from 1, `0` before
  the first write); a change MUST name the version it was based on, and
  the vault answers `conflict` if it differs.
- Ids the vault assigns (`item_id`, `rule_id`, `entry_id`) are ULIDs.
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
  | `device.transferred` | `device_id` (the new app), `old_device_id` (§6.7.1) |
  | `device.transfer` | `transfer_id`, `state` (`aborted`), `reason` (§6.7.1) |
  | `credential.alarm` | `alarm_id`, `state` (`frozen`, `rotation_required`, `resolved`) (§3.5.9) |
  | `vault.release` | `release` (PCR0 hex), `release_number`; sent once after a vault first runs under a new release (§11.10.6) |
  | `credential.changed` | `version` (§3.5.5) |
  | `credential.deleted` | — |
  | `item.changed` | `item_id`, `version` (§10.7) |
  | `item.deleted` | `item_id` (§10.7) |
  | `tag.changed` | `version`: the registry, or tags on items, changed (§10.8) |
  | `profile.changed` | `version` |
  | `settings.changed` | `version` |
  | `feed.updated` | `item_id`, `seq` |
  | `feed.deleted` | `item_id`, `seq` |
  | `connection.changed` | `connection_id`, `version` (`connection.update`, §10.4) |
  | `block.added`, `block.removed` | `block_id` (§10.4) |
  | `connection.authenticate.decided` | `request_id`, `approved` (§10.4) |
  | `device.session` | `device_id`, `expires_at` (absent when the session ended) (§6.8) |
  | `approval.decided` | `approval_id`, `approved` (§6.8) |
  | `leash.grant.changed` | `grant_id`, `agent_id`, `version` (§10.11) |
  | `leash.grant.revoked` | `grant_id`, `agent_id` (§10.11) |
  | `leash.agent.suspended` | `agent_id`, `suspended` (§10.11) |
  | `grant.changed` | `grant_id`, `state` (`active`, `used`, `expired`, `revoked`) (§10.12) |
  | `grant.request.decided` | `request_id`, `approved` (§10.12) |
  | `share.rule.changed` | `rule_id`, `version` (§10.12) |
  | `share.rule.deleted` | `rule_id` (§10.12) |
  | `share.decided` | `rule_id`, `included`, `declined` (§10.12) |
  | `critical-secret-use.decided` | `request_id`, `approved` (§10.13) |
  | `action.changed` | `action_id`, `version`: its configuration changed (§10.14) |
  | `action.decided` | `invocation_id`, `approved` (§10.14) |
  | `action.offers` | `connection_id`: the actions it offers changed (§10.14) |
  | `intro.changed` | `intro_id`, `state` (§10.15) |
  | `location.share.changed` | `share_id`, `state` (`active`, `ended`): an outgoing share (§10.16) |
  | `location.history.changed` | `count`: positions were deleted from the location log (§10.16) |
  | `presence.changed` | `version` (§10.17) |
  | `wallet.changed` | `wallet_id`, `version` (§10.18) |
  | `wallet.signed` | `wallet_id`, `txid` (§10.18) |
  | `wallet.deleted` | `wallet_id` (§10.18) |

  These go to the owner's app and desktops other than the sender (not agents), never with
  secret values; devices fetch what changed.

### 10.2 Lifecycle and sessions

| Type | Request body | Response / event body |
|---|---|---|
| `vault.enrolled` | — | §11.3 |
| `vault.enroll.confirm` (app) | `{}` | `{}` |
| `vault.status` (app, desktop, agent) | `{}` | `{vault_id, state_seq, header_seq, provisional, devices, connections}` |
| `vault.lock` (app, desktop) | `{}` | `{}`; then `vault.locking` |
| `vault.delete` (app: the holder, a recovering app, or the enrolling app before a credential exists) | `{confirm: "delete my vault", credential?, utk_id, sealed{pin, password?}}` | `{}`; then the deletion of §12.5. `bad_request` without the exact phrase or a needed member; `bad_pin`, `backoff`, `bad_password`, `credential_frozen` / `rotation_required` (holder during an alarm), `forbidden` |
| `vault.locking` (ephemeral) | — | `{reason?}`, with `exp` = now + 60 s; `reason` is `"recovery"` when a recovery request locked the vault (§11.11.1) |
| `relay.token.issued` | — | `{kind: "standing" \| "reconnect", token}` |
| `relay.token.refresh` (req) | `{}` | `{kind: "standing", token}` |
| `identity.rotate` | — | `{rotation: <identity.rotate statement, §3.4>}` |
| `relay.address.update` | — | `{relay: {url, mailbox, pk}, token, reconnect_token?}` |

### 10.3 Devices (§6.7)

| Type | Request body | Response / event body |
|---|---|---|
| `device.pair.create` (app) | `{role: "desktop" \| "agent"}` | `{pairing_id, link, exp}`; `{role: "app"}` is answered `one_app` (§6.7) |
| `device.pair.pending` (to apps) | — | `{pairing_id, pending_id, role, name, sas}`; `name` is the new device's self-asserted `profile.name` |
| `device.pair.approve` (app) | `{pairing_id, session_seconds?, grants?}`; `session_seconds` (60–86,400) only for a desktop or agent: its first access session (§6.8); `grants` only for an agent: 1–32 LEASH grant specifications (§10.11), signed at the approval (`credential_locked` outside the unlock window) | `{}` |
| `device.pair.reject` (app) | `{pairing_id}` | `{}` |
| `device.paired` (to the new device) | — | `{device_id, role, vault_id, release, release_number, session_expires_at?, transfer?, credential_version?}` (the release the vault runs under); `transfer: true` and the credential's `credential_version` for a transferred app (§6.7.1) |
| `device.list` (app, desktop) | `{}` | `{devices: [{id, kind, state, name, ik, profile?, created_at?, last_active_at?, session_expires_at?}]}` |
| `device.unlink` (app) | `{device_id}` | `{}`; `forbidden` for the app itself (0.9.0: it leaves by a transfer or a recovery) |
| `device.unlinked` (to the unlinked device, best effort) | — | `{reason?}`: `"transferred"` for the old app of a transfer (§6.7.1), `"replaced"` for the old app of a recovery (§11.11.5) |
| `device.transfer.create` (the holder) | `{}` | `{transfer_id, link, exp}`; `exists` while a transfer is open; `credential_frozen` or `rotation_required` during an alarm (§6.7.1) |
| `device.transfer.pending` (to the holder) | — | `{transfer_id, name, sas}`; `name` is the new app's self-asserted `profile.name` |
| `device.transfer.approve` (the holder) | `{transfer_id, credential, utk_id, sealed{password, pin}}` | `{exp}`: the new app must finish its handshake by then; `bad_pin`, `backoff`, `bad_password`, `stale_credential`, `credential_frozen`, `utk_invalid` |
| `device.transfer.reject` (the holder) | `{transfer_id}` | `{}`; cancels the transfer before or after the scan, or after the approval until the new app finishes |
| `device.session.request` (desktop, agent) | `{seconds?}` (60–86,400, default 3,600) | `{request_id, exp}` |
| `device.session.pending` (to apps) | — | `{request_id, device_id, role, name, seconds, exp}` |
| `device.session.approve` (app) | `{request_id, seconds?}` | `{device_id, session_id, expires_at}` |
| `device.session.deny` (app) | `{request_id}` | `{}` |
| `device.session.granted` (to the device) | — | `{session_id, expires_at}` |
| `device.session.end` (app: `{device_id}`; desktop, agent: `{}`, its own) | as left | `{}` |
| `device.session.ended` (to the device) | — | `{reason: "denied" \| "ended"}` |
| `approval.pending` (to apps) | — | `{approval_id, device_id, role, name, type, body, exp}`; `body` is the held request's body |
| `approval.waiting` (to the requester) | — | `{approval_id, request_id, exp}` |
| `approval.decide` (app) | `{approval_id, approve: bool}` | `{result}`: `"ok"` or the error code the held request was answered with |

- `last_active_at` is when the vault last processed a durable message from
  the principal, to the minute; `session_expires_at` is present while an
  access session lasts.
- A held request that is approved is executed when the decision arrives,
  so `approval.decide` answers with its outcome; the requester gets the
  request's own response.

### 10.4 Connections (§6.4)

| Type | Request body | Response / event body |
|---|---|---|
| `connection.invite.create` | `{ttl_seconds: 600 \| 3600 \| 86400 \| 604800}` | `{invite_id, link, exp, remote}` |
| `connection.invite.list` | `{}` | `{invites: [{invite_id, exp, remote}]}` |
| `connection.invite.cancel` | `{invite_id}` | `{}` |
| `connection.invite.accept` | `{link}` | `{connection_id, state: "pending"}` |
| `connection.request.pending` | — | `{pending_id, invite_id, sas, remote, profile?}` |
| `connection.approve`, `.decline` | `{pending_id}` | `{}` |
| `connection.list` | `{}` | `{connections: [<connection>]}` |
| `connection.get` | `{connection_id}` | `<connection>` |
| `connection.update` | `{connection_id, version, alias?, note?, tags?, favorite?, archived?}` (at least one) | `{version}` |
| `connection.remove` | `{connection_id}` | `{}` |
| `connection.removed` (V↔V) | — | `{}` |
| `connection.event` | — | `{connection_id, event: "added" \| "removed" \| "stale" \| "rekeyed" \| "reconnected" \| "failed" \| "profile"}`; `profile`: the connection's shared profile changed (§10.8) |
| `block.add` | `{connection_id \| pending_id, note?}` (exactly one of the ids) | `{block_id}` |
| `block.remove` | `{block_id}` | `{}` |
| `block.list` | `{}` | `{blocks: [{block_id, ik, name?, note?, created_at}]}` |

```json
connection: { "id": "<id>", "kind": "connection", "state": "active", "name": "...", "ik": "<b64>",
              "profile": { }, "created_at": "<ts>", "last_active_at": "<ts>",
              "version": 2, "alias": "...", "note": "...", "tags": ["family"],
              "favorite": true, "archived": false }
```

The D→V types above are sent by `app` or `desktop` devices (§6.4 "Who
approves"); for desktops, `connection.invite.create`,
`connection.invite.accept`, `connection.remove` and `block.remove` are
step-up types (§6.8).

- **Metadata.** `alias` (at most 128 bytes), `note` (at most 1,024 bytes),
  `tags` (at most 16 distinct tags matching `[a-z0-9_.-]{1,32}`),
  `favorite` and `archived` are the owner's own metadata. They are never
  sent to the peer, are versioned as one object per connection (§10.1;
  `version` is `0` before the first update) and are announced to the
  other devices as `sync.event{kind: "connection.changed"}`. `""` clears
  `alias` or `note`; `tags` replaces the list. `name` and `profile` remain
  the peer's self-asserted values (§10.8).
- **`last_active_at`** is when the vault last processed a durable message
  from the connection, to the minute; `created_at` is when the connection
  was made.

**Block list.** `block.add` blocks a connection or the sender of a pending
connection request:

- A connection is removed as §7.4 "Peer blocked" says (the peer gets a
  best-effort `connection.removed`, never a reason) and its `ik` and relay
  key are recorded in a block entry.
- A pending request is declined and its `hs.init` identity (`from.ik`,
  `from.relay.pk`) recorded.
- An identity already blocked is answered `exists`; the list holds at most
  1,000 entries (`limit`). `note` is at most 256 bytes.
- A vault MUST refuse (drop and audit as `drop.blocked`) a connection
  `hs.init` whose `from.ik` or collect `sender` is on its block list, and
  answers `connection.invite.accept` of a blocked identity's invitation
  with `blocked`.
- A block entry follows neither the peer's identity rotation nor a new
  relay key of the peer: it guards against reconnecting by accident, while
  reaching the vault at all always needs a new invitation from its owner
  (§6.4).
- `block.remove` deletes the entry. The owner may then connect with the
  same peer again through a new invitation and approval (§7.4).
- Changes are announced as `sync.event` `block.added` / `block.removed`,
  and audited (`connection.blocked`, `connection.unblocked`).

**Member authentication.** The handshake (with the SAS, §6.3) authenticates
a connection's *vault*. `connection.authenticate.*` asks the connection's
*member* to prove that they are present now: their app approves, and their
vault signs a fresh challenge with the member's **credential key**
(§3.5.1), which only the member's password unlocks.

| Type | Request body | Response / event body |
|---|---|---|
| `connection.authenticate.request` (app, desktop) | `{connection_id, context?}` | `{request_id, exp}` |
| `connection.authenticate.challenge` (V↔V) | — | `{request_id, nonce, context?}`, with `exp` |
| `connection.authenticate.pending` (V→D, apps and desktops) | — | `{connection_id, request_id, context?, exp}` |
| `connection.authenticate.approve` (app) | `{request_id}` | `{}`; `credential_locked` outside the unlock window |
| `connection.authenticate.deny` (app, desktop) | `{request_id}` | `{}` |
| `connection.authenticate.response` (V↔V) | — | `{request_id, status: "signed", key, sig, signed_at, rotations?}` or `{request_id, status: "denied"}` |
| `connection.authenticate.rotated` (V↔V) | — | `{rotations: [<statement>, ...]}` (1–32 credential-key rotation statements, §3.5.5) |
| `connection.authenticate.key` (V→D, every owner app and desktop) | — | `{connection_id, key}`: the pinned key followed a rotation |
| `connection.authenticate.result` (V→D, every owner app and desktop) | — | `{connection_id, request_id, authenticated, key?, key_changed?, reason?}` |
| `connection.authenticate.list` (app, desktop) | `{}` | `{states: [{connection_id, key?, verified_at?, last_result?, last_at?}]}` |

- `nonce` is 32 random bytes; `context` is at most 256 bytes and shown to
  the member. A challenge lives 10 minutes (`exp`). A vault keeps at most
  8 outstanding challenges it sent per connection (`limit`) and 4 it
  received (more are dropped and audited).
- To approve, the app opens the credential's unlock window
  (`credential.unlock`, §3.5.3) and sends `connection.authenticate.approve`;
  the use extends the window. The vault signs

  ```
  m   = challenger_ik (32) || responder_ik (32) || nonce (32) || request_id (26) || context
  sig = Ed25519(credential key, "vettid/vms/2/conn-auth" || m)
  ```

  where `challenger_ik` is the requesting vault's `ik` and `responder_ik`
  the signing vault's, each as the other side has it on record. `key` is
  the credential key's public key.
- The requesting vault checks that the response answers an outstanding
  challenge it sent to that connection, verifies `sig` under `key` over
  `m`, and tells every owner device the verdict: `reason` is `denied` or
  `bad_signature`. It pins `key` at the first success. A later success
  under another key sets `key_changed: true` and re-pins, unless the
  pinned key leads to it through valid rotation statements (below); apps
  MUST show a key change.
- **Following a credential-key rotation.** A vault records, per
  connection, the credential key it last signed a response with (the key
  that connection pinned).
  - At `credential.rotate` (§3.5.5) it sends every active connection with
    such a key `connection.authenticate.rotated` carrying its statements
    from that key to the new one, in order.
  - A signed response whose `key` differs from the one recorded for that
    connection carries the same chain as `rotations`, so a requester that
    missed a delivery catches up.
  - The receiver follows the chain from its pinned key: each statement's
    `old_key` MUST equal the previous one's `new_key` (the first's the
    pinned key), both signatures MUST verify, and the chain is at most 32
    statements. On success it pins the last `new_key` and tells every owner
    device with `connection.authenticate.key` (a delivered chain) or with
    `key_changed: false` (a response).
  - **Failure.** A chain that does not verify (forged, unsigned, broken or
    too long) changes nothing: it is dropped and audited
    (`connection.authenticate.rotation_rejected`), and the next
    authentication under the new key reports `key_changed: true`. A
    receiver with no pinned key ignores `rotated`.
- Approvals, denials and verdicts are audited
  (`connection.authenticate.requested`, `.signed`, `.denied`,
  `connection.authenticated`, `connection.authenticate_failed`,
  `connection.authenticate.key_rotated`,
  `connection.authenticate.rotation_rejected`); an incoming challenge is a
  feed item.

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

### 10.6 Credential (§3.5)

Every type below is sent by the vault's app, except
`credential.version`, which an `app` or `desktop` may send. The types that
carry or return a blob (`credential.get`, `.ack`, `.unlock`, `.rotate`,
`.password.change`, `.delete`) and `credential.alarm.confirm` are the
**holder's** only (§3.5.9); `credential.recover` and `credential.reset`
are the recovering app's only (§11.11.5). Critical
items, the member's data inside the credential, are `item.*` types with
`sensitivity: "critical"` (§10.7); they follow the rules of this section
for `credential`, `utk_id` and `sealed`.

- `credential` is the standard base64 of a §3.5.2 blob.
- `utk_id` and `sealed` carry the UTK-sealed payload (§3.5.4). The
  payload members are shown in `{…}` after `sealed`: `password` and
  `new_password` (UTF-8, 8–1,024 bytes), `item_id`, `item`, `reply_key`,
  `request_id`, `payload_sha256` and `pin` (§6.7.1).
- Types that carry `sealed` can answer `utk_invalid` (§3.5.4). Types that
  carry `credential` follow §3.5.3: they can answer `backoff`,
  `stale_credential` and `bad_password`, and on success they rotate the
  CEK and return the new `credential` and its version. They also follow
  §3.5.9: a clone is answered `credential_frozen`, and during an alarm
  they answer `credential_frozen` or `rotation_required`; the old app of
  an approved transfer gets `transfer_pending` (§6.7.1).
- Every response to a type that spent a UTK carries `utks` (an array of
  §3.5.4 UTKs, possibly empty) to replenish the app's pool.

| Type | Request body | Response body |
|---|---|---|
| `credential.utk.get` | `{}` | `{utks}` (tops the app's pool up to 20) |
| `credential.create` | `{utk_id, sealed{password}}` | `{credential, version, key, utks}`; `exists` if the vault has a credential |
| `credential.get` | `{}` | `{credential, version, updated_at}`: the latest blob, to the holder only (§3.5.9); `not_found` if the vault holds none (§3.5.6) |
| `credential.ack` | `{version}` | `{}`: the app holds this version (§3.5.3) |
| `credential.version` | `{}` | `{exists, version?, key?, updated_at?, alarm?}`; `alarm` = `{alarm_id, state, at}` while a clone alarm is open (§3.5.9) |
| `credential.unlock` | `{credential, utk_id, sealed{password}}` | `{credential, version, expires_at, utks}` (§3.5.3 unlock window) |
| `credential.lock` | `{}` | `{}` |
| `credential.rotate` | `{credential, utk_id, sealed{password}}` | `{credential, version, key, utks}`; the vault also rotates `ik` and `kem` (§3.4) |
| `credential.password.change` | `{credential, utk_id, sealed{password, new_password}}` | `{credential, version, utks}` |
| `credential.delete` | `{credential, utk_id, sealed{password}}` | `{}`; the critical items go with it (§10.7) |
| `credential.recover` | `{utk_id, sealed{password}}` | `{credential, version, utks}` (§11.11.5); `credential_lost` if the vault keeps no copy of the latest blob (backup off). 0.9.0 removed the member-supplied `credential` |
| `credential.reset` | `{utk_id, sealed{password}}` | `{credential, version, key, utks}`: a new credential after a recovery with the backup off; the old credential and every critical item are destroyed (§11.11.5); `exists` if the vault keeps the latest blob (use `credential.recover`) |
| `credential.alarm` (V→D, to the holder; durable) | — | `{alarm_id, kind: "clone", state: "frozen", at, presenter: "holder" \| "other", version}`: an urgent alert (§3.5.9) |
| `credential.alarm.confirm` | `{alarm_id, mine: bool}` | `{state: "rotation_required"}`; `not_found` if no such alarm is open (§3.5.9) |
| `pin.change` | `{pin, new_pin}` | `{}`; `bad_pin` if `pin` is wrong |

- `key` is the credential key's public key (base64). `version` is the
  credential's version (§3.5.2). In the `item.*` types, whose own
  `version` is the item's, the credential's is `credential_version`.
- `reply_key` is a 1,216-byte KEM `ek`.
- **Change notices.** Every new version sends
  `sync.event{kind: "credential.changed", version}` to the owner's other
  devices (`credential.deleted` for a delete).
- **`pin.change`** re-derives the DEK from `new_pin` (§3.3.1, fresh salt)
  and re-encrypts the state and the header. Its crash-safe write order is
  specified together with its implementation (§15).
- 0.7.0 removed `credential.secret.add`, `.get`, `.list`, `.delete` and
  `.catalog`: critical secrets are critical items (§10.7), and what a
  connection may use is decided by share rules (§10.12).

### 10.7 Items

Everything the member stores is an **item**: a name, a category, typed
**fields**, free-form **tags** (§10.8) and a **sensitivity** that decides
where the vault keeps it. Items replace the profile fields, vault-held
secrets and critical secrets of 0.6.0 (VAULT-ITEMS, owner decisions of
2026-10-03). Templates (a passport, a login, a bank account) belong to
the apps, which pre-fill fields and suggest tags and a sensitivity from
them; a shared registry of recommended templates is kept with the
reference implementation (vettid-vault `docs/item-templates.json`). The
vault validates shape and size only.

```json
item: { "item_id": "<ULID>", "version": 3, "name": "Passport", "category": "identity_document",
        "sensitivity": "data|secret|critical", "template": "passport", "tags": ["identity", "travel"],
        "fields": [ { "field_id": "f1", "label": "Number", "kind": "text", "value": "…" },
                    { "field_id": "f2", "label": "Expires", "kind": "date", "value": "2031-04-30" } ],
        "notes": "…", "created_at": "<ts>", "updated_at": "<ts>" }
```

**Members.**

- `name` is 1–128 bytes. `category` matches `[a-z][a-z0-9_]{0,31}`
  (default `other`); the recommended categories are `identity_document`,
  `login`, `payment_card`, `bank_account`, `medical`, `insurance`,
  `vehicle`, `contact`, `note`, `crypto_wallet` and `other`. `template`
  (optional) matches `[a-z0-9_.-]{1,64}` and is opaque to the vault.
  `notes` is at most 16,384 bytes. `tags` is at most 16 tags (§10.8).
- **Text.** No string member of an item may contain a control character
  (U+0000–U+001F, U+007F), except line feed and tab in `notes` and in
  `multiline` and `password` values.
- **Fields** are ordered, at most 64. `label` is 1–64 bytes. `field_id`
  is assigned by the vault (`f1`, `f2`, ... from a counter of the item,
  never reused): in `item.put` a field either names a `field_id` of the
  item's current version (the same field, possibly relabelled) or has
  none (a new field); any other `field_id` is `bad_request`.
- **Kinds** drive the apps' input and display; the vault checks only the
  shape of a `value`. Every kind accepts `""` (not filled in):

  | `kind` | `value` |
  |---|---|
  | `text` | a string of at most 16,384 bytes, without line breaks |
  | `multiline` | a string of at most 16,384 bytes |
  | `number` | a decimal: `-?[0-9]{1,32}(\.[0-9]{1,32})?` |
  | `date` | `YYYY-MM-DD` or `YYYY-MM`, a valid calendar date |
  | `email` | at most 254 bytes: one `@` between a non-empty local part and domain, no white space |
  | `phone` | at most 32 bytes of digits, spaces and `+-().`, with at least one digit |
  | `url` | an absolute URI with a scheme, at most 2,048 bytes, no white space |
  | `password` | a string of at most 16,384 bytes; apps mask it and reveal it on purpose |
  | `otp` | a TOTP seed: an `otpauth://` URI of at most 2,048 bytes, or a base32 secret (RFC 4648 alphabet, case-insensitive, 16–256 characters, optional `=` padding) |
  | `address` | an object `{street?, street2?, city?, region?, postal_code?, country?}` of strings of at most 256 bytes without line breaks; `country` is an ISO 3166-1 alpha-2 code in upper case; other members are refused |
  | `file` | reserved for blob references (owner decision 4: files later); refused with `bad_request` |

- **Size.** An item's encoding as in `item.get` with every value (the
  canonical JSON the vault returns) is at most 65,536 bytes; a vault
  holds at most 2,000 items, critical ones included (`limit`).

**Sensitivity**, chosen per item at creation (default `data`; owner
decision 1):

| `sensitivity` | Kept in | Owner access | Shared |
|---|---|---|---|
| `data` | DEK state | apps and desktops, values in `item.get` | by share rules and grants (§10.12) |
| `secret` | DEK state | apps; desktops with step-up (§6.8); values only through `item.reveal`, audited | by share rules and grants (§10.12) |
| `critical` | DEK state, its values and notes encrypted under an item key that only the Protean Credential holds (§3.5.2); its metadata (name, category, template, tags, field ids, labels and kinds) in the clear in DEK state | apps only, each read or change a credential operation with the password (§3.5.3) | never readable by anyone else: a share rule can at most make it *usable* (§10.13) |

- A critical item is at most 64 fields and its encoding at most 12,288
  bytes (its content travels in one UTK payload, §3.5.4); a vault holds
  at most 1,000 critical items (`limit`).
- **Envelope encryption** (owner decision of 2026-10-03). A critical
  item's values and notes are encrypted under a random 32-byte item key:

  ```
  sealed = nonce (24) || XChaCha20-Poly1305(item key, nonce, aad, values)
  aad    = "vettid/vms/2/critical-item" || 0x00 || vault_id || 0x00 || item_id
           || 0x00 || uint64be(gen) || (0x00 || field_id)*    (the item's field ids, in order)
  values = {"fields": [{"field_id", "value"}], "notes"?}
  ```

  The ciphertext is kept with the item in DEK state; the key and its
  generation `gen` only inside the credential (§3.5.2). Without the
  credential and the password the vault cannot decrypt the values, so
  every §3.5 property holds as before: the CEK rotates at every use, old
  blobs are dead, inputs are UTK-sealed, outputs reply-key-sealed, and no
  plaintext is retained after the operation.
- **Item keys rotate on every use of the item.** Each operation that
  opens an item (`item.reveal`, `item.put`, a critical-item use, §10.13)
  re-encrypts it under a fresh key with `gen` + 1, in the same flush as
  the CEK rotation; `credential.rotate` and `credential.recover` re-key
  every critical item. Rationale: a key someone once obtained (from an
  old blob opened with its CEK and the password, or from a compromised
  release during an operation) stops opening the item at its next use,
  as an old blob stops opening at the credential's next use; re-keying
  one item costs one AEAD pass of at most 12 KiB. Re-keying every item at
  every credential use would also cover items not used since, at a cost
  that grows with the number of items; `credential.rotate`, which apps
  SHOULD offer at least yearly (§3.5.5), does that on demand.
- `item.sensitivity` changes it. `data` ↔ `secret` is a metadata change.
  Moving to or from `critical` is a credential operation: the vault moves
  the values between DEK state and the credential itself, without them
  crossing the session. Apps MUST warn the member before an item leaves
  `critical`: its values then live in DEK state, readable by the vault
  without the password.
- The tag `@profile` is allowed only on `data` items (§10.8); an item
  carrying it cannot leave `data` (`bad_request`).

| Type | Request body | Response body |
|---|---|---|
| `item.put` (app; desktop: step-up) | `data`, `secret`: `{item_id?, version?, sensitivity?, name, category?, template?, tags?, fields?, notes?}` | `{item_id, version, updated_at}` |
| | `critical` (app): `{version?, sensitivity: "critical", tags?, credential, utk_id, sealed{password, item_id?, item}}`, where `item` is `{name, category?, template?, fields?, notes?}` | `{item_id, version, updated_at, credential, credential_version, utks}` |
| `item.get` (app, desktop) | `{item_id}` | `<item>`: a `data` item with its values; a `secret` or `critical` item without `value`s and `notes`, with `has_notes` |
| `item.reveal` (app; desktop: step-up) | `secret`: `{item_id, fields?: [<field_id>]}` (a `data` item: `{item_id}`, as `item.get`) | `<item>` with its values (only those `fields`, without `notes`, if given) |
| | `critical` (app): `{item_id, credential, utk_id, sealed{password, item_id, reply_key}}` | `{item_id, version, values_sealed, credential, credential_version, utks}` |
| `item.list` (app, desktop) | `{tags?, match?, category?, sensitivity?, after?, limit?}` | `{items: [<item without values and notes>], next?}` |
| `item.tag` (app; desktop: step-up) | `{item_id, version, tags}` | `{version}` |
| `item.sensitivity` (app; desktop: step-up, `data` ↔ `secret` only) | `{item_id, version, sensitivity}`; to or from `critical` (app) also `credential, utk_id, sealed{password, item_id}` | `{version}`; with the credential also `{credential, credential_version, utks}` |
| `item.delete` (app; desktop: step-up) | `{item_id}`; `critical` (app): `{item_id, credential, utk_id, sealed{password, item_id}}` | `{}`; `critical`: `{credential, credential_version, utks}` |

- **Critical forms are app-only.** A desktop's request in a critical form
  (one that carries `credential`, names `sensitivity: "critical"`, or
  acts on a critical item) is answered `forbidden` at once, never held
  for an app's approval it could not pass (§6.8).
- **Create and replace.** Without `item_id`, `item.put` creates an item
  (`version` absent); with it, it replaces the item's name, category,
  template, tags, fields and notes (`version` required, `not_found`,
  `conflict`, §10.1). A replacement keeps the item's sensitivity
  (`sensitivity`, if given, MUST equal it; `item.sensitivity` changes it).
  `tags` absent leaves the tags as they are. For a critical item the
  content travels in the UTK-sealed `item`, and `item_id` (to replace)
  inside the payload, so that a session attacker can neither read it nor
  redirect it to another item; only `version` and `tags` are outside.
- **Reading.** `item.get` never returns the values of `secret` or
  `critical` items: the member reveals them on purpose. `item.reveal` of
  a `secret` item returns them in the clear inside the session (the
  response is cached like any other, §8.2) and is recorded as
  `item.revealed`. `item.reveal` of a `critical` item opens the
  credential and returns the values sealed to the request's one-time
  reply key (§3.5.4) as `values_sealed`, whose plaintext is
  `{"fields": [{"field_id", "value"}], "notes"?}`; it is recorded as
  `item.revealed` and is a feed item.
- **Listing.** `item.list` returns items sorted by `item_id`, filtered by
  `tags` (1–16 tags, normalised as in §10.8; `match` `any`, the default,
  or `all`), `category` and `sensitivity`. `limit` is 1–500 (default
  100); the vault returns fewer items when the response would exceed
  131,072 bytes. `next` is present when more items match: the next call
  passes it as `after`.
- **Tags** change with `item.put` or `item.tag` (no password, for every
  sensitivity: tags are metadata). A tag change can include or withdraw
  the item in share rules (§10.12); the apps show the effect before
  saving.
- **Deleting** an item withdraws it from every share rule and revokes its
  grants (§10.12). A critical item's values are removed from the
  credential.
- `credential.delete` (§10.6) deletes every critical item.
- **Change notices.** `sync.event` `item.changed` (`item_id`, `version`)
  or `item.deleted` (`item_id`), never with values.
- **Audit and feed.** `item.added`, `item.updated` (content or tags),
  `item.deleted`, `item.sensitivity_changed`, `item.revealed`
  (`ref` = `item_id`); revealing a critical item is also a feed item
  (`item.revealed`).

### 10.8 Tags, profile and settings

**Tags.** One namespace of member-defined tags labels items and defines
sharing: a tag means nothing to connections or agents until a share rule
names it (§10.12; owner decision 2).

- **Normalisation.** The vault removes leading and trailing spaces, maps
  `A`–`Z` to `a`–`z` and replaces runs of spaces by one; the result MUST
  match `[a-z0-9][a-z0-9 _-]{0,31}` (`bad_request` otherwise). Tags are
  kept sorted, duplicates after normalisation merged.
- **Reserved tags** start with `@`. The only one is `@profile` (below);
  any other `@` tag is `bad_request`. Reserved tags cannot be named by a
  share rule, merged or deleted.
- **Tag names never leave the vault** in any message to a connection:
  connections see items (name, category, the field labels they may see),
  never tags or rules. The exception is an agent's own signed delegation
  (§10.11), which carries its rule's tags (owner decision of 2026-10-03,
  §10.11).
- **The registry** holds optional presentation per tag, versioned as one
  object (§10.1): `color` (`#rrggbb`), `icon` (`[a-z0-9_.-]{1,64}`, an app
  icon name) and `description` (at most 256 bytes); at most 512 entries
  (`limit`).

| Type | Request body | Response body |
|---|---|---|
| `tag.list` (app, desktop) | `{after?, limit?}` | `{version, tags: [{tag, color?, icon?, description?, items, rules: [<rule_id>]}], next?}` |
| `tag.set` (app, desktop) | `{version, tag, color?, icon?, description?}` | `{version}` |
| `tag.delete` (app; desktop: step-up) | `{version, tag, dry_run?}` | `{version, items}` |
| `tag.merge` (app; desktop: step-up) | `{version, from: [<tag>], into, dry_run?}` | `{version, items, rules, shares: [{rule_id, item_id, mode}], shares_total}` |

- `tag.list` lists every tag in the registry, on an item or named by a
  rule, sorted: `items` is the number of items carrying it, `rules` the
  share rules naming it (the apps show both on every tag). It is paged
  like `item.list`: `limit` 1–1,000 (default 500), at most 131,072 bytes,
  `next` (the last tag returned) to pass as `after`.
- `tag.set` creates or replaces a registry entry (members absent are
  cleared).
- `tag.delete` removes the tag from the registry and from every item. A
  tag named by a share rule is refused with `in_use`: removing it from
  the rule could widen what the rule shares.
- `tag.merge` (1–16 `from` tags; `into` new or existing) replaces each
  `from` tag by `into` on every item and in every share rule (duplicates
  removed); registry entries of `from` tags go, and `into` keeps its own
  entry or takes the first `from` tag's. A rename is a merge of one tag.
  Items that then newly match a rule are handled as re-tagged (§10.12);
  `shares` lists them, with the rule's `mode` (`ask`: asked, `auto`:
  included), within 131,072 bytes, and `shares_total` counts them. A
  merge of a tag that an agent's rule names is refused with `in_use`:
  the rule's tags are in its signed delegation (§10.11), which only the
  member can sign again (`share.rule.set`).
- With `dry_run: true`, `tag.delete` and `tag.merge` change nothing and
  answer what they would do; `version` is then the current one.
- `tag.set`, `tag.delete` and `tag.merge` send one
  `sync.event{kind: "tag.changed", version}`; the items they change take
  new versions without `item.changed` notices. They are audited as
  `tag.changed` (`ref` = the new version).

**Profile.** What connections see of the member is a small profile
object, the display name and photo, plus the member's `data` items
tagged **`@profile`** (owner decision 3). Sent by `app` or `desktop`.

| Type | Request body | Response body |
|---|---|---|
| `profile.get` | `{}` | `{version, name, photo?}` |
| `profile.set` | `{version, name?, photo?}` | `{version}` |
| `profile.update` (V↔V) | — | `{version, name, photo?, items: [{item_id, name, category, fields: [{field_id, label, kind, value}]}]}` |

- `name`, the display name, is at most 128 bytes. `photo` is base64 of a
  JPEG or PNG image of at most 65,536 bytes; in `profile.set`, `""`
  removes it. The version rules of §10.1 apply to the profile object.
- **The shared profile** is `name`, `photo` and every `data` item tagged
  `@profile`, sorted by `item_id`, with all of its fields (not its notes,
  tags or other members). At most 32 items carry `@profile`, and a
  `profile.update` body is at most 196,608 bytes: a change that would
  exceed either is refused with `limit`.
- After a change of the profile object, `sync.event{kind:
  "profile.changed"}`. Whenever the shared profile changes (the name, the
  photo, or an `@profile` item's tag, name, category or fields), the
  vault sends `profile.update` to every active connection (§9.3). Its
  `version` is a counter of the shared profile, distinct from the
  profile object's.
- A receiver parses `profile.update` strictly (the field rules of §10.7),
  keeps the one with the highest `version` per connection and ignores
  older ones (§8.4), shows it as the connection's `profile` (§10.4) and
  notifies its owner devices with `connection.event{event: "profile"}`.
  It is the peer's self-asserted data, and apps MUST present it as such.
- 0.7.0 removed the profile's own fields, `shared` and `order`: they are
  `@profile` items, and anything else reaches a connection only through
  share rules and grants (§10.12).

**Settings.** Owner policy, versioned as one object. Sent by `app` or
`desktop`.

| Type | Request body | Response body |
|---|---|---|
| `settings.get` | `{}` | `{version, settings: {<key>: <value>}}`, every known key with its current or default value, plus the `app.*` keys set |
| `settings.set` | `{version, set: {<key>: <value>}}` | `{version}` |

| Key | Value | Default |
|---|---|---|
| `connections.auto_approve_in_person` | boolean (§6.4) | `false` |
| `credential.backup` | boolean (§3.5.6) | `true` |
| `credential.unlock_ttl_seconds` | integer 30–3,600 (§3.5.3) | 300 |
| `feed.retention_days` | integer 1–365 | 30 |
| `location.history.enabled` | boolean: keep the member's own location log (§10.16); turning it off deletes the log | `false` |
| `location.history.retention_days` | integer 1–365 | 30 |
| `location.history.interval_seconds` | integer 60–3,600: the log's cadence | 300 |
| `app.<name>` | string of at most 4,096 bytes, or `null` to remove; `<name>` matches `[a-z0-9_.-]{1,48}`; at most 64 | — |

`app.*` keys are opaque to the vault; apps use them for preferences that
follow the owner across devices. Unknown keys outside `app.*` are refused
with `bad_request`. Changes send `sync.event{kind: "settings.changed"}`.

### 10.9 Audit and feed

The vault keeps two records of what happened:

- the **audit log**, append-only and hash-chained, for security review;
- the **feed**, the owner's activity list, with read and archive state
  shared by the owner's devices.

Neither holds message text, item values, tags or keys. Both are DEK
state.
All types are sent by `app` or `desktop`.

**Audit.**

| Type | Request body | Response body |
|---|---|---|
| `audit.list` | `{connection_id?, kinds?: [<prefix>], before_seq? \| after_seq?, limit?}` | `{entries: [<entry>], head, seq, next_before_seq? \| next_after_seq?}`; newest first, or oldest first with `after_seq` |
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
- **The log is append-only.** No type changes or deletes an entry, and
  no principal can shorten it: entries are dropped only by the fixed
  retention, 730 days or 10,000 entries, whichever comes first. The oldest
  kept entry's `prev` is the hash of the last dropped one, so the chain
  still links.
- **Tampering and rollback are detectable.** The log is part of DEK
  state, so its integrity rests on the state's AEAD and its freshness on
  `state_seq` (§13.2): a rolled-back log is a rolled-back state. Apps
  additionally anchor it: an app keeps the highest (`seq`, `head`) it has
  verified and, with `after_seq` = that `seq`, checks that the next
  entries chain from that `head`. A log that does not extend the anchor
  MUST be reported to the member as tampered. `seq` in the response is the
  newest entry's.
- **Drop entries are bounded.** At most 60 `drop.*` entries per kind and
  principal per hour; the 61st is written once as `drop.suppressed` with
  `ref` = the suppressed kind. A peer cannot flood the log out.
- Kinds: `vault.unlocked`, `vault.locked`; `device.paired`,
  `device.unlinked`; `connection.added`, `connection.removed`,
  `connection.stale`, `connection.reconnected`; `identity.rotated`;
  `credential.created`, `credential.rotated`, `credential.password_changed`,
  `credential.password_failed`, `credential.unlocked`, `credential.deleted`;
  `credential.recovered`; `credential.clone_detected` (`ref` =
  `alarm_id`, `device_id` = the presenter), `credential.alarm.confirmed`
  (`ref` = `<alarm_id>:mine` or `<alarm_id>:not_mine`),
  `credential.alarm.resolved` (`ref` = `alarm_id`), `credential.reset`
  (§3.5.9, §11.11.5); `vault.pin_failed` (a wrong PIN at a transfer's
  approval, §6.7.1); `device.transfer.started`,
  `device.transfer.approved`, `device.transferred`,
  `device.transfer.aborted`, `device.transfer.attestation_failed`
  (`ref` = `transfer_id`), `device.replaced` (`device_id` = the old app a
  recovery removed) (§6.7.1, §11.11.5); `item.added`, `item.updated`, `item.deleted`,
  `item.sensitivity_changed`, `item.revealed` (`ref` = `item_id`),
  `tag.changed` (`ref` = the registry's new version) (§10.7, §10.8);
  `settings.changed` (`ref` = the new version); `recovery.requested`, `recovery.replaced`, `recovery.bad_code`,
  `recovery.attestation_failed`, `recovery.registered`,
  `recovery.device_paired`, `recovery.completed`, `recovery.cancelled`,
  `recovery.expired`, `recovery.voided` (§11.11.6); `message.sent`,
  `message.received` (no content; `ref` = `message_id`);
  `connection.blocked`, `connection.unblocked` (`ref` = `block_id`);
  `connection.authenticate.requested`, `connection.authenticate.signed`,
  `connection.authenticate.denied`, `connection.authenticated`,
  `connection.authenticate_failed` (`ref` = `request_id`);
  `device.session.granted`, `device.session.ended`, `approval.granted`,
  `approval.denied` (`ref` = `approval_id`) (§6.8);
  `connection.authenticate.key_rotated`,
  `connection.authenticate.rotation_rejected` (§10.4); `call.outgoing`,
  `call.incoming`, `call.answered`, `call.ended` (`ref` = `call_id`, no
  SDP or keys) (§10.10); `leash.grant.issued`, `leash.grant.updated`,
  `leash.grant.revoked`, `leash.rate_limited` (`device_id` = the agent,
  `ref` = `grant_id`), `leash.agent.suspended`, `leash.agent.resumed`,
  `leash.referrals_limited`, and, summarised per agent and hour,
  `leash.allowed`, `leash.refused`, `leash.item.read`,
  `leash.item.used` and `leash.throttled` with their `<kind>.summary`
  entries (`ref` = the count) (§10.11); `grant.requested`,
  `grant.denied` (`ref` = `request_id`), `grant.issued`,
  `grant.received`, `grant.fetched`, `grant.revoked` (`ref` = `grant_id`)
  (§10.12); `share.rule.created`, `share.rule.updated`,
  `share.rule.deleted` (`ref` = `rule_id`), `share.included`,
  `share.declined`, `share.withdrawn` (`ref` = `item_id`, with the
  subject's `connection_id` or `device_id`) (§10.12);
  `critical-secret.use.requested`, `critical-secret.used`,
  `critical-secret.use.denied`, `critical-secret.use.result`
  (`ref` = `request_id`) (§10.13); `action.configured`
  (`ref` = `action_id`), `action.invoked`, `action.approved`,
  `action.denied`, `action.completed` (`ref` = `invocation_id`)
  (§10.14); `intro.created`, `intro.offered`, `intro.accepted`,
  `intro.declined`, `intro.connecting`, `intro.closed`
  (`ref` = `intro_id`) (§10.15); `location.share.started`,
  `location.share.stopped`, `location.share.received`,
  `location.share.ended`, `location.requested` (`ref` = `share_id` or
  `request_id`), `location.history.deleted` (`ref` = the number
  deleted), `location.history.shared`, `location.history.received`
  (`ref` = `share_id`) (§10.16); `wallet.created`, `wallet.deleted`,
  `wallet.address_issued` (`ref` = `wallet_id`), `wallet.signed`
  (`ref` = `txid`) (§10.18); `drop.suppressed`;
  and `drop.<reason>` for every message the vault dropped
  or refused (§6.3, §6.6, §7.3, §8.4), with the runtime's reason, such as
  `drop.rate_limited` or `drop.one_app` (§6.7).

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
  `item.revealed` (`ref` = `item_id`; critical items), `credential.rotated`,
  `device.session.pending` (`ref` = `request_id`), `approval.pending`
  (`ref` = `approval_id`), `connection.authenticate.requested`
  (`ref` = `request_id`), `call.missed` (`ref` = `call_id`),
  `leash.rate_limited` (`ref` = `grant_id`), `leash.item.read`
  (`ref` = `item_id`; the first per agent and hour),
  `leash.agent.suspended`, `leash.referrals_limited`, `grant.request`
  (`ref` = `request_id`),
  `grant.revoked`, `grant.shared` (`ref` = `grant_id`), `share.pending`
  (`ref` = `rule_id`), `critical-secret.use.request`
  (`ref` = `request_id`), `action.request` (`ref` = `invocation_id`),
  `intro.request` (`ref` = `intro_id`), `location.shared`
  (`ref` = `share_id`), `location.request` (`ref` = `request_id`),
  `wallet.signed` (`ref` = `txid`), `credential.alarm` (priority
  `urgent`, `ref` = `alarm_id`), `device.transferred` (`ref` =
  `transfer_id`), `device.replaced` (`device_id` = the old app),
  `credential.reset`,
  and `guide`. Apps render
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

### 10.10 Calls

1:1 voice and video calls between connections (CALLING-SERVICE). Signalling
travels over the relay inside the E2E sessions: device → its vault →
the peer vault → the peer's devices. Media flows directly or through TURN,
end-to-end encrypted under `k_call`, which only the two devices of the
call hold. Sent by `app` or `desktop` devices, and by connections where
marked; never by agents. A vault takes part in at most one call at a time.

**Devices.** An app, or a desktop within its access session (§6.8), places
and answers calls, each with its own key exchange. The access session is
the authorization: call types are not step-up types, and placing or
answering a call needs no per-call approval. A desktop without a session
is not rung (§9.1) and its `call.start` is answered `session_required`.
Agents never place or take calls.

**No handoff.** A call stays on the device that placed or answered it for
its whole life. There is no handoff or transfer between devices, and no
message for one: to switch devices the member ends the call and starts a
new one on the other device.

| Type | Request body | Response / event body |
|---|---|---|
| `call.start` (D→V) | `{connection_id, call_id, media: "audio" \| "video", sdp, ek, ek_sig}` | `{call_id, exp, ice_config, ice_sig}`; `busy`, `exists`, `not_found`, `connection_unavailable`, `bad_request` (also for a share signature that does not verify) |
| `call.offer` (V↔V, with `exp`) | — | `{call_id, media, sdp, ek, device_ik, device_sig, vault_sig}` |
| `call.offer` (V→D, with `exp`) | — | `{call_id, connection_id, media, sdp, ek, device_ik, device_sig, vault_sig, peer_ik, exp, ice_config, ice_sig}` |
| `call.ringing` (D→V, V↔V, V→D; ephemeral) | — | `{call_id}` |
| `call.answer` (D→V) | — | `{call_id, sdp, enc, enc_sig}` |
| `call.answer` (V↔V) | — | `{call_id, sdp, enc, device_ik, device_sig, vault_sig}` |
| `call.answer` (V→D) | — | `{call_id, sdp, enc, device_ik, device_sig, vault_sig, peer_ik}` |
| `call.ice` (D→V, V↔V, V→D; ephemeral) | — | `{call_id, candidates: [{candidate, sdp_mid?, sdp_mline_index?}]}` |
| `call.end` (D→V, V↔V, V→D) | — | `{call_id, reason}` |
| `call.list` (D→V) | `{limit?}` (1–200, default 50) | `{calls: [{call_id, connection_id, direction: "in" \| "out", media, state, reason?, started_at, answered_at?, ended_at?}]}`, newest first |

- `call_id` is a ULID chosen by the calling device (it is signed into the
  share before the vault sees it); the vault refuses one already in use
  (`exists`). `media` (`audio` or `video`) is in the offer; video is
  negotiated in the SDP as usual. `sdp` is 1 byte to
  32 KiB; `ek` is a 1,216-byte KEM `ek` and `enc` 1,120 bytes (§10, the
  call key). A `call.ice` carries 1–16 candidates, each `candidate` at most
  1,024 bytes, `sdp_mid` at most 64 bytes, `sdp_mline_index` 0–1,023.
  `reason` is `hangup`, `decline`, `busy`, `timeout`,
  `answered_elsewhere`, `unavailable` or `failed`. `state` is `ringing`,
  `active` or `ended`.
- **Placing a call.** The caller's device generates the ephemeral KEM key,
  signs its share (below) and sends `call.start`. The vault refuses with
  `busy` while another call is ringing or active, checks and vouches for
  the share, sends the connection `call.offer` with `exp` = now + 45 s,
  records the sending device as the call's device, and answers with its
  signed ICE configuration.
- **Ringing.** The callee's vault drops an offer without `exp` or with an
  `exp` more than 90 s ahead, and treats a repeated `call_id` as a
  duplicate. If a call is ringing or active it answers `call.end{busy}`.
  Otherwise it sends every owner app and desktop (within its access
  session, §9.1) `call.offer` with the same `exp` and its own signed ICE
  configuration. A ringing device MAY send `call.ringing`, which the vault
  forwards once to the caller's vault, which forwards it to the call's
  device.
- **Answering.** The first answer wins. The first device to send `call.answer` (with `enc`,
  §10, the call key) becomes the callee's call device; the vault forwards
  the answer to the caller's vault and tells its other devices
  `call.end{answered_elsewhere}`. A device answering a call that is no
  longer ringing gets `call.end{unavailable}`. The caller's vault
  forwards the answer to the call's device only; that device derives
  `k_call` with its private KEM key.
- **ICE.** A device's `call.ice` is forwarded to the peer vault, which
  forwards it to its call's device, or to every owner device while its
  call is still ringing. Only the call's device may send it; a vault
  forwards at most 256 per call. `call.ice` and `call.ringing` are
  ephemeral (`exp` = now + 30 s) and forwarded from memory (§8.5).
- **Ending.** The call's device, or any owner device while an incoming
  call rings (declining), sends `call.end`; the vault forwards it to the
  peer vault and tells its other devices. A vault that receives
  `call.end` from the peer tells all its owner devices. An incoming call
  that ends before it was answered (or is answered `busy`) is a missed
  call (feed `call.missed`). Removing or blocking the connection ends its
  live calls (`unavailable`). A ringing call stops counting as busy at its
  `exp`, an active call 12 h after it was answered.
- **Authority.** A vault acts on a call message from a connection only
  for a call with that connection, and on one from a device only as
  stated above; anything else is dropped.
- **History.** The vault keeps the latest 200 calls (no SDP, no keys).

**Signed key-exchange shares.** The device that makes a share (the
caller's `ek`, the answerer's `enc`) signs it with its identity key; its
own vault vouches for it to the peer vault:

```
m          = role || 0x00 || call_id || 0x00 || media || 0x00 || share
             role "offer": share = ek, media = "audio" | "video"
             role "answer": share = enc, media = ""
device_sig = Ed25519(device ik, "vettid/vms/2/call-share" || m)       # ek_sig / enc_sig
vault_sig  = Ed25519(vault ik,  "vettid/vms/2/call-vouch" || device_ik (32) || m)
```

What each party checks:

| Party | Checks | On failure |
|---|---|---|
| The device's own vault (`call.start`, D→V `call.answer`) | `device_sig` under the `ik` of the sending device's paired record | Refuses: `bad_request` for `call.start`; `call.end{unavailable}` to the answering device; audited `drop.call_share` |
| The peer vault (V↔V `call.offer`, `call.answer`) | `vault_sig` under the connection's pinned `ik` (§6.3, followed through `identity.rotate`), and `device_sig` under `device_ik` | Drops (audited `drop.call_share`): an offer rings nobody; an answer is not passed on and the call keeps ringing until it ends or times out |
| The peer device (V→D `call.offer`, `call.answer`) | `vault_sig` under `peer_ik` (the connection's `ik` as its own vault has it on record, the same as `connection.get` returns) and `device_sig` under `device_ik` | MUST NOT use the share (no answer, no media key) |

The relay, the hosts and the peer vault therefore cannot swap a share
unnoticed. **Residual:** each member's own vault can. It vouches for which
`device_ik` is its member's device and tells its own devices `peer_ik`, so
it could substitute a share in either direction of its member's calls (and
then learn `k_call`). A member's own vault is trusted for that member's
calls, as it is for everything else of the member (§2.1).

**Vault-signed ICE configuration** (CALLING-SERVICE §6). Each vault gives
only its own devices an ICE configuration, for each call, signed by its
`ik`:

```
ice_config = standard base64 of the exact bytes
             {"v":1,"call_id":"<id>","exp":<unix s>,"ice_servers":[{"urls":["..."],"username":"...","credential":"..."}]}
ice_sig    = standard base64 of Ed25519(vault ik, "vettid/vms/2/ice" || those bytes)
```

- The JSON is in canonical form: members in the order shown, no
  whitespace, `username` and `credential` both present or both absent; at
  most 8 servers of 1–4 URLs (`stun:`, `stuns:`, `turn:` or `turns:`, at
  most 512 bytes, no spaces or control characters).
- A device MUST verify `ice_sig` under its vault's current `ik`, and that
  `call_id` is the call's and `exp` has not passed, and MUST NOT use
  servers from any other source. The calling service therefore cannot
  inject or reorder servers.
- The servers and short-lived credentials come from the vault's ICE
  issuer (CALLING-SERVICE §5: coturn `use-auth-secret` or a managed
  provider), valid 6 h. Without a calling service the list is empty and
  devices use host and server-reflexive candidates. How the issuer's
  shared secret reaches the vault is open (CALLING-SERVICE §10).

**PQC.** `k_call` comes from MLKEM768X25519 (suite 2, PQC Phase 1).
DTLS-SRTP below the frame encryption is classical and not relied upon
(CALLING-SERVICE §7). The ICE configuration's signature is Ed25519 and
becomes hybrid with suite 3.

### 10.11 LEASH: the member's agents

LEASH (Lightweight Encrypted Agent Secret Handling, `vettid/LEASH`) is
VettID's standard for delegating to AI agents: the member's data stays in the vault,
the member decides what an agent may do, and every access is audited.
The vault implements LEASH's vault interface for its member's own agents.
An agent's LEASH connector is a paired device of role `agent` (§6.7).
LEASH's terms map as follows:

| LEASH | Here |
|---|---|
| Enrollment: a one-time token; the owner reviews and approves | Agent pairing (§6.7): a 10-minute QR; the agent's self-asserted name and the SAS are shown; an app approves |
| Connector key pair; an encrypted channel with forward secrecy | The agent's `ik` and `kem`, and the §6 session (epochs, rekeys) |
| Connection Contract | The agent's **grants** (below), each a delegation signed by the member's credential key; issued with the pairing or later by an app, with the member present (the unlock window) |
| Approval mode | Per grant: `ask` (the default) or `auto`. LEASH's "automatic for all" is not offered |
| Rate limits; suspension and owner notification | Per grant: `per_hour` and `per_day`; past a limit the grant refers requests to an app until its window ends, and the owner is notified. Per agent: refusal cooldowns, a referral cap and suspension after repeated refusals (below) |
| Action permissions | The scope `items.read` (share rules with the agent as subject, §10.12) and the delegable owner types |
| Expiry | Per grant (`expires_at`), and the agent's access session (§6.8) |
| `leash/request_secret` (pattern 1) | `agent.request{op: "item.get"}` |
| `leash/execute_action` (pattern 2) | `agent.request{op: "item.use"}` |
| `leash/check_status` | `approval.waiting`, then the held request's response (§6.8) |
| `leash/list_available` | `agent.request{op: "catalog"}` |
| `leash/connection_info` | `leash.grant.list` from the agent (its own grants) and `vault.status` |
| Instant revocation | `leash.grant.revoke`, `device.session.end`, `device.unlink` (§7.4) |
| Audit with integrity protection | The hash-chained audit log (§10.9), `leash.*` kinds |
| Implementation tier | Tier 1: a hardware-isolated vault (AWS Nitro Enclaves) |

The connector's platform binding and binary attestation (LEASH §3.4) are
the agent's own and out of the vault's scope: the vault knows an agent by
its `ik` and relay key.

**Grants.** A grant gives one agent one scope:

```json
grant: { "grant_id": "<ULID>", "agent_id": "<device id>", "version": 1, "scope": "message.send",
         "approval": "ask", "connections": ["<id>"],
         "per_hour": 60, "per_day": 1000, "expires_at": "<ts>", "issued_at": "<ts>",
         "delegation": "<b64>", "delegation_sig": "<b64>", "key": "<b64>" }
```

- `scope` is one of:

  | Scope | Lets the agent send |
  |---|---|
  | `items.read` | `agent.request` (`catalog`, `item.get`, `item.use`) on the items the grant's share rule includes (below) |
  | `connection.list`, `connection.get`, `message.send`, `message.list`, `message.get`, `message.read`, `profile.get`, `action.list`, `action.invoke` | That owner type: the **delegable** types |

  No other type is delegable. In particular an agent is never given a type
  only apps may send, `item.*`, `tag.*` or `share.*` (it sees items only
  through LEASH), `credential.*`, `device.*`, `approval.*`, `leash.*`
  (agents may send `leash.grant.list` for their own grants),
  `settings.*`, `profile.set`, invitations, `connection.approve`,
  `.decline`, `.remove` or `.update`, `block.*`, `call.*`, `grant.*`,
  `critical-secret-use.*` or `connection.authenticate.*`, nor (0.8.0)
  any `location.*`, `presence.*` or `wallet.*` type.
- `approval` is `ask` (the default: every request is referred to an app,
  §6.8) or `auto` (allowed without approval, within the rate limits).
- `connections` (1–64 connection ids) restricts the types whose body
  carries `connection_id` (`connection.get`, `message.send`, `.list`,
  `.get`, `.read`, `action.invoke`) to those connections; it is refused
  (`bad_request`) for other scopes. A request matches a grant only if it
  meets its restrictions; a request without the restricted member never
  matches.
- `per_hour` (1–3,600) and `per_day` (1–86,400) bound the requests the
  grant allows without approval, in windows that start at the first such
  request; for an `auto` or `items.read` grant they default to 60 and
  1,000, and they are refused for any other `ask` grant. Requests an app
  approved are not counted.
- `expires_at` is optional, in the future and at most 365 days ahead (an
  `items.read` grant: its rule's `expires_at`, §10.12); an expired grant
  matches nothing and is dropped. `status_ttl` (60–3,600 s,
  default 900) is the lifetime of the grant's status statements (below).
- An agent holds at most 32 grants, its `items.read` grants included
  (`limit`). `version` follows §10.1.

**Agent share rules (`items.read`).** A share rule whose subject is an
agent (§10.12) is that agent's grant of scope `items.read`:

- An app issues, replaces or deletes it with `share.rule.set` and
  `share.rule.delete` (§10.12); issuing or replacing it signs a
  delegation (below), so it needs the unlock window (`credential_locked`
  outside it). It appears among the agent's grants (`leash.grant.list`,
  `leash.grant.updated`) with `grant_id` = its `rule_id`, `approval` =
  its `mode`, and its `tags`, `match`, `access`, `uses`, `per_hour`,
  `per_day`, `expires_at` and `status_ttl`. `leash.grant.issue` and
  `device.pair.approve{grants}` refuse scope `items.read`
  (`bad_request`); `leash.grant.revoke` of it deletes the rule.
- Its `mode` decides **inclusion** as for a connection (§10.12): `ask`,
  the default (owner decision 5), asks the member for each item that
  gains the rule; `auto` includes such items without asking. A rule
  always names its tags, so `auto` covers only items the member tagged
  for it (as 0.6.0 required `auto` reads to name their secrets).
- Owner decision (2026-10-03): an **included** item is read without a
  further approval within the rule's `per_hour` and `per_day`; past
  them, requests are referred to an app as for any grant (below), so that
  `ask` means one prompt per item rather than one per read.
- It never includes a `critical` item: critical items are never
  reachable by agents. `uses` counts the reads (`item.get` and
  `item.use`) of each included item; an item with no use left is no
  longer included.

**Decisions** (§6.8). For a request of an agent within its access
session, the vault takes the agent's unexpired grants whose scope is the
request's (for `agent.request`, its `op`'s) and whose restrictions the
request meets:

0. a suspended agent, or a request of a scope in its cooldown (below):
   it **refuses** without looking further (`forbidden`, counted as
   *throttled*);
1. no grant: it **refuses** (`forbidden`, counted as *refused*) and
   starts or extends the scope's cooldown;
2. an `auto` grant, or an `items.read` grant whose rule includes the
   item (for `catalog`, any `items.read` grant), within both of its
   windows: it **allows** the request and counts it on that grant;
3. otherwise it **refers** the request to an app (`approval.pending`,
   §6.8), up to the referral cap (below). The first referral of an
   `auto` or `items.read` grant past a limit in a window records
   `leash.rate_limited`,
   in the audit log and as a high-priority feed item.

An `agent.request` whose body does not parse is answered `bad_request`.
When an app approves a referred request, the vault executes it only if a
grant still covers it and the agent is not suspended (§6.8); that check
counts nothing.

**Refusals do not become spam.** Refused requests cost the agent nothing
to repeat but cost the vault work and the member attention, so they are
bounded per agent:

- **Cooldown per scope.** After a refusal, the agent's requests of that
  scope (for an owner type, the type) are throttled for 1 s, then 2 s,
  4 s, ... doubling after each further refusal, up to 5 min. A covered
  request, an hour without refusals, or a new grant of that scope ends
  the cooldown. An agent that retries once loses seconds; a loop is
  slowed to one examined request per scope every 5 minutes (about 19 in
  its first hour).
- **Referral cap.** At most **20 referrals per agent per hour** reach the
  member's apps (besides §6.8's limit of 8 held at once). Further
  requests that would be referred are throttled, and the first time in
  the hour the member gets a high-priority feed item
  (`leash.referrals_limited`). Twenty prompts an hour is already more
  than a person answers with care; more would train the member to
  approve without reading.
- **Suspension.** **30 refusals** (refused or throttled) **within an
  hour** suspend the agent: all of its grants are paused (its requests
  are throttled, and referred ones are not executed on approval), it is
  told in `leash.grant.updated{suspended: true}`, and the member gets a
  high-priority feed item (`leash.agent.suspended`) and
  `sync.event{leash.agent.suspended}`. An app ends it with
  `leash.agent.resume{agent_id}`, which also clears the cooldowns and
  counts. Thirty is above what the cooldown lets one scope reach in an
  hour (about 19), so an agent that only retries a refused request is
  slowed, not suspended; one that keeps sending while throttled, or
  probes many scopes, is suspended within minutes.

**Audit summaries.** Agent activity cannot push older entries out of the
audit log (§10.9). Per agent and window of one hour (from the agent's
first event in it), the first event of each kind is written singly;
later ones are counted, and when the window ends the vault writes one
`<kind>.summary` entry whose `ref` is the count of events not written
singly. The kinds are `leash.allowed` (`ref` = `grant_id`),
`leash.refused` (`ref` = the scope), `leash.item.read` and
`leash.item.used` (`ref` = `item_id`), and `leash.throttled` (only
ever summarised). An agent therefore adds at most two entries per kind
and hour. The vault has no timers: a window's summaries are written when
the agent's next window starts, at its suspension or resumption, or
when it is unlinked.

**`agent.request`** operates only on the items the agent's `items.read`
grants include (above). An item none of them includes (or that has no
use left) is not covered, so the request is refused (`forbidden`, §6.8)
whether or not the item exists. Critical items are never reachable by
agents (§3.5).

- `catalog` lists the included items' metadata: `{items: [{item_id,
  name, category, labels: [{field_id, label, kind}]}]}`, never tags,
  rules or values.
- `item.get{item_id, fields?}` returns `{item_id, name, category,
  fields: [{field_id, label, kind, value}], notes?}` (LEASH pattern 1,
  controlled exposure; `notes` only without `fields`; an unknown field is
  `not_found`), recorded as `leash.item.read` in the audit log and the
  feed (the first per agent and hour; then summarised).
- `item.use{item_id, field_id, action: "hmac-sha256", data}` uses a
  field without exposing it (LEASH pattern 2): HMAC-SHA-256 with the
  value's UTF-8 bytes as the key over `data` (1–16,384 bytes, base64),
  answered `{item_id, field_id, action, result}` (32 bytes); recorded as
  `leash.item.used`. An `address` field cannot be used (`not_found`).
  HTTP requests made by the vault with an injected secret need egress
  beyond the relay and are not offered (§15).

**Every grant is a signed delegation.** The member's **credential key**
(§3.5.1) signs each grant when it is issued, replaced or given with a
pairing: a statement, verifiable without the vault, that the member
delegated the scope to the agent's key. The agent receives it with its
grants and can present it.

```
delegation     = standard base64 of the exact bytes
                 {"v":1,"vault_ik":"<b64>","agent_ik":"<b64>","grant_id":"<ULID>","version":1,
                  "scope":"<scope>","approval":"ask","connections":["<id>"],
                  "tags":["<tag>"],"match":"any","access":"read","uses":10,"per_hour":60,"per_day":1000,
                  "status_ttl":<s>,"iat":<unix s>,"exp":<unix s>}
delegation_sig = standard base64 of Ed25519(credential key, "vettid/vms/2/leash" || those bytes)
key            = the credential key's public key
```

- **Format.** The LEASH paper defines the Connection Contract (§3.2:
  scope, approval mode, rate limits, action permissions, expiry) but no
  wire format for it. This statement carries the contract's terms and
  the claims of vettid.dev's LEASH token (issuer, the agent's key, grant
  id and version, scope) as canonical JSON: members in the order shown,
  no whitespace, `connections` only when the grant has them; `tags`,
  `match`, `access`, `per_hour` and `per_day` exactly for scope
  `items.read` (`uses` when its rule has it); ids and keys as in the
  grant, `status_ttl` the lifetime of its status statements in seconds
  (below), `iat` the issue time.
- **Tags in the delegation** (owner decision of 2026-10-03). An
  `items.read` delegation carries its rule's tag names, so a relying
  party the agent shows it to sees them: the one place tag names leave
  the vault (§10.8), as VAULT-ITEMS §6 asks ("the signed delegation
  carries the rule"). The agent is the member's own and shows its
  delegation only to parties it deals with.
- **Lifetime.** `exp` is the grant's `expires_at` in whole seconds, and
  is absent when the grant has none: LEASH's contract expiry is optional
  (§3.2). (The 24 h cap of the first 0.6.0 draft came from vettid.dev's
  token format, not from LEASH, and is gone.)
- **Revocation** follows LEASH §3.4: the vault invalidates a revoked
  grant at once, and the connector stops serving within one heartbeat.
  Here the vault is the enforcement point and never relies on a
  delegation; the agent is told at once in `leash.grant.updated`, and its
  connector MUST stop presenting a delegation that is no longer among
  its current grants. A relying party outside the vault MUST check the
  canonical form, the signature under the member's key (pinned, for a
  connection, through §10.4), `exp` if present, and that the presenter
  proves possession of `agent_ik`, and SHOULD require a current status
  statement (below), which bounds how long a revoked delegation can be
  shown.
- **The member present.** Signing uses the credential key, so issuing
  needs the member: only an app issues or replaces a grant, and only
  within the credential's unlock window (`credential.unlock`, §3.5.3;
  `credential_locked` outside it), which each signature extends. A
  pairing approval with `grants` likewise needs the window: the grants
  are signed at the approval for the agent's `ik` from its `hs.init`,
  and take effect when the pairing completes. Revoking and resuming
  sign nothing and need no window.
- A replacement is signed again under its new `version`. A
  `credential.rotate` does not re-sign grants: their delegations name
  the old key, which verifiers follow through the rotation statements
  (§3.5.5).

**Status statements ("stapling").** A delegation names its **status
issuer**: the member's vault, by `vault_ik`. The vault signs short-lived
statements that the delegation is still in force, and the agent staples
the current one to the delegation it presents. They need neither the
credential nor the member (they grant nothing new), so the vault issues
them on its own:

```
status     = standard base64 of the exact bytes
             {"v":1,"delegation":"<b64 SHA-256(delegation bytes)>","grant_id":"<ULID>",
              "status":"valid","issued_at":<unix s>,"not_after":<unix s>}
status_sig = standard base64 of Ed25519(vault ik, "vettid/vms/2/leash-status" || those bytes)
rotations  = the vault's identity.rotate statements (§3.4) from the delegation's vault_ik
             to the ik that signed, in order; absent when it has not rotated
```

- **Lifetime.** `not_after` = `issued_at` + the delegation's
  `status_ttl`, and never past the delegation's `exp`. `status_ttl` is
  set per grant (`leash.grant.issue{status_ttl}`): 60–3,600 s, default
  900. It is the revocation latency for relying parties outside the
  vault: 15 minutes by default keeps a revoked delegation usable for at
  most a quarter of an hour while an agent refreshes about four times an
  hour per grant; the member may shorten it to a minute for sensitive
  scopes; an hour is the cap, beyond which a revocation would wait
  longer than LEASH's "within one heartbeat" (§3.4) can reasonably mean.
- **Only for delegations in force.** The vault issues a statement only
  for an unexpired, unrevoked grant of an agent that is not suspended; a
  revoked grant gets no new statement, so its last one lapses within
  `status_ttl`. A locked vault (§12.1) issues none: the mechanism fails
  closed, and an agent whose member's vault stays locked loses its
  statements within `status_ttl`. Refreshing uses the agent's E2E session
  and needs its access session (§6.8).
- **Delivery.** Every grant in `leash.grant.updated` and in an agent's
  `leash.grant.list` carries a fresh `status`, `status_sig` and
  `rotations`; `leash.status.get{grant_id}` returns a fresh one
  (`not_found` for a grant that is not the agent's or not in force,
  `forbidden` while the agent is suspended). The reference client
  refreshes a statement when less than a quarter of its lifetime (at
  least a minute) remains.
- **Rotation of the vault's `ik`.** The delegation is not re-signed when
  the vault's `ik` rotates (that would need the member's credential key
  for every grant): statements are signed by the current `ik` and carry
  the rotation chain from the delegation's `vault_ik`, which each link
  signs with both keys (§3.4), at most 32 links. A verifier therefore
  needs nothing but what the agent presents.
- **Verification by a relying party that is not connected to the vault**
  (normative). Given the delegation, `delegation_sig`, the member's
  credential key it trusts, the statement, `status_sig`, `rotations` and
  its clock, it MUST check, in order:
  1. the delegation's canonical form and `delegation_sig` under the
     member's key, and that `now` < `exp` if `exp` is present;
  2. the statement's canonical form;
  3. that `rotations` is a valid chain from the delegation's `vault_ik`
     (each link as in §3.4); the statement's signer is the chain's last
     key (the delegation's `vault_ik` if empty);
  4. `status_sig` under that key;
  5. that `delegation` equals SHA-256 of the delegation's bytes and
     `grant_id` the delegation's;
  6. `issued_at` − 60 s ≤ `now` ≤ `not_after` + 60 s (clock skew);
  7. that the presenter proves possession of `agent_ik` (for example by
     signing the relying party's challenge, as LEASH's connector does).

  The reference verifier is `leashwire.VerifyPresented` in vettid-vault
  (steps 1–6). **Residual:** a revocation takes effect for relying
  parties within `status_ttl` (plus skew). How a relying party comes to
  trust the member's credential key in the first place (member
  authentication, §10.4, for a VettID connection; otherwise LEASH's
  enrollment and trust model) is outside this document.

| Type | Request body | Response / event body |
|---|---|---|
| `leash.grant.issue` (app, within the unlock window) | `{agent_id, grant_id?, version?, scope, approval?, connections?, per_hour?, per_day?, expires_at?, status_ttl?}` (not `items.read`); without `grant_id` a new grant (`version` absent); with it, a replacement of that grant (`version` required; `conflict`); `credential_locked` outside the window | `<grant>`, with its `delegation`, `delegation_sig` and `key` |
| `leash.grant.revoke` (app, desktop) | `{grant_id}` | `{}` |
| `leash.grant.list` (app, desktop: `{agent_id?}`; agent: `{}`, its own) | as left | apps and desktops: `{grants: [<grant>], suspended: [<agent_id>]}`; an agent: `{grants: [<grant>], suspended}` |
| `leash.grant.updated` (V→D, to the agent) | — | `{grants: [<grant>], suspended}`: all of its grants, after every change and at suspension and resumption |
| `leash.agent.resume` (app) | `{agent_id}` | `{}`; `not_found` unless the agent is suspended |
| `leash.status.get` (agent) | `{grant_id}` | `{grant_id, status, status_sig, rotations?}`; `not_found`, `forbidden` (suspended) |
| `agent.request` (agent) | `{op: "catalog"}`, `{op: "item.get", item_id, fields?}` or `{op: "item.use", item_id, field_id, action: "hmac-sha256", data}` | `{items}`, `{item_id, name, category, fields, notes?}` or `{item_id, field_id, action, result}` |

- `agent_id` names an active device of role `agent` (`not_found`
  otherwise). A grant replaced or issued for an agent is sent to it in
  `leash.grant.updated`, within its access session (§6.8); an agent
  fetches its grants with `leash.grant.list` when a session starts.
- `leash.grant.revoke` deletes the grant at once (an `items.read` grant:
  its share rule). Unlinking the agent revokes all of its grants and
  deletes its share rules (§7.4). Removing or blocking a connection
  revokes every grant that names it in `connections`: its delegation
  names the connection and cannot be re-signed without the member.
- Changes are announced as `sync.event` `leash.grant.changed`,
  `leash.grant.revoked` or `leash.agent.suspended` (to apps and
  desktops) and audited (`leash.grant.issued`, `.updated`, `.revoked`,
  `leash.agent.suspended`, `.resumed`, `leash.referrals_limited`).

### 10.12 Share rules and grants: sharing with connections

The member shares items with a connection, or with one of their agents
(§10.11), by **share rules** over tags: "Dr Lee may read my items tagged
*medical*". Underneath, every item a rule makes readable to a connection
is a **grant**: the connection fetches the item's current values, sealed
to its fetching device, at most `uses` times and until the grant expires
or is revoked. A connection can also ask for something specific with a
one-off grant request, which the member answers.

**Share rules.**

```json
share_rule: { "rule_id": "<ULID>", "version": 1,
              "subject": { "connection_id": "<id>" },
              "tags": ["medical"], "match": "any", "access": "read", "mode": "ask",
              "uses": 10, "expires_at": "<ts>", "include_existing": true,
              "created_at": "<ts>", "updated_at": "<ts>",
              "included": ["<item_id>"], "pending": ["<item_id>"], "declined": ["<item_id>"] }
```

- `subject` is `{connection_id}` (an active connection) or `{agent_id}`
  (an agent, §10.11; `not_found` otherwise). It cannot change.
- `tags` is 1–16 tags (§10.8), none reserved. `match` is `any` (the
  default: an item carrying one of them) or `all` (every one).
- `access` is `read`, the only value: `data` and `secret` items the rule
  includes become readable by the subject. A `critical` item is never
  readable: a connection rule can at most make it **usable** for
  critical-item use (§10.13), and an agent rule never includes it.
- `mode` is `ask` (the default, owner decision 2026-10-03) or `auto`.
- `uses` (1–10,000) bounds the fetches of each included item; absent,
  fetches are not counted against a limit (each is still audited).
  `expires_at` (in the future, at most 3,650 days ahead) ends the rule;
  absent, it lasts until deleted. `include_existing` (default `true`)
  applies the rule to the items that already match it (below).
- `included`, `pending` and `declined` list the rule's items in each
  state (below). A vault holds at most 64 rules per subject and 512 in
  all, and at most 4,096 pending items (`limit`).

**Matching and inclusion.** An item **matches** a rule while the rule is
in force and the item's tags meet `tags` and `match`; an agent rule
never matches a `critical` item. Each matching item is, for that rule,
**pending** (the member was asked), **included** or **declined**:

- **Mode `ask`.** When an item **gains** the rule (it matches after a
  change and either did not match before or gained one of the rule's
  tags: a new item, a re-tag, a merge, a rule that now names its tag),
  it becomes pending and the member's apps and desktops get
  `share.pending` ("Share *Allergy list* with *Dr Lee*?"). The member
  decides with `share.decide`. A declined item is remembered and not
  asked again until it gains the rule again.
- **Mode `auto`.** An item that gains the rule is included at once,
  without asking. The apps show the impact before a rule or a tag change
  is saved (`dry_run`, below).
- **`include_existing`.** When a rule is created (or replaced), the items
  that already match it gain it if `include_existing` is `true`; with
  `false` only later gains count. `share.rule.set{dry_run: true}` lists
  them first, so the member confirms the preview either way.
- **Withdrawal.** An included or pending item that stops matching (its
  tag removed, the rule changed, deleted or expired, the item deleted or
  moved to or from `critical`) is withdrawn at once: pending, it is
  dropped; included, its grant is revoked (the connection is told
  `data.revoked`) or, for an agent, its reads end. A move to or from
  `critical` withdraws the item from every rule and then lets it gain
  the rules it matches.
- A rule replaced from `ask` to `auto` includes its pending items.

| Type | Request body | Response / event body |
|---|---|---|
| `share.rule.set` (app; desktop: step-up; an agent subject: app within the unlock window) | `{rule_id?, version?, subject, tags, match?, access?, mode?, uses?, expires_at?, include_existing?, per_hour?, per_day?, status_ttl?, dry_run?}` | `<share_rule>` (an agent rule with its delegation, §10.11); with `dry_run`: `{matches: [{item_id, name, category, sensitivity, state?}], total}` |
| `share.rule.list` (app, desktop) | `{connection_id? \| agent_id?, after?, limit?}` | `{rules: [<share_rule>], next?}` |
| `share.rule.delete` (app, desktop) | `{rule_id}` | `{}` |
| `share.pending` (V→D, apps and desktops) | — | `{rule_id, subject, items: [{item_id, name, category, sensitivity}], reason: "rule" \| "tagged"}` |
| `share.decide` (app; desktop: step-up) | `{rule_id, items: [<item_id>], approve}` | `{included: [<item_id>], declined: [<item_id>]}` |

- `share.rule.set` without `rule_id` creates a rule (`version` absent);
  with it, it replaces the rule (`version` required, `not_found`,
  `conflict`). `per_hour`, `per_day` and `status_ttl` are only for agent
  rules (§10.11). With `dry_run: true` it changes nothing and lists the
  items the rule would match, with their current `state` for a
  replacement, within 131,072 bytes (`total` counts them all). A
  desktop's request for an agent subject is answered `forbidden` at once
  (the delegation needs the credential key, §6.8).
- `share.rule.list` is sorted by `rule_id` and paged like `item.list`:
  `limit` 1–500 (default 50), at most 131,072 bytes, `next`.
- `share.pending` is sent for each batch of items that became pending
  (split into several messages of at most 131,072 bytes when large):
  `reason` is `rule` when a rule was created or replaced, `tagged` when
  items changed. It is also a feed item (`share.pending`, `ref` =
  `rule_id`). `share.decide` decides the listed pending items of the rule
  (1–500; items not pending are ignored; none pending is `bad_request`).
- Removing or blocking a connection, or unlinking an agent, deletes its
  rules (§7.4).
- **Change notices.** `sync.event` `share.rule.changed` (`rule_id`,
  `version`), `share.rule.deleted` (`rule_id`) and `share.decided`
  (`rule_id`, `included`, `declined`).
- **Audit.** `share.rule.created`, `share.rule.updated`,
  `share.rule.deleted` (`ref` = `rule_id`); `share.included`,
  `share.declined`, `share.withdrawn` (`ref` = `item_id`, with the
  subject's `connection_id` or `device_id`); every fetch as
  `grant.fetched` (below).

**Grants.** A grant lets one connection read one item. Grants come from
share rules (one per included readable item, carrying `rule_id`), from
one-off requests the member decides, and from shared actions (§10.14).

```
B app            B vault                   A vault                    A app
  |--grant.request-->|--data.request---------->|--grant.pending---------->|
  |                  |                         |<--grant.decide-----------|
  |<--grant.event----|<--data.decided----------|                          |
  |                  |<--data.shared-----------|  (a share rule included an item)
  |--grant.fetch{reply_key}-->|--data.fetch--->|  checks the grant, counts a use
  |<--grant.value{value_sealed}--|<--data.value|                          |
```

```json
grant: { "grant_id": "<ULID>", "connection_id": "<id>", "direction": "given|received",
         "kind": "item", "ref": "<item_id>", "fields": ["f1"], "label": "...", "rule_id": "<ULID>",
         "name": "...", "category": "...", "uses": 3, "used": 1, "expires_at": "<ts>",
         "state": "active|used|expired|revoked", "created_at": "<ts>" }
```

- **Items.** A grant's item is `{kind: "item", ref: <item_id>, fields?}`:
  `fields` (1–64 `field_id`s) restricts it to those fields; without it
  the whole item (with its notes) is granted. Only `data` and `secret`
  items are granted; a `critical` item never is (§10.13).
- **Descriptors.** Grants travel between the vaults as
  `{grant_id, kind, ref, fields?, label?, rule_id?, name, category,
  labels: [{field_id, label, kind}], uses?, expires_at?}`: the item's
  name, category and the labels of the granted fields, never its tags,
  sensitivity or values. `uses` and `expires_at` are absent for a rule
  grant without them.
- **One-off requests.** `grant.request` asks for 1–16 items, each
  `{kind: "item", ref: <item_id>, fields?, label?}` (an item the asker
  knows from the catalog or an earlier grant) or
  `{kind: "category", ref: <category>, label?}` ("your insurance card":
  the member picks the item). `label` (at most 128 bytes) is the asker's
  description.

| Type | Request body | Response / event body |
|---|---|---|
| `grant.request` (app, desktop) | `{connection_id, items: [<item>], uses?, expires_in?, reason?}` | `{request_id}` |
| `data.request` (V↔V) | — | `{request_id, items, uses, expires_in, reason?}` |
| `grant.pending` (V→D, apps and desktops) | — | `{request_id, connection_id, items: [{kind, ref, fields?, label?, available}], uses, expires_in, reason?, exp}` |
| `grant.decide` (app; desktop: step-up) | `{request_id, approve, items?: [<index>], answers?: [{index, item_id, fields?}], uses?, expires_in?}` | `{grants: [{grant_id, kind, ref}]}` |
| `data.decided` (V↔V) | — | `{request_id, approved, grants?: [<descriptor>]}` |
| `data.shared` (V↔V) | — | `{grants: [<descriptor>]}` (1–64) |
| `grant.event` (V→D, apps and desktops) | — | `{connection_id, event: "granted" \| "shared" \| "denied" \| "revoked", request_id?, grant_id?, grants?}` |
| `grant.fetch` (app, desktop) | `{grant_id, reply_key}` | `{fetch_id}` |
| `data.fetch` (V↔V) | — | `{fetch_id, grant_id, reply_key}` |
| `data.value` (V↔V) | — | `{fetch_id, grant_id, value_sealed, uses_left?}` or `{fetch_id, grant_id, error}` |
| `grant.value` (V→D, to the device that fetched) | — | `{connection_id, fetch_id, grant_id, value_sealed?, uses_left?, error?}` |
| `grant.revoke` (app, desktop) | `{grant_id}` (given or received) | `{}` |
| `data.revoked` (V↔V) | — | `{grant_id}` |
| `grant.list` (app, desktop) | `{}` | `{given: [<grant>], received: [<grant>], pending: [{request_id, connection_id, items, uses, expires_in, reason?, exp}], requested: [{request_id, connection_id, items, state}]}` |
| `grant.catalog` (app, desktop) | `{connection_id}` | `{request_id}` |
| `data.catalog.get` (V↔V) | — | `{request_id}` |
| `data.catalog` (V↔V) | — | `{request_id, items: [{item_id, name, category, labels: [{field_id, label, kind}], grant_id?, uses_left?, usable?}], truncated?}` |
| `grant.catalog.result` (V→D, to the device that asked) | — | `{connection_id, request_id, items, truncated?}` |

- **Sizes.** `uses` 1–100 (default 1: one fetch) for one-off grants;
  `expires_in` 60–31,536,000 s (default 604,800, 7 days); `reason` at
  most 256 bytes; `reply_key` a 1,216-byte KEM `ek`.
- **Asking.** The member's vault ignores a `data.request` whose
  `request_id` it already holds from that connection (from another
  connection it is dropped and audited, `drop.grant_duplicate`), keeps
  at most 16 pending requests per connection (more are dropped and
  audited, `drop.grant_limit`) and answers a request undecided after 7
  days as denied. `available` tells the member whether an `item` entry
  resolves now (an existing `data` or `secret` item with those fields);
  a `category` entry is available when the member answers it. A `data.*`
  message that does not parse is dropped and audited
  (`drop.grant_malformed`), never answered.
- **Deciding.** An approval grants each listed entry (`items` holds
  indices into the request's items; default all): an `item` entry if it
  is available; a `category` entry only through an `answer`, which names
  the member's item (and optionally its fields) for that index. The
  request's `uses` and `expires_in` apply unless the decision sets
  others; `bad_request` if nothing is granted. A vault holds at most
  1,000 active given and 1,000 active received grants (`limit`); ended
  grants and decided requests are kept 30 days for `grant.list`, then
  pruned. The asking vault keeps at most 1,000 requests and 64
  outstanding catalog requests (`limit`). A denial, or no decision in 7
  days, answers `data.decided{approved: false}`.
- **Shared by a rule.** When share rules include readable items for a
  connection, its vault sends `data.shared` with their descriptors (one
  message per change, split so that each holds at most 64 descriptors
  and 131,072 bytes). The receiving vault
  records them as received grants and tells its apps and desktops
  `grant.event{event: "shared"}`; it drops a `data.shared` whose grants it
  already holds.
- **Fetching.** The member's vault answers a `data.fetch` only for a
  grant it gave that connection. `error` is `not_found` (unknown, or
  given to another connection), `revoked`, `expired`, `exhausted` (no
  use left) or `unavailable` (the item, or a granted field, no longer
  exists, or the item is now `critical`). Otherwise it counts one use
  and seals the item's current content: the UTF-8 JSON
  `{"item_id", "version", "name", "category", "fields": [{field_id,
  label, kind, value}], "notes"?}`, restricted to the granted fields
  (and without `notes` when `fields` is given), at most 65,536 bytes:

  ```
  (enc, ctx)   = SetupBaseS(reply_key, info = "vettid/vms/2/grant" || 0x00 || grant_id || 0x00 || fetch_id)
  value_sealed = enc || ctx.Seal(aad = "", pt = content)
  ```

  A `data.fetch` repeating a `fetch_id` it answered is answered again
  without counting a use. A grant whose last use is spent is `used`.
  Every refusal is audited (`drop.grant_<error>`). The asking vault
  forwards a `grant.fetch` whatever its own record says: the member's
  vault decides.
- The asking vault keeps a fetch for 10 minutes (at most 64 outstanding,
  `limit`) and forwards `data.value` only to the device that fetched,
  within its access session (§6.8); it never sees the value. The
  `reply_key`'s private half lives only in that device's memory, for
  that fetch.
- **Per-connection catalog.** A connection's catalog is what the member
  made visible to it: one entry per active grant given to it (rule or
  one-off: `grant_id`, the granted fields' labels, `uses_left` when
  counted) and one per critical item its rules include (`usable: true`,
  §10.13). `grant.catalog` asks the connection's vault, which answers
  `data.catalog` with at most 1,000 entries and 131,072 bytes
  (`truncated: true` when it left entries out). Each connection sees only
  its own catalog; tags and rules are never in it.
- **Revoking.** Either side may revoke: the member's vault stops
  answering for the grant, the other side is told `data.revoked`, and
  both tell their owner devices (`grant.event{revoked}` on the asking
  side, `sync.event{grant.changed}` on both). Revoking a grant that has
  already ended succeeds and changes nothing. Revoking a rule grant does
  not change the rule: the item stays included without a grant until it
  is withdrawn and gains the rule again.
- **Removal.** Removing or blocking a connection drops its grants, both
  ways, its pending requests and its fetches, without notice (§7.4).
- **Audit and feed.** `grant.requested` (both sides), `grant.issued`,
  `grant.denied`, `grant.received`, `grant.fetched` (each use, on the
  member's side), `grant.revoked`; an incoming request is a feed item
  (`grant.request`, high), and so are a revocation by the other side
  (`grant.revoked`) and items shared by a connection's rule
  (`grant.shared`).
- 0.7.0 replaced grant items `{kind: "field" | "secret"}` by
  `{kind: "item"}`, the `cataloged` flag and the one catalog for every
  connection by share rules and per-connection catalogs, and added
  `data.shared`.

### 10.13 Critical-item use by a connection

A connection never receives a critical item's values (§3.5, §10.7). It
may ask the member to **use** one, a signing key for example, for one
operation; the member consents in their app with the credential
password, for that use only, and the connection receives only the
result.

```
B app            B vault                   A vault                      A app
  |--critical-secret-use.request-->|--critical-secret.use-->|--critical-secret-use.pending-->|
  |                  |             |                        |<--critical-secret-use.approve---|
  |                  |             |                        |   {credential, utk_id,          |
  |                  |             |                        |    sealed{password, request_id, payload_sha256}}
  |<--critical-secret-use.result---|<--critical-secret.result{status, signature, public_key}--|
```

| Type | Request body | Response / event body |
|---|---|---|
| `critical-secret-use.request` (app, desktop) | `{connection_id, item_id, field_id, operation: "sign" \| "auth", payload, context?}` | `{request_id}` |
| `critical-secret.use` (V↔V) | — | `{request_id, item_id, field_id, operation, payload, context?}` |
| `critical-secret-use.pending` (V→D, apps and desktops) | — | `{request_id, connection_id, item_id, field_id, name, label, operation, payload, payload_sha256, context?, exp}` |
| `critical-secret-use.approve` (app) | `{request_id, credential, utk_id, sealed{password, request_id, payload_sha256}}` | `{request_id, status, credential, version, utks}` |
| `critical-secret-use.deny` (app, desktop) | `{request_id}` | `{}` |
| `critical-secret.result` (V↔V) | — | `{request_id, status: "ok", signature, public_key}` or `{request_id, status: "denied" \| "expired" \| "unavailable" \| "unsuitable"}` |
| `critical-secret-use.result` (V→D, apps and desktops) | — | `{connection_id, request_id, status, signature?, public_key?}` |
| `critical-secret-use.list` (app, desktop) | `{}` | `{incoming: [{request_id, connection_id, item_id, field_id, name, label, operation, payload_sha256, context?, exp}], outgoing: [{request_id, connection_id, item_id, field_id, operation, state, status?}]}` |

- **What can be asked.** Only a critical item that a share rule of that
  connection includes (it is then `usable` in the connection's catalog,
  §10.12), and one of its fields. Any other `item_id` or `field_id` is
  answered `unavailable` at once, without asking the member, and audited
  (`critical-secret.use.requested` and `critical-secret.use.denied`);
  an item the rule does not include is not told apart from a missing
  one. `payload` is 1–4,096 bytes (base64) and `context` at most 256
  bytes; the app MUST show both, the item's name and field label, and
  the connection's name, to the member. A vault keeps at most 8 pending
  requests per connection (more are answered `unavailable`) and answers
  `expired` after 24 h; a repeated `request_id` is ignored.
- **Consent per use.** `critical-secret-use.approve` is one use of the
  credential (§3.5.3), from an app: the UTK-sealed payload carries the
  password, the `request_id` and `payload_sha256` = SHA-256(`payload`).
  The vault refuses (`bad_request`) unless both equal the pending
  request's, so the password authorizes exactly this request and this
  payload, and an attacker in the app's session can neither redirect nor
  replay it (§3.5.4). It answers `utk_invalid`, `backoff`,
  `stale_credential` and `bad_password` as §3.5.3 does, and the request
  stays pending for another attempt.
- **The use.** The vault opens the credential, decrypts the field's value
  with the item key (§10.7), performs the operation, re-keys the item and
  rotates the CEK (§3.5.3, the new blob in the response), and wipes the
  plaintext and the keys. Nothing is retained:
  there are no standing allowances, and the next use needs the password
  again. The value MUST be the standard base64 of a 32-byte Ed25519 seed
  (a `password` or `text` field, for example); otherwise the status is
  `unsuitable` (the credential has still been opened and rotated).
  - `sign`: `signature = Ed25519(seed, payload)`, the payload as is, for
    protocols that need the member's key to sign their own messages.
  - `auth`: `signature = Ed25519(seed, "vettid/vms/2/critical-auth" ||
    requester_ik (32) || owner_ik (32) || request_id (26) || payload)`,
    bound to both vaults' `ik` as each has the other on record, like
    §10.4.

  `public_key` is the seed's Ed25519 public key. If the item or field
  has left the credential, or the item is no longer included for that
  connection, when the member approves, the status is `unavailable`.
  `status` in the approval's response is the result sent to the
  connection; `version` there is the credential's.
- A denial answers `denied`. The asking vault keeps its requests for
  25 h and forwards results to its apps and desktops; later or unknown
  results, and results from another connection, are dropped. It verifies
  an `ok` result first: `signature` under `public_key` over the payload
  (`sign`) or over the `auth` message with both vaults' `ik` as it has
  them on record; one that does not verify is dropped and audited
  (`drop.critical_signature`).
- **Audit and feed.** `critical-secret.use.requested` (both sides),
  `critical-secret.used`, `critical-secret.use.denied`,
  `critical-secret.use.result`; an incoming request is a high-priority
  feed item (`critical-secret.use.request`); `sync.event`
  `critical-secret-use.decided`.
- The type names are kept from 0.6.0; 0.7.0 replaced `secret_id` by
  `item_id` and `field_id`, and `credential.secret.catalog` by share
  rules.

### 10.14 Shared actions

A member lets chosen connections **invoke actions** on their vault: a
fixed catalog of operations built into each release, run by the vault
itself (native code in the vault's process, §12.4, no third-party code),
under a permission mode the member sets per action. A connection learns
which actions it may invoke from the member's offer; an invocation is
answered with the action's result or a refusal.

**The catalog** (catalog version 3). Each action has a fixed `action_id`
and `version`, a parameter and a result schema, and a sensitivity:

| `action_id` (version 1) | Sensitivity | `params` | `result` |
|---|---|---|---|
| `items.share` | sensitive | `{item_id, fields?: [<field_id>]}`; `fields` 1–64 | `{grants: [<grant descriptor>]}` (§10.12) |
| `audit.recent` | normal | `{limit?}`, 1–50, default 20 | `{entries: [{kind, at, direction?}]}` |
| `wallet.request-address` | normal | `{asset: "BTC"}` | `{asset, network, address}` |
| `wallet.request-payment` | critical | `{asset: "BTC", amount_sats, address, memo?}`; `amount_sats` 1–2,100,000,000,000,000, `address` 14–90 alphanumeric characters, `memo` at most 280 bytes | `{status: "signed", txid}` |

- **`items.share` goes through grants (§10.12)**, the same consent and
  delivery as a request the member decided: if the member's
  configuration lists the item (`items`) and it is available (a `data`
  or `secret` item with the requested fields), the action creates, for
  the invoking connection, one grant of it (restricted to `fields` if
  given), with `uses` 1 and an expiry of 10 minutes, and returns its
  descriptor. The connection fetches the values with `grant.fetch`,
  sealed to its fetching device; the invoking vault records the grant as
  received, and either side can revoke it as any grant. Otherwise the
  status is `unavailable`. Critical items are never shared.
- Catalog version 2 (0.7.0) replaced version 1's `profile.fields.read`
  and `secrets.share` by `items.share`: profile fields and vault-held
  secrets are both items now, and the two actions would be the same.
- **`audit.recent`** returns the newest entries of the member's audit log
  (§10.9) whose `connection_id` is the invoking connection, at most
  `limit`: only `kind`, `at` and `direction`, never `ref`, other
  connections' entries or `drop.*` entries.
- **Wallet actions** (§10.18) run on the one wallet the member's
  configuration names (`items` = `[wallet_id]`; without it they are
  `unavailable`):
  - `wallet.request-address` returns a receive address of that wallet's
    receiving account (`address_type`, by default P2TR) for the invoking
    connection, the same one until the member's app
    reports it used (`wallet.address.used`), then a new one; audited as
    `wallet.address_issued`.
  - `wallet.request-payment` asks the member to pay `amount_sats` to
    `address` (the invoking member's choice, usually from their own
    wallet). Its approval is the spend: `action.respond{invocation_id,
    approve: true, psbt, credential, utk_id, sealed{password, item_id,
    request_id, payload_sha256}}` from an app within the unlock window,
    where `item_id` is the wallet, `request_id` the `invocation_id` and
    `payload_sha256` the PSBT's hash. Besides §10.18's signing policy the
    PSBT MUST pay exactly `amount_sats` to `address` (which MUST be of
    the wallet's network) and nothing to anyone but the wallet itself
    (`invalid_psbt` otherwise). An error leaves the invocation pending.
    On success the response holds `txid`, the `summary` and the signed
    `tx` for the app to broadcast, and the connection gets
    `{status: "signed", txid}`: the transaction is signed and handed to
    the member's app, which broadcasts it; the requester watches its
    chain for `txid`.
- Catalog version 3 (0.8.0) makes the wallet actions available and adds
  `address` to `wallet.request-payment` (version 1 was never available,
  so its number is kept).
- `param_schema` and `result_schema` (JSON Schema 2020-12 documents in
  `action.list`) describe the shapes above for apps. The vault checks
  parameters with its own strict parser per action, never with a general
  schema engine; parameters that do not parse are answered
  `unavailable`.

**Permission modes**, per action (`action.configure`); every action
starts in `default-deny`:

| Mode | Offered to | Runs |
|---|---|---|
| `default-deny` | nobody | never: invocations are `unavailable` |
| `allowlist` | the connections in `connections` | at once, without asking |
| `prompt-each-time` | every active connection, or only `connections` if given | after the member approves each invocation (`action.pending`, `action.respond`) |
| `default-allow` | every active connection | at once, without asking |

- A **sensitive** action cannot be `default-allow` (`bad_request`).
- A **critical** action can only be `default-deny` or
  `prompt-each-time`, and is approved only by an **app within the
  credential's unlock window** (§3.5.3; `credential_locked` otherwise):
  the member's phone must be there.
- `items` (1–64 `item_id`s) bounds `items.share`; without it the action
  shares nothing. For a wallet action it names exactly one wallet.

**Offers.** After every configuration change, and when a connection
becomes active, the member's vault sends each affected active connection
`action.offered` with the complete list of actions it may invoke (empty
when none). The receiving vault keeps the latest list per connection
(`action.list{connection_id}`) and tells its owner devices
`sync.event{kind: "action.offers", connection_id}`.

| Type | Request body | Response / event body |
|---|---|---|
| `action.list` (app, desktop) | `{connection_id?}` | without it: `{catalog_version, actions: [{action_id, version, sensitivity, available, param_schema, result_schema, mode, config_version, connections?, items?}]}`; with it, what that connection offers: `{actions: [{action_id, version, prompt}]}` |
| `action.configure` (app; desktop: step-up) | `{action_id, version?, mode, connections?, items?}`; `version` is the configuration version it is based on (`conflict` if stale, §10.1) | `{version}` (the new configuration version) |
| `action.offered` (V↔V) | — | `{actions: [{action_id, version, prompt}]}` (at most 64) |
| `action.invoke` (app, desktop) | `{connection_id, action_id, params}` | `{invocation_id}` |
| `action.invocation` (V↔V) | — | `{invocation_id, action_id, version, params}` |
| `action.pending` (V→D, apps and desktops) | — | `{invocation_id, connection_id, action_id, sensitivity, params, exp}` |
| `action.respond` (app, desktop; critical: app in the unlock window) | `{invocation_id, approve}` | `{status}`: the result sent |
| `action.result` (V↔V) | — | `{invocation_id, status: "ok", result}` or `{invocation_id, status: "denied" \| "expired" \| "unavailable"}` |
| `action.result` (V→D, apps and desktops) | — | `{connection_id, invocation_id, action_id, status, result?}` |

- The member's vault answers `unavailable` for an action that is not in
  its catalog, not offered to that connection, of another `version`,
  whose parameters do not parse, or that cannot run (not told apart);
  and when it already holds 8 pending invocations from that connection,
  or has had 60 invocations from it in the last hour (refused ones
  count, so a connection that keeps invoking stays refused). Malformed
  `action.*` messages from a connection are dropped and audited
  (`drop.action_malformed`). A pending
  invocation is answered `expired` after 24 h, and `unavailable` when a
  configuration change stops offering it to that connection. A repeated
  `invocation_id` is ignored.
- `params` is at most 4 KiB, `result` at most 16 KiB.
- `action.invoke` needs an offer for that `action_id` from the
  connection (`not_found` otherwise); the invoking vault keeps its
  invocations 25 h and forwards results to its apps and desktops; later
  or unknown results are dropped.
- A device's `action.invoke` is a request to its own vault; between the
  vaults the invocation is the event `action.invocation`, so that no type
  is both a request and an event (§10).
- Agents: `action.list` and `action.invoke` are delegable (§10.11).
- Removing or blocking a connection removes it from every
  configuration's `connections` and drops its offers and invocations
  (§7.4).
- **Audit and feed.** `action.configured` (`ref` = `action_id`),
  `action.invoked` (both sides), `action.approved`, `action.denied`,
  `action.completed` (`ref` = `invocation_id`); an invocation waiting
  for the member is a high-priority feed item (`action.request`);
  `sync.event` `action.changed` (`action_id`, `version`),
  `action.decided`, `action.offers`.
- In vettid.dev, invocations and results were published to subjects
  that the receiving vault did not listen on. Here they are types inside
  the connection's session, classified like every message by the session
  that decrypts them (§13.6).

### 10.15 Introductions

A member may **introduce** two of their connections to each other. Only
the member can start one: a connection never sees, lists or asks for the
member's other connections, and there is no request to be introduced.

```
A vault             B vault (introducer)              C vault
  |<--intro.offer{peer: what B shows}--|--intro.offer{peer}------------->|
  |--intro.answer{accept}------------->|<--intro.answer{accept}----------|
  |<--intro.connect{peer_ik}-----------|   (only when both accepted)      |
  |--intro.invite{link}--------------->|--intro.link{link}-------------->|
  |<----------------- hs.init (§6.4, remote invitation) -----------------|
  |   connection.request.pending{introduced_by}; A's member approves (SAS)
```

1. B's app sends `intro.create` naming two active connections, `a` and
   `c`, and what each will be shown of the other (`to_a` is shown to A
   about C, `to_c` to C about A): a `name` and an optional `note`, chosen
   by B and presented as B's words.
2. B's vault sends each an `intro.offer` with only that. Their apps show
   it (`intro.pending`) and their members accept or decline; each answer
   goes back to B only (`intro.answer`).
3. When **both** have accepted, B's vault sends A `intro.connect` with
   C's `ik` as B has it on record. A's vault makes a remote invitation
   (§6.4, TTL 24 h or the relay's maximum if lower) that it accepts only
   from that `ik` (an `hs.init` from another identity is dropped and
   audited, `drop.intro_mismatch`, and the invitation stays usable), and
   returns its link to B (`intro.invite`). B relays it to C
   (`intro.link`), and C's vault accepts it as `connection.invite.accept`
   would. A's member then approves the request as any remote one, with
   the SAS (§6.4); `connection.request.pending` carries
   `introduced_by` (A's connection id of B).
4. If either declines, B cancels, or the introduction has not been
   linked within 7 days, B's vault sends `intro.closed` to each party it
   had offered it to (except one that declined, which has closed its own
   copy), without a reason, and each closes its offer (A also cancels an
   invitation it made and that has not been used). If A cannot make the
   invitation it closes its copy and tells its devices; B's introduction
   then closes at its expiry.
5. **States.** At B: `offered` → `connecting` (both accepted) →
   `linked` (the link relayed) or `closed`. At A and C: `pending` →
   `accepted` → `connecting` or `closed`; a `connecting` offer is no
   longer subject to the 7-day expiry (the invitation's own lifetime
   governs). Ended records are kept 30 days for `intro.list`. Neither A nor C learns anything about the other
   beyond what B chose to show them before they answered: no key, relay
   address, link or answer of the other.

| Type | Request body | Response / event body |
|---|---|---|
| `intro.create` (app; desktop: step-up) | `{a, c, to_a: {name, note?}, to_c: {name, note?}}` | `{intro_id, exp}` |
| `intro.cancel` (app, desktop) | `{intro_id}` | `{}` |
| `intro.list` (app, desktop) | `{}` | `{made: [{intro_id, a, c, state, exp}], received: [{intro_id, connection_id, peer, state, exp}]}` |
| `intro.accept`, `intro.decline` (app; desktop: step-up for accept) | `{intro_id}` | `{}` |
| `intro.offer` (V↔V, B → A, C) | — | `{intro_id, peer: {name, note?}, exp}` |
| `intro.answer` (V↔V, A, C → B) | — | `{intro_id, accept}` |
| `intro.connect` (V↔V, B → A) | — | `{intro_id, peer_ik}` |
| `intro.invite` (V↔V, A → B) | — | `{intro_id, link}` |
| `intro.link` (V↔V, B → C) | — | `{intro_id, link}` |
| `intro.closed` (V↔V, B → A, C) | — | `{intro_id}` |
| `intro.pending` (V→D, apps and desktops of A and C) | — | `{intro_id, connection_id, peer, exp}` |
| `intro.event` (V→D, apps and desktops) | — | `{intro_id, event: "accepted" \| "declined" \| "connecting" \| "closed", connection_id?}`; B's devices get each answer (and `sync.event{intro.changed, state: "linked"}` once the link is relayed); A's and C's only `connecting` and `closed` |

- **Limits.** `a` ≠ `c`, both active connections of B; at most one open
  introduction per pair and 16 open per vault (`limit`); `name` 1–128
  bytes, `note` at most 256. A receiving vault keeps at most 4 open
  offers per introducer and 16 in all (more are dropped and audited,
  `drop.intro_limit`) and ignores a repeated `intro_id`.
- **Authority.** A vault acts on `intro.answer` and `intro.invite` only
  from the party it sent the offer or `intro.connect` to, on
  `intro.connect`, `intro.link` and `intro.closed` only from the
  introducer of an offer it holds and accepted, and drops anything else
  (`drop.intro`). C's vault accepts the link only once and only while it
  holds the accepted offer.
- **What B learns** is each answer and that the link was relayed; the
  connection itself is between A and C.
- Removing or blocking a connection closes the introductions it takes
  part in (an introducer's offers are dropped without notice).
- Agents never introduce or answer introductions.
- **Audit and feed.** `intro.created`, `intro.offered` (on A and C),
  `intro.accepted`, `intro.declined`, `intro.connecting`, `intro.closed`
  (`ref` = `intro_id`); an offer is a high-priority feed item
  (`intro.request`); `sync.event{kind: "intro.changed", intro_id,
  state}`.

### 10.16 Location

A member shares their location with **one connection at a time**, by an
explicit, expiring share: once (a single position) or continuously
(positions at a cadence until an expiry), at a precision the member
chooses. The member's device sends positions to its own vault, which
reduces them to the share's precision and forwards them to the
connection's vault **from memory**: a position is never written to the
sending vault's state or outbox (§8.5). The receiving vault keeps the
latest position (and the trail, if the sharer allowed it) only while the
share is active. Either side can stop a share. A connection can ask the
member to share. Sent by `app` or `desktop` devices (a desktop within its
access session, §6.8), and by connections where marked; never by agents.

```
A app            A vault                          B vault                 B apps
  |--location.share.start-->|--location.shared{share_id,...}-->|--location.event{started}-->|
  |--location.update(lat,lon,...)-->|  reduce to precision; cadence
  |                         |--location.update{share_id,...} (ephemeral)-->|--location.update-->|
  |--location.share.stop--->|--location.stopped{share_id}----->|--location.event{stopped}-->|
```

| Type | Request body | Response / event body |
|---|---|---|
| `location.share.start` (app; desktop: step-up) | `{connection_id, mode: "once" \| "continuous", precision?, duration_seconds?, interval_seconds?, history?, request_id?}` | `{share_id, expires_at}`; `not_found`, `connection_unavailable`, `limit`, `bad_request` |
| `location.update` (D→V, ephemeral) | — | `<sample>`: `{lat, lon, accuracy_m?, altitude_m?, speed_mps?, heading_deg?, at}` |
| `location.update` (V↔V, ephemeral) | — | `{share_id, lat, lon, accuracy_m, altitude_m?, speed_mps?, heading_deg?, at}` |
| `location.update` (V→D, ephemeral) | — | `{connection_id, share_id, lat, lon, accuracy_m, altitude_m?, speed_mps?, heading_deg?, at}`, to apps and desktops |
| `location.share.stop` (app, desktop) | `{share_id}` (an outgoing or an incoming share) | `{}`; `not_found` |
| `location.share.list` (app, desktop) | `{}` | `{outgoing: [{share_id, connection_id, mode, precision, interval_seconds?, history, device_id, started_at, expires_at, last_sent_at?}], incoming: [{share_id, connection_id, mode, precision, interval_seconds?, history, started_at, expires_at, last?}]}` (active shares, sorted by `share_id`) |
| `location.get` (app, desktop) | `{connection_id, history?}` | `{share_id, mode, precision, expires_at, last?, history?}`; `not_found` without an active incoming share from that connection |
| `location.request` (app, desktop) | `{connection_id, note?}` | `{request_id}`; `limit` (one per connection per 10 minutes) |
| `location.shared` (V↔V) | — | `{share_id, mode, precision, interval_seconds? (continuous), history, expires_at}` |
| `location.stopped` (V↔V) | — | `{share_id}` |
| `location.requested` (V↔V) | — | `{request_id, note?}` |
| `location.event` (V→D) | — | `{event: "started" \| "stopped", direction: "in" \| "out", connection_id, share_id, mode?, precision?, expires_at?}` |
| `location.request.pending` (V→D) | — | `{request_id, connection_id, note?, exp}` |

- **Starting.** `mode` `continuous`: `duration_seconds` 300–604,800
  (default 3,600) and `interval_seconds` 10–3,600 (default 60); `once`:
  neither (`bad_request`), and the share lasts 15 minutes, the window in
  which its single position is delivered and shown. `precision` is
  `approximate` (the default, owner decision of 2026-10-03), `exact` or
  `city`. `history` (default
  `false`) lets the receiving vault keep the trail. `request_id` answers
  a `location.request.pending` (it closes it). A vault keeps one outgoing
  share per connection: a new start ends the old one (`location.stopped`
  first) and at most 64 outgoing shares (`limit`). The device that starts
  a share is its **source**: only that device's positions feed it.
- **Positions.** `lat` −90 to 90 and `lon` −180 to 180 (JSON numbers),
  `accuracy_m` 0–1,000,000, `altitude_m` ±100,000, `speed_mps`
  0–10,000, `heading_deg` 0 to less than 360, and `at` (the fix's time)
  no more than 5 minutes ahead and 1 hour behind. A device's
  `location.update` is ephemeral (no response, `exp` required, §8.5);
  invalid ones are dropped (`drop.location_malformed`).
- **Forwarding.** For each active outgoing share whose source is the
  sender, the vault forwards the position as V↔V `location.update`, from
  memory (§8.5), with `exp` = the earlier of the share's expiry and now +
  max(2 × interval, 60 s) (`once`: the share's expiry):
  - `continuous`: at most one position per 0.9 × `interval_seconds`
    (positions in between are dropped); `once`: the first position, after
    which the share ends;
  - reduced to the share's precision first: `exact` rounds `lat`/`lon` to
    5 decimals (about 1 m); `approximate` replaces them by the centre of
    their 0.01° cell (about 1 km), `accuracy_m` at least 1,000, and drops
    `altitude_m`, `speed_mps` and `heading_deg`; `city` uses a 0.1° cell
    (about 11 km) and `accuracy_m` at least 10,000. Cells are fixed, so a
    connection that sees a member cross a cell boundary learns that the
    member was near it; apps SHOULD say so.
- **Receiving.** A vault accepts `location.shared` from a connection (a
  new share replaces an earlier incoming share from it; at most 256
  incoming shares; a repeated or ended `share_id` is ignored; `expires_at`
  in the future and at most 7 days ahead), tells its apps and desktops
  (`location.event{started}`) and creates a feed item. It accepts a
  position only for an active incoming share **from the connection that
  sent it**, with `exp` at most 24 h ahead, at most one per
  max(5 s, interval / 2), and only one for a `once` share (others are
  dropped: `drop.location`, `drop.location_rate`,
  `drop.location_malformed`). It keeps the latest position as `last`
  (with `received_at`) and, if `history`, a trail of at most 1,000, and
  forwards each position to its apps and desktops from memory
  (`exp` now + 60 s).
- **Stopping and expiry.** `location.share.stop` of an outgoing share
  ends it and tells the connection (`location.stopped`); of an incoming
  share it deletes it and asks the sharer to stop (`location.stopped`),
  which ends it there (`location.event{stopped, direction: out}`). At
  `expires_at` both vaults end the share without a message. The receiving
  vault deletes an incoming share **with its positions** when it stops or
  expires; nothing of it is kept.
- **Requests.** `location.request` sends `location.requested`; the
  receiving vault accepts one per connection per 10 minutes and at most
  16 pending (24 h), tells its apps and desktops
  (`location.request.pending`) and creates a feed item. There is no
  decline message: the member answers by starting a share, or not.
- Removing or blocking a connection drops every share and request with
  it (§7.4).
- **Audit and feed.** `location.share.started`, `location.share.stopped`
  (`direction` out or in), `location.share.received`,
  `location.share.ended`, `location.requested` (both sides) (`ref` =
  `share_id` or `request_id`, never a position); feed items
  `location.shared` and `location.request`; `sync.event`
  `location.share.changed{share_id, state: "active" | "ended"}`.
- **Retention is the peer's.** The receiving vault deletes positions as
  above, but the receiving member's devices have seen them, and a vault
  is only trusted for what its own member decides (§2.1): precision,
  cadence and expiry, which the sending vault enforces, are the
  protection.
- Location is not shared through share rules or grants (§10.12): every
  share is its own consent.

**The member's location log** (owner decision of 2026-10-03). The
member may have their vault keep their **own** location history. It is
separate from sharing: the log is never shared by share rules, grants or
actions, and leaves the vault only as a snapshot the member sends through
one of their existing location shares. There is no export or backup of
it outside the service (owner decision).

| Type | Request body | Response / event body |
|---|---|---|
| `location.history.list` (app; desktop: step-up) | `{from?, to?, after?, limit?}` | `{enabled, retention_days, interval_seconds, count, points: [{lat, lon, accuracy_m, at}], next?}`, oldest first |
| `location.history.delete` (app; desktop: step-up) | `{from?, to?}` (neither: everything) | `{deleted}` |
| `location.history.share` (app; desktop: step-up) | `{share_id, from, to}` | `{sent}`; `not_found` (no such active outgoing share), `connection_unavailable` |
| `location.snapshot` (V↔V) | — | `{share_id, points: [{lat, lon, accuracy_m, at}]}` (at most 500) |
| `location.event` (V→D) | — | also `{event: "snapshot", direction: "in", connection_id, share_id, points}` |

- **Settings** (§10.8): `location.history.enabled` (default `false`),
  `location.history.retention_days` (1–365, default 30) and
  `location.history.interval_seconds` (60–3,600, default 300).
- **Recording.** While enabled, the vault records the positions its
  member's devices send (`location.update`, D→V; the app sends them at
  the member's cadence whether or not it is sharing), at most one per
  0.9 × `interval_seconds`, with `lat`/`lon` rounded to 5 decimals and
  `accuracy_m`, without altitude, speed or heading. A recorded position
  is a write to DEK state at the batch's flush; because the device's
  message is ephemeral (§8.5) a crash before that flush loses it.
- **Bounds.** Positions older than the retention are dropped. Older
  positions are thinned: all of the last 24 hours are kept, then at most
  one per 15 minutes up to 7 days, then one per 3 hours. The log holds at
  most 5,000 positions (the oldest go first): a year at the finest
  cadence is about 4,900 positions, about 400 KB of state.
- **Access.** Only the member's apps, and desktops with an app's
  approval of each request (§6.8), list, delete or share the log; agents
  and connections never. `list` filters by `from` and `to` (inclusive)
  and pages by `after` (the `at` of the last position returned, `next`);
  `limit` 1–1,000 (default 500).
- **Deleting.** `location.history.delete` removes the positions in a
  range, or all of them. Turning `location.history.enabled` off deletes
  the whole log at once (apps warn first). Deletions are audited
  (`location.history.deleted`, `ref` = the number deleted) and send
  `sync.event{kind: "location.history.changed", count}`.
- **Snapshots.** `location.history.share` sends the connection of an
  active outgoing share the positions between `from` and `to` (the newest
  500 if more), reduced to that share's precision, as
  `location.snapshot`. The receiving vault accepts it only for an active
  incoming share from that connection, keeps it with the share (as
  `snapshot` in `location.get`) and deletes it with the share; it tells
  its apps and desktops (`location.event{snapshot}`). Audited as
  `location.history.shared` and `location.history.received`
  (`ref` = `share_id`).

### 10.17 Presence

Presence is on demand (§9.2): no heartbeats.

| Type | Request body | Response / event body |
|---|---|---|
| `presence.get` (app, desktop) | `{}` | `{version, state, share, except}` |
| `presence.set` (app; desktop: step-up) | `{version, state?, share?, except?}` | `{version}`; `conflict` |
| `presence.query` (app, desktop) | `{connection_id}` | `{ping_id, exp}`; `not_found`, `connection_unavailable` |
| `presence.ping` (V↔V, ephemeral) | — | `{ping_id}` |
| `presence.pong` (V↔V, ephemeral) | — | `{ping_id, state, last_active?}` |
| `presence.result` (V→D, ephemeral) | — | `{connection_id, ping_id, state, last_active?}`, to the asking device |

- **The policy** is one versioned object (§10.1): `state` is
  `available` (the default), `busy`, `away` or `invisible`; `share` is
  `all` (the default) or `none`; `except` (0–1,024 connection ids,
  deduplicated and sorted) inverts `share` for those connections, so a
  member can turn presence off (or on) per connection. Absent members of
  `presence.set` keep their values. Changes send
  `sync.event{kind: "presence.changed", version}`.
- **Asking.** `presence.query` sends the connection `presence.ping` (from
  memory, `exp` = now + 30 s) and answers `{ping_id, exp}`. A vault pings
  each connection at most once a minute: a query within the minute
  returns the earlier `ping_id` and `exp` (and repeats its result if one
  arrived). If no result arrives before `exp`, the app shows presence as
  unknown.
- **Answering.** A vault answers a ping with `presence.pong` (from
  memory, `exp` = now + 30 s) only if its `state` is not `invisible`, its
  policy shares with that connection, and it has not answered that
  connection in the last minute. Otherwise it **does not answer**: a
  refusal is indistinguishable from a locked or offline vault.
  `last_active` is the newest activity of the member's apps and desktops
  (§10.3), rounded down to 5 minutes; it is absent when none is known.
- The asking vault accepts a pong only for a pending ping it sent to that
  connection, before its `exp`, with `state` `available`, `busy` or
  `away` and `last_active` not in the future, and sends the asking device
  `presence.result` from memory (`exp` = now + 60 s). Anything else is
  dropped without an audit entry. Pings are not audited.
- Removing or blocking a connection removes it from `except` and drops
  its pings (§7.4). Agents never ask or answer.

### 10.18 Wallet

The member's Bitcoin wallets. Each wallet is one BIP39 recovery phrase
with **two accounts**: BIP86 (taproot, P2TR key path, BIP340 Schnorr
signatures) and BIP84 (native segwit v0, P2WPKH). The phrase is a
**critical item** (§10.7): its values are encrypted under an item key
that only the Protean Credential holds, so the vault cannot spend
without the member's password. The vault keeps both account keys (the
public halves) in DEK state and derives receive and change addresses
without the password. New wallets receive on P2TR (owner decision).
**The vault never talks to a chain** (owner decision): the member's app
finds the wallet's coins with its own chain source, builds a PSBT
(BIP174), and the vault checks and signs it; the app broadcasts the
transaction.

```
app (chain source)                                   vault
  |-- wallet.create{address_type?, credential, sealed{password, item?{mnemonic}}} -->|  critical item + both account keys
  |   (an imported phrase: scans both accounts' descriptors, then wallet.update{address_type})
  |-- wallet.address.new ------------------------------------------->|  m/86'/c'/0'/0/i (or m/84'/…)
  |   (finds coins and previous transactions on its chain source)
  |-- wallet.psbt.inspect{psbt} ------------------------------------>|  the vault's summary: shown to the member
  |-- credential.unlock, then wallet.sign{psbt, credential, sealed{password, item_id, payload_sha256}} -->|
  |<-- {txid, tx, summary, credential, ...} -------------------------|
  |   (broadcasts tx)
```

| Type | Request body | Response body |
|---|---|---|
| `wallet.create` (app) | `{name, network?, address_type?, tags?, credential, utk_id, sealed{password, item?}}`; `item` = `{mnemonic, passphrase?}` to import a phrase | `<wallet>` and `{credential, credential_version, utks}`; `limit`, `bad_request` |
| `wallet.list` (app, desktop) | `{}` | `{wallets: [<wallet>]}` |
| `wallet.get` (app, desktop) | `{wallet_id}` | `<wallet>` |
| `wallet.update` (app, desktop) | `{wallet_id, version, address_type}` | `{version}`; `conflict` |
| `wallet.address.new` (app, desktop) | `{wallet_id, type?, change?, label?}` | `<address>`; `limit` |
| `wallet.address.list` (app, desktop) | `{wallet_id, type?, change?, after?, limit?}` | `{addresses: [<address>], next?}` |
| `wallet.address.used` (app, desktop) | `{wallet_id, addresses: [<address string>]}` (1–256) | `{marked, version}` |
| `wallet.psbt.inspect` (app, desktop) | `{wallet_id, psbt}` | `<summary>`; `invalid_psbt` |
| `wallet.sign` (app) | `{wallet_id, psbt, broadcast?, credential, utk_id, sealed{password, item_id, payload_sha256}}` | `<summary>` and `{tx, credential, credential_version, utks}`; `credential_locked`, `invalid_psbt`, `unavailable` (`broadcast` without a chain source) |
| `wallet.history` (app, desktop) | `{wallet_id, limit?}` (1–200, default 50) | `{transactions: [{txid, at, sending_sats, change_sats, fee_sats, payees: [{address, amount_sats}], connection_id?, invocation_id?}]}`, newest first |
| `wallet.balance` (app, desktop) | `{wallet_id}` | `{confirmed_sats, unconfirmed_sats}`; `unavailable` without a vault-side chain source (every release) |

```json
wallet:  { "wallet_id": "<item_id>", "version": 4, "name": "Savings", "network": "mainnet",
           "fingerprint": "73c5da0a", "address_type": "p2tr",
           "accounts": [
             { "type": "p2tr", "path": "m/86'/0'/0'", "xpub": "xpub6…",
               "descriptors": { "receive": "tr([73c5da0a/86'/0'/0']xpub6…/0/*)", "change": "tr([…]xpub6…/1/*)" },
               "next_receive": 3, "next_change": 1 },
             { "type": "p2wpkh", "path": "m/84'/0'/0'", "xpub": "xpub6…",
               "descriptors": { "receive": "wpkh([73c5da0a/84'/0'/0']xpub6…/0/*)", "change": "wpkh([…]/1/*)" },
               "next_receive": 0, "next_change": 0 } ],
           "created_at": "<ts>" }
address: { "address": "bc1p…", "type": "p2tr", "index": 2, "change": false, "path": "m/86'/0'/0'/0/2",
           "label": "…?", "connection_id": "<id>?", "used": false, "issued_at": "<ts>" }
summary: { "txid": "<64 hex>", "inputs": [{"txid", "vout", "amount_sats", "type", "path"}],
           "outputs": [{"address", "amount_sats", "change", "type?", "path?"}],
           "total_in_sats", "sending_sats", "change_sats", "fee_sats", "vsize" }
```

- **Networks.** `network` is `mainnet` (the default), `testnet` (testnet3
  and testnet4), `signet` or `regtest`; coin type 0 on mainnet and 1
  otherwise. A release accepts `mainnet`, `testnet` and `signet`;
  `regtest` only development builds. `xpub` is an account key in BIP32
  serialisation (`xpub`/`tpub` versions, for both accounts);
  `fingerprint` is the master key's.
- **Accounts.** Every wallet holds the BIP86 account m/86'/c'/0' (`type`
  `p2tr`: key-path-only outputs, the output key tweaked with no script
  tree as BIP86 says) and the BIP84 account m/84'/c'/0' (`p2wpkh`).
  `address_type` names the account that receives: new addresses
  (`wallet.address.new` without `type`) and `wallet.request-address`
  (§10.14) come from it. It is `p2tr` by default.
- **Imported phrases.** The vault cannot tell which account of an
  imported phrase has history. The app scans both accounts' descriptors
  on its chain source and sets the receiving account, at
  `wallet.create{address_type}` or afterwards with `wallet.update`
  (versioned, §10.1). Coins of either account can be spent, together, in
  any PSBT, and change can go to either account.
- **Create.** One credential operation (§3.5.3). Without `item` the vault
  generates 256 bits of entropy (a 24-word phrase); with it, it imports
  `mnemonic` (12, 15, 18, 21 or 24 BIP39 English words, any case and
  spacing, checksum verified, stored in canonical form) and `passphrase`
  (printable ASCII, at most 256 bytes: the enclave has no Unicode
  normalisation). The vault creates a critical item (`category`
  `crypto_wallet`, `template` `wallet.btc`, `name`, `tags`) with two
  `password` fields, "Recovery phrase" and "Passphrase", and keeps both
  accounts. `wallet_id` is the item's `item_id`. A vault holds at most
  16 wallets.
- **The phrase is the member's.** The member backs it up with
  `item.reveal` of the wallet's item (values sealed to a reply key,
  §10.7). The wallet owns its item: `item.put` and `item.sensitivity` of
  it are refused with `in_use` (a changed phrase would no longer match
  the accounts); `item.tag` works as for any item; `item.delete` of it
  (a credential operation) or `credential.delete` deletes the wallet
  (`sync.event{wallet.deleted}`). A share rule that matches the item can
  make it at most usable (§10.13), for which a phrase is `unsuitable`.
- **Addresses.** `wallet.address.new` issues the next index of an
  account's receive chain (or its change chain with `change: true`); at
  most 2,000 addresses per wallet, both accounts together.
  `wallet.address.used` records addresses the app saw funded, so that a
  connection's address is replaced (`wallet.request-address`, §10.14).
  `wallet.address.list` lists one account and chain (`type` defaults to
  `address_type`); `next` pages by `index`; `limit` 1–500 (default 100).
- **The signing policy.** The vault signs a PSBT (`psbt`: standard base64
  of BIP174 version 0, at most 65,536 bytes) only if:
  - it has 1–64 inputs and 1–64 outputs, transaction version 1 or 2;
  - every input spends an output of **one of the wallet's accounts**,
    shown by a derivation with the wallet's fingerprint, which the vault
    re-derives and checks with the output script:
    - P2WPKH: a BIP32 derivation m/84'/c'/0'/{0,1}/i with the
      compressed key;
    - P2TR: a taproot BIP32 derivation m/86'/c'/0'/{0,1}/i with the
      x-only internal key and no leaf hashes (and `tap_internal_key`, if
      present, MUST equal it); the vault applies the BIP86 tweak and
      compares the output key. Script-path data (`tap_leaf_script`,
      `tap_merkle_root`, script-spend signatures) is refused;
  - every input carries the **full previous transaction**, whose txid
    MUST equal the outpoint's (and `witness_utxo`, if present, MUST equal
    that output), so the amounts the vault signs for are the real ones (a
    lying source cannot make two signatures over misstated amounts,
    CVE-2020-14199). Taproot signature hashes commit to every input's
    amount and script (BIP341), so the vault computes them only from
    these verified outputs; no duplicate inputs, no finalised or
    partially signed inputs; sighash SIGHASH_ALL, or for P2TR
    SIGHASH_DEFAULT (the absent sighash) or SIGHASH_ALL;
  - every output is a standard address (P2PKH, P2SH, P2WPKH, P2WSH or
    P2TR) of the wallet's network, of at least 330 sats; an output with
    one of the accounts' derivations (BIP32 or taproot, as for inputs),
    re-derived and checked, is **change**;
  - the fee (inputs minus outputs) is positive and at most 1,000 sat/vB of
    the signed transaction's virtual size (its stripped size, plus per
    input a P2WPKH witness of 108 weight units or a P2TR one of 66, 67
    with SIGHASH_ALL).

  Otherwise the answer is `invalid_psbt` with a short reason as
  `message` (`malformed`, `foreign_input`, `previous_tx`,
  `derivation_key`, `internal_key`, `input_script`, `fee_rate`,
  `other_payee`, …). `wallet.psbt.inspect` applies the same checks
  without the credential and returns the summary that `wallet.sign`
  would sign for; apps MUST show it (the payees, amounts, change and fee)
  to the member before asking for the password.
- **Spending is a critical action.** `wallet.sign` is app only, needs the
  credential's unlock window (`credential_locked` otherwise, before the
  UTK is spent) and is one credential operation: the UTK payload's
  `item_id` MUST be the wallet and `payload_sha256` the SHA-256 of the
  PSBT's bytes (`bad_request` otherwise), so the password authorises this
  PSBT of this wallet only. The vault decrypts the phrase with the item
  key, derives the keys of both accounts (checking them against the
  stored account keys), signs every input (ECDSA for P2WPKH; a BIP340
  Schnorr key-path signature with the BIP86-tweaked key for P2TR),
  checks each signature with the script engine, re-keys the item
  (§10.7), rotates the CEK and wipes the phrase, seed and keys. It
  returns the final transaction (`tx`, hex) and its `txid`;
  `broadcast: true` is `unavailable` in every release. Signed
  transactions are kept in the history (the latest 200), their inputs'
  and change outputs' addresses marked used, and the change account's
  `next_change` moves past the change the PSBT used.
- Agents never use wallets: no wallet type is delegable (§10.11).
  Desktops read, issue addresses, choose the receiving account and
  inspect, but never create or sign.
- **Change notices.** `sync.event` `wallet.changed{wallet_id, version}`
  (created, receiving account changed, addresses issued or used),
  `wallet.signed{wallet_id, txid}`, `wallet.deleted{wallet_id}`.
- **Audit and feed.** `wallet.created`, `wallet.deleted`
  (`ref` = `wallet_id`), `wallet.address_issued` (to a connection;
  `ref` = `wallet_id`), `wallet.signed` (`ref` = `txid`, also a feed
  item). No address, amount or key is in the audit log.
- **Chain access (§12.2).** The enclave reaches only the relay, KMS and
  the attestation status list. A vault-side chain source (an allowlisted
  chain API) is not part of this version; the reference implementation
  keeps an interface for it (`wallet.balance`, `broadcast`).
- `crypto_keys` in the credential (§3.5.2) stays reserved and empty:
  wallets are critical items.

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
 |--credential.utk.get, credential.create, vault.enroll.confirm =========> vault (§3.5.7)
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
  "cancel_recovery": true,
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
When the request carries `cancel_recovery` (present only as `true`,
§11.11.4), the string has a thirteenth line, the literal
`cancel_recovery`.

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
  "update": {"to": "<pcr0>", "result": "moved|refused|abandoned", "code": "<reason>"},
  "recovery_cancelled": true, "vault_bundle": "<b64>"}`
  — `update` is present only if the request carried `release_update`, or a
  pending move was completed (§11.10.4). After `moved` the vault is locked
  and sealed to the new release; `header_seq` is the new header's, and
  `token` is absent (the vault did not resume).
  — `recovery_cancelled` is present when the unlock cancelled a recovery
  (§11.11.4); `vault_bundle` only for the app a recovery registered
  (§11.11.5).
- `{"ok": false, "code": "bad_pin|backoff|unknown_device|attestation|state_rollback|vault_missing|manifest|wrong_release|release_key|retry|recovery_pending",
  "header_seq": m, "retry_after": <s>}` — `recovery_pending`: a recovery
  is in progress and the request did not cancel it (§11.11.4); it is
  answered before the PIN is tried and is not a PIN failure.

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
| Vault table | `user_guid`, **`vault_id`** (opaque, 128-bit random, 32 lowercase hex characters, assigned by the API at a member's first enrollment; the routing key for alternate-channel requests), `state` (`enrolling`, `locked`, `unlocked`, `deleted`), **lease** (`instance_id`, `lease_expires_at`), **`sealed_release`** (the PCR0 the vault is sealed to; routing aid, §11.10.5), **`vault_version`** (release that last opened the vault), **`state_version`** (vault-state format version), **`alarm`** (`kind`, `alarm_id`, `at`, `emailed_at`; the last host alarm, below) and `alarm_pending`, `created_at`, `updated_at` | account lifetime |
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
- **Host alarms** (0.9.0). The vault reports a clone alarm (§3.5.9) as
  the lifecycle event `alarm.credential_clone`, once per alarm. It
  carries nothing but its kind, the `vault_id` and the usual release
  fields: no device, version or time from the vault. The parent records
  it on the vault row, **whatever the lease** (an alarm is never lost to a
  lease race): `alarm = {kind: "credential_clone", alarm_id, at}`, where
  the parent makes `alarm_id` (a ULID) and `at` (Unix seconds), and
  `alarm_pending = true`. The member API emails the member and clears
  `alarm_pending` (MEMBER-API). Alarm kinds other than those listed here
  are rejected by the parent. A dishonest host can suppress the email but
  not the vault's own alert to the app, its freeze or its audit entry.
- **Deletion notice** (0.9.0). On the lifecycle event `deleted` (§12.5)
  the parent also records `alarm = {kind: "vault_deleted", alarm_id, at}`
  and `alarm_pending = true`, whatever the lease: the vault's own audit
  log is gone, so the member API emails the member and then deletes the
  vault rows (MEMBER-API), after which the member enrolls afresh.
- **Lifecycle values are advisory.** `vault_version` should match the
  `release` in the attested descriptor of the reporting instance, but a
  dishonest parent could misreport any of these values. They therefore serve
  the account site and operations only, never security decisions.

**The SQS message** goes to the leased instance's queue. Retention is 5 min,
with a DLQ after 3 receives:

```json
{ "v": 1, "op": "enroll|unlock|lock|delete|recovery|recovery_cancel|recovery_register",
  "vault_id": "...", "user_guid": "...", "request_id": "<ULID>",
  "etk_kid": "<16 hex; enroll, unlock and recovery_register only>",
  "envelope": "<b64; enroll, unlock and recovery_register only>",
  "browser_key": "<b64 65-byte P-256 point; recovery only>",
  "enqueued_at": "<RFC 3339>" }
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
  after an abandonment (§11.10.4); `alarm.credential_clone` (above).

`lock` and `delete` carry no envelope. Locking is harmless, and deletion
through the API is an operator power the host has anyway (§13.5). The
recovery operations are in §11.11; `recovery_register` carries a
12,288-byte padded request like enroll and unlock, and the response to
`recovery` is the sealed code (5,252 bytes, §11.11.2). None of them takes
the lease: the vault is not left open.

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
that is attested once, when the app enrolls (§11.3), is transferred to
(§6.7.1) or registers for a recovery (§11.11.3), and then signs the
challenge at every unlock.

- **Android (hardware key attestation).**
  - At enrollment or pairing, the app generates a non-exportable EC P-256
    signing key in Android Keystore with `setAttestationChallenge(challenge)`,
    in StrongBox if the device has it and in the TEE otherwise, and sends the
    key's certificate chain.
  - The enclave verifies the chain up to a Google hardware attestation root
    pinned in the image, then checks the attestation extension: the
    challenge; attestation and key security level `TrustedEnvironment` or
    `StrongBox` (never `Software`); `RootOfTrust` with `deviceLocked` true and
    `verifiedBootState` `Verified`, or `SelfSigned` with an allowlisted
    `verifiedBootKey` (GrapheneOS, below); the `attestationApplicationId` package
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
- **GrapheneOS** (owner decision, 2026-10-03; 0.9.0). GrapheneOS runs
  with the device's bootloader locked to its own signing key, so the
  attestation reports `verifiedBootState` `SelfSigned`. The enclave
  accepts `SelfSigned` **only** when `verifiedBootKey` (32 bytes) equals
  one of the GrapheneOS verified boot key fingerprints pinned in the
  release (vettid-vault `vms/pins`); `deviceLocked` true is still
  required, and every other check is unchanged. `Verified` is accepted as
  before; `Unverified` and `Failed` are refused, and so is `SelfSigned`
  with any other key (another custom OS, or a self-built one).
  - Source: the GrapheneOS Attestation Compatibility Guide,
    <https://grapheneos.org/articles/attestation-compatibility-guide>, which
    tells apps to "enforce that `verifiedBootState` is either `Verified`
    or `SelfSigned`" and, for `SelfSigned`, to "check that
    `verifiedBootKey` matches one of the official GrapheneOS verified boot
    keys".
  - The allowlist is part of the release: adding a device family or
    changing a key is a release update (§11.10). Fingerprints as of
    2026-10-03 (SHA-256, lowercase hex):

    | Device | `verifiedBootKey` |
    |---|---|
    | Pixel 10a | `d8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80` |
    | Pixel 10 Pro Fold | `55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3` |
    | Pixel 10 Pro XL | `141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74` |
    | Pixel 10 Pro | `4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093` |
    | Pixel 10 | `3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7` |
    | Pixel 9a | `0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b` |
    | Pixel 9 Pro Fold | `af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c` |
    | Pixel 9 Pro XL | `55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023` |
    | Pixel 9 Pro | `f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86` |
    | Pixel 9 | `9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de` |
    | Pixel 8a | `096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e` |
    | Pixel 8 Pro | `896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c` |
    | Pixel 8 | `cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233` |
    | Pixel Fold | `ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842` |
    | Pixel Tablet | `94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230` |
    | Pixel 7a | `508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4` |
    | Pixel 7 Pro | `bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f` |
    | Pixel 7 | `3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1` |
    | Pixel 6a | `08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031` |
    | Pixel 6 Pro | `439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c` |
    | Pixel 6 | `f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8` |

  - OWNER DECISION (recommended: GrapheneOS only). Other hardened OSes
    (for example CalyxOS) would each be an allowlist entry in a release;
    none is added until requested.
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

### 11.11 Recovery

Recovery lets a member who has lost **their app** (the vault's one app,
§6.7) get back into their vault. A member who still holds the old phone
uses a direct transfer instead (§6.7.1). They need:

- their account (member session and email);
- 24 hours during which nobody cancels;
- a new attested app;
- their PIN;
- their Protean Credential password, when the vault keeps the latest
  blob (`credential.backup` on). With the backup off the credential is
  lost, and the recovery can only reset it or delete the vault
  (§11.11.5).

The new app **replaces** the old one: the old app is removed and its keys
revoked, and the credential copy it held is dead. Desktops and agents are
kept (owner decision, 2026-10-03).

There is one flow and no bypass:

```
Portal      Member API                   Enclave (vault process)        Owner devices
 |--POST /api/vault/recovery{browser_key}-->|                                |
 |          |--queue: recovery----------------->| lock running vault -------->| vault.locking{recovery}
 |          |   email: requested + cancel link  | mint code; header record   |
 |          |<--slot: code sealed to browser key-|                            |
 |          (24 h; cancel from portal, email link or an owner app's unlock)  |
 |--GET /api/vault/recovery (after available_at)--> sealed code              |
 | decrypt in the browser; show the QR (rendered locally)                    |
New app --scan QR--> POST /api/vault/recovery/register --queue--> code + device attestation:
         |                                       unlock key added (header)   |
New app --POST /api/vault/unlock (PIN; enclave backoff)--> vault opens; vault_bundle
New app --hs.init (purpose app, ctx = recovery_id) --> device record, restricted
New app --credential.recover{password} (credential backoff)--> credential handed over;
         the app becomes the vault's app (holder); the old app is removed
         (backup off: credential_lost --> credential.reset, or vault.delete)
```

While the vault is locked it has no DEK (§12.1). The recovery record
therefore lives in the **sealed header**, which a vault process can open
without the PIN (§3.3). It holds:

- `recovery_id`;
- the state: `pending` or `registered`;
- `requested_at`, `not_before` and `expires`;
- the code's hash and the count of wrong codes;
- the registered app's `ik`, `kem`, relay key, name and attestation
  binding.

The header also keeps a log of the steps taken while the vault was locked
(at most 64). The vault moves that log into the audit log (§10.9) at the
next unlock.

#### 11.11.1 Request

`POST /api/vault/recovery` (§11.11.7) enqueues the operation `recovery`,
carrying the browser's public key. It goes to the instance holding the
vault's live lease, or else to a live instance of the vault's
`sealed_release`. The queue message's `request_id` is the `recovery_id`.

The enclave:

1. **locks the vault if it is running.** It finishes the batch, flushes,
   and sends `vault.locking{reason: "recovery"}` to the owner's devices.
   That notice is the only one owner devices can get from the vault:
   once it is locked, the vault does not touch the relay;
2. in the vault's process, refuses the recovery if the sealed header has no
   credential (`has_credential` false, §3.5.7): a vault without a
   credential cannot be recovered;
3. otherwise mints the code and writes the recovery record into the sealed
   header (`header_seq` + 1);
4. returns the code, or the refusal, sealed to the browser key (§11.11.2)
   as the response slot's envelope.

If a recovery is already recorded, a new request replaces it and voids
the older code. The API allows only one active recovery per vault.

#### 11.11.2 The code

- **Form.** The code is 20 random bytes (160 bits), written as 32
  Crockford base32 characters (`0-9A-HJKMNP-TV-Z`, upper case, no
  padding). It is single-use and bound to `vault_id` and `recovery_id`.
- **Hash.** The header keeps only

  ```
  SHA-256("vettid/vms/2/recovery-code" || 0x00 || vault_id || 0x00 || recovery_id || 0x00 || code)
  ```

  The code itself is never stored or logged, by the enclave or the API.
- **When it is valid.** The code is valid from `not_before` = request + 24 h
  until `expires` = `not_before` + 24 h. The enclave enforces these times
  with its own clock, independently of the API.
- **Wrong codes.** After 5 wrong codes the recovery is void and its record
  is removed.
- **Sealed to the browser.** The portal makes a P-256 key pair in the
  browser (WebCrypto, non-extractable, kept in IndexedDB) and sends the
  public key with the request. The enclave seals the code to it:

  ```
  out = 0x01 || eph (65) || nonce (12) || AES-256-GCM(k, nonce, aad = out[0:78], pt)
  k   = HKDF-SHA-256(ikm = ECDH(eph, browser_key), salt = eph || browser_key,
                     info = "vettid/vms/2/recovery-code-seal" || 0x00 || vault_id || 0x00 || recovery_id, L = 32)
  pt  = {"v":1,"vault_id","recovery_id","code","not_before","expires_at"} || 0x00 padding
      | {"v":1,"vault_id","recovery_id","error":"no_credential"} || 0x00 padding
  ```

  The second form tells the portal that the vault has no credential and
  cannot be recovered (§11.11.1); nothing is recorded.

  `out` is exactly 5,252 bytes, the size of every result in a response
  slot. If the enclave cannot answer (an unknown vault, another member's
  vault, a store failure), the slot holds random bytes of that size and the
  portal cannot decrypt them. The member then requests again.
- **QR.** After `not_before`, the API releases the sealed code to the
  portal. The portal decrypts it and shows the code as a QR rendered in the
  page; no third-party QR service is used. The QR payload is the compact
  JSON

  ```json
  {"v":1,"t":"r","vault_id":"<id>","recovery_id":"<ULID>","code":"<32 chars>"}
  ```

  The portal also shows the code as text, in groups of four, for typing.
- **Why the vault mints the code.** VettID's servers never hold the code
  in a usable form: the API stores only the ciphertext sealed to the
  member's browser. The 24 h delay and the expiry are enforced inside the
  enclave. So a copy of the API's tables, or an operator reading them,
  cannot register a device, and neither can an API that releases the
  ciphertext early.
- **Residual: the portal's code.** A VettID that serves malicious portal
  code to the member's browser can read the code; the browser key protects
  data at rest, not against the page's own author. Such an attacker still
  needs the PIN and the password, guessed online under the enclave's
  backoffs. The same holds for an attacker who controls the member's email
  and account session for 24 h without being noticed.
- **PQC exception.** The browser seal uses P-256 ECDH, the only key
  agreement in WebCrypto. A recorded ciphertext is worthless to a future
  quantum attacker, because the code expires within 48 h and is
  single-use. This is the one place where §1.1 item 7 does not apply.

#### 11.11.3 Register

The new app scans the QR and sends `vault.recovery.register` over the
alternate channel. Like `vault.unlock`, the request is sealed to the ETK
of the instance named by `GET /api/vault/enclave` and padded to 12,288
bytes:

```json
{ "user_guid": "...", "vault_id": "...", "request_id": "<ULID>",
  "recovery_id": "<ULID>", "code": "<32 chars>",
  "app": { "ik": "<b64>", "kem": "<b64 ek>",
           "relay": {"url": "<base>", "mailbox": "<id>", "pk": "<b64>"},
           "name": "<device name>", "device_attest": { } } }
```

The enclave applies the binding and replay rules of §11.3 and §11.6. It
then checks, in this order:

1. the recovery exists and `recovery_id` matches;
2. the recovery is still `pending`;
3. the code has not expired;
4. `not_before` has passed;
5. the code matches the hash, compared in constant time;
6. the device attestation is valid (§11.7), over the challenge with this
   request's `request_id`, the `vault_id` and the inner `ts`. It is checked
   only after the code matched, so a failure leaves the code usable.

On success it adds the app to the header's unlock keys and sets the state
to `registered`; the code is spent.

The answer is `vault.recovery.result`, sealed to `app.kem` and padded like
unlock results:

- `{"ok": true}`, or
- `{"ok": false, "code": "no_recovery|used|expired|too_early|bad_code|attestation|bad_request|retry"}`.

A request the enclave cannot read or bind is answered with random bytes.

#### 11.11.4 Cancel

A recovery is cancelled by any of:

- the portal or the email link: `POST /api/vault/recovery/cancel` and
  `/cancel-link`, which enqueue `recovery_cancel`;
- an owner app's `vault.unlock` with `cancel_recovery: true`. It cancels
  only if the unlock succeeds (PIN, device assertion), and the result says
  `recovery_cancelled: true`;
- expiry, or the fifth wrong code.

Cancelling removes the record and any registered unlock key. A recovered
app that was already paired but has not finished `credential.recover` is
unlinked at the next unlock (§7.4).

While a recovery is in progress, an unlock by any app other than the
registered one is refused with `recovery_pending`, without trying the
PIN. That keeps a thief who holds a lost phone and its PIN out of the
vault for the 24 h, unless they cancel. Cancelling is always allowed,
because it only reduces exposure. Owner apps learn of the recovery from
`vault.locking{reason}`, from `recovery` in `GET /api/vault/status`
(§11.11.7), or from `recovery_pending`, and can cancel from there.

#### 11.11.5 Unlock, password and handover

1. **PIN.** The registered app unlocks with `vault.unlock` and the PIN,
   under the normal enclave backoff (§11.8).
   - The app does not know the vault's relay key yet, so its `token` is an
     open token for its own mailbox. The vault ignores the token of a
     device it has no record of.
   - The result carries `token` (a standing token for the vault's mailbox)
     and `vault_bundle` (`{v, suite, ik, kem, relay}`, as in
     `vault.enrolled`). The bundle is authenticated by being sealed to
     `app.kem`, which only the attested enclave received, inside the
     register request.
2. **Handshake.** The app sends `hs.init` with purpose `app` and `ctx` =
   `recovery_id`. It is accepted without approval, exactly as the first
   app's handshake (§11.3), because its keys were bound at registration.
   The resulting device record is **recovering**:
   - it may send only `credential.utk.get`, `credential.recover`,
     `credential.reset`, `vault.delete`, `vault.status` and the token and
     address types (anything else is `forbidden`);
   - it receives no fan-out;
   - it is not announced to the other devices.
3. **Password.** The app first gets UTKs with `credential.utk.get`, which a
   recovering app may send. It then sends `credential.recover{utk_id,
   sealed{password}}`.
   - The vault opens its own copy of the latest blob (§3.5.6) with the
     current CEK and the password, under the credential's password
     backoff (§3.5.3). 0.9.0 removed the member-supplied blob: there is
     no off-device copy to supply (§3.5.6).
   - As with every use, the vault then rotates the CEK, re-keys every
     critical item (§10.7) and returns the new blob (`{credential,
     version, utks}`). The copy on the lost phone becomes undecryptable.
   - **The new app replaces the old one,** in the same flush:
     - the device becomes the vault's app and the credential's holder
       (§3.5.9), and the recovery record is removed;
     - every other device of role `app` is removed as by `device.unlink`
       (§7.4): `device.unlinked{reason: "replaced"}` best effort, its
       relay key denylisted, its unlock key and UTK pool removed, audit
       `device.replaced` and a feed item, `sync.event{kind:
       "device.unlinked"}`;
     - **desktops and agents are kept**, with their access sessions and
       LEASH grants;
     - the other devices receive `sync.event{kind: "device.paired"}`.
   - A clone alarm that is open (§3.5.9) moves to `rotation_required`:
     the recovered app must rotate before using the credential.
4. **Backup off: no recovery of the credential, only of access.** When
   the vault keeps no copy of the latest blob (`credential.backup` off,
   §3.5.6), there is nothing to recover and nothing may be recovered
   (owner decision, 2026-10-03: otherwise a bad actor could retrieve
   secrets). The recovery restores **access to the vault only**, so that
   the member can reset the credential or delete the vault:
   `credential.recover` answers `credential_lost` without opening
   anything, and the device stays restricted. No message on this path
   returns any credential content or critical item: a recovering app
   cannot send `credential.get`, `credential.version` or any item type
   (`forbidden`), `credential.reset` destroys the critical items before
   it creates the new credential, and `vault.delete` returns `{}`. The
   member lost the credential and every critical item with the phone. The
   app explains this and offers (owner decision, 2026-10-03):
   - **a new credential**: `credential.reset{utk_id, sealed{password}}`
     with a new password. The vault destroys the old credential and every
     critical item (as `credential.delete`, §3.5.5), creates a new
     credential (version 1, a new credential key, no rotation statement),
     and completes the recovery exactly as in step 3: the app becomes the
     holder and replaces the old app. It answers `{credential, version,
     key, utks}`, audits `credential.reset` and creates a feed item.
     `credential.reset` is refused with `exists` when the vault does keep
     the latest blob: the member must then use `credential.recover` with
     the password.
   - **deleting the vault**: `vault.delete` (§10.2, §12.5) with the PIN
     alone: the password cannot be checked, the credential being lost, and
     the account, the email and the 24 h wait already stood in front of
     the PIN. With the backup on, a recovering app's `vault.delete` needs
     the password too, checked against the vault's copy.
   - With the backup off a recovery therefore rests on the account (email
     and session), the 24 h wait and the PIN, not on the password. It
     exposes no critical item: they are destroyed. That is the price of
     keeping no copy outside the phone.
5. **No credential, no recovery.** A vault without a credential is refused
   at the request (§11.11.1). `credential.recover` on such a vault answers
   `credential_required` and the device stays restricted. There is no
   completion on the PIN alone, except the reset of step 4.

#### 11.11.6 Limits and audit

- **Enclave limits:**
  - 5 wrong codes per recovery;
  - the PIN backoff (§11.8);
  - the credential password backoff (§3.5.3);
  - one recovery per vault (a new request replaces the old).
- **Member API limits** (§11.11.7): requests, registrations, cancels and
  status polls are rate-limited.
- **Audit in the vault.** Every step is recorded (`recovery.*` kinds,
  §10.9). Steps taken while the vault was locked are written from the
  header's log at the next unlock.
- **Audit in the API.** The API audits the request, every cancel, the
  release of the sealed code and every register request. It never
  records the code, the browser key or envelopes.

#### 11.11.7 Member API routes

All routes follow MEMBER-API conventions. Each of the following requires
a member session and the current terms:

| Route | Body | Answer |
|---|---|---|
| `POST /api/vault/recovery` | `{browser_key}` (b64 of 65 bytes) | `202 {recovery_id, available_at, expires_at}` |
| `GET /api/vault/recovery` | — | `{recovery: {recovery_id, state, requested_at, available_at, expires_at, sealed_code?} \| null}` |
| `POST /api/vault/recovery/cancel` | `{recovery_id}` | `200 {}` |
| `POST /api/vault/recovery/register` | `{vault_id, request_id, instance_id, etk_kid, envelope}` | `202 {vault_id, request_id}`; the result is polled like unlock (`GET /api/vault/requests/{id}`) |

The email link uses its own route, `POST /api/vault/recovery/cancel-link`
with body `{token}`. It needs no session: the token stands in for it.

- **State.** `state` is `pending`, `available` (from `available_at`, when
  `sealed_code` is returned), `cancelled` or `expired`. `sealed_code` is
  the slot's 5,252 bytes; the API returns it only between `available_at`
  and `expires_at`.
- **Request.** The API accepts a request only for a vault in a state other
  than `enrolling`, and only when no recovery is `pending` or `available`
  (`409 recovery_active`). It records the recovery on the vault row and
  sends the member an email with a single-use cancel link (a random
  256-bit token; the API stores its SHA-256).
- **Register.** The API forwards a register only while the recovery is
  `available` (`409 recovery_not_available` otherwise). The enclave
  re-checks everything; the API's gate only saves work.
- **Cancel.** A cancel marks the recovery `cancelled`, enqueues
  `recovery_cancel` and emails the member.
- **Status.** `GET /api/vault/status` adds `recovery: {state,
  available_at} | null`, so that owner apps can show the recovery and
  offer to cancel it.

#### 11.11.8 Decisions

- **The recovered app replaces the old app; desktops and agents are
  kept** (owner decision, 2026-10-03, replacing 0.4.1's "old owner devices
  are kept"). The old app is removed at `credential.recover` (or
  `credential.reset`), its unlock key and device keys revoked, and the
  credential copy it held is under a destroyed CEK. A stolen phone:
  - cannot use the vault during the 24 h (`recovery_pending`), though it
    can cancel the recovery;
  - after the recovery, is no longer a device of the vault.
- **No recovery without the credential** (owner decision, 2026-10-03).
  - With the backup on, a recovery always ends with the member's
    credential password against the vault's copy of the latest blob.
  - With the backup off, no copy exists and **no recovery of the
    credential is possible** (owner decision, 2026-10-03: a recovery that
    could return secrets could hand them to a bad actor). The recovery
    restores access to the vault only, so that the member can reset the
    credential (destroying the critical items) or delete the vault
    (§11.11.5 step 4, §12.5). A vault never runs without a credential
    (§3.5.7).
  - A vault without a credential is not recoverable. It cannot exist past
    enrollment anyway (§3.5.7).

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
- **No chain access.** The wallet (§10.18) adds no egress: the member's
  app is the chain source (owner decision, 0.8.0).
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

### 12.5 Vault deletion

A vault is deleted on one of three authorities:

| Authority | Request | What it needs |
|---|---|---|
| The holder (§3.5.9) | `vault.delete` (§10.2) | the phrase `delete my vault`, the PIN and the credential password over the current blob, both UTK-sealed; both backoffs apply; refused (`credential_frozen`, `rotation_required`) while a clone alarm is open |
| A recovering app (§11.11.5) | `vault.delete` | the phrase and the PIN; and the password against the vault's copy when it keeps one (backup on). With the backup off, the PIN only (OWNER DECISION, §15). Allowed during an alarm: the recovery path |
| The enrolling app of a vault without a credential (§3.5.7) | `vault.delete` | the phrase and the PIN |
| The host | the queue operation `delete` (§11.5): account cancellation (MEMBER-API) | the member API's own checks |

A running vault deletes itself with the full semantics below; the host's
`delete` asks a running vault to do so (as a lock with the reason
`delete`) and otherwise erases the stored objects itself. Desktops and
agents cannot delete a vault.

**Order.** The steps run in this order, so that a crash at any point
converges to "deleted", never to a vault that runs again:

1. **Mark**, in the request's flush: state and sealed header record
   `deleting`. In the same flush the credential (CEK, credential state,
   UTK pools) and the features' secrets are destroyed; every active
   connection is sent `connection.removed`, every owner device
   `device.unlinked{reason: "vault_deleted"}`; every token the vault
   issued is revoked at the relay by `jti` and every peer's relay key by
   `sub` (§7.4); open invitation claims are deleted; a transfer ends. The
   requester's `{}` follows. Nothing else in the batch is handled.
2. **Relay mailbox, then drain** (0.9.1): the vault deletes its own relay
   mailbox (RELAY-PROTOCOL 0.5.0 §6.10, `DELETE /v1/mailbox` signed with
   the vault relay key), once. With it go every message waiting there,
   the denylist, blobs and the vault's claims, and from then on every
   deposit is refused (`mailbox_unknown`), so the revocations and claim
   deletions queued in step 1 are moot and are dropped from the outbox.
   If the request fails (a relay before 0.5.0 answers `not_found`, or
   the relay is unreachable after the client's retries), they stay
   queued as the fallback. Then the outbox is delivered once, best effort:
   the notices go to the connections' and devices' own mailboxes.
3. **Zeroize**: every key and the DEK are wiped; the vault is locked and
   its process exits (§12.4).
4. **Erase**, through the parent's store with conditional deletes, a
   missing object counting as deleted: the state object; the headers of
   every release the vault knew (a pending move's target and source),
   its own release's header last, since that header is the deletion
   marker; and the enclave's member index object if it still names this
   vault (§11.5).
5. **Report** the lifecycle event `deleted` (§11.5). The parent marks the
   row `deleted` and records the `vault_deleted` notice; the member API
   emails the member and deletes the vault rows (MEMBER-API).

**Convergence.** A header that records `deleting` is never opened again:
an unlock, a recovery request, registration or cancellation that reads
it finishes step 4 instead (and answers as for a missing vault). A crash
after step 1 therefore loses at most the best-effort notices, the relay
mailbox deletion and the revocations, never the deletion of the vault.
Deletion is idempotent.

**The relay mailbox.** The relay key exists only in the running vault
(§1.1 decision 3), so only step 2 can delete the mailbox; the relay's
delete is idempotent, so a repeat is harmless. Order: the mailbox goes
after the marking flush (a vault that is not yet marked can still run
again and must keep its mailbox) and before zeroize (which destroys the
key). Deleting it before the drain makes the queued revocations
unnecessary: a deposit into a mailbox that no longer exists is refused
whatever token it carries. The key is never registered again (step 3
destroys it), and the relay keeps a tombstone that would refuse every
token minted before the deletion even if it were (RELAY-PROTOCOL §6.10).
The mailbox stays registered only where step 2 could not delete it: a
crash between steps 1 and 2, a relay before 0.5.0 or one unreachable at
that moment (then the revocations apply, as in 0.9.0), and a vault the
host erases while it is locked (no key; its tokens expire on their own).
There, messages already deposited expire after `message_ttl_seconds` (14
days) and the registration stays, empty, with a key nobody holds.

**What is left.** Nothing of the vault's contents: state, headers and
index are erased, and the DEK, CEK and keys existed only in the
enclave's memory. The member API keeps its own audit records
(MEMBER-API).

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
| Reconnect token | Nothing without the holder's relay key (sender-bound), and even then only a 4-message quota of `hs.init`s that must be signed by the stored `ik` | Denylist its `jti` (removal does, §7.4) |
| Session epoch key | Read and forge messages in that epoch and direction. Vault-to-vault epochs last at most 24 h. | Next rekey |
| Vault `ik` or `kem` | Impersonate the vault in new handshakes and read new `hs.init`s | Credential rotation, `identity.rotate`, rekey |
| ETK | PINs in requests sealed to it (≤ 25 h). Requires breaking the enclave. | Enclave restart |
| Owner app (the vault's one app) | Whatever its role allows, including unlock attempts if the PIN is known; with the PIN and the password, a transfer to another phone (§6.7.1) | Recovery (§11.11), which replaces it |
| Desktop | Within an access session, what desktops may send; step-up types (secret items' values, item and tag changes, profile, settings, share rules and decisions, invitations, removals, grant decisions, action configurations, introductions, location shares, the location log, the presence policy) only with an app's approval; never critical items or wallet spends; nothing after the session ends (§6.8) | `device.session.end`; unlink |
| Agent | Within its access session, only what its LEASH grants cover: through `ask` grants nothing without an app's approval of each request (at most 20 referrals an hour), through `auto` grants up to their rate limits; LEASH operations only on the `data` and `secret` items its share rules include, never critical ones; never app-only types, invitations, credential, device or grant management. Refused requests are throttled and repeated ones suspend it; its activity is summarised in the audit log, so it cannot push older entries out (§10.11) | `leash.grant.revoke`, `device.session.end`, `device.unlink`; suspension is automatic |
| A LEASH delegation (every grant) | A claim, to relying parties that trust the member's credential key, that the agent holds that scope, until the grant's `expires_at` if any; the vault never relies on it. A relying party that requires a status statement accepts a revoked delegation for at most its `status_ttl` (≤ 1 h, default 15 min) plus skew; one that does not can be shown it until `exp` (§10.11) | `leash.grant.revoke` (no new statements); a shorter `status_ttl` |
| The vault's `ik` as status issuer | Signing statements that keep a revoked or suspended agent's delegations "valid" for relying parties; it grants nothing in the vault itself. An approved release does only what §10.11 says (§2.1) | Rotate the `ik` (§3.4): the chain moves the issuer; revoke the grants |
| A status statement | Nothing beyond its `not_after`: it names one delegation by hash and is useless without it and the agent's key | — |
| Issuing grants | Only with the member present: an app within the credential's unlock window, since the credential key signs each grant (§10.11) | — |
| A connection holding a grant | The granted item's current values (the granted fields), at most `uses` times, until expiry or revocation; no other item or field. Values are sealed to the fetching device, so the connection's vault never holds them (§10.12) | `grant.revoke`; removing or blocking the connection |
| A connection named in a share rule | The `data` and `secret` items the rule includes: in `ask` mode only those the member approved, in `auto` mode every item that gains a matching tag; at most usable, never readable, critical items. Its own catalog only; never the member's tags, rules or other connections' catalogs. Removing the tag, deleting the rule or its expiry ends future fetches at once (§10.12) | `item.tag`, `share.rule.delete`, `grant.revoke`; removing the connection |
| A tag change | In `auto` rules, sharing the re-tagged item without a prompt: apps preview the effect (`dry_run`), and desktops need an app's approval for tag changes (§6.8, §10.8) | Remove the tag (the grant is revoked at once) |
| A connection asking to use a critical item | Nothing without the member's password for each use, bound to that request and payload; then one signature (`sign` over the payload as shown to the member, or the domain-separated `auth`), never the key (§10.13) | Deny; remove the tag or the rule that makes it usable |
| A connection offered actions | Only the built-in actions offered to it, under their modes: one-use, 10-minute grants of the items the member configured (values sealed to its device), its own entries of the audit log; nothing at all of a critical action without the member's app in the unlock window; at most 60 invocations an hour and 8 pending (§10.14) | `action.configure` (mode `default-deny`), `grant.revoke`, removing the connection |
| A member's vault code for actions | Actions run natively in the vault's process (§12.4) from a catalog fixed in the release; no third-party or downloaded code (§10.14) | A release update (§11.10) |
| A connection, about the member's other connections | Nothing: no type lists them to a connection or lets it ask for an introduction; it learns of another connection only when the member introduces them, only what the member chose to show, and connects only if both accept and then approve each other with the SAS (§10.15) | Decline; `block.add` |
| The introducer | Each party's answer; it relays the invitation, so it could substitute a party it is connected to, but the parties still approve each other with the SAS, and the invitation accepts only the `ik` B named (§10.15) | Compare the SAS out of band; decline |
| A connection the member shares location with | Positions at the share's precision (`exact` about 1 m; `approximate` a 0.01° cell; `city` a 0.1° cell), at most one per 0.9 × the interval, until the share's expiry (at most 7 days) or stop; a trail only if the member allowed it; whatever its own member saw. Cells are fixed: crossing a boundary reveals being near it (§10.16) | `location.share.stop`; removing the connection |
| The sending vault's state | No position: positions are forwarded from memory, never stored or queued (§8.5, §10.16) | — |
| A connection asking for location or presence | One location request per 10 minutes (a feed item); one presence answer per minute, only if the policy shares with it; a refusal is silence, like a locked vault (§9.2, §10.17) | `presence.set{except}`, `share: none`, `invisible`; `block.add` |
| Presence | Whether the member's vault is unlocked, the member's chosen `state` and `last_active` to 5 minutes, to connections the policy allows, on demand only (§10.17) | `presence.set` |
| An app's session (wallet) | Inspection, addresses and history; no spend: spending needs the password (UTK-sealed, bound to the wallet and the PSBT's hash) and the unlock window (§10.18) | Unlink the device; change the password |
| The member's chain source (the app's) | It learns the wallet's addresses and spends. Lying, it can withhold coins (a failed spend), offer spent coins (a transaction that never confirms) or raise the fee to the 1,000 sat/vB cap; it cannot misstate input amounts (previous transactions are required and their txids checked), redirect change (re-derived by the vault) or alter a payment request's payee or amount (checked exactly). The app shows the vault's own summary before the member approves (§10.18) | Use another chain source (own node, Electrum server) |
| A connection with `wallet.request-address` | A receive address of the configured wallet, the same one until it is used; addresses link payments to that connection only (§10.14, §10.18) | `action.configure` (mode `default-deny`) |
| A connection with `wallet.request-payment` | A request the member sees and approves with the password per payment; nothing without the member's app in the unlock window (§10.14, §10.18) | Deny; `default-deny` |
| The member's location log | Only the member's own devices see it (desktops with an app's approval each time); it leaves the vault only as a snapshot the member sends through one of their shares, at that share's precision; at most `retention_days` (≤ 365) and 5,000 positions, thinned with age; off by default, deleted when turned off; no export (§10.16) | `location.history.delete`; turn it off |
| Decrypted vault state (location log) | Where the member has been, within the log's retention and thinning, if the member turned it on (§10.16) | Turn the log off (deletes it) |
| Decrypted vault state (wallet) | Each wallet's account keys: every address, past and future, and so the wallet's balance and history on chain; never the phrase or keys, which are a critical item (§10.18) | Move the funds to a new wallet |
| The Bitcoin libraries (btcd) | Parsing PSBTs from the member's own app and deriving keys, in the vault's process only (never the supervisor), so a flaw reaches only that vault (§12.4, §13.3) | A release update |
| A call's media key `k_call` | That call's media; it exists only on the two devices of the call, whose key-exchange shares are signed by the devices and vouched for by their vaults (§10.10) | Hang up |
| PIN alone | Nothing without a registered, attested app | `pin.change` |
| An app's copy of the Protean Credential | Nothing without the current CEK, which only the vault holds and which rotates at every use; password guesses only online, through the holder's session with a UTK, under the backoff (§3.5.8). Presenting it while it is not the current blob is a clone: refused, the app alerted, the member emailed, credential operations frozen until a forced rotation (§3.5.9) | Any use of the credential (a new CEK; the old blob is dead); the forced rotation |
| A clone presented through the holder's session (a stolen session and an old copy, or a restored phone backup) | Nothing: refused with `credential_frozen`, never opened; the alarm freezes credential operations (messaging continues) until the holder confirms and rotates (§3.5.9) | `credential.alarm.confirm`, then `credential.rotate`; change the password and PIN if it was not the member |
| A thief with the app's session and the PIN, without the password | No deletion: the holder's `vault.delete` needs the password too (§12.5) | — |
| The member's account, email and PIN, for 24 h unnoticed, with the backup off | A recovery that restores access only: a reset or a deletion, never the credential or a critical item (§11.11.5, §12.5) | Cancel the recovery; turn the backup on |
| VettID (operator) | Deleting a vault (the host's `delete`, an operator power it had anyway, §13.5 list), never reading it; the member is emailed | — |
| A byte-identical copy of the current blob, used before the member's next use | Undetectable at that moment; a use still needs the password and the holder's session. The member's next use then presents a stale copy and raises the alarm (§3.5.9) | The alarm and the forced rotation |
| A dishonest host, about clone alarms | Suppressing or delaying the member's email; not the vault's alert to the app, its freeze or its audit entry (§11.5) | — |
| A transfer (§6.7.1) | Moving the app needs the holder's session, the PIN and the password; the new phone must pass device attestation; the old app is removed and its copy dead | Recovery, if the member lost the phone to it |
| A recovery with `credential.backup` off | The account (email and session) for 24 h unnoticed and the PIN: a new credential, with every critical item destroyed, or deletion of the vault; never the old critical items (§11.11.5) | Cancel within the 24 h; keep the backup on |
| A GrapheneOS device | Treated as any attested app: accepted only with a locked bootloader and a verified boot key pinned in the release (§11.7) | A release update removes a key |
| An app's session keys | No password or secret value (UTK and reply-key sealing), no replay (single-use UTKs), no redirected payloads (§3.5.4) | Unlink the device |
| Credential password alone | Nothing without the blob and a paired app | `credential.password.change` |
| Member's email and account session (24 h, unnoticed) | A recovery: one new attested app that replaces the member's app. Still needs the PIN and, with the backup on, the password, online, under both backoffs (§11.11.2); with the backup off, a reset that destroys the critical items (§11.11.5) | Cancel; the app sees `recovery_pending` and `vault.locking{recovery}` |
| VettID's API tables | Nothing: the recovery code is stored only sealed to the member's browser, and the enclave enforces the 24 h (§11.11.2) | — |
| Decrypted vault state (DEK) | Everything in it (`data` and `secret` items included), plus offline guessing of the credential password against the current CEK and the latest blob (§3.5.8); critical items' values stay encrypted under item keys that only the credential, sealed under the password, holds (§10.7) | Rotate the relay key and the credential; change the password |
| A critical item key (from an old blob with its CEK and the password, or from a compromised release during an operation) | That item's ciphertext of that generation only; nothing after the item's next use, which re-keys it (§10.7) | Use the item, or `credential.rotate` (re-keys every item) |
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

### 13.7 A vault reports only to its owner

(Owner decision, 2026-10-03: "real vaults should only ever report to
their owner. Period.")

- A vault MUST send its credential state, alarms, freezes, transfers,
  recoveries, device list, settings, audit log, feed and vault status
  only to its owner's devices (§9.1), each within its role (§6.8).
- To its host it reports only the content-free lifecycle events and
  alarms of §11.5 (`enrolled`, `unlocked`, `locked`, `moved`, `deleted`,
  `alarm.credential_clone`).
- To a connection it sends only what the member's features share with
  that connection by the member's own decisions: messages, calls, the
  shared profile, granted and shared items, action results,
  introductions, location and presence under their policies, the
  credential key's public rotation statements and the signatures the
  member approved (§10.4, §10.13). A refused or failed credential
  operation (wrong password, backoff, an alarm or freeze) leaves a
  connection's request pending; it never tells the connection why.
- It never answers a principal that is not its owner's device, its
  connection or its host; a holderless vault (§3.5.9) adopts no one.

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
2. **Schemas.** Lifecycle, sessions, devices and access sessions,
   connections, messaging, the credential, items, tags, profile, settings,
   audit, feed, calls, LEASH, grants, critical-secret use and shared
   actions are in §10.1–§10.14, and location, presence and the wallet
   (0.8.0) in §10.16–§10.18. Still open: the `sync.since` cursor, and the crash-safe write order of
   `pin.change` (with its implementation).
3. **Push.** Specify the push-gateway integration (§14) when that service is
   scheduled.
4. **Desktop unlock.** Revisit if a desktop attestation mechanism becomes
   available.
5. **Release updates.** Implementation in V3: generate the §16 release
   vectors in vettid-vault, the KMS policy shapes in VAULT-PLAN, and an
   app UX review of the approval screen.
6. **ICE issuer secret.** How the coturn shared secret (or a managed
   provider's credentials) reaches the enclave (CALLING-SERVICE §5, §10).
7. **LEASH action execution and revocation status.** LEASH's HTTP action
   (the vault makes a request with an injected secret) needs egress from
   the enclave beyond the relay and KMS allowlist; signed delegations
   (§10.11) have no online revocation status. Both wait for a decision on
   enclave egress and a public status route.
8. **Files in items.** The `file` field kind (§10.7) is reserved until
   blob storage and its size policy are decided (VAULT-ITEMS owner
   decision 4).
9. **Critical item capacity.** Resolved (owner decision of 2026-10-03):
   envelope encryption (§10.7) keeps only item keys in the credential,
   about 90 bytes per item, so 1,000 critical items fit within §3.5.2's
   131,072 bytes and every credential operation still carries the whole
   blob within one message (§5.5).
10. **List sizes.** `grant.list`, `critical-secret-use.list` and
    `action.list` are not paged. With share rules a vault can hold 1,000
    given grants, so `grant.list` can outgrow one message (§5.5); page it
    (`after`, `limit`, `next`, as `item.list`) in its next revision.
11. **Wallet scope.** Multisig and script-path taproot spends, RBF fee
    bumps, and a vault-side chain source (an allowlisted chain API in the
    enclave's egress, with its privacy and trust costs, §10.18) are not in
    0.8.0; the member's app is the chain source (owner decision). The fee
    cap (1,000 sat/vB) is fixed per release.
12. **Relay mailbox deletion.** Resolved (owner decision of 2026-10-04;
    0.9.1): RELAY-PROTOCOL 0.5.0 adds the owner-signed `DELETE
    /v1/mailbox` (§6.10), and a vault deletion uses it in step 2 (§12.5).
    Left: a vault the host erases while it is locked cannot delete its
    mailbox (there is no relay key outside the PIN-protected state, §1.1
    decision 3); its tokens expire on their own.
13. **OWNER DECISIONS of 0.9.0** (each with the recommendation the text
    follows; to confirm at review):
    1. Recovery with the backup off restores access only: reset the
       credential (critical items destroyed) or delete the vault
       (§11.11.5). Decided 2026-10-03.
    2. "That was me" and "not me" both force the rotation (§3.5.9).
       Recommended: yes.
    3. The clone email goes through a content-free host alarm that the
       member API turns into an email (§3.5.9, §11.5). Recommended: yes;
       the vault has no email egress.
    4. A blob with the current version but other bytes, or a version above
       the current one, is a clone (§3.5.9). Recommended: yes.
    5. A transfer does not re-check the old app's device attestation
       (§6.7.1). Recommended: no re-check.
    6. `SelfSigned` boot is accepted for GrapheneOS only (§11.7).
       Recommended: GrapheneOS only, others on request.
    7. At most 4 alarm emails per vault per day (MEMBER-API).
       Recommended: 4.
    (Items 2–7 were confirmed by the owner on 2026-10-03.)
    8. `vault.delete` from a recovering app with the backup off, or from
       the enrolling app before a credential exists, needs the PIN only
       (§12.5). Recommended: yes: there is no password to check, and the
       recovery's 24 h and the account (or, before a credential, the
       enrollment minutes earlier) gate it; deletion exposes nothing.

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

- **0.9.1** (2026-10-04): vault deletion deletes the relay mailbox (owner
  decision of 2026-10-04).
  - §1.2: RELAY-PROTOCOL 0.5.0; mailbox deletion (§6.10).
  - §12.5: step 2 deletes the vault's relay mailbox (`DELETE
    /v1/mailbox`) after the marking flush and before the drain; on
    success the queued revocations and claim deletions are dropped (moot);
    on failure (a relay before 0.5.0, an unreachable relay) they remain the
    fallback. Why this order, and where the mailbox can remain (a crash
    between steps 1 and 2, an old or unreachable relay, a locked vault the
    host erases).
  - §15 item 12: resolved.

- **0.9.0** (2026-10-03): one app per vault (owner decisions of
  2026-10-03, PROTEAN-CREDENTIAL §4).
  - §1.1 item 8, §3.1, §6.7: a vault has exactly one app, the holder of
    the credential; apps are bound only at enrollment, by a transfer or by
    a recovery; `device.pair.create{role: "app"}` answers `one_app`; any
    other app `hs.init` is dropped (`drop.one_app`). Desktops and agents
    are unchanged.
  - §3.5.3, §3.5.5, §3.5.9 (new): the holder; only it sends blob-carrying
    types; the clone rule (only the holder's retry with the previous,
    unconfirmed version is `stale_credential`); on a clone: refusal
    (`credential_frozen`), alarm, urgent `credential.alarm` to the app,
    feed item, audit, host alarm; freeze of credential operations while
    messaging continues; `credential.alarm.confirm`; forced
    `credential.rotate` (state `rotation_required`).
  - §3.5.6: no off-device copy and no export of the credential; losing
    the phone with the backup off loses the credential and every critical
    item; the app MUST warn before turning the backup off.
  - §6.4, §6.7.1 (new), §10.3: direct transfer to a new phone
    (`device.transfer.create`, `.pending`, `.approve` with PIN and
    password, `.reject`; CEK rotated at approval; one flush at `hs.fin`
    moving the holder and removing the old app; failure and abort cases).
  - §11.11, §11.11.5, §11.11.8: the recovered app replaces the old app
    (removed, keys revoked; desktops and agents kept); `credential.recover`
    without the member-supplied blob; backup off: `credential_lost`, then
    `credential.reset` or `vault.delete`; with the backup off the recovery
    restores access only and returns no credential content.
  - §11.5: the lifecycle event `alarm.credential_clone` and the vault-row
    `alarm` and `alarm_pending`; MEMBER-API emails the member. The
    `deleted` event also records a `vault_deleted` notice.
  - §10.2, §12.5 (new): `vault.delete` from the holder (phrase, PIN,
    password; refused during an alarm), a recovering app (PIN, and the
    password when the vault keeps the blob) or the enrolling app before a
    credential exists (PIN), and the host's `delete`: mark, notify and
    revoke, drain, zeroize, erase (own header last), report; any later
    touch of a marked header finishes it. The relay mailbox cannot be
    deleted (RELAY-PROTOCOL 0.4.0): everything is denylisted; a relay
    route is recommended (§15).
  - §3.5.9, §13.7 (new): a holderless vault never adopts an app; a vault
    reports only to its owner's devices, its host (content-free events)
    and, as the member's features decide, its connections.
  - §11.7: `SelfSigned` accepted with a GrapheneOS verified boot key pinned
    in the release (deviceLocked still required); `Unverified` and
    `Failed` refused.
  - §10.1: `one_app`, `credential_frozen`, `rotation_required`,
    `credential_lost`, `transfer_pending`; `sync.event` kinds
    `credential.alarm`, `device.transferred`, `device.transfer`. §10.6:
    `credential.alarm`, `.alarm.confirm`, `.reset`, the holder-only types,
    `alarm` in `credential.version`. §10.9: audit and feed kinds. §13.5:
    rows for clones, transfers, backup-off recovery, the host and
    GrapheneOS. §15: follow-ups 12 and 13 (owner decisions).
- **0.8.0** (2026-10-03): V4 batch 4 (vettid-vault): location, presence
  and the wallet.
  - §10.16 (new): location shares with one connection: `once` or
    `continuous` (5 minutes to 7 days, cadence 10 s–1 h), precision
    `approximate` (the default), `exact` or `city` applied by the sending
    vault,
    positions ephemeral and forwarded from memory (never in the sender's
    state), kept by the receiver only while the share is active (trail
    only if allowed), either side stops, `location.request`; limits,
    audit and feed kinds. The member's own location log (owner
    decision): opt-in settings, recording from the devices' positions at
    the member's cadence, retention, thinning and a 5,000-position cap,
    owner devices only, deletion, snapshots through a share
    (`location.history.*`, `location.snapshot`), no export.
  - §9.2, §10.17 (new): presence: `presence.query` → `ping` → `pong` →
    `presence.result`, the policy (`state`, `share`, `except`), one ping
    and one answer per peer per minute; a refusal is silence (0.7.0
    answered `unknown`); ping and pong are events, not a request.
  - §10.18 (new): wallets: a BIP86 (P2TR key path, BIP340) and a BIP84
    (P2WPKH) account per BIP39 phrase kept as a critical item, P2TR
    receiving by default, the app choosing the receiving account of an
    imported phrase (`address_type`, `wallet.update`) (generated or imported; owned by the wallet:
    `item.put`/`item.sensitivity` `in_use`; `item.delete` deletes the
    wallet); addresses from the account key; the PSBT signing policy
    (own inputs and change of either account re-derived, taproot
    derivations and the BIP86 tweak checked, no script paths, previous
    transactions required for every input,
    standard outputs of the network, fee cap); spending as a credential
    operation bound to the wallet and the PSBT's hash, in the unlock
    window; the app as the chain source (owner decision); history;
    `mainnet`, `testnet`, `signet` (`regtest` in development builds).
  - §10.14: catalog version 3: `wallet.request-address` (`network` in the
    result) and `wallet.request-payment` (`address` added; approval is
    the spend; result `{status: "signed", txid}`) run on the configured
    wallet.
  - §10.1: `invalid_psbt`, `unavailable`; `in_use` for a wallet's item;
    `sync.event` kinds `location.share.changed`, `location.history.changed`, `presence.changed`,
    `wallet.changed`, `wallet.signed`, `wallet.deleted`. §10.9: audit and
    feed kinds. §10 registry: the wallet, location and presence rows
    (the placeholders `wallet.address.share` and `wallet.payment.request`
    are dropped: the wallet actions replace them). §6.8: step-up for
    `location.share.start`, `location.history.*` and `presence.set`.
    §10.8: `location.history.*` settings. §7.3, §8.5:
    `location.update` and the presence events are ephemeral. §3.5.2:
    `crypto_keys` stays empty. §3.5.4: the wallet's payload members.
    §10.11: no location, presence or wallet type is delegable. §12.2: no
    chain egress. §13.5: location, location log, presence and wallet
    rows. §15: follow-up 11.
- **0.7.0** (2026-10-03): V4 items (vettid-vault): one item model with
  tags and share rules (VAULT-ITEMS, owner decisions 1–5 of 2026-10-03).
  - §10.7 (new): items: name, category (recommended list), template,
    typed fields (`text`, `multiline`, `number`, `date`, `email`, `phone`,
    `url`, `password`, `otp`, `address`; `file` reserved) with vault
    assigned, never reused field ids, notes, tags and a sensitivity per
    item (`data`, `secret`, `critical`); `item.put`, `.get`, `.reveal`,
    `.list` (filters by tags, category and sensitivity; paged), `.tag`,
    `.sensitivity`, `.delete`; limits (64 fields, 16 KiB per value, 64 KiB
    per item, 2,000 items; critical: 12 KiB per item, 1,000 items);
    `secret` values only revealed on purpose (audited); critical items
    envelope-encrypted (values in DEK state under per-item keys that only
    the credential holds, re-keyed at every use of the item and at
    `credential.rotate` and `.recover`); critical operations are
    credential operations with the content and the item id sealed to a
    UTK and values returned sealed to a reply key; moves to and from `critical` done by the vault without values
    crossing the session; app-only forms refused to desktops at once.
    Replaces §10.7 secrets and `credential.secret.*`.
  - §10.8: tags (normalisation, one namespace, reserved `@profile`, never
    sent to connections), the tag registry (`tag.list`, `.set`, `.delete`,
    `.merge`, with `dry_run`); the profile is a display name and photo
    plus the `data` items tagged `@profile` (at most 32), sent in
    `profile.update` with its own counter; profile fields, `shared` and
    `order` removed.
  - §10.12: share rules (`share.rule.set`, `.list`, `.delete`,
    `share.pending`, `share.decide`) for a connection or an agent: tags
    with `any` or `all`, `read` access, `ask` (default) or `auto`, uses,
    expiry, `include_existing` with a preview; inclusion, gains, remembered
    declines, withdrawal on tag removal, rule change, deletion or expiry;
    readable inclusions are grants (`rule_id`, no use limit or expiry
    unless the rule has one) announced by `data.shared`; grants of items
    with optional field lists; one-off requests by item or by category,
    answered by the member; descriptors carry name, category and labels,
    never tags; per-connection catalogs (granted and usable items).
    Replaces the `cataloged` flag and the one catalog for everyone.
  - §10.11: the data scopes (`secrets.catalog`, `.get`, `.use`) become an
    agent's share rules (scope `items.read`, signed delegations carrying
    the rule's tags, match, access, uses and rate limits; owner
    decisions of 2026-10-03: reads of included items within the rule's
    limits; tags in the delegation); `agent.request` ops `catalog`, `item.get`,
    `item.use`; audit kinds `leash.item.read`, `leash.item.used`.
  - §10.13: critical-item use names `item_id` and `field_id` and needs a
    rule that makes the item usable for that connection;
    `credential.secret.catalog` removed.
  - §10.14: catalog version 2: `items.share` replaces
    `profile.fields.read` and `secrets.share`; configurations bound by
    `items`.
  - §3.3, §3.5, §3.5.2, §3.5.4, §6.8 (step-up types), §8.2, §10 registry,
    §10.1 (`in_use`, ids, `sync.event` kinds `item.*`, `tag.changed`,
    `share.*`), §10.6, §10.9 (audit and feed kinds), §13.5 (share-rule
    and tag-change rows, a critical item key), §15 (follow-ups 8–10;
    9 resolved by envelope encryption).

- **0.6.0** (2026-10-03): V4 batch 3 (vettid-vault): LEASH, grants,
  critical-secret use, shared actions.
  - §10.11 (new): LEASH for the member's agents, mapped onto pairing,
    access sessions and approvals: grants per agent with a scope (three
    LEASH operations and nine delegable owner types), `ask` or `auto`
    approval, restrictions to connections or secrets, hourly and daily
    limits that fall back to referral, and expiry; the decision (allow,
    refer, refuse) behind §6.8's hook; `agent.request` for the catalog,
    retrieval and HMAC use of cataloged secrets; `leash.grant.issue`,
    `.revoke`, `.list`, `.updated`, `leash.agent.resume`; every grant is
    a delegation signed by the credential key, with short-lived status
    statements signed by the vault's `ik` ("stapling": a 15-minute
    default lifetime, at most an hour, none for revoked or suspended
    grants or from a locked vault, the `ik` rotation chain carried,
    normative offline verification for relying parties) (issuing and pairing with
    grants need an app within the unlock window; lifetime and revocation
    from LEASH §3.2 and §3.4); per-agent refusal cooldowns (1 s doubling
    to 5 min), at most 20 referrals an hour, suspension after 30
    refusals in an hour until an app resumes the agent; per-agent hourly
    audit summaries of allowed, refused, throttled, read and used
    events.
  - §6.7, §10.3: `device.pair.approve{grants}` carries an agent's initial
    grants. §6.8: `agent.request` goes through the policy; a referred
    request runs on approval only while a grant covers it; `grant.decide`
    `action.configure`, `intro.create` and `intro.accept` are step-up
    types. §9.1: agents get no fan-out.
  - §10.12 (new): grants of profile fields (the per-connection profile
    overrides deferred in 0.4.0) and cataloged vault-held secrets: ask,
    decide, fetch with uses and expiry, revoke from either side; values
    sealed to a one-time key of the fetching device; the catalog.
  - §10.13 (new): critical-secret use: a connection asks, the member
    consents with the password for each use (UTK payload bound to the
    request and the payload's hash), the CEK rotates, only a signature
    (`sign` or the domain-separated `auth`) leaves the vault;
    `credential.secret.catalog`. §3.5.4: the payload members.
  - §10.14 (new): shared actions as a built-in catalog run by the vault
    (`profile.fields.read` and `secrets.share` through one-use grants,
    `audit.recent`, `wallet.request-address`, `wallet.request-payment`
    defined and `unavailable` until the wallet), permission modes per
    action (`default-deny`, `allowlist`, `prompt-each-time`,
    `default-allow`; none for sensitive, critical only with an app in the
    unlock window), offers, invocations, results and limits, without the
    vettid.dev mis-routing (owner decision 2026-10-03).
  - §10.15 (new): introductions started only by the member: both parties
    accept, then the first makes an invitation bound to the other's `ik`
    that the introducer relays; the parties approve each other as usual.
  - §10: flows between vaults are events correlated by ids (the registry's
    V↔V `req` entries for actions and grants are gone); registry rows.
    §10.7: `discoverability` takes effect. §10.1: `sync.event` kinds;
    `forbidden` and `credential_locked` uses. §10.9: audit and feed kinds.
    §13.5: agent, delegation, grant, critical-use and action rows. §15:
    schemas; follow-up 7.

- **0.5.0** (2026-10-03): V4 batch 2 (vettid-vault): connections polish,
  calls, device and agent sessions.
  - §6.8 (new): access sessions for desktops and agents, requested by the
    device and granted by an app (or with the pairing approval); step-up
    types a desktop sends only with an app's approval; the LEASH hook for
    agents (allow, refer to an app, refuse; never app-only types);
    approvals (`approval.pending`, `.waiting`, `.decide`), expiry and
    ending. Replaces `agent.approval.pending` / `.decide` in the registry;
    `agent.request` is reserved for LEASH.
  - §9.1: fan-out reaches desktops only within their access session.
  - §10.4: `connection.update` (the owner's alias, note, tags, favorite,
    archived; versioned, never sent to the peer); `created_at` and
    `last_active_at` in listings; the block list (`block.add` of a
    connection or a pending request, `block.remove`, `block.list`) and its
    refusal of blocked identities; member authentication
    (`connection.authenticate.*`), signed with the member's credential key
    within the unlock window, pinned by the requester.
  - §10.10 (new): call signalling: `call.start`, `call.offer`,
    `call.ringing`, `call.answer`, `call.ice`, `call.end`, `call.list`; one
    call at a time (`busy`); the media key agreed by the two devices (the
    KEM in §10 is now run by the answering device, not its vault); each
    vault signs the ICE configuration for its own devices.
  - §8.5: `call.ringing` is ephemeral; ephemeral forwards are memory-only.
  - §7.4: unlinking ends the device's access session.
  - §10.1: error codes `session_required`, `denied`, `approval_timeout`,
    `busy`, `credential_locked`, `blocked`; `sync.event` kinds
    `connection.changed`, `block.added`, `block.removed`,
    `connection.authenticate.decided`, `device.session`,
    `approval.decided`. §10.3: `device.pair.approve{session_seconds}`,
    `device.list` fields. §10.9: audit and feed kinds. §13.5: desktop and
    call-key rows. §15: follow-up 6.
  - Owner review of the first 0.5.0 draft:
    - §3.5.5, §10.4: credential-key rotation statements, signed by the old
      and the new credential key at `credential.rotate`, delivered
      (`connection.authenticate.rotated`, and `rotations` in responses) to
      the connections that pinned the member's key, which follow the
      chain instead of reporting a key change; forged or broken chains
      are rejected and audited.
    - §7.4, §6.7: a removed or blocked connection's tokens are denylisted
      by `jti`, not by relay key, so the owner can connect with the same
      peer again through a new invitation and approval (after
      `block.remove` for a block); a fresh connection replaces an older
      record of the same peer.
    - §10.10: desktops within an access session place and answer calls
      (no per-call approval); first answer wins; no call handoff between
      devices; the calling device chooses `call_id`; key-exchange shares
      are signed by the device and vouched for by its vault, and checked
      by the peer vault and the peer device (residual: each member's own
      vault).

- **0.4.1** (2026-10-03): the owner's Protean Credential design,
  recovery and backup, audit immutability.
  - §3.5 (rewritten, owner corrections of 0.4.0):
    - the CEK rotates at every use, and the old CEK is destroyed, so old
      blobs are undecryptable;
    - the latest blob is kept until the app confirms it (`credential.ack`),
      so a lost response never loses the credential;
    - UTK/LTK one-time transaction keys (hybrid suite 2, a pool of 20 per
      app) seal every operation's critical payload inside the session,
      single-use and bound to type and request;
    - secret values return sealed to a one-time reply key, so those
      responses are cached normally;
    - LAT is superseded by Nitro attestation (decision 2026-01-08);
    - a vault without a credential is restricted and stays provisional
      (§3.5.7); `has_credential` is in the sealed header.
  - §10.6: every credential type rewritten around `utk_id`/`sealed`, new
    `credential.utk.get` and `credential.ack`; §10.1: `utk_invalid`,
    `credential_required`; §8.2: no type needs volatile responses now.
  - §11.3: `credential.create` before `vault.enroll.confirm`.
  - §11.11 (new): recovery when every owner app is lost. The request locks
    the vault; a vault-minted, single-use code sealed to the member's
    browser key becomes valid after 24 h (enforced by the enclave) for
    24 h; a new attested app registers with it, unlocks with the PIN and
    receives the credential only after the password (with the member's own
    blob when the backup is off); a vault without a credential is refused;
    old devices are kept; cancel by the portal, the email link or an owner
    app's unlock; limits, audit, member API routes.
  - §3.5.6: the vault's copy of the credential is normative, under the
    `credential.backup` setting (on by default).
  - §10.9: the audit log is append-only with fixed retention (the
    `audit.retention_days` setting is removed), anchored by apps through
    `after_seq`, rollback-protected by `state_seq`; `drop.*` entries are
    bounded; recovery and settings kinds.
  - §10.2: `vault.locking{reason}`. §10.6: `credential.recover`. §10.8:
    `credential.backup`. §11.4: `cancel_recovery` (13th signing line),
    `recovery_pending`, `recovery_cancelled`, `vault_bundle`. §11.5: the
    recovery queue operations. §13.5: recovery rows.

- **0.4.0** (2026-10-02): V4 batch 1 (vettid-vault) and the owner's
  decision to keep the full Protean Credential.
  - §3.5 (new): the Protean Credential, held by the member's app, sealed to
    a vault-held hybrid-KEM CEK and under a password key, usable only with
    the member's password per operation; the blob format, use rules,
    password backoff, unlock window, lifecycle, and what VettID and the
    vault can and cannot do with it. (0.4.0 dropped the UTK/LTK
    transaction keys; 0.4.1 restores them.)
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
