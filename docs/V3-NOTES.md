# V3 notes: alternate channel, enclave shell, parent

V3a implemented the enclave side of VAULT-MESSAGING 0.3.1 §11 in process:
everything the enclave decides, with the hardware and AWS behind
interfaces. V3b adds the supervisor, the real NSM, the enclave's TLS
egress and SigV4 KMS client, and the parent with its AWS backends (second
half of this file). This file records implementation choices the spec
leaves open, the runtime fixes made on the way, and spec questions with
proposed wording.

## What runs where

| Concern | V3a | V3b (release build) | Development and tests |
|---|---|---|---|
| NSM | `enclave.NSM` | `enclave/nsm`: `/dev/nsm` ioctl, CBOR via `internal/cbor` | TEST-ONLY `enclavetest.FakeNSM` (test Nitro CA) |
| KMS | `enclave.KMS` | `enclave/awskms`: KMS JSON API, SigV4 in-repo, over `enclave/egress` | the same client against `enclavetest.KMSServer` (HTTPS, test TLS root, SigV4 verified) in front of `enclavetest.FakeKMS` |
| Status list | `Options.StatusList` | fetched hourly over the egress (GTS roots) by the supervisor | the same fetch against a local TLS server |
| Queue, parent, response slots, leases, registry | `enclavetest.World` in process | `parent` over vsock; SQS, DynamoDB | `parent` over TCP; LocalStack (integration) or `internal/parenttest` (e2e, unit) |
| Store | `vault/store` Memory and Dir | supervisor `hostStore` → parent → S3 conditional writes | the same → LocalStack S3 or `parenttest.Objects` |
| Release pins | `enclave.ReleaseConfig`: vendor roots, Android package, iOS App ID; manifest keys, sealing account/region, Android signer digests and the release number are empty (fail closed) until V5 | unchanged; plus the TLS roots and `ReleaseRelayURL` | `enclavetest.DevSupervisor` |

New dependencies: none. CBOR (Nitro documents, App Attest), DER (the
Android attestation extension, whose tags reach [724]) and CMS are parsed
by small in-repo decoders (`internal/cbor`, `internal/der`, `enclave/cms`)
instead of `fxamacker/cbor` and a PKCS#7 library: they accept only what
these formats use, reject indefinite lengths (CBOR), duplicate keys and
trailing data, and are fuzzed. That keeps the enclave's trusted code base
small; the cost is a few hundred lines we own.

## Spec questions

The spec questions raised in V3a (the response slot and
`vault.enroll.result`, result binding and codes, per-release `header_seq`,
re-enrollment, what the device key signs, the pairing challenge, iOS
counters, the sealed-object format, `seal_key_verified.verified_by`, the
policy-check wording, status-list and Android details, §16 sizes) are
settled in VAULT-MESSAGING **0.3.1**, which this code follows.

## Implementation choices the spec leaves open

1. **Member index.** For re-enrollment the enclave keeps an index object
   from a member to its vault (`users/<sha256(user_guid)>/vault`, holding
   only the vault id). Replacing a provisional vault overwrites its state
   and this release's header with version-matched writes; a header without
   state (an interrupted enrollment) is overwritten too.
2. **One manager per vault.** An unlock for a vault the instance runs locks
   (flushes) it first. `delete` destroys the state and this release's
   header; the §7.4 revocations on deletion need the unlocked vault and
   come with `vault.delete` (V4).
3. **Manifest strictness.** Manifest bytes must be compact JSON; unknown
   members are ignored (§5.3); an empty `releases` array is refused;
   `notes` must be `https`. The enclave requires its own entry's PCR1 and
   PCR2 to equal its measurements and its number to equal the embedded
   release number.
4. **ETK rotation** after 23 h, so a current descriptor never expires;
   requests are processed one at a time per instance.
5. **PINs** are 4–32 ASCII digits.
6. **App Attest assertions** are verified as ECDSA P-256 with SHA-256 over
   `nonce` (0.3.1 §11.7); to be confirmed on a device in V6.
7. **History:** V2 nested `vault.enrolled`'s bundle under `vault`; V3a uses
   the spec's flat `{v, suite, ik, kem, relay}`.

## Runtime fixes made in V3a

- **Outbox order per mailbox.** A deposit waiting for a retry (an `hs.fin`
  whose deposit a lock interrupted) let later deposits to the same mailbox
  overtake it, and the device dropped new-epoch traffic that arrived before
  `hs.fin`. Deposits to one mailbox now stay in order; an interrupted drain
  is not counted as a failed attempt; locking drains the outbox first and
  skips the direct `vault.locking` while deposits to the device are queued.

# V3b: supervisor, parent and AWS transport

## Components

| Package / command | Runs | What it does |
|---|---|---|
| `cmd/vault-enclave` | enclave (PID 1) | Release build: vsock, `/dev/nsm`, pinned roots, `enclave.ReleaseConfig`. `-tags devenclave` (`vault_dev.go`): TCP, fake NSM, test roots (`enclavetest.DevSupervisor`) |
| `enclave/supervisor` | enclave | Control connection, instance (ETKs, alternate channel), vault managers, lease-lost and memory-pressure locks, descriptor push, status-list fetch, sanitized logs to the parent |
| `enclave/nsm` | enclave | `NSM_IOCTL_REQUEST` (`_IOWR(0x0A, 0, 32)`) with `Attestation` and `DescribePCR` CBOR requests |
| `enclave/egress` | enclave | The only way out: HTTPS to an allowlist, TLS 1.3 only, per-host pinned roots, host-name verification, ALPN h2 required for HTTP/2 hosts, no redirects, a few shared connection pools per host |
| `enclave/awskms` | enclave | KMS `GenerateDataKey`/`Decrypt` (Recipient, `RSAES_OAEP_SHA_256`) and `DescribeKey`/`GetKeyPolicy`/`ListGrants`, SigV4 signing, credentials from the parent |
| `internal/hostproto` | both | Frames (kind, id, length-prefixed fields; ≤ 64 MiB), request/reply/notification multiplexing, 16 KiB chunked writes, the egress connection header |
| `internal/vsock` | both | `AF_VSOCK` dial/listen with `golang.org/x/sys/unix` and the runtime poller; every write chunked to 16 KiB |
| `parent`, `cmd/vault-parent` | host | Control server, TCP forwarder, SQS queue and consumer, registry, leases, slots, S3, credentials, health |
| `internal/parenttest` | tests | In-memory S3/SQS/DynamoDB with the same conditional semantics |
| `internal/memberapitest` | tests | Stand-in for vettid.org `lambda/member/vault.ts` over the same DynamoDB tables and SQS queues |
| `client` (`MemberAPI`, `EnrollVia`, `UnlockVia`, `LockVia`) | apps | The member API's vault routes; `vaultctl api-enroll`, `api-unlock`, `api-lock` (dev) |

## Process model (D4): goroutines, not processes

VAULT-PLAN D4 says "one vault manager process per unlocked vault". V3b
runs one vault manager **goroutine** per unlocked vault inside the
supervisor process, and proposes rewording D4 (below). Reasons:

1. **D5 already puts every vault's traffic through one process.** TLS ends
   in the enclave over a few HTTP/2 connections shared by all vaults, so
   one process holds the TLS session keys and sees every vault's relay
   requests (tokens, mailbox ids) before encryption. A per-vault process
   would have to hand its HTTP requests to that process over IPC; the
   supervisor would see them anyway.
2. **The unlock happens in the supervisor.** The alternate channel (ETK
   decryption, device attestation, the manifest, the KMS key check, DEK
   derivation in `vault.UnlockAlt`) runs where the ETKs live. Moving the
   resulting manager to a child would mean exporting the DEK and the
   decrypted state across IPC from a process that already held them.
3. **Same TCB, same image, same user.** Inside one enclave every process
   is the same measured binary; process separation would not change what
   an attacker with code execution in the enclave can reach (a sibling's
   memory through `/proc` or ptrace, unless privileges are split, which
   the image does not do).
4. **Memory.** A Go process costs ~5–10 MB before it holds a vault; with
   goroutines the enclave fits more vaults per GiB.

What processes would have given, and what replaces it:

| Property | Replacement |
|---|---|
| A crash in one vault does not take the others down | `runRecovered` (enclave) recovers a vault run-loop panic: the vault is zeroized without a flush (`ErrPanic`) and reported `Stopped`; the supervisor recovers panics in request handling (the request gets no answer and expires) |
| Per-vault memory accounting and eviction | `MaxVaults` and `MemoryHigh` (default 70 % of `MemTotal`, `GOMEMLIMIT` 85 %): the least recently active vault (last state write or unlock) is locked like an owner request (§12.3), then `runtime.GC` and `debug.FreeOSMemory` |
| Locking frees every copy of the vault's secrets | Lock zeroizes the DEK, keys and sessions (V2); copies the Go runtime made (JSON buffers, strings) stay until the GC reuses the memory. **Residual**; candidate fix: Go's `runtime/secret` once it leaves `GOEXPERIMENT` |

## Enclave ↔ parent

- **Ports** (vsock, parent CID 3): control 5000, egress 5001. The enclave
  dials both; the parent listens. Development uses TCP on the same
  protocol.
- **Control** (`internal/hostproto`): requests with ids in both
  directions, replies, and ordered notifications. Enclave → parent:
  `Hello [release PCR0, boot id]` → `[instance_id, fresh|resume]`,
  `StoreGet/Put/Delete`, `Credentials`. Parent → enclave: `Queue [message]`
  → `[response]`, `LeaseLost [vault_id]`, `Ping` → `[running vaults]`,
  `Shutdown`. Notifications: `Descriptor`, `Lifecycle`, `Stopped`
  (split brain, error), `Log`.
- **The parent chooses the instance id** (`-instance-id`, default random
  `vi-<hex>`) and tells the enclave in `Hello`; descriptors carry it. If a
  reconnecting parent names another id, the enclave exits (its
  descriptors would be wrong).
- **Egress**: one vsock connection per outbound TCP connection, starting
  with `0x01 ‖ len ‖ host ‖ port`; the parent answers one byte and then
  splices. The parent allows exactly `relay.vettid.org`,
  `kms.<region>.amazonaws.com` and `android.googleapis.com`, port 443; the
  enclave allows the same hosts on its side and verifies them by TLS.
- **Large writes**: every write on a vsock connection, in both
  directions and on both ends, is at most 16 KiB (`hostproto.ChunkSize`),
  for the Nitro vsock large-write bug vettid.dev hit.
- Not carried over from vettid.dev: the baked vsock shared secret (the
  parent is untrusted; authenticating it would add nothing), NATS, the
  seed/vote/invite/LEASH proxies, parent-side envelope parsing,
  parent-side replay and freshness checks, the RSA PKCS#1 v1.5 fallback,
  and anything that calls `PutKeyPolicy`.

## TLS chains (confirmed 2026-10-02)

Fetched with `openssl s_client -showcerts` and verified with Go's
`crypto/tls` using only the pinned pools, TLS 1.3:

| Host | Served chain | Verified chain (pinned anchor) | ALPN |
|---|---|---|---|
| relay.vettid.org (ACM) | leaf → Amazon RSA 2048 M01 → Amazon Root CA 1 (cross-signed by Starfield Services Root CA – G2) | leaf → M01 → **Amazon Root CA 1** | h2 |
| kms.us-east-1.amazonaws.com, kms.eu-west-1.amazonaws.com | leaf → Amazon RSA 2048 M04 → Amazon Root CA 1 (cross-signed by Starfield Services Root CA – G2) | leaf → M04 → **Amazon Root CA 1** | **http/1.1 only** |
| android.googleapis.com | leaf (CN edgecert.googleapis.com, SAN includes the host) → WR2 → GTS Root R1 (cross-signed by GlobalSign Root CA) | leaf → WR2 → **GTS Root R1** | h2 |

- The Starfield cross-certificate is served but not needed: Go anchors at
  the self-signed Amazon Root CA 1 in the pool. Starfield and GlobalSign
  are **not** pinned.
- Pinned (`vms/pins`, by SHA-256 fingerprint): Amazon Root CA 1–4 for the
  relay and KMS (2–4 cover the other key types ACM and AWS endpoints issue
  under, so a re-issued certificate does not force a release; valid to
  2038/2040), and GTS Root R1, R3, R4 for Google (valid to 2036). GTS Root
  R2 is not pinned.
- **KMS does not offer HTTP/2.** KMS requests use HTTP/1.1 keep-alive
  connections (4 pools of at most 4 connections each); relay and Google
  traffic use shared HTTP/2 connections (relay: 4 pools of one connection
  each in release builds). A vault's long-poll holds one stream; at the
  ALB's 128 streams per connection the relay pools carry about 500 unlocked
  vaults before requests queue.
- Each HTTP/2 pool allows exactly one connection (`MaxConnsPerHost` 1):
  otherwise concurrent first requests each dial, briefly giving every
  vault its own connection (`egress.TestSharedHTTP2`).

## KMS client

- SigV4 is ~150 lines in `enclave/awskms`; it matches the AWS SigV4 test
  suite (get-vanilla, post-vanilla, query order) and, in tests only, the
  AWS SDK's signer on 200 random KMS-shaped requests. The SDK is never
  linked into the enclave (`make check-tcb`).
- Credentials come from the parent (`Credentials` request: the instance
  role's temporary credentials) and are cached until 5 minutes before
  they expire; `ExpiredTokenException`, `UnrecognizedClientException` or
  `InvalidSignatureException` refresh them once.
- A `GenerateDataKey` or `Decrypt` answer that carries `Plaintext` is
  refused; `Decrypt` must echo the `KeyId` it was asked for. Errors are
  reported by AWS error type only.
- The V3a sealer and §11.10.7 check run unchanged against the real
  responses (`awskms.TestRecipientRoundTrip`, the integration test).

## Parent

- **Reads of queue messages**: `v`, `op`, `vault_id`, `request_id` only
  (to take the lease and answer the slot). The message is forwarded byte
  for byte; envelopes, sealed results and stored objects are never parsed
  or logged. Of the enclave's answer it reads `request_id`, `status` and
  the envelope's size (5,252 bytes, as the API requires).
- **Order per request**: acquire the lease (enroll, unlock) → forward →
  lifecycle events (which precede the answer on the connection) → slot
  → release the lease if the vault did not open → delete the message.
  Without an answer (enclave gone, timeout) the message stays for
  redelivery (replay set, or `etk_unknown` after an enclave restart).
- **Leases** (`#lease` map `{instance_id, lease_expires_at}`): acquire if
  absent, expired or own; renew every 60 s (length 180 s) while the
  enclave reports the vault running; a renewal that finds another holder,
  or transient failures until 15 s before the lease lapses, is "lease
  lost": the enclave locks the vault (§12.3). Lifecycle writes and lease
  releases are conditional on the lease being this instance's (or absent),
  so a split-brain loser never overwrites the winner's row.
- **Registry**: written every 20 s only while the enclave answers `Ping`
  and has pushed a descriptor; `expires_at` = now + 10 min (TTL); deleted
  when the enclave disconnects and at shutdown. `load` = running vaults.
- **Queue**: created at boot (retention 300 s, visibility 120 s, long
  poll, SSE, redrive after 3 receives when `-dlq-arn` is set), deleted at
  shutdown; a sweeper deletes queues of instances without a registry row
  (or a heartbeat older than 1 h) once they are 15 minutes old.
- **S3**: version = ETag; create-only = `If-None-Match: *`; matched =
  `If-Match`; deletes use `If-Match` too. Keys are limited to `vaults/` and
  `users/` (the V3a member index).
- **Restart detection**: the enclave sends a random boot id in `Hello`. A
  new boot id releases every lease the parent held (the vaults died with
  the enclave's memory). A parent that has just started answers `fresh`,
  and the enclave locks every vault before serving (nobody renews their
  leases).
- **Shutdown** (SIGTERM): `Shutdown` → the enclave locks every vault
  (flush, `vault.locking`, lifecycle `locked`); then the registry row and
  the queue are deleted.
- **Credentials**: the instance role through IMDSv2
  (`credentials/ec2rolecreds`), or static development credentials
  (`-static-credentials`).
- **Logs**: JSON (`log/slog`), ids and counts only; the enclave's log
  records arrive as `source=enclave`.

## Dependencies

- **Enclave**: no new module. `golang.org/x/sys` (already required
  through `x/crypto`) becomes a direct dependency for `AF_VSOCK` and the
  NSM ioctl. `github.com/hf/nsm` and `github.com/mdlayher/vsock` were not
  used: the NSM needs two CBOR request shapes that `internal/cbor` already
  encodes and decodes strictly, and vsock needs ~150 lines over
  `x/sys/unix`; both libraries would bring `fxamacker/cbor` or
  `mdlayher/socket` into the TCB. HTTP/2 is the standard library's.
- **Parent and tests only** (never in the enclave, `make check-tcb`):
  `github.com/aws/aws-sdk-go-v2` (core and SigV4 for the test cross-check),
  `service/s3`, `service/sqs`, `service/dynamodb`, `credentials`
  (static and `ec2rolecreds`), `feature/ec2/imds`, and their internal
  modules and `github.com/aws/smithy-go`. Not `config` (it would pull SSO,
  STS and INI parsing the host does not need).

## Development mode and `make check-tcb`

- `cmd/vault-enclave/vault_dev.go` carries `//go:build devenclave`,
  `release.go` carries `//go:build !devenclave`.
- `make check-tcb` now also fails if the enclave binary
  (`./cmd/vault-enclave`, `GOOS=linux`) links the AWS SDK, smithy, the
  parent, `enclavetest`, `parenttest`, `memberapitest`, `relaytest`,
  `devenclave` or the vector-only packages, and if it does not link the
  real NSM and vsock packages.

## Tests

- Unit: `hostproto` (framing, chunked writes, multiplexing, fuzzed),
  `vsock` (loopback, where `vsock_loopback` exists), `nsm` (request
  encoding, responses, ioctl number, fuzzed), `egress` (allowlist, pinned
  roots, host names, TLS 1.3, ALPN, redirects, shared connections),
  `awskms` (SigV4 vectors and SDK agreement, Recipient round trip through
  the fake KMS endpoint, credential refresh, plaintext refusal),
  `supervisor` (host store mapping, writes never cancelled), `parent`
  (registry, store prefixes, requests and slots, leases, lease loss,
  enclave restart, fresh parent, forwarder allowlist).
- `e2e.TestHostStack` (`make e2e`): parent and supervisor in process with
  the in-memory backends, the real relay behind a TLS front and the fake
  KMS endpoint: enroll, unlock, lock, the vault cap evicting the least
  recently active vault, `etk_unknown` after an enclave restart and the
  released leases, parent shutdown.
- `integration.TestV3Exit` (`make integration`, CI job `integration`,
  ~30 s plus builds): LocalStack, the real relay, `vault-parent` and
  `vault-enclave` (dev) binaries, the member API stand-in and `vaultctl`:
  enroll; a second member's vault connects and exchanges messages; lock;
  a message while locked; unlock; a rolled-back state object
  (`state_rollback`), another device key (`attestation`) and a replayed
  unlock (dropped, the vault not reopened) are refused; a release move 3 →
  4 across two instances; a split brain between two release-4 instances,
  where the instance whose conditional write loses locks the vault; and
  shutdown deleting the queues, with no PIN or envelope in any log.
  `parent.TestAWSBackend` checks the conditional writes and table
  conditions against LocalStack.
- **LocalStack gap**: LocalStack 4.9 does not implement `If-Match` on
  `DeleteObject` (real S3 does). With `-aws-endpoint` the parent emulates
  it with HEAD + DELETE (not atomic); against AWS it always sends
  `If-Match`.
- Hardware-only (V5): the real NSM ioctl, vsock framing between a real
  enclave and parent, KMS policies with real attestation.

## Runtime fixes made in V3b

- **A cancelled conditional write looked like a split brain.** Locking a
  vault cancels its run loop; if a state write was in flight, the store
  call returned "cancelled" although the parent completed the write. The
  vault kept its old version, its final flush then conflicted with its
  own write, and it zeroized without `vault.locking` or a `locked` event.
  Store writes and deletes now always run to completion
  (`context.WithoutCancel`, bounded by 60 s). A write whose outcome stays
  unknown (the connection to the parent drops) still makes the next write
  conflict, which locks the vault: safe, and logged.
- `Instance.Lock`/`LockAll`/`Vaults` let the supervisor lock vaults for
  memory pressure, lease loss and shutdown; locks report a final flush
  that lost (`vault.ErrSplitBrain`).
- A vault whose run loop ends on an error is locked by the supervisor
  (before, it stayed in memory, unlocked and idle).

## Spec and plan questions (proposed wording)

1. **§11.1 lease of a dead holder.** The parent takes a lease only if it
   is absent, expired or its own; the API already treats a lease whose
   holder is not live as no lease and forwards to another instance, whose
   parent then cannot take it for up to 180 s (the request expires and the
   app retries). Implemented literally. Proposed: "…succeeds only if the
   lease is absent, expired, already its own, **or held by an instance
   that is not live (§11.1), in which case the write is conditional on
   the exact lease it replaces**."
2. **§11.1 when the lease is taken; §11.5 slot statuses.** The parent
   cannot know whether the enclave will open the vault, so it takes the
   lease before forwarding and gives it back if the vault did not open.
   When the lease is held elsewhere it does not forward and writes the
   slot `expired`; it also writes `expired` when the enclave gives no
   answer to a message it cannot parse. Proposed for §11.1: "The parent
   acquires the lease before it forwards an enroll or unlock; if another
   instance holds it, the parent does not forward the request and marks
   its slot `expired` (§11.9). If the vault does not open, the parent
   releases the lease." For §11.5: "The parent writes `status: done` …,
   or `status: expired` for a request it did not forward or the enclave
   could not read." (MEMBER-API's table lists only `done` as a host
   write.)
3. **§11.5 lifecycle writes.** Proposed: "The parent writes lifecycle
   events only while it holds the vault's lease or no lease exists, so an
   instance that lost a split brain cannot overwrite the holder's values."
4. **§12.2 shared connections.** AWS KMS endpoints do not offer HTTP/2,
   and WebSocket collect cannot share HTTP/2 connections (no RFC 8441 in
   the relay). Proposed: "Each instance carries every vault's relay
   requests over a few shared HTTP/2 connections (the collect loop uses
   long-poll inside the enclave); KMS requests use a small pool of
   HTTP/1.1 keep-alive connections, because the KMS endpoints offer no
   HTTP/2."
5. **§12.3 restarts and an unreachable parent.** Proposed rows: "Parent
   restart (enclave still running) | The enclave locks every vault before
   serving the new parent (it holds no leases for them)." and "Parent
   unreachable for 120 s | Every vault is locked (its lease can no longer
   be renewed)."
6. **§11.1 renewal failures.** Proposed: "A renewal that finds another
   holder, or renewals that keep failing until 15 s before the lease
   expires, count as a lost lease."
7. **VAULT-PLAN D4.** Proposed: "One vault manager per unlocked vault
   inside the enclave, as an isolated goroutine of the supervisor (panic
   recovery, per-vault accounting and eviction); see vettid-vault
   docs/V3-NOTES.md for why not processes."
8. **VAULT-PLAN §5.2 roots.** Record the chains above: Amazon Root CA 1
   anchors both relay.vettid.org and the KMS endpoints (the Starfield
   cross-sign is served but not needed), GTS Root R1 anchors
   android.googleapis.com; pinned: Amazon Root CA 1–4, GTS Root R1, R3, R4.
9. **vettid.org account deletion (MEMBER-API, `lambda/jobs/cleanup.ts`).**
   Besides `vaults/<vault_id>/`, the enclave stores one index object per
   member, `users/<hex SHA-256("vettid/vms/2/user\0" ‖ user_guid)>/vault`
   (V3a, holding only the vault id). Proposed: the cleanup job deletes it
   too, with `s3:DeleteObject` on `users/*`.
10. **Lifecycle values.** `state_version` is written as a number; the API
    type allows a string or number.
