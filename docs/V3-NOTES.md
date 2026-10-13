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
| `enclave/vaultproc`, `internal/vaultipc`, `internal/seccomp` | enclave (one process per vault) | The vault process, its channel to the supervisor, and its syscall filter |
| `cmd/vault-enclave` | enclave (PID 1) | Release build: vsock, `/dev/nsm`, pinned roots, `enclave.ReleaseConfig`. `-tags devenclave` (`vault_dev.go`): TCP, fake NSM, test roots (`enclavetest.DevSupervisor`) |
| `enclave/supervisor` | enclave | Control connection, instance (ETKs, outer decryption), vault processes and their scoped channels, lease-lost and memory-pressure locks, descriptor push, status-list fetch, sanitized logs to the parent |
| `enclave/nsm` | enclave | `NSM_IOCTL_REQUEST` (`_IOWR(0x0A, 0, 32)`) with `Attestation` and `DescribePCR` CBOR requests |
| `enclave/egress` | enclave | The only way out: HTTPS to an allowlist, TLS 1.3 only, per-host pinned roots, host-name verification, ALPN h2 required for HTTP/2 hosts, no redirects, shared connections per host, as many as the enclave allows (below) |
| `enclave/awskms` | enclave | KMS `GenerateDataKey`/`Decrypt` (Recipient, `RSAES_OAEP_SHA_256`) and `DescribeKey`/`GetKeyPolicy`/`ListGrants`, SigV4 signing, credentials from the parent |
| `internal/hostproto` | both | Frames (kind, id, length-prefixed fields; ≤ 64 MiB), request/reply/notification multiplexing, 16 KiB chunked writes, the egress connection header |
| `internal/vsock` | both | `AF_VSOCK` dial/listen with `golang.org/x/sys/unix` and the runtime poller; every write chunked to 16 KiB |
| `parent`, `cmd/vault-parent` | host | Control server, TCP forwarder, SQS queue and consumer, registry, leases, slots, S3, credentials, health |
| `internal/parenttest` | tests | In-memory S3/SQS/DynamoDB with the same conditional semantics |
| `internal/memberapitest` | tests | Stand-in for vettid.org `lambda/member/vault.ts` over the same DynamoDB tables and SQS queues |
| `client` (`MemberAPI`, `EnrollVia`, `UnlockVia`, `LockVia`) | apps | The member API's vault routes; `vaultctl api-enroll`, `api-unlock`, `api-lock` (dev) |

## Process model (D4): one OS process per vault

Owner decision after the first V3b review: "one process per vault, no
chance of leakage" (VAULT-PLAN D4 and §5.3, VAULT-MESSAGING 0.3.2 §12.4).

**Supervisor** (PID 1, `enclave/supervisor`): the NSM broker, the ETKs and
the outer decryption, binding and replay check of alternate-channel
requests (`enclave.Instance`), the egress (TLS, shared HTTP/2 pool), the
parent link, and the vault processes' lifecycle (`procHost`). It holds no
DEK, pepper, relay/identity/KEM/session key or plaintext state. It sees
the PIN transiently: it decrypts an enroll or unlock with the ETK, hands
the decrypted request (`enclave.Job`) to the vault's process and wipes
its copy and the decrypted buffers as soon as `Open` returns.

**Vault process** (`enclave/vaultproc`, the enclave binary re-executed
with `__vault-process`, so there is one measured image): started for an
enroll or unlock, it builds an `enclave.Core` whose dependencies all go
through its channel, generates its own ephemeral RSA Recipient key, has
the supervisor attest that key (the attestation binds only the public
key), and unwraps KMS's `CiphertextForRecipient` itself; derives the DEK;
runs the vault manager and every feature handler; builds and signs its
relay requests (the relay key never leaves it); encrypts its state. It
exits on lock, so all of its memory is released; this closes the
"secrets left in the Go heap after lock" gap of the goroutine design.
The §11.10.7 key-policy check runs here too (it is the process that
decides to seal; the KMS answers it checks are TLS-authenticated public
data, so nothing is gained by checking in the supervisor, and the vault
process then trusts no verdict from outside).

**Channel** (`internal/vaultipc` over `hostproto` frames on a socketpair,
version "1"):

| Direction | Kind | Fields | Scope enforced by the supervisor |
|---|---|---|---|
| sup → vault | `Open` | version, instance_id, PCR0–2, job (9 fields) → ok, result, running | once per process |
| sup → vault | `Lock` | → ok \| split_brain | |
| vault → sup | `StoreGet` / `StorePut` / `StoreDelete` | key, data, if_match | `vaults/<own id>/…` and the member's own index object read/write; the member's previous vault (from the index, at enrollment) read-only |
| vault → sup | `AttestRecipient` | RSA public key (DER) | RSA 2048–4096 only, no user_data or nonce (a vault cannot obtain an attestation that could forge an ETK descriptor) |
| vault → sup | `AttestVault` | vault bundle, nonce | only while an enrollment is being opened; the supervisor computes user_data |
| vault → sup | `KMS` | op, key ARN, a, b | ops GenerateDataKey, Decrypt, DescribeKey, GetKeyPolicy, ListGrants; ARN in the pinned namespace |
| vault → sup | `HTTP` | method, URL, headers, body | https to the relay host(s) only, port 443, GET/POST/PUT/DELETE; a signed request must verify (relayauth) under the one relay key this process has used |
| vault → sup | `StatusList` | → list, fetched_at | |
| vault → sup | `Lifecycle` (notification) | event, vault_id, … | own vault_id only |
| vault → sup | `Log` (notification) | level, message, k/v | tagged with the vault id |

Every other kind is answered `denied`. `vault.Unlocked()` counts
DEK-holding managers per process; the host-stack tests assert the
supervisor's count does not move while vaults are unlocked.

**Hardening applied per vault process:**

- own uid and gid (`UIDBase` + slot, release base 200000), no
  supplementary groups (needs root: PID 1 in the enclave is);
- `PR_SET_DUMPABLE 0` (set in the process before it reads anything) and
  `RLIMIT_CORE 0`; non-dumpable processes cannot be traced or have their
  `/proc/<pid>/mem`/`environ` read, even by their own uid (tested);
- seccomp filter (`internal/seccomp`, ~60 lines, `PR_SET_NO_NEW_PRIVS`,
  TSYNC): `socket`, `socketpair`, `ptrace`, `process_vm_readv/writev` →
  EPERM, foreign architecture → kill. Justification: AF_VSOCK is not
  namespaced, so without it a vault process could open its own connection
  to the parent's control port; the process needs no socket beyond its
  inherited channel. Release builds exit if the filter cannot be
  installed;
- no inherited descriptor but the channel (fd 3; Go opens everything
  close-on-exec), stdin/stdout/stderr on `/dev/null`, working directory
  `/`, environment `GOMEMLIMIT`, `GOMAXPROCS=2`, `GOTRACEBACK=none` only;
- rlimits: `RLIMIT_AS` 4 GiB (Go needs headroom for its arenas),
  `RLIMIT_NOFILE` 64, no core files; `GOMEMLIMIT` 512 MiB;
- `PDEATHSIG SIGKILL` and its own process group; a closed channel also
  ends it.

**Supervisor:** `PR_SET_DUMPABLE 0`; `/dev/nsm` chmod 0600 (only root,
the supervisor, opens it); Yama `ptrace_scope` 3 where the kernel has it.

**The enclave's kernel (release builds only, `Config.OwnKernel`):**
before it reaches the parent the supervisor writes `0` to
`/proc/sys/user/max_user_namespaces` and `1` to
`/proc/sys/kernel/unprivileged_bpf_disabled`, and reads both back.

- The pinned kernel (4.14.256) is built with user namespaces. In one, an
  unprivileged process is root with every capability over the
  namespaces it creates with it: it can mount file systems, cgroup
  hierarchies among them. That is a large part of the kernel that a
  vault process has no use for, and it is where flaws of this kernel
  generation sit that let such a process run a program as real root (the
  cgroup v1 `release_agent` file was writable from such a namespace until
  4.14.266). A program run that way is outside the vault processes' uid,
  limits and system-call filter.
- With the limit at 0 nobody, root included, can create a user
  namespace: `clone` and `unshare` with `CLONE_NEWUSER` answer ENOSPC.
  The limit belongs to the initial user namespace and only a process
  with `CAP_SYS_RESOURCE` there may write it; a vault process has no
  capability. Nothing in the enclave uses a user namespace: the
  supervisor starts vault processes with a uid, a gid and a process
  group, and neither the Go runtime nor `os/exec` creates namespaces
  unless asked to.
- If the limit cannot be set or does not read back as 0, the supervisor
  logs an error and starts no vault process (every enroll and unlock
  fails). A failed bpf setting is logged and reported only: the calls it
  closes are also none a vault process makes.
- Development binaries and tests never write either file (they run on
  a machine they share). The self-test checks both settings from the
  supervisor and the refusal from inside a vault process
  (docs/SMOKE.md).
- `perf_event_paranoid` is left alone: its default, 2, is the strictest
  value this kernel knows.

**Locks:** owner request, memory pressure (least recently active vault
while available memory is under 15 %), the vault cap, a lost lease, a lost
parent and shutdown send `Lock` (flush, `vault.locking`, exit); a process
that does not answer within 60 s is killed. A process that detects a
split brain zeroizes and exits (code 3) without flushing; the supervisor
reports it to the parent (`Stopped split_brain`), which releases the
lease if it is still its own.

**Not done (future):** a per-handler CPU-time limit (RLIMIT_CPU would
count the whole process lifetime); a seccomp allow list; a read-only,
empty root for vault processes (the enclave's rootfs is already
read-only in practice, and they own no files).

**To confirm on hardware (V5):** that the Nitro enclave kernel has
`CONFIG_SECCOMP_FILTER` (release vault processes refuse to run without
it), `/proc` mounted (re-exec via `/proc/self/exe`), setuid/setgid to
unprivileged ids, and Yama (optional).

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
- **Parent unreachable** (§12.3; owner decision H3 of 2026-10-12, S11;
  VAULT-HOST-PROTOCOL §13 point 1). Until S10 the 120 s ran from the loss
  of the control connection, so a parent that stayed connected and did
  nothing (hung, stopped, dishonest) was never unreachable. Now:
  - *The rule.* One clock: the time since the parent's last `Ping`
    (`link.heard`). `maintain` checks it every 10 s (`checkParent`), and
    at more than 120 s (`Config.DownLock`) with a vault running it locks
    every vault. Whether there is a connection does not enter into it,
    and a new connection does not start the count again: only a `Ping`
    does, counted when it is read, whatever the answer. Without a
    connection there are no pings, so the old rule is contained in this
    one: a lost parent has its vaults locked 120 s after its last ping,
    which is up to 20 s (one ping interval) sooner than before.
  - *Only while a vault runs.* With no vault running the count starts
    again at every check: there is nothing to lock. A vault that is
    unlocked before the parent's first ping (after the enclave's start,
    after a new session: the parent pings when the descriptor arrives,
    behind whatever table writes it has queued, and then every 20 s, and
    it forwards queue messages meanwhile) then has the whole 120 s, to within the 10 s of the check, instead of being locked
    at once. A parent cannot turn this into a way round the rule: the
    count only starts again when every vault is locked. And not under a
    parent that was found unreachable: it stays so until it pings, so a
    vault that turns up under it (an unlock that was half way when the
    others were locked) is locked by the next check, within 10 s.
  - *What a ping proves.* That the peer of the socket is alive and reads
    and writes. Not that it renews leases: the enclave cannot see the
    lease table. A dishonest parent can ping and renew nothing, as it
    could keep the connection open before; what stops two instances
    writing one vault is still the conditional state write, not this
    rule. The rule is for the parent that has hung or been stopped.
  - *Locking, once the parent is found unreachable* (`checkParent`).
    Three things, so that it takes seconds whatever the parent does and
    however many vaults run. (1) The parent is marked gone
    (`link.gone`): until its next `Ping` is read, every call to it fails
    at once (`errDown`), connection or not. Without that, a parent whose
    process lives and whose path to the store does not (it stops pinging
    because its registry write hangs, answers the hello of a new
    connection, and answers no store request) held each vault's final
    flush for 60 s. (2) The connection is closed, which frees the calls
    that wait on it; `Run` dials again as after any loss, and a hello
    does not make the parent reachable. (3) The vaults lock all at once
    (`procHost.LockAllWithin`), not one after another and not behind a
    queue request that is being processed, and a process that has not
    locked after 10 s (`lockAllWithin`) is killed. So **every vault has
    locked or been killed within 10 s of the check that found the parent
    unreachable**: 120 to 130 s after the last ping for the check, 140 s
    at most for the last vault. A vault's lock still does what a lock
    does (flush, `vault.locking`, exit); the 10 s are for the relay
    requests in it. With the relay reachable a lock is a few round trips
    (what is left in the outbox, then one `vault.locking` deposit for
    each of the owner's devices) and vaults lock. With the relay path
    out as well, each of those requests waits for the egress (10 s for
    the parent's connect, or 15 s + 10 s until a silent shared connection
    is given up, 75 s at most), so the vault is killed at 10 s instead:
    its state write had already failed and its devices could not have
    been told. The order inside a vault's lock is not changed here.
  - *The parent is told.* It counts a vault as running, and renews its
    lease, until it hears otherwise, and here it would not: a vault's own
    `locked` finds no connection and a killed process sends nothing. The
    supervisor keeps the vaults it ended (`link.stopped`) and sends a
    `Stopped` for each when the parent's next `Ping` is read, before any
    call is let through again: `locked`, `split_brain`, or `error` for a
    killed one. The parent drops the vault from its running set and
    releases the lease if it still held it, unless an enroll or unlock
    of that vault is under way and has taken the lease (as for `locked`):
    the report is of the run before. The `Ping` itself is counted before
    the reports are queued, so a full queue delays the reports and the
    calls, not the count. A report counts as told only when it has been
    written to the connection and that connection is still the link's
    (`Conn.Flush`): one that was merely queued may sit on a connection
    that has ended. Until every report is told they are kept and the
    parent stays unreachable; the next connection's `Ping` tries again,
    so a report may be written twice, which is the same to the parent as
    once because no vault can open in between. A report whose vault runs
    again when it could be told is dropped. Written is not read: a
    connection that ends after the write and before the parent has read
    it still loses the report (the open point below). They are kept in memory: an
    enclave restart loses them, and the parent then drops everything
    anyway (a new boot id).
  - *What a vault loses.* Nothing that was stored. The final flush fails
    before anything is sent, so the last durable state is the last
    successful state write, and what the vault had taken from the relay
    since then was not acked and is still there (§8.3). A failed flush is
    not a conflict: nothing is zeroized as a split brain (`persist`
    returns `ErrSplitBrain` only for `store.ErrConflict`), and the next
    unlock reads the state anew. A killed process is the same without
    `vault.locking` to its devices.
  - *Warnings.* The enclave logs "no ping from the parent: every vault
    is locked if none comes" at half the time (60 s) while a vault runs,
    once for each time the count started, with the seconds and the number
    of vaults and no vault's name. The parent logs "heartbeat took longer
    than its interval" when a ping and its registry write take more than
    20 s.
  - *Clock.* `Config.Now` is `time.Now` in the release build, and both
    readings carry Go's monotonic clock: a step of the wall clock does
    not move the count.
  - *The reader at its limit.* At 128 of the parent's requests in flight
    the reader stops reading (`hostproto.MaxInflight`; VAULT-HOST-PROTOCOL
    §13 point 6, not changed here), so a ping the parent did send would
    wait in the socket. The parent of this repository has about a dozen
    in flight at most. The connection tells the link when its reader
    waits (`hostproto.Options.OnWait`), and that time is not counted as
    silence, up to 120 s of it between two pings: a reader that never
    goes on delays the lock to 240 s and no further.
  - *Write timeout.* A frame to the parent that is not written within
    60 s (`writeTimeout`, per frame) ends the connection, like any write
    error; the clock above then runs as for any lost connection. 60 s is
    the time a call waits for its answer: a parent that is only slow (its
    own reader waits while it handles 128 store requests, or while its
    table writes are 1,024 behind) is not cut off before the calls it is
    slow with have failed anyway. The parent's own connection, and the
    supervisor's connections to its vault processes, are as before (no
    timeout).
  - *Notifications when the outgoing queue (256 frames) is full.* `Log`
    is dropped and counted (`link.logRecord`; "log records dropped: the
    parent was not reading" with the count since the start, logged by
    `maintain` when it grew): logging never waits for the parent, and a
    lost record loses an operator a line. `Lifecycle`, `Stopped` and
    `Descriptor` wait as before (`link.notify`), because the parent acts
    on them: its set of running vaults and so its lease renewals and
    releases, the vault table (app key, backup bit, name requests, the
    clone alarm's email), the split-brain count, the registry row. The
    wait is now bounded by the write timeout: either a frame leaves and
    there is room, or the connection ends. What was queued on a
    connection that ends is lost, as it always was; the parent keeps its
    running set over a `resume`, so a `locked` lost that way leaves it
    renewing a lease for a vault that is not running until it restarts
    (not new, and not changed here: a report of the running set at the
    hello would close it).
  - *The parent's side.* The parent pings before it writes the registry
    row, on one ticker (`Parent.publish`): that is what ties a ping to
    the registry, and it stays. The row's write now has 10 s
    (`registryWriteTimeout`): a table that does not answer (the SDK's
    client has no response timeout) no longer holds the ticker, and the
    next tick pings again, so a parent whose registry is unreachable
    keeps its vaults unlocked as it did before this rule.
  - *Leases, when the table does not answer.* With the pings going on,
    locking is then the parent's to do, by "lease lost" (§11.1): a
    renewal that got no answer used to wait for ever, on the first vault,
    and nobody was told while the leases ran out. Now a renewal is given
    up after 10 s (`leaseRenewTimeout`), and never later than the moment
    the first lease is lost (15 s before it ends); once one was given up,
    the rest of that pass calls nothing and judges every lease by its age,
    so a pass is one wait however many vaults run; after a failed pass
    the next comes in 5 s, not 60. The enclave is told `LeaseLost` for
    each vault from 15 s before its lease ends. **Limit:** it is told one
    vault at a time and waits for each lock (up to 60 s), as before, so
    with hundreds of vaults the last ones are told after their leases
    ended; the conditional state write still guards those. A follow-up:
    one request that locks them together.
  - *Other calls of the parent that have no time limit of their own*
    (not changed; none of them decides a lock): the queue's long poll,
    message delete, manifest read, slot write and lease acquire, read and
    take-over on the request path (a hang holds one of the 8 request
    workers; the message comes back after its visibility time); the
    store get, put and delete and the credentials the enclave asks for
    (the enclave gives up after 60 s; the parent's handler stays, one of
    128); the sweeper's list, heartbeat read and queue delete (the sweep
    stops); the queue's creation at start. With a limit already: the
    lifecycle and lease-release writes (30 s), the registry row's delete
    (10 s; 60 s at shutdown). The parent calls no KMS.
  - *Versions.* No wire change. The S10 parent (`release/staging/10`)
    sends `Ping` every 20 s exactly as this one does (from the heartbeat
    ticker, and once when a descriptor arrives), so a new enclave with
    an old parent behaves as with a new one, less the 10 s on the
    registry write: an S10 parent whose table hangs stops pinging and has
    its vaults locked. A new parent with an S10 enclave: the parent's
    changes are a timeout on its own table write and a log record;
    nothing the enclave sees differs. A parent that is restarted answers
    the next hello `fresh`, and the enclave locks every vault then, as
    before. `deploy/host/` is not touched. The development enclave's
    `-down-lock` defaults to 30 s: with it the parent's `-heartbeat` has
    to be well under 30 s (devstack 10 s, the integration test 2 s).
  - *Open: events lost with a connection.* What was queued on a
    connection that ends is lost, and so is a lifecycle event raised
    while there is none; the parent keeps its set of running vaults over
    a `resume`. A `locked` lost that way leaves the parent renewing the
    lease of a vault that does not run until the parent restarts. The
    vaults ended by the lock above are told (`Stopped`, above), so the
    running set and the leases come right; what the `locked` event
    carries besides (app key, backup bit) is not sent again, and any
    other event lost with a connection is still lost. For the member:
    nothing while unlock requests route to the instance that holds the
    lease, which opens the vault again; if that parent's heartbeat is
    also stale for over 90 s, another instance may take the lease. To
    close it: the enclave reports its running set at the hello (a wire
    change, for a later release).
  - *Spec edits this needs* (vettid.org, not made here): VAULT-MESSAGING
    §12.3, the row "Parent unreachable for 120 s" in its final wording
    (the rule; "only while a vault runs"; the 10 s check; every vault
    locked or killed within 10 s more; what a vault loses), and §11.1
    (a renewal without an answer counts as failed after 10 s);
    VAULT-HOST-PROTOCOL §3.4 (the write timeout; `Log` dropped when the
    queue is full, the others wait; the reader's wait not counted), §4.3
    (the rule; no call until the next `Ping`; the connection closed; the
    hello changes nothing; unreachable until a `Ping` even with no vault
    running), §6.2 (`LeaseLost` also when renewals get no answer), §6.3
    (a ping is counted when read; the row's write has 10 s), §7.3
    (`Stopped` also for the vaults ended while the parent was
    unreachable, sent at its next `Ping`; `error` for a killed one), §7.4
    (the new records), §9 (120 s without a `Ping`; 60 s per frame; 10 s
    to lock; 10 s registry write; 10 s lease renewal, 5 s retry), §11.3
    (`Ping`: not asking now locks every vault; the control connection
    kept open and silent), §12 (new: the parent MUST send `Ping` at least
    every 30 s and MUST NOT let a table write delay the next; the parent
    MUST treat a lease renewal without an answer as failed; the enclave
    MUST lock every vault after 120 s without one, MUST NOT count a
    connection or a hello as a ping, and MUST NOT call a parent it found
    unreachable before its next `Ping`), §13 point 1 closed and a new
    point for the lost events and for `LeaseLost` one vault at a time.
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
  traffic use shared HTTP/2 connections.
- **The enclave decides how many HTTP/2 connections a host gets**
  (VAULT-RELAY-SCALING 0.1.1, D3; `enclave/egress/h2pool.go`). A vault's
  long-poll holds one stream. Requests fill the first connection that has
  a free stream, so one connection carries every vault until its streams
  are in use (128 at the relay's load balancer); only then is another
  opened, one at a time (concurrent first requests wait for it instead of
  each dialing, which would briefly give every vault its own connection:
  `egress.TestSharedHTTP2`). The pool is built on `net/http`'s
  `ClientConn` (Go 1.26), not on `http.Transport`'s own pool, which opens
  as many connections as the host's announced limit makes it and does not
  report that limit. 900 held long-polls use 8 connections, and a quick
  request beside them does not wait (`egress.TestGrowthAtStreamLimit`,
  to be run on every Go update).
  - *Bounds.* At most 16 connections per host (2,048 streams at 128,
    above the 1,024 vault processes). No second connection when the host
    announces fewer than 32 streams, or has not announced any: a new
    connection carries one request until its limit can be read (the
    library does not say when SETTINGS arrived), fewer than 32 after a
    second. Connections are opened at 2 a second after a burst of 32,
    failed dials included.
  - *Connections the host is closing* (GOAWAY: no new requests, below
    its limit) do not count toward the 16 for 30 s, while their requests
    end, and are then closed (a long-poll ends in 25 s; a request still
    on one fails and is sent again by the vault). Only 16 connections are
    let off the count in any 5 minutes; further ones count while they
    close. So there can be up to 32 connections for 30 s, once in 5
    minutes, and 16 otherwise, also against a host that closes its
    connections, or lowers their stream limit once they are full, in
    order to be given more. A full connection that is closing cannot be
    told from a full one until one of its requests ends.
  - *At a bound* requests wait for a stream, oldest first, until their
    own deadline (75 s for a relay request), and are counted. The
    longest-waiting request looks again every second even if nothing
    woke it (the library does not report every change).
  - *A dial that fails* fails the request that started it and every
    request that was waiting when it started; later ones dial again.
  - *Connections that stop answering.* Every connection is pinged after
    15 s without a frame from the host and closed if the ping is not
    answered in 10 s (`http.HTTP2Config`); a busy connection is never
    pinged. Without it a connection whose host was gone kept its
    timed-out requests' streams for good (the library holds a cancelled
    stream until a ping is answered) and its place among the 16. A
    connection that answers pings but no request for 90 s is closed too.
  - *A host that announces exactly 100 streams.* 100 is what the library
    assumes before SETTINGS arrive, and it does not say when they did
    (neither `ClientConn` nor its state hook), so such a connection is
    trusted only once it has answered a request. If its first requests
    are all long-polls it carries 1, after a second 31, until one is
    answered (up to 25 s), and no other connection is opened meanwhile.
    The relay's and the push gateway's load balancers announce 128;
    android.googleapis.com announces 100 and its first request is quick.
    A relay front end that announced 100 would show as `relay_streams`
    0 or 100 with `relay_waiting` above 0 in the metrics record.
  - *Re-sending.* A request the host did not process (a GOAWAY that
    names it, REFUSED_STREAM, a connection that stopped taking requests)
    is sent once more, as the library's pool did. Any other failure goes
    back to the vault; its relay client signs and sends again.
  - *Per vault.* A vault process has at most 8 relay and push requests
    in flight (`maxVaultEgress`); further ones wait within their own 75 s
    and are then answered an error. A vault needs its long-poll, one
    request of its run loop and a push wake. Without the limit 16
    processes could hold all 2,048 streams. KMS requests are not limited
    this way (HTTP/1.1, as before).
    A process that reaches its limit is counted once, for the instance
    (`relay_vault_limit` in the Stats reply and in the parent's metrics
    record, not a metric); it is not logged, because the supervisor's log
    goes to the parent and would say which vault it was.
- **Metrics** (VAULT-RELAY-SCALING §6). Every minute the parent asks the
  enclave for its relay counts (`hostproto.KindStats`; the enclave
  answers from a snapshot at most a second old, and asking changes
  nothing) and logs one record in CloudWatch's embedded metric format,
  namespace `VettID/Vault`, dimension `InstanceId` only: `UnlockedVaults`,
  `EgressOpen<Class>` and `EgressOpened<Class>` (`Relay`, `KMS`, `Push`,
  `Other`), `RelayRequestsInFlight`, `RelayStreamWaitMax` (ms; the
  longest in the current minute and the one before), `RelayRequestErrors`,
  `RelayGrowthRefused`. Counters are the increase since the record
  before.

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
  absent, expired or own, or take over the lease of an instance that is
  not live (no heartbeat for 90 s), conditional on the exact old lease
  (0.3.2); renew every 60 s (length 180 s) while the
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
- Process model: `supervisor.TestChannelScope` (a vault process cannot
  reach another vault's objects, another member's index, KMS keys outside
  the namespace, KMS or other hosts over HTTP, user_data attestations, or
  the supervisor-only kinds), `vaultproc.TestServeRefusesMalformedOpen`,
  `vaultproc.TestHardenNotDumpable`, `seccomp.TestFilter`,
  `enclave.TestJobRoundTrip`/`FuzzParseJob`, `vaultipc.FuzzDecodeHeaders`,
  and `e2e.TestVaultProcessIsolation` (two vaults in two processes, no DEK
  in the supervisor, processes not dumpable, killing one leaves the other
  running, the killed vault reopens in a new process).
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
- A vault whose run loop ends on an error is locked (before, it stayed in
  memory, unlocked and idle); in a vault process the process then exits.

## Spec and plan questions

All resolved in VAULT-MESSAGING **0.3.2** (vettid.org docs PR
"Docs: Vault Messaging 0.3.2; D4 process per vault"), with the owner's
decisions: the lease takeover (1) is approved and implemented
(`Tables.TakeoverLease`, conditional on the exact old lease); D4 (7) is
a process per vault, not goroutines. The original questions, for the
record:

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
