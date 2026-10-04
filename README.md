# vettid-vault

The VettID vault: the code that runs inside an AWS Nitro Enclave, holds a
member's keys and vault state while it is unlocked, and talks to the
member's devices, agents and connections over the
[VettID relay](https://github.com/vettid/vettid-relay).

## Status

**Phase V3b — supervisor, parent and AWS transport.** On top of the V1
crypto and wire library, the V2 vault runtime and the V3a alternate
channel, the enclave now runs as a supervisor plus one OS process per
unlocked vault (VAULT-MESSAGING 0.3.2 §12.4: the supervisor never holds a
vault's DEK or keys) with the real NSM, talks to its parent over vsock, and
reaches the relay, AWS KMS and Google's attestation status list only
through TLS it terminates itself against pinned roots, with its own SigV4
KMS client. The parent (outside the trusted code base) runs the
instance's SQS queue, registry heartbeat, vault leases, response slots and
the S3 vault data bucket. An integration test runs it all against
LocalStack, the real relay and a stand-in for the member API
([VAULT-PLAN](https://github.com/vettid/vettid.org/blob/master/docs/VAULT-PLAN.md)
§4 V3). Nothing here is deployed yet (V5).

### Enclave shell, parent and transport (V3b)

| Package / command | What it does |
|---|---|
| `cmd/vault-enclave`, `enclave/supervisor` | PID 1 in the enclave: control connection to the parent, ETKs and the outer decryption of the alternate channel, the vault processes and their scoped channels, lease-lost and memory-pressure locks, status-list fetch, sanitized logs |
| `enclave/vaultproc`, `internal/vaultipc`, `internal/seccomp` | One vault's process (the same binary re-executed): unseals with its own KMS Recipient key, runs the manager and features, signs its relay requests; its channel to the supervisor; its syscall filter |
| `enclave/nsm` | `/dev/nsm`: attestation documents and PCRs (CBOR over the NSM ioctl) |
| `enclave/egress` | The enclave's only egress: HTTPS to an allowlist, TLS 1.3 against per-host pinned roots, shared HTTP/2 connections |
| `enclave/awskms` | AWS KMS JSON API with in-repo SigV4 and Recipient attestation |
| `internal/hostproto`, `internal/vsock` | Enclave ↔ parent framing (16 KiB chunked writes) and AF_VSOCK sockets |
| `parent`, `cmd/vault-parent` | Host side: vsock control server, TCP forwarder (allowlist, port 443), SQS queue and consumer, instance registry, leases, response slots, S3 conditional writes, role credentials, health endpoint |
| `internal/parenttest`, `internal/memberapitest` | TEST-ONLY in-memory AWS backends, and a stand-in for the member API's vault routes over DynamoDB and SQS |

### Crypto and wire (V1)

| Package | Spec | What it does |
|---|---|---|
| `vms/suite` | §4, §13.4 | Suite 2: HPKE base mode (MLKEM768X25519 `0x647a`, HKDF-SHA256, ChaCha20-Poly1305) on Go's `crypto/hpke`, single-use contexts, XChaCha20-Poly1305, labels, key ids, Ed25519 helpers, downgrade rules and suite pinning |
| `vms/envelope` | §5 | v2 envelope (session and sealed modes), strict parsing, inner plaintext, padding buckets, size limits, claim-check blobs, ULIDs |
| `vms/handshake` | §6 | hs.init / hs.resp / hs.fin for pairing, connections, rekeys and reconnects; key schedule and SAS; epochs, keyrings and retention; rotation chains; reconnect-token rules |
| `vms/invite` | §6.4, §6.7 | Claim bundles, their encryption and hash commitment, QR / link payloads, invite TTLs |
| `vms/altchan` | §11 | ETK and vault `user_data`, device-attestation challenge, unlock and release-approval signing strings; requests, results and descriptors; `device_attest` / `device_assertion` wire shapes |
| `vms/vectors` | §16 | Generates and checks the test vectors |

### Alternate channel, attestation and release updates (V3a)

| Package | Spec | What it does |
|---|---|---|
| `vms/pins` | §11.2, §11.7 | Pinned vendor roots: AWS Nitro, Google hardware attestation, Apple App Attest (checked by fingerprint) |
| `vms/nitro` | §11.2, §11.3 | Nitro attestation documents: COSE_Sign1 ES384, chain, PCRs, user_data, nonce, freshness — the code apps mirror |
| `vms/manifest` | §11.10.1 | The signed release manifest: strict parsing, ECDSA P-256 over the exact bytes, pinned keys, serial rule |
| `vms/devattest` | §11.7 | Android key attestation and iOS App Attest (attestations, assertions, counters), the Google status list |
| `enclave` | §11, §11.10 | ETK lifecycle and descriptors, request binding and replay, enroll, unlock, lock, release moves, KMS sealing (`NSM` and `KMS` interfaces) |
| `enclave/keypolicy` | §11.10.7 | The sealing-key policy check as a pure function over KMS responses |
| `enclave/cms` | §11.10.2 | CMS EnvelopedData unwrap for KMS Recipient responses (RSA-OAEP-SHA-256 only) |
| `internal/cbor`, `internal/der` | — | Small strict decoders for the trusted code base |
| `internal/enclavetest` | — | TEST-ONLY fake NSM and KMS, test attestation authorities, and a `World` that plays the member API, queues and parent; never linked into release packages (`make check-tcb`) |

### Runtime (V2)

| Package | Spec | What it does |
|---|---|---|
| `vault` | §3.3, §6–§9, §12, §13.2 | The vault manager: DEK-encrypted state and sealed header (`Sealer` interface), create/unlock with backoff and rollback checks, collect loop (long-poll or WebSocket), routing by sender / recipient kid / session only, pairing, invitations, reconnects, rekeys, rotation, the issued-token registry, outbox, dedupe, response cache, ack-after-flush, lock and the split-brain guard, and the feature-handler registry |
| `vault/store` | §12.3 | Object store with create-only and version-matched writes: in-memory and local directory (S3 in V3) |
| `features/messaging` | §10 | 1:1 messages: send, deliver, receipts, history |
| `features/calls`, `vms/callwire` | §10.10 | Call signalling (offer, answer, ICE, ringing, end, history), the vault-signed ICE configuration and the device-to-device call key (V4 batch 2) |
| `features/connauth` | §10.4 | Member authentication between connections, signed with the credential key (V4 batch 2) |
| `features/items`, `features/itemspec` | §10.7, §10.8, §10.12 | The member's items (typed fields, tags, sensitivity data, secret or critical; critical values envelope-encrypted under item keys that only the Protean Credential holds), the tag registry, the profile (name, photo, `@profile` items) and share rules over tags for connections and agents, `ask` by default (V4 items) |
| `features/leash`, `vms/leashwire` | §10.11 | LEASH for the member's agents: grants, the allow/refer/refuse decision behind the runtime's `AgentPolicy` hook, `agent.request` on the items the agent's share rules include (`items.read`), initial grants at pairing, delegations signed with the credential key (V4 batch 3, V4 items) |
| `features/grants`, `vms/sharewire` | §10.12 | 1:1 grants of items between connections (from share rules, requests and actions), contents sealed to the fetching device; per-connection catalogs (V4 batch 3, V4 items) |
| `features/critical` | §10.13 | Critical-item use by a connection, with the member's password for each use (V4 batch 3, V4 items) |
| `features/actions` | §10.14 | Shared actions offered to connections by allowlist (V4 batch 3; the wallet actions in V4 batch 4) |
| `features/location` | §10.16 | 1:1 location shares with a connection: once or continuous, expiring, precision and cadence enforced by the sending vault, positions forwarded from memory (V4 batch 4) |
| `features/presence` | §9.2, §10.17 | On-demand presence pings with a per-connection policy; refusals are silent (V4 batch 4) |
| `features/wallet`, `vms/btc` | §10.18 | Bitcoin wallets: BIP86 (taproot, the default) and BIP84 accounts whose recovery phrase is a critical item, addresses without the password, PSBT signing under a signing policy as a credential operation; the member's app is the chain source (V4 batch 4; btcd libraries, vault process only) |
| `client` | §6.7, §9.1, §11 | Reference client for an app, desktop or agent: verify enclaves and manifests, enroll and unlock over the alternate channel, approve release updates, pair (with device attestation), session and rekeys, requests and events, token refresh |
| `cmd/vaultctl` | — | Test driver over `client`; dev builds (`-tags devenclave`) also create and run vaults, and enroll and unlock through an in-process enclave |
| `cmd/devstack` | — | Long-running local dev stack for app development (relay, LocalStack, parent, dev enclave, member API stand-in, vaultctl peer, control port). Dev builds only (`-tags devenclave`); without the tag it is a stub (`make check-tcb`) |
| `devenclave` | — | Dev sealer and direct create/unlock with a PIN. Every file carries the `devenclave` tag; release builds cannot compile it in (`make check-tcb`) |

The runtime follows VAULT-MESSAGING 0.2.3, which includes the body schemas
(§10.1–§10.5) and the DEK and at-rest formats (§3.3.1) settled during V2.
What V2 deliberately leaves for later is listed in
[`docs/V2-NOTES.md`](docs/V2-NOTES.md); the V3a choices, what waits for
V3b, and the spec questions raised are in [`docs/V3-NOTES.md`](docs/V3-NOTES.md).

Dependencies: the Go standard library, `golang.org/x/crypto`
(XChaCha20-Poly1305, Argon2id), and
[`vettid-relay`](https://github.com/vettid/vettid-relay)'s public
`relayclient` and `relayauth` packages (which bring
`github.com/coder/websocket` for WebSocket collect).
No new third-party dependency in V3a: CBOR, DER and CMS are parsed by small
in-repo decoders rather than a general library, to keep the enclave's
trusted code base small and strict. V3b adds none to the enclave either
(`golang.org/x/sys` for vsock and the NSM ioctl was already required); the
parent alone uses the AWS SDK for Go v2 (S3, SQS, DynamoDB, SSM for the
control-queue policy, credentials, IMDS), which `make check-tcb` keeps out of the enclave binary. V3b choices
(process model, TLS chains, protocol, spec questions) are in
[`docs/V3-NOTES.md`](docs/V3-NOTES.md).
[`docs/MUST-COVERAGE.md`](docs/MUST-COVERAGE.md) maps every MUST in §4–§6,
the V2 runtime rules of §7–§13 and the V3a rules of §11–§13 to the tests
that cover them.

## Test vectors

[`testdata/vectors/`](testdata/vectors) holds the §16 vectors as JSON:
`keys`, `hpke`, `envelope_sealed`, `envelope_session`, `handshake` (every
key-schedule value, SAS and both signatures), `invite`, `altchan` (0.3.0
unlock signing string and 12,288-byte requests) and `release` (manifest
signature and release approval, equal to §16). All
keys come from fixed, public, **test-only** seeds. Every file states its
inputs, including the values §16 leaves open.

- `go test ./vms/vectors` re-derives every value from the receiving side.
- `go test -tags vmsvectors ./vms/vectors` regenerates the files through
  the library's sending code, with every random draw scripted, and requires
  identical bytes. `make vectors` (`go generate ./vms/vectors`) rewrites them.
- Deterministic randomness exists only in `vmsvectors` builds; `make
  check-tcb` fails if it is linked into a library package.

**Cross-implementation checks are still pending.** The vectors are
produced by Go's `crypto/hpke` and cross-checked against an independent
in-repo HPKE key schedule, but have not yet been reproduced with Apple
CryptoKit (X-Wing) or BouncyCastle. Until they are, treat the
MLKEM768X25519 interoperability claim as unverified.

## Spec clarifications

Where VAULT-MESSAGING 0.2.1 was silent or ambiguous (the `identity.rotate`
format, blob layout, per-purpose handshake fields, padding strictness,
encodings, device attestation fields), the choices made here were folded
into the spec as **0.2.2**; the code follows 0.2.2.

## Development

Requires Go 1.26 or later. `make e2e` builds the relay with
`go install github.com/vettid/vettid-relay/cmd/relay@<go.mod version>` into
the user cache directory (network access on first run).

A dev vault by hand (dev build of vaultctl):

```sh
go build -tags devenclave -o bin/vaultctl ./cmd/vaultctl
bin/vaultctl -state app.json init -role app -name phone -relay http://localhost:8080
ID=$(bin/vaultctl -state app.json vault-create -store ./dev-vault -relay http://localhost:8080 -pin 246802 -app app.json)
bin/vaultctl vault-run -store ./dev-vault -vault-id $ID -pin 246802 &
bin/vaultctl -state app.json enroll-wait
bin/vaultctl -state app.json request vault.status
```

The alternate channel by hand, with an in-process enclave (TEST-ONLY
fakes; dev build):

```sh
bin/vaultctl -state app.json init -role app -name phone -relay http://localhost:8080
bin/vaultctl -state app.json altchan-enroll -store ./dev-ac -relay http://localhost:8080 -guid me -pin 135791 -platform ios
bin/vaultctl -state app.json altchan-unlock -store ./dev-ac -relay http://localhost:8080 -guid me -pin 135791 &
bin/vaultctl -state app.json request vault.status
# a release move: run releases 3 and 4, approve 4
bin/vaultctl -state app.json altchan-unlock -store ./dev-ac -relay http://localhost:8080 -guid me -pin 135791 -releases 3,4 -approve 4
```

The whole stack (V3b) is easiest through the integration test, which
builds `vault-parent`, the dev `vault-enclave` and `vaultctl`, starts the
relay behind a TLS front with the test root, LocalStack, and the member
API stand-in, and drives them with `vaultctl api-enroll`, `api-unlock`,
`api-lock` and `request`:

```sh
make integration   # docker compose up LocalStack (1.5 GiB cap), run, tear down
```

### Local dev stack for app development

`cmd/devstack` runs the same stack as a long-lived service that a phone
reaches over `adb reverse` (vettid-android's `devStack` build and its
instrumented tests): the real `vettid-relay` binary at the `go.mod`
version, LocalStack, `vault-parent` (release build, TCP mode), the dev
`vault-enclave` (fake NSM and KMS, TEST-ONLY roots, test release 3), the
member API stand-in and a second member's vault enrolled with `vaultctl`
(the peer). Every key is TEST-ONLY; nothing survives a restart.

```sh
# from a checkout
go run -tags devenclave ./cmd/devstack -dev-device-policy device-policy.json
# or by commit, without a checkout
go run -tags devenclave github.com/vettid/vettid-vault/cmd/devstack@<commit> -dev-device-policy device-policy.json
adb reverse tcp:18080 tcp:18080; adb reverse tcp:18081 tcp:18081; adb reverse tcp:18082 tcp:18082
```

It builds the binaries from its own source tree (the checkout, or the
module cache for `@<commit>`; `-src DIR` overrides) into `-data DIR`
(default `$XDG_CACHE_HOME/vettid-devstack`), writes `run/ready.json`
when up, keeps `run/logs/` (`relay.log`, `parent.log`, `enclave.log`,
`compose.log`; request lines on stderr carry method, path and status
only) and stops on SIGINT or SIGTERM, tearing everything down. `go run`
does not forward SIGTERM to the program, so under `go run` the stack also
stops when the `go` process exits (`kill <go run pid>` works); a script
may instead `go build -tags devenclave -o devstack ...` and signal the
binary. One stack per data directory.

| Flag | Default | |
|---|---|---|
| `-relay-port` | 18080 | the relay, plain HTTP; tokens name it `https://relay.vettid.test`, so clients map that origin to this port |
| `-api-port` | 18081 | the member API stand-in (`Authorization: Bearer <user_guid>`) |
| `-ctl-port` | 18082 | dev control (below) |
| `-dev-device-policy` | — | extends the dev enclave's device-attestation policy (below) |
| `-localstack` | — | an external LocalStack endpoint; without it, `integration/docker-compose.yml` is started (one container, 1.5 GiB cap) and stopped on exit, and an already running LocalStack on :4566 is refused rather than shared |
| `-compose` | `podman compose`, else `docker compose` | compose command |
| `-wait-free-mem` | 8 | refuse to start unless this many GB of memory are available (0: no check); `-mem-wait 10m` keeps re-checking |

Everything listens on 127.0.0.1. Child processes run with
`GOMAXPROCS=2` and builds with `-p 2`. The control port (TEST-ONLY):

| Endpoint | |
|---|---|
| `GET /dev/health` | `{"ok": true}` |
| `GET /dev/info` | what `ready.json` holds |
| `GET /dev/trust` | the test Nitro root (DER, base64), the test manifest keys (SPKI DER, base64), the relay URL, and the dev device policy in force (`null`: TEST policy only) |
| `POST /dev/peer/request` | `{"type": T, "body": {...}}`: `vaultctl request` on the peer; answers the vault's response |
| `POST /dev/peer/event` | `{"type": T, "match": {k: v}, "timeout_s": N}`: waits (default 90 s, at most 300) for a peer event of type T whose body matches; others are kept for later calls |

**Dev device policy.** The dev enclave verifies device attestation
against the TEST policy (`internal/enclavetest.Policy`: the TEST Android
CA, `com.vettid.app`, the TEST signing digest, the TEST GrapheneOS boot
key). `vault-enclave -dev-device-policy FILE` (devenclave builds only;
release builds do not contain the flag, `make check-tcb`) adds to it, so
a real phone's Keystore attestation can enroll against the dev stack:

```json
{
  "google_attestation_roots": true,
  "android_packages": ["com.vettid.app.dev", "com.vettid.app.devstack"],
  "android_signers_sha256": ["<SHA-256 of the debug signing certificate>"],
  "grapheneos_boot_keys": true
}
```

`google_attestation_roots` adds the pinned Google Hardware Attestation
roots (`pins.GoogleAttestationRoots`, including Key Attestation CA1, the
2025 EC root); `android_roots_pem` adds further self-signed CA roots (PEM
strings); `android_packages` are accepted besides `com.vettid.app`;
`android_signers_sha256` are 64 hex digits or keytool's colon-separated
form (`keytool -list -v -keystore ~/.android/debug.keystore -storepass
android | grep SHA256`); `grapheneos_boot_keys` adds the pinned GrapheneOS
verified boot keys (`pins.GrapheneOSVerifiedBootKeys`) for
`verifiedBootState` SelfSigned. Parsing is strict (no unknown or duplicate
members, at most 32 KiB, bounded lists) and the policy must add
something; it never removes the TEST entries, so TEST attesters keep
working. The status list stays the stack's empty one.

The stack's own test runs with `make integration`.

The enclave image is built reproducibly from `Dockerfile.enclave`
(`scripts/build-eif.sh` turns it into an EIF and writes
`measurements.json`); the hardware smoke test (`vault-parent -selftest`)
is described in [`docs/SMOKE.md`](docs/SMOKE.md).

On a release host, `vault-parent` runs under systemd with the units and
scripts in [`deploy/host/`](deploy/host/README.md), which vettid.org's
release AMI installs. It needs `-queue-policy-param`, the SSM parameter
holding the instance queue's access policy
(`/vettid-org/<stage>/vault/control-queue-policy`), and exits before
creating anything if that parameter is missing, empty or invalid (fail
closed); only `-selftest` runs without it.

Releases are built by the `release` workflow (two clean arm64 builds with
a pinned nitro-cli toolchain, compared byte for byte, attested) and
checked, signed and published as described in
[`docs/RELEASING.md`](docs/RELEASING.md), which also explains how anyone
can rebuild a release and match its PCRs (`release/rebuild.sh`), and the
compatibility matrix that keeps live releases working. `vaultctl keycheck`
runs the enclave's §11.10.7 check on a live release key; `vaultctl
manifest` renders, checks and signs release manifests.

Release constants (VAULT-MESSAGING 0.10.0 §11.10.8) are per channel:
`enclave/releasecfg/prod.json` and `staging.json` are committed and
embedded by the build tag `vettid_channel_prod` / `vettid_channel_staging`,
which `CHANNEL=prod|staging scripts/build-eif.sh` selects (default `none`:
no constants, the smoke-test image, which refuses every enrollment and
unlock). The build refuses a channel file with a `TODO-…` placeholder or a
missing value (`go run ./cmd/releasecfg check prod`); the production
values wait for owner decisions O1 (vault account), O3 (manifest keys) and
O8 (Android signing digests).

```sh
make test      # go test ./..., the vector regeneration check, `make channels`
make channels  # each channel's embedded constants and enclave build
make race      # the same under -race
make lint      # go vet + staticcheck (pinned), default and vmsvectors builds
make check-tcb # no vector-only, dev-enclave or test code in release packages;
               # no AWS SDK or parent in the enclave binary; cmd/devstack and
               # -dev-device-policy only in devenclave builds
make e2e       # runtime + client against the real relay binary (race),
               # and the parent + supervisor in process
make fuzz      # every fuzz target, FUZZTIME executions each (default 50000x)
make vectors   # regenerate testdata/vectors
make scan      # gitleaks over the full history
```

## License

[AGPL-3.0](LICENSE).
