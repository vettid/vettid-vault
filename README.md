# vettid-vault

The VettID vault: the code that runs inside an AWS Nitro Enclave, holds a
member's keys and vault state while it is unlocked, and talks to the
member's devices, agents and connections over the
[VettID relay](https://github.com/vettid/vettid-relay).

## Status

**Phase V2 — vault runtime in dev mode.** On top of the V1 crypto and wire
library, the repository has the vault runtime (one manager per unlocked
vault), the first feature (1:1 messaging), a reference client for owner
devices and the `vaultctl` test driver. It runs against a real relay, with
a development sealer and direct PIN unlock standing in for the enclave and
the alternate channel, which arrive in V3 with the supervisor, parent and
enclave image
([VAULT-PLAN](https://github.com/vettid/vettid.org/blob/master/docs/VAULT-PLAN.md)
§4). Nothing here is deployed yet.

### Crypto and wire (V1)

| Package | Spec | What it does |
|---|---|---|
| `vms/suite` | §4, §13.4 | Suite 2: HPKE base mode (MLKEM768X25519 `0x647a`, HKDF-SHA256, ChaCha20-Poly1305) on Go's `crypto/hpke`, single-use contexts, XChaCha20-Poly1305, labels, key ids, Ed25519 helpers, downgrade rules and suite pinning |
| `vms/envelope` | §5 | v2 envelope (session and sealed modes), strict parsing, inner plaintext, padding buckets, size limits, claim-check blobs, ULIDs |
| `vms/handshake` | §6 | hs.init / hs.resp / hs.fin for pairing, connections, rekeys and reconnects; key schedule and SAS; epochs, keyrings and retention; rotation chains; reconnect-token rules |
| `vms/invite` | §6.4, §6.7 | Claim bundles, their encryption and hash commitment, QR / link payloads, invite TTLs |
| `vms/altchan` | §11 | The pure helpers §16 pins: ETK and vault `user_data`, device-attestation challenge, unlock signing string; `device_attest` / `device_assertion` wire shapes |
| `vms/vectors` | §16 | Generates and checks the test vectors |

### Runtime (V2)

| Package | Spec | What it does |
|---|---|---|
| `vault` | §3.3, §6–§9, §12, §13.2 | The vault manager: DEK-encrypted state and sealed header (`Sealer` interface), create/unlock with backoff and rollback checks, collect loop (long-poll or WebSocket), routing by sender / recipient kid / session only, pairing, invitations, reconnects, rekeys, rotation, the issued-token registry, outbox, dedupe, response cache, ack-after-flush, lock and the split-brain guard, and the feature-handler registry |
| `vault/store` | §12.3 | Object store with create-only and version-matched writes: in-memory and local directory (S3 in V3) |
| `features/messaging` | §10 | 1:1 messages: send, deliver, receipts, history |
| `client` | §6.7, §9.1, §11.3 | Reference client for an app, desktop or agent: enroll or pair, session and rekeys, requests and events, token refresh |
| `cmd/vaultctl` | — | Test driver over `client`; dev builds (`-tags devenclave`) also create and run vaults |
| `devenclave` | — | Dev sealer and direct create/unlock with a PIN. Every file carries the `devenclave` tag; release builds cannot compile it in (`make check-tcb`) |

Body schemas the spec does not yet define, at-rest formats, and the spec
issues found in V2 are in [`docs/V2-NOTES.md`](docs/V2-NOTES.md).

Dependencies: the Go standard library, `golang.org/x/crypto`
(XChaCha20-Poly1305, Argon2id), and
[`vettid-relay`](https://github.com/vettid/vettid-relay)'s public
`relayclient` and `relayauth` packages (which bring
`github.com/coder/websocket` for WebSocket collect).
[`docs/MUST-COVERAGE.md`](docs/MUST-COVERAGE.md) maps every MUST in §4–§6,
and the V2 runtime rules of §7–§13, to the tests that cover them.

## Test vectors

[`testdata/vectors/`](testdata/vectors) holds the §16 vectors as JSON:
`keys`, `hpke`, `envelope_sealed`, `envelope_session`, `handshake` (every
key-schedule value, SAS and both signatures), `invite` and `altchan`. All
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
ID=$(bin/vaultctl -state app.json vault-create -store ./dev-vault -relay http://localhost:8080 -pin 2468 -app app.json)
bin/vaultctl vault-run -store ./dev-vault -vault-id $ID -pin 2468 &
bin/vaultctl -state app.json enroll-wait
bin/vaultctl -state app.json request vault.status
```

```sh
make test      # go test ./... and the vector regeneration check
make race      # the same under -race
make lint      # go vet + staticcheck (pinned), default and vmsvectors builds
make check-tcb # no vector-only, dev-enclave or test code in release packages
make e2e       # runtime + client against the real relay binary (race)
make fuzz      # every fuzz target, FUZZTIME each (default 20s)
make vectors   # regenerate testdata/vectors
make scan      # gitleaks over the full history
```

## License

[AGPL-3.0](LICENSE).
