# vettid-vault

The VettID vault: the code that runs inside an AWS Nitro Enclave, holds a
member's keys and vault state while it is unlocked, and talks to the
member's devices, agents and connections over the
[VettID relay](https://github.com/vettid/vettid-relay).

## Status

**Phase V1 — crypto and wire library.** This repository currently holds only
the library that implements the cryptography and wire formats of the vault
messaging spec: the suite 2 construction (HPKE with the MLKEM768X25519
hybrid KEM), the v2 envelope, and the session handshake. The vault runtime,
supervisor, parent and enclave image come in later phases
([VAULT-PLAN](https://github.com/vettid/vettid.org/blob/master/docs/VAULT-PLAN.md)
§4). Nothing here is deployed yet.

| Package | Spec | What it does |
|---|---|---|
| `vms/suite` | §4, §13.4 | Suite 2: HPKE base mode (MLKEM768X25519 `0x647a`, HKDF-SHA256, ChaCha20-Poly1305) on Go's `crypto/hpke`, single-use contexts, XChaCha20-Poly1305, labels, key ids, Ed25519 helpers, downgrade rules and suite pinning |
| `vms/envelope` | §5 | v2 envelope (session and sealed modes), strict parsing, inner plaintext, padding buckets, size limits, claim-check blobs, ULIDs |
| `vms/handshake` | §6 | hs.init / hs.resp / hs.fin for pairing, connections, rekeys and reconnects; key schedule and SAS; epochs, keyrings and retention; rotation chains; reconnect-token rules |
| `vms/invite` | §6.4, §6.7 | Claim bundles, their encryption and hash commitment, QR / link payloads, invite TTLs |
| `vms/altchan` | §11 | The pure helpers §16 pins: ETK and vault `user_data`, device-attestation challenge, unlock signing string; `device_attest` / `device_assertion` wire shapes |
| `vms/vectors` | §16 | Generates and checks the test vectors |

Dependencies: the Go standard library and `golang.org/x/crypto` (for
XChaCha20-Poly1305 only). [`docs/MUST-COVERAGE.md`](docs/MUST-COVERAGE.md)
maps every MUST in §4–§6 to the test that covers it.

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

Requires Go 1.26 or later.

```sh
make test      # go test ./... and the vector regeneration check
make race      # the same under -race
make lint      # go vet + staticcheck (pinned), default and vmsvectors builds
make check-tcb # no vector-only code in library packages
make fuzz      # every fuzz target, FUZZTIME each (default 20s)
make vectors   # regenerate testdata/vectors
make scan      # gitleaks over the full history
```

## License

[AGPL-3.0](LICENSE).
