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
supervisor, parent and enclave image come in later phases (see the plan
below). Nothing here is deployed yet.

## Specifications

The specifications live in the
[vettid.org repository](https://github.com/vettid/vettid.org/tree/master/docs),
which is the **source of truth**:

- [VAULT-MESSAGING.md](https://github.com/vettid/vettid.org/blob/master/docs/VAULT-MESSAGING.md)
  — keys, the cryptographic construction, the v2 envelope, sessions,
  invitations, reconnects and pairing.
- [VAULT-PLAN.md](https://github.com/vettid/vettid.org/blob/master/docs/VAULT-PLAN.md)
  — how and in what order the vault is built.
- [RELAY-PROTOCOL.md](https://github.com/vettid/vettid.org/blob/master/docs/RELAY-PROTOCOL.md)
  and [PQC-MIGRATION.md](https://github.com/vettid/vettid.org/blob/master/docs/PQC-MIGRATION.md)
  — background.

[`docs/VAULT-MESSAGING.md`](docs/VAULT-MESSAGING.md) is a copy of the
messaging spec at the version this code implements. If it differs from the
copy in vettid.org, vettid.org wins.

## Development

Requires Go 1.26 or later.

```sh
make test      # go test ./...
make race      # go test -race ./...
make lint      # go vet + staticcheck (pinned)
make fuzz      # every fuzz target, FUZZTIME each (default 20s)
make scan      # gitleaks over the full history
```

## License

[AGPL-3.0](LICENSE).
