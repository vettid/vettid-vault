# V3a notes: alternate channel, device attestation, release updates

V3a implements the enclave side of VAULT-MESSAGING 0.3.1 §11 in process:
everything the enclave decides, with the hardware and AWS behind
interfaces. This file records implementation choices the spec leaves
open, what waits for V3b, and the runtime fixes made on the way.

## What runs where

| Concern | V3a (this phase) | V3b |
|---|---|---|
| NSM | `enclave.NSM`; TEST-ONLY `enclavetest.FakeNSM` signs real COSE_Sign1 documents under a test CA | `/dev/nsm` |
| KMS | `enclave.KMS`; TEST-ONLY `enclavetest.FakeKMS` evaluates key policies and Recipient attestation, returns real CMS envelopes | HTTPS client with SigV4, TLS terminated in the enclave (pinned Amazon roots) |
| Status list | `Options.StatusList` (a parsed, timestamped list) | fetch over TLS the enclave terminates (Google Trust Services roots) |
| Queue, parent, response slots, leases, registry | `enclavetest.World` plays them in process | parent over vsock, SQS, DynamoDB, leases |
| Store | `vault/store` Memory and Dir | S3 conditional writes |
| Release pins | `enclave.ReleaseConfig`: vendor roots, Android package, iOS App ID; manifest keys, sealing account/region, Android signer digests and the release number are empty (fail closed) until V5 | filled per release |

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

## V3b

The parent (vsock mux, per-instance SQS queue, instance registry,
leases, S3 store, TCP forwarder with the relay/KMS/Google allowlist,
role credentials), the enclave's TLS client with pinned roots and shared
HTTP/2 connections, the SigV4 KMS client, the status-list fetcher, the
supervisor (process per vault, memory pressure), the real NSM, and the
docker-compose exit test of VAULT-PLAN §4 V3.
