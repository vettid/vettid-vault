# V3a notes: alternate channel, device attestation, release updates

V3a implements the enclave side of VAULT-MESSAGING 0.3.0 §11 in process:
everything the enclave decides, with the hardware and AWS behind
interfaces. This file records the choices made where the spec is silent
or ambiguous (each with proposed spec wording), what waits for V3b, and
the runtime fixes made on the way.

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

## Choices made, and proposed spec wording

1. **Enrollment result.** §11.3 defines no response-slot answer for
   `vault.enroll`. The enclave answers every enrollment with
   `vault.enroll.result`, sealed to `app.kem`, padded to 4,096 bytes, `re` =
   `request_id`: `{"ok": true, "vault_id"}` or `{"ok": false, "code"}` with
   `vault_exists`, `release_key`, `manifest`, `attestation`, `bad_request`
   or `retry`. *Proposed (§11.3, after the `vault.enrolled` block):* "The
   enclave also answers in the response slot with `vault.enroll.result`,
   sealed to `app.kem` and padded to 4,096 bytes: `{"ok": true, "vault_id"}`
   or `{"ok": false, "code": "vault_exists|release_key|manifest|attestation|bad_request|retry"}`."
2. **Result inner plaintexts** carry `re` = the request's `request_id` and
   `status: "ok"` (the outcome is in the body), so an old result cannot be
   presented as the answer to a new request. *Proposed (§11.4):* "The
   result's inner `re` is the request's `request_id`."
3. **Unanswerable requests.** Without a matching header and unlock key
   there is no KEM to seal to; the enclave answers with random bytes of the
   sealed-result size (5,252), indistinguishable to the API and parent. So
   `unknown_device` and `vault_missing` (when the header is missing) are
   never sealed. *Proposed (§11.4):* "If no unlock key matches `device_ik`,
   or the signature does not verify, the enclave answers with random bytes
   of the result's size."
4. **Codes beyond §11.4's list:** `retry` (§11.9 state write conflict, and
   KMS or store failures), and `release_key` at unlock when the running
   release's own key fails its first check (§11.10.7) — the header cannot
   be written. *Proposed:* add `retry` and `release_key` to the failure
   codes of §11.4.
5. **`moved` results carry no `token`**: the vault does not resume under N.
   *Proposed (§11.4):* "`token` is absent when `update.result` is `moved`."
6. **What the device key signs** (§11.7, §11.10.3): Android signs the
   32-byte challenge as the *message* with SHA256withECDSA (DER); iOS
   asserts with `clientDataHash` = the challenge itself. For approvals,
   Android signs the string's bytes and iOS uses `clientDataHash` =
   SHA-256(string). *Proposed (§11.7):* "Android: ECDSA P-256 with SHA-256
   over the 32 challenge bytes (the key's digest is SHA-256); iOS:
   `clientDataHash` = challenge."
7. **App Attest assertion signatures** are verified as ECDSA P-256 with
   SHA-256 over `nonce` = SHA-256(authenticatorData ‖ clientDataHash), as
   common server implementations do. To be confirmed on a device in V6.
8. **Two iOS assertions in one unlock** (unlock + approval): each must
   exceed the counter stored before the request, they must differ, and the
   header keeps the larger. *Proposed (§11.10.3):* "Both assertions'
   counters must exceed the stored counter and differ; the enclave stores
   the larger."
9. **Pairing challenge** (§6.7): the §11.7 challenge with the `hs.init`
   inner `id` as `request_id`, an empty `vault_id` (the new device does not
   know it yet) and the `hs.init` inner `ts`. *Proposed (§6.7):* "`device_attest`
   is over `SHA-256("vettid/vms/2/devatt" || hs.init id || "" || hs.init ts)`."
10. **`header_seq` per release.** Each release has its own header object,
    and a move or failures under N+1 raise only N+1's `header_seq`. An app
    that sends its overall maximum to N when abandoning a move would be
    refused with `state_rollback`. The client keeps `header_seq` per
    release. *Proposed (§13.2 and §11.10.6):* "The app stores `header_seq`
    per release and sends, as `min_header_seq`, the value it holds for the
    release the request is sealed to."
11. **`seal_key_verified` records who checked.** The record is
    `{key_arn, policy_sha256, verified_by}` (the PCR0 of the checking
    release). A release that finds a record made by another release (N's
    check of N+1's key, written at the move) re-checks before its first
    header write. *Proposed (§11.10.7 "When"):* "…rely on that record if it
    was made by the same release; a release re-checks a record made by
    another release before its first header write."
12. **Sealed object format** (`Seal_R` in §3.3.1): `0x01 ‖ len ‖ key_arn ‖
    len ‖ CiphertextBlob ‖ nonce ‖ XChaCha20-Poly1305(data key, nonce,
    "vettid/vms/2/seal" ‖ 0 ‖ release ‖ 0 ‖ key_arn ‖ 0 ‖ aad, plaintext)`.
    The enclave takes the key ARN from the object (required to be in the
    pinned namespace) to call `Decrypt` with it as `KeyId`, and then
    requires it to equal the verified manifest's `seal_key` (else
    `manifest`). This lets it answer manifest failures sealed, as §11.4
    requires, although the header is opened before the manifest is
    verified. The data key is cached while the vault is unlocked.
13. **Policy check strictness** (§11.10.7): `NotPrincipal`, `NotAction`
    and `NotResource` are refused in every statement, Deny included (check 4
    lists the allowed members); operators, condition keys and action names
    match case-sensitively (case variants are refused, never assumed
    equivalent); `Resource` is a string; `PolicyName`, if present, is
    `default`. `DescribeKey` must show `AWSAccountId` = the pinned account
    and `MultiRegion` present and false, and must not carry
    `CustomKeyStoreId`, `CloudHsmClusterId` or `XksKeyConfiguration`;
    `ListGrants` must not carry `NextMarker`. Unknown members of the KMS
    responses are ignored; known members with another type fail. *Proposed:*
    replace "rejected in `Allow` statements" with "rejected in any
    statement".
14. **Status list.** Every listed serial counts as revoked whatever its
    `status` (`SUSPENDED` too); freshness is the enclave's own fetch time.
15. **Android acceptance details:** every certificate's validity at
    enrollment; `attestationVersion` ≥ 3; purposes ⊆ {SIGN, VERIFY} and
    containing SIGN, algorithm EC, curve P-256, origin GENERATED, root of
    trust — all hardware-enforced; every package in
    `attestationApplicationId` equal to the app's and every signing digest
    pinned. *Proposed (§11.7):* name the minimum attestation version.
16. **`vault_exists`.** The enclave keeps an index object from a member to
    its vault (`users/<sha256(user_guid)>/vault`, holding only the vault id)
    and refuses a vault id already used, or a member whose vault is
    confirmed, provisional for less than 24 h, or sealed to another release
    (it cannot tell). The host can delete the index; that only re-enables
    the API's own control, which the host has anyway (§13.5).
17. **One manager per vault:** an unlock for a vault the instance runs
    locks (flushes) it first. Lock and delete need no envelope (§11.5).
    `delete` destroys the state and this release's header; the §7.4
    revocations on deletion need the unlocked vault and come with
    `vault.delete` (V4).
18. **Manifest bytes** must be compact JSON; unknown members are ignored
    (§5.3); an empty `releases` array is refused; `notes` must be `https`.
    The enclave also requires its own entry's PCR1 and PCR2 to equal its
    measurements, and its number to equal the embedded release number.
19. **Nitro document chains are evaluated at the document's timestamp.**
    Signing certificates are short-lived while descriptors are served for
    up to 24 h; freshness is the separate < 26 h rule. *Proposed (§11.2
    step 1):* "…to the AWS Nitro root, at the document's timestamp".
20. **ETK rotation** happens after 23 h, so a current descriptor never
    expires; the previous ETK stays valid for 1 h. Requests are processed
    one at a time per instance.
21. **Lifecycle:** `enrolled` and `unlocked` at enrollment; `moved` with
    the target release; an abandonment reports `moved` back to N.
22. **PINs** are 4–32 ASCII digits.
23. **`vault.enrolled`'s bundle** now has the spec's shape `{v, suite, ik,
    kem, relay}` (V2 nested it under `vault`).
24. **§16** still shows the 0.2.2 altchan block ("vault.unlock envelope
    (5252 B …)"). With 0.3.0 the unlock is padded to 12,288 bytes: the
    envelope is 13,444 bytes (`altchan.json`). The release block's values
    all match (`release.json`). *Proposed (§16):* "vault.unlock envelope
    (13,444 B, randomness 64 x 0x13)".

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
