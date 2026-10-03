# VAULT-MESSAGING §4–§6 requirements → tests

Every MUST / MUST NOT in VAULT-MESSAGING 0.2.3 §4–§6 (plus the §13.4 and
§13.6 rules they rely on), and the named test that covers it. Normative
rules without the keyword (the §6.2 field rules, the §6.3 key schedule) are
included where they are security-relevant. Package paths are under `vms/`.

Runtime requirements (approval, persistence, dedupe, acks) are covered by
the vault runtime's tests (phase V2): `vault.*` tests run in-process
against a stub relay, and `e2e.*` tests (`make e2e`) run the runtime, the
reference client and the real vettid-relay binary. The V2 section at the
end covers §7, §8, §11.8, §12 and §13.2.

| § | Requirement | Test(s) |
|---|---|---|
| 3.2 | Follow FIPS 203, RFC 9180 and the MLKEM768X25519 definition | `suite.TestSuite2Parameters`, `hpkederand.TestAgreesWithCryptoHPKE`, `vectors.TestVectors` (hpke) |
| 3.4 | `identity.rotate`: both signatures verify, old ≠ new, links chain, ≤ 32 links | `handshake.TestRotationChain`, `handshake.FuzzParseRotation` |
| 4.1 | Suite 1 MUST NOT be sent | `envelope.TestEnvelopesCarrySuite2` |
| 4.1 | Suite 1 MUST NOT be accepted (header, offer, chosen, pin) | `suite.TestSuite1NeverAccepted`, `envelope.TestParseStrictHeader` ("suite 1"), `handshake.TestInitFieldRules` ("suite 1 offered"), `handshake.TestDowngradeChosenSuite` |
| 4.1 | Labels embed the suite number | `suite.TestLabelsEmbedSuite`, `suite.TestInfoBindsLabel` |
| 4.2 | Session mode: fresh random 192-bit nonce per message | `envelope.TestSessionNonceFreshAndRandom`, `envelope.TestRetransmissionNewEnvelopeSameID` |
| 4.3 | Sealing: SetupBaseS(ek_R, "vettid/vms/2/sealed"), AAD = header[0:1140], enc 1,120 bytes | `envelope.TestSealedRoundTrip`, `envelope.TestAADIsWholeHeader`, `vectors.TestVectors` (envelope_sealed) |
| 4.3 | MUST NOT reuse a context for a second message | `suite.TestContextSingleUse`, `envelope.TestMustNotReuseHPKEContext` |
| 4.4 | kid = SHA-256("vettid/vms/2/kid" ‖ ek)[0:8]; all-zero = anonymous | `suite.TestKidOf`, `vectors.TestVectors` (keys) |
| 4.4 | Receiver MUST NOT trial-decrypt under other principals' keys | `handshake.TestMustNotTrialDecrypt`, `envelope.TestOpenSealedKidMustMatchKey`, `handshake.TestSessionDirectionKids` |
| 5.2 | Byte layout; header 44 / 1,140; overhead 60 / 1,156 | `envelope.TestLayoutSizes`, `vectors.TestVectors` (both envelopes) |
| 5.2 | Non-zero flags MUST be rejected | `envelope.TestParseStrictHeader` ("flags", "flags high") |
| 5.2 | AAD is the whole header | `envelope.TestAADIsWholeHeader` |
| 5.3 | `v` MUST (= 1) | `envelope.TestInnerMustFields` |
| 5.3 | `id` MUST be a ULID | `envelope.TestInnerMustFields`, `envelope.TestULID` |
| 5.3 | A retransmission MUST reuse `id`, in a new envelope | `envelope.TestRetransmissionNewEnvelopeSameID` |
| 5.3 | `type` MUST | `envelope.TestInnerMustFields`, `envelope.TestValidType` |
| 5.3 | `ts` MUST, RFC 3339 UTC with milliseconds | `envelope.TestInnerMustFields` |
| 5.3 | `seq` in session mode, per epoch and direction from 1 | `envelope.TestInnerMustFields`, `handshake.TestHandshakeAllPurposes` |
| 5.3 | `body` MUST | `envelope.TestInnerMustFields` |
| 5.3 | Unknown fields ignored; strict types, no duplicate names, valid UTF-8, canonical base64, integers ≤ 2^53−1, `re`/`status`/`error` rules | `envelope.TestInnerMustFields`, `envelope.FuzzParseInner` |
| 5.4 | Padding buckets (512 to 16 KiB, then 16 KiB); alternate channel 4,096 | `envelope.TestPaddingBuckets`, `envelope.TestLayoutSizes` |
| 5.4 | Receivers MUST reject malformed padding, including over-padding | `envelope.TestMustRejectMalformedPadding`, `envelope.FuzzUnpad` |
| 5.5 | Envelope MUST fit `max_payload_bytes`; padded inner ≤ 245,760 | `envelope.TestSizeLimits`, `envelope.TestParseStrictHeader` ("not a bucket") |
| 5.5 | Claim-check MUST be used for content that would not fit | `envelope.TestSizeLimits` (`DecideBlob`), `envelope.TestBlobRoundTrip` |
| 5.5 | Receiver MUST check the blob's `sha256` before decrypting | `envelope.TestBlobRoundTrip` |
| 6.2 | hs.init: sender_kid anonymous or kid(from.kem); recipient_kid = kid(ek_R) | `handshake.TestHandshakeKids`, `handshake.TestHandshakeSenderKidMismatch` |
| 6.2 | hs.resp: recipient_kid = kid(eph) | `handshake.TestHandshakeKids` |
| 6.2 | Rekey hs.init travels in session mode; K_s = previous rk | `handshake.TestRekeyMustTravelInSessionMode`, `handshake.TestRekeyAndRetention`, `handshake.TestRekeyCtxMustBeCurrentEpoch` |
| 6.2 | Field rules (`profile`, `rotations`, `device_attest`, `ctx`, tokens per purpose, relay address, `eph` ≠ `from.kem`) | `handshake.TestInitFieldRules`, `handshake.TestRespFieldRules`, `handshake.TestRelayAddrRules`, `handshake.TestInitEphMustDifferFromStatic`, `handshake.FuzzParseInit`, `handshake.FuzzParseResp` |
| 6.3 | Key schedule, th1/th, kids, rk, epoch_id, SAS | `vectors.TestVectors` (handshake), `handshake.TestSASBothSides` |
| 6.3 | Session kids per direction (i2r: recipient kid_i2r, sender kid_r2i) | `handshake.TestSessionDirectionKids`, `vectors.TestVectors` (hs.fin) |
| 6.3 | I MUST verify sig_R before using any epoch key, MUST abort on failure | `handshake.TestMustVerifySigRAndAbort`, `handshake.TestJunkDoesNotCancelHandshake` |
| 6.3 | Abort only once a message decrypted under eph; junk is dropped | `handshake.TestJunkDoesNotCancelHandshake`, `handshake.TestMustVerifySigRAndAbort` |
| 6.3 | R activates the epoch only after sig_I verifies | `handshake.TestMustActivateOnlyAfterSigI` |
| 6.3 | Collect `sender` MUST equal from.relay.pk (hs.init) and the record (later) | `handshake.TestMustCheckCollectSender`, `handshake.TestRekeyRequiresRecordIdentity` |
| 6.3 | SAS depends only on hs.init | `handshake.TestSASBothSides` |
| 6.4 | Invite TTL MUST be ≤ both relay limits; app MUST NOT offer more | `invite.TestInviteTTL` |
| 6.4 | Remote invites: auto-approval MUST NOT apply | `invite.TestAutoApproval` |
| 6.4 | Bundle encryption; MUST check `h` before decrypting; MUST reject wrong `kind`, `exp` ≠ `e`, expired | `invite.TestInviteFlow`, `invite.TestBundleCommitment`, `invite.TestBundleChecks`, `invite.TestQRStrict`, `vectors.TestVectors` (invite) |
| 6.4 | Single use per invite_id; reject expired, used or revoked invites | `vault.TestInviteSingleUse`, `vault.TestInviteCancelled`, `vault.TestInviteExpiry`, `invite.TestBundleChecks` |
| 6.4 | Remote invites stay pending; auto-approval MUST NOT apply; no hs.resp while pending | `vault.TestRemoteInviteStaysPending`, `e2e.TestPairConnectMessage` |
| 6.4 | Pending connection requests dropped after 7 days | `vault.TestPendingConnectionExpires` |
| 6.4, 6.7 | Apps or desktops approve connections; only apps create and approve pairings; agents neither | `vault.TestApprovalRoles`, `e2e.TestPairConnectMessage` |
| 6.5 | Epoch ends at 24 h / 10,000 (vault↔vault), 7 d (device) | `handshake.TestEpochPolicy` |
| 6.5 | Lower th1 wins a simultaneous rekey | `handshake.TestSimultaneousRekeyLowerTh1Wins` |
| 6.5 | Previous send keys deleted at activation; receive keys kept 16 days | `handshake.TestRekeyAndRetention` |
| 6.6 | Token class by collect `jti`; messages on a reconnect token (or without `jti`) other than a sealed reconnect hs.init MUST be dropped and audited | `handshake.TestReconnectTokenPermittedUse`, `vault.TestReconnectTokenMisuseDropped`, `e2e.TestReconnectAfterExpiry` |
| 6.6 | Reconnect when the held standing token expired; then messages flow | `e2e.TestReconnectAfterExpiry` |
| 6.6 | Responder MUST accept a reconnect only if sender = record, from.ik reached by a valid chain, sig_I verifies | `handshake.TestReconnectWithRotations`, `handshake.TestReconnectRejections` |
| 6.6 | Initiator verifies sig_R through the responder's chain | `handshake.TestReconnectWithRotations`, `handshake.TestReconnectRejections` ("responder chain wrong") |
| 6.6 | `from.kem` MUST equal the chain's final `new_kem` | `handshake.TestReconnectWithRotations`, `handshake.TestReconnectRejections` |
| 6.6 | Reconnect token lifetime ≤ 365 d and relay cap; re-mint < 60 d | `handshake.TestReconnectTokenParameters` |
| 6.7 | Vault MUST NOT send hs.resp before approval; apps approve; drop after 10 min and denylist the jti | `vault.TestPairingApprovalFirst`, `vault.TestInviteExpiry`, `e2e.TestPairConnectMessage` |
| 6.7 | Re-paired device MUST use a new relay key; hs.init from a denylisted relay key refused | `vault.TestRepairWithOldRelayKeyRefused` |
| 13.4 | Records pin the highest suite; lower suites rejected | `suite.TestDowngradePin`, `handshake.TestDowngradeChosenSuite` |
| 13.4 | sig_R covers th, which covers the `suites` offer | `handshake.TestDowngradeSuitesStripDetected` |
| 13.6 | Envelope and inner parsers MUST be fuzzed | `envelope.FuzzParse`, `envelope.FuzzUnpad`, `envelope.FuzzParseInner`, `handshake.Fuzz*`, `invite.Fuzz*`, `altchan.Fuzz*`, `strictjson.FuzzParseObject` |
| 13.6 | Tag and key comparisons MUST be constant-time | `vms.TestNoVariableTimeComparisons` |
| 13.6 | No keys, PINs, tokens, signatures or plaintext in logs or errors | `vms.TestErrorsAreSentinels`, `suite.TestRedaction`, `handshake.TestEpochRedacted` |
| 13.6 | Dev-mode (here: deterministic vector) code excluded at compile time | `suite.TestReleaseBuildHasNoVectorHooks`, `make check-tcb` |
| 11.7 | `device_attest` / `device_assertion` wire shape (verification is V3) | `altchan.TestDeviceAttestRoundTrip`, `altchan.TestDeviceAssertion`, `altchan.FuzzParseDeviceAttest`, `altchan.FuzzParseDeviceAssertion`, `handshake.TestInitFieldRules` |
| 8.4 | Reject `ts` > 5 min ahead; durable > 16 d old; expired `exp` | `envelope.TestInnerCheckTime` |

## V2 runtime (§7, §8, §9, §11.8, §12, §13.2)

| § | Requirement | Test(s) |
|---|---|---|
| 3.3 | Sealed header holds no relay key, session keys or feature data | `vault.TestHeaderContents` |
| 3.3.1 | DEK = HKDF(Argon2id(PIN), pepper); parameters below t=1, m=8 MiB refused; state bound to vault_id and state_seq | `vault.TestKDF`, `vault.TestStateBlobBinding` |
| 5.3 | Unknown type without `re` answered with `unsupported_type`; role not allowed → `forbidden` | `vault.TestRequestResponseAndDedupe` |
| 11.3 | First app: purpose app, ctx = vault_id, pre-authorized keys only | `e2e.TestPairConnectMessage`, `e2e.TestVaultctlSmoke` |
| 7.1 | Token kinds, lifetimes and quotas (peer 20,000 / 512 MiB; reconnect 4 / 64 KiB, ≤ 365 d) | `vault.TestTokenQuotas` |
| 7.2 | Re-mint standing tokens < 10 d, reconnect < 60 d; holder refresh | `vault.TestRemintStanding`, `e2e.TestReconnectAfterExpiry` |
| 7.3 | 60 durable messages per peer per minute; excess acked, dropped, audited | `vault.TestPeerRateLimit` |
| 7.4 | Connection removed / device unlinked: notice, denylist sub, delete tokens, sessions, outbox | `e2e.TestRevokeConnection`, `vault.TestRepairWithOldRelayKeyRefused` |
| 7.4 | Invite or pairing cancelled or expired: denylist jti, delete claim | `vault.TestInviteCancelled`, `vault.TestInviteExpiry` |
| 8.1 | Response: same type, `re`, `status`, to the requester only; unmatched `re` dropped | `vault.TestRequestResponseAndDedupe`, `vault.TestUnmatchedResponseDropped` |
| 8.2 | Dedupe by relay msg_id and by inner id per principal; cached responses for 24 h | `vault.TestRequestResponseAndDedupe`, `e2e.TestRestartDedupe` |
| 8.3 | Ack only after the durable flush; outbox deposited after the ack | `vault.TestAckOnlyAfterFlush`, `e2e.TestRestartDedupe` |
| 8.4 | Reject `ts` > 5 min ahead and, for durable types, > 16 d old | `vault.TestTimestampWindow`, `envelope.TestInnerCheckTime` |
| 8.5 | Ephemeral types: `exp` required, acked after handling, in-memory dedupe | `vault.TestEphemeralClass` |
| 8.6 | Error table: token_revoked / mailbox_unknown terminal, token_expired → reconnect | `vault.TestDepositErrors`, `e2e.TestRevokeConnection`, `e2e.TestReconnectAfterExpiry` |
| 9.1 | One deposit per owner device; responses to the requester only | `e2e.TestPairConnectMessage` |
| 11.8 | Backoff after 3 failures; failures counted in header_seq; never wipe | `vault.TestBadPINBackoff` |
| 12.2 | Collect by long-poll and WebSocket; unlock order (re-mint, reconnect, rekey devices, drain, collect) | `e2e.TestPairConnectMessage` (WebSocket vault), `e2e.TestReconnectAfterExpiry`, `e2e.TestVaultctlSmoke` |
| 12.3 | Owner lock: flush, `vault.locking`, zeroize | `e2e.TestLockUnlockRollback` |
| 12.3 | Split-brain guard: zeroize immediately, no flush, no ack | `vault.TestSplitBrainZeroizes`, `e2e.TestSplitBrainLocksSecondWriter` |
| 13.2 | Refuse state behind the header, or below the client's minimums | `vault.TestRollbackRefused`, `e2e.TestLockUnlockRollback` |
| 13.6 | Classification only by sender, recipient kid and decrypting session | `vault.TestSenderMismatchDropped`, `vault.FuzzDeviceMessage` |
| 13.6 | Dev sealer and PIN constructors excluded at compile time | `make check-tcb` |

## V3a alternate channel, attestation and release updates (§11, §12, §13; 0.3.1)

`enclave.*` tests run the enclave in process (fake NSM and KMS, test
roots, in-memory relay); `e2e.TestAltchan*` and `e2e.TestVaultctlAltchan`
run it against the real vettid-relay binary. MUSTs of the app side are
covered by the reference client (`client.*`).

| § | Requirement | Test(s) |
|---|---|---|
| 5.4 | enroll and unlock requests padded to exactly 12,288 bytes; results 4,096; every outcome the same size | `altchan.TestSealOpen`, `enclave.TestUniformSizes`, `vectors.TestVectors` (altchan, 13,444-byte envelope) |
| 11.2 | ETK descriptor and attestation: user_data = SHA-256("vettid/vms/2/etk" ‖ descriptor), not_after ≤ issue + 24 h; ETK rotates (≤ 24 h, at start), previous valid 1 h | `enclave.TestETKLifecycle`, `altchan.TestDescriptor`, `vectors.TestVectors` (altchan) |
| 11.2 | App MUST verify the chain to the Nitro root, PCR0-2 against the manifest (active to enroll), reject debug PCRs, check user_data, not_after, < 26 h | `client.TestVerifyEnclave`, `nitro.TestVerifyRoundTrip`, `nitro.TestVerifyRejects` |
| 11.2, 11.10.6 | Never send a PIN to an older release than the last unlocked into (except abandoning) | `enclave.TestAbandonMove` (`ErrRollbackRel`) |
| 11.3 | Binding: user_guid / request_id must equal the queue message; inner ts within 5 min; inner id = request_id; sender_kid all-zero | `enclave.TestETKLifecycle` (stale ts), `enclave.TestReplayRefused`, `enclave.FuzzProcessBody` |
| 11.3 | device_attest REQUIRED; manifest REQUIRED (own active entry, own key checked before the first seal, else release_key) | `enclave.TestDeviceAttestationRefused`, `enclave.TestSealKeyPolicyRefused` |
| 11.3 | A confirmed vault MUST NOT be replaced (vault_exists); a provisional one may be after 24 h; re-enrollment with the member's existing vault_id (refused if confirmed, < 24 h or sealed to another release; otherwise replaced) | `e2e.TestAltchanEnrollUnlock`, `enclave.TestProvisionalReplacement`, `enclave.TestReenrollSameVaultID` |
| 11.3 | `vault.enroll.result` in the response slot, sealed to app.kem, 4,096 bytes, `re` = request_id | `enclave.TestEnrollUnlock`, `altchan.TestSealOpen` |
| 11.3 | vault.enrolled attestation: nonce, user_data over the bundle, PCRs | `enclave.TestEnrolledAttestationChecked`, `e2e.TestAltchanEnrollUnlock` |
| 11.3 | First app's handshake, provisional window | `e2e.TestAltchanEnrollUnlock`, `e2e.TestPairConnectMessage` |
| 11.4 | Unlock order: header, unlock key + sig, device assertion, backoff, rollback, manifest, DEK | `enclave.TestBadPINAndBackoff`, `enclave.TestRollbackRefused`, `enclave.TestManifestRefused`, `enclave.TestDeviceAttestationRefused` |
| 11.4 | Results sealed to the device's kem; unknown device / bad signature dropped with a same-size answer | `enclave.TestUnknownDeviceDropped`, `enclave.TestUniformSizes` |
| 11.4, 13.2 | App MUST warn on state_rollback | `client.OpenUnlockResult` returns the code; `vaultctl altchan-unlock` prints the warning |
| 11.1, 11.2 | `instance_id` is `[A-Za-z0-9_-]{1,48}` (configuration and descriptors) | `enclave.TestInstanceIDValidated`, `altchan.TestDescriptor`, `altchan.TestValidInstanceID` |
| 11.5 | Queue message: `etk_kid` and `envelope` absent for lock/delete; response `{v, request_id, status: done\|etk_unknown, envelope?}` | `enclave.TestQueueMessage`, `enclave.TestETKLifecycle` (`etk_unknown` without envelope) |
| 11.6 | Replayed request_id refused while its ETK lives; destroyed ETK → etk_unknown | `enclave.TestReplayRefused`, `enclave.TestETKLifecycle`, `e2e.TestAltchanEnrollUnlock` |
| 11.7 | Android: chain to a pinned root, challenge, TEE/StrongBox, RootOfTrust locked + Verified, package and signer digests, signing-only generated P-256 key; status list ≤ 24 h at enrollment and pairing, ≤ 7 d at unlock | `devattest.TestAndroidHappyPath`, `devattest.TestAndroidRejects`, `enclave.TestDeviceAttestationRefused` |
| 11.7 | iOS: App Attest chain, nonce, key id, App ID, production aaguid, counter 0; assertions with increasing counters | `devattest.TestIOS`, `enclave.TestBadPINAndBackoff` (iOS app) |
| 11.7, 6.7 | App pairing carries device_attest; binding into the unlock keys | `vault.TestPairingDeviceAttestation`, `e2e.TestAltchanEnrollUnlock` (paired iOS app unlocks) |
| 11.7 | Vendor roots pinned (and the test roots never accepted by them) | `pins.TestFingerprints`, `pins.TestRootsValid`, `devattest.TestAndroidRejects` ("google roots"), `devattest.TestIOS` ("apple root"), `nitro.TestVerifyRejects` ("aws root") |
| 11.8 | Backoff after 3 failures (30 s …), reset on success, never wipe; manifest failures not counted | `enclave.TestBadPINAndBackoff`, `enclave.TestManifestRefused`, `vault.TestBadPINBackoff` |
| 11.10.1 | Manifest: strict format, ECDSA P-256 over the exact bytes under a pinned key, key_id; serial lower than seen MUST be refused (apps and enclave); no debug PCRs | `manifest.TestSpecVector`, `manifest.TestVerify`, `manifest.TestParseRejects`, `client.TestVerifyManifestSerial`, `enclave.TestManifestRefused`, `vectors.TestReleaseVectors` |
| 11.10.3 | Approval string, signed by the device attestation key; bound to the request; iOS counter increases | `altchan.TestApprovalSigningString`, `vectors.TestReleaseVectors`, `enclave.TestReleaseMove` (iOS) |
| 11.10.4 | Move sequencing: checks in order (target, downgrade, approval, seal_key, pending), record the move, seal to N+1 create-only, lock, report moved | `enclave.TestReleaseMove`, `enclave.TestSealKeyPolicyRefused`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.4 | Pending move completed without a new approval after a step-7 failure; a different target does not change it | `enclave.TestPendingMoveCompletes` |
| 11.10.4 | Confirmation at N+1 deletes header/N; N MUST refuse a vault that left (wrong_release); N cannot open N+1's header | `enclave.TestReleaseMove`, `enclave.TestWrongReleaseRefused` |
| 11.10.4 | Abandoning an unconfirmed move | `enclave.TestAbandonMove`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.4 | Forward only: equal or lower releases refused (downgrade) | `enclave.TestReleaseMove`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.7 | Key identity, metadata, no grants, policy shape, Deny ignored, actions, attestation condition, principals; the passing example and every must-fail variant | `keypolicy.TestExamplePasses`, `keypolicy.TestMustFailVariants`, `keypolicy.TestMoreRefusals`, `keypolicy.FuzzCheckPolicy`, `keypolicy.FuzzPolicyDocument` |
| 11.10.7 | Check before the first seal under a key (enrollment: release_key; move: seal_key); record seal_key_verified | `enclave.TestSealKeyPolicyRefused`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.2 | Sealing: GenerateDataKey/Decrypt with Recipient attestation; CMS RSA-OAEP-SHA-256 only (no PKCS#1 v1.5, no SHA-1 defaults); pinned namespace | `cms.TestUnwrap`, `cms.FuzzUnwrap`, `enclave.TestSealKeyPolicyRefused` (namespace), `enclave.TestWrongReleaseRefused` |
| 12.3 | Lock (owner / API): finish, flush, vault.locking, zeroize; queued deposits delivered first | `enclave.TestEnrollUnlock`, `vault.TestOutboxOrderPerMailbox`, `e2e.TestAltchanReleaseUpdates` |
| 13.6 | Parsers fuzzed: attestation documents, X.509 extension, CBOR, DER, manifest, policy JSON, CMS, requests, results, queue messages | `cbor.FuzzDecode`, `der.FuzzParse`, `nitro.FuzzVerify`, `devattest.Fuzz*`, `manifest.Fuzz*`, `keypolicy.Fuzz*`, `cms.FuzzUnwrap`, `altchan.FuzzParse*`, `altchan.FuzzOpenResult`, `enclave.Fuzz*` |
| 13.6 | Constant-time comparisons; sentinel errors in vms/ | `vms.TestNoVariableTimeComparisons`, `vms.TestErrorsAreSentinels` (cover vms/nitro, vms/manifest, vms/devattest) |
| 13.6 | Dev-mode attestation and sealing excluded at compile time | `make check-tcb` (no devenclave, enclavetest, relaytest, hpkederand or mlkemtest in release packages, including enclave/...) |

## V3b supervisor, parent and AWS transport (§11.1, §11.5, §12, §13; 0.3.1)

Unit tests run each part alone; `e2e.TestHostStack` runs the parent and
the supervisor in process (in-memory AWS); `integration.TestV3Exit` runs
the binaries against LocalStack, the real relay and the member API
stand-in (`make integration`).

| § | Requirement | Test(s) |
|---|---|---|
| 11.1 | One SQS queue per instance, `<prefix>vault-control-<instance_id>`, created at boot and deleted at shutdown; sweeper for gone instances | `parent.TestRegistryAndStore`, `parent.TestAWSBackend`, `integration.TestV3Exit` (queues deleted) |
| 11.1 | Registry `{instance_id, release, queue_url, descriptor, attestation, heartbeat_at}`, heartbeat ≤ 30 s, only while the enclave answers | `parent.TestRegistryAndStore`, `integration.TestV3Exit` (API routes by the registry) |
| 11.1 | Lease acquired with a conditional write (absent, expired or own), renewed every 60 s for 180 s, released on lock | `parent.TestRequestsAndLeases`, `parent.TestAWSBackend`, `integration.TestV3Exit` |
| 11.1, 12.3 | Lease lost → the vault locks; split brain: the losing conditional write zeroizes without flushing | `parent.TestRequestsAndLeases` (lease lost), `integration.TestV3Exit` (split brain between two instances) |
| 11.5 | Parent forwards the queue message unchanged; writes `{status, envelope?, code?}` (envelope exactly 5,252 bytes, `etk_unknown` as a host code), lifecycle events, then deletes the message | `parent.TestRequestsAndLeases`, `e2e.TestHostStack` (`etk_unknown`), `integration.TestV3Exit` |
| 11.5 | Lifecycle events (`enrolled`, `unlocked`, `locked`, `moved`) in the vault table | `parent.TestAWSBackend`, `integration.TestV3Exit` (sealed_release follows the move) |
| 11.6 | A request replayed by the host is dropped (vault not reopened) | `integration.TestV3Exit` |
| 11.10.4–5 | Release move across instances of two releases; the next unlock routes to the new release | `integration.TestV3Exit` |
| 11.10.7 | `DescribeKey`, `GetKeyPolicy` (`default`), `ListGrants` over TLS the enclave terminates, SigV4-signed in the enclave with credentials from the parent | `awskms.TestRecipientRoundTrip`, `awskms.TestSigV4Suite`, `awskms.TestSigV4MatchesSDK`, `integration.TestV3Exit` |
| 11.10.2 | `GenerateDataKey`/`Decrypt` with `Recipient` (`RSAES_OAEP_SHA_256`); no plaintext accepted | `awskms.TestRecipientRoundTrip`, `awskms.TestPlaintextRefused` |
| 12.2 | TLS ends in the enclave: pinned roots only, host name verified, TLS 1.3; parent forwards TCP to the allowlist on 443 only | `egress.TestRefusals`, `parent.TestForwarder`, `pins.TestTLSFingerprints` |
| 12.2 | A few shared HTTP/2 connections per instance carry every vault's relay requests | `egress.TestSharedHTTP2`, `integration.TestV3Exit` (two vaults on one instance) |
| 12.3 | Memory pressure: the least recently active vault is locked like an owner request | `e2e.TestHostStack` (vault cap) |
| 12.3 | Enclave restart: vaults die with it and their leases are released; parent shutdown locks every vault | `parent.TestEnclaveRestartReleasesLeases`, `e2e.TestHostStack` |
| 13.3 | The parent parses no envelopes and logs none; nothing secret in logs | `parent.TestRequestsAndLeases` (no envelope bytes logged), `integration.TestV3Exit` (no PIN or envelope in parent or enclave logs) |
| 13.6 | Parsers fuzzed: host frames, NSM responses | `hostproto.FuzzParse`, `nsm.FuzzDecodeResponse` |
| 13.6 | Release enclave builds link no dev code, test fakes, AWS SDK or parent; they link the real NSM and vsock | `make check-tcb` |
| 11.1 (0.3.2) | A lease held by an instance that is not live is taken over, conditional on the exact old lease | `parent.TestRequestsAndLeases`, `parent.TestAWSBackend` |
| 12.4, 13.6 (0.3.2) | One process per vault; the supervisor holds no DEK or keys | `e2e.TestHostStack`, `e2e.TestVaultProcessIsolation` (`vault.Unlocked()` unchanged in the supervisor) |
| 12.4 | Lock ends the vault's process; killing one vault's process affects no other | `e2e.TestHostStack`, `e2e.TestVaultProcessIsolation` |
| 12.4 | The channel is scoped to the vault: its objects, its member's index, previous vault read-only at enrollment, relay requests under its own key, namespace KMS keys, no arbitrary attestation | `supervisor.TestChannelScope` |
| 12.4 | Per-process uid/gid, non-dumpable, seccomp (no sockets, ptrace or cross-process memory), rlimits | `vaultproc.TestHardenNotDumpable`, `seccomp.TestFilter`, `e2e.TestVaultProcessIsolation` (`/proc` closed); uid switching needs root (hardware, V5) |
| 13.6 (0.3.2) | The channel is parsed strictly and fuzzed | `enclave.FuzzParseJob`, `vaultipc.FuzzDecodeHeaders`, `hostproto.FuzzParse`, `vaultproc.TestServeRefusesMalformedOpen` |
| 13.6 | Vault and feature code cannot import enclave/host packages, use unsafe or cgo; the vault process links no network, NSM or parent code; the supervisor links no feature code | `make check-tcb` |


## V4 batch 1: credential, secrets, profile, settings, audit, feed (§3.4, §3.5, §9.3, §10.1, §10.6–§10.9; 0.4.0)

Feature handlers are tested in their packages through
`internal/featuretest` (a fake host, and the runtime's sender-kind rule
before `Handle`); the same flows run through the runtime and the real relay
in `e2e.TestCredentialFlow`, `e2e.TestProfileSecretsAuditFeed` and
`e2e.TestVaultctlSmoke` (vaultctl's feature commands).

| § | Requirement | Test(s) |
|---|---|---|
| 3.5.1, 3.5.2 | Blob: HPKE to the CEK over a password layer (Argon2id + HKDF), header as AAD, bound to `vault_id`; refuse KDF parameters below t=1, m=8 MiB | `credential.TestBlobLayers`, `credential.FuzzOpen` |
| 3.5.2, 10.6 | Strict plaintext, request envelopes and UTK payloads: categories, value sizes, ≤ 64 secrets, versions agree | `credential.FuzzParseInner`, `credential.FuzzParseEnvelope`, `credential.FuzzParsePayload`, `credential.TestSecretLimit`, `credential.TestBadBodies` |
| 3.5.3 | Every use carries the blob and the password; every use rotates the CEK and destroys the old one, so the previous blob is undecryptable (not only refused) | `credential.TestCEKRotatesOnEveryUse`, `e2e.TestCredentialFlow` |
| 3.5.3 | Wrong password: `bad_password`, counted, audited; backoff after 5 failures; success resets | `credential.TestBadPasswordAndBackoff`, `e2e.TestCredentialFlow` |
| 3.5.3 | No plaintext, password or secret value in vault state | `credential.TestSecretsAndReplyKey` |
| 3.5.3 | A lost response never loses the credential: the latest blob is kept until `credential.ack` (even with backup off) and fetched with `credential.get`; responses are cached | `credential.TestLatestBlobKeptUntilAck` |
| 3.5.4 | UTK pool of 20, refill by 10 under 10, expiry, single use (`utk_invalid` on reuse), bound to the device, the type and the request id | `credential.TestUTKPool`, `credwire.TestPayloadBinding`, `credwire.FuzzOpenPayload`, `e2e.TestCredentialFlow` (reuse refused, replenishment through the relay) |
| 3.5.4 | Secret values return sealed to a one-time reply key carried in the UTK payload; nothing secret in the clear in the response | `credential.TestSecretsAndReplyKey`, `credwire.TestValue` |
| 8.2 | A volatile response is neither cached nor written to state; a retransmission is executed again (runtime rule; no type of 0.4.1 needs it) | `vault.TestVolatileResponses` |
| 3.5.7 | A vault without a credential answers `credential_required` except to the listed types, stays provisional, records `has_credential` | `vault.TestCredentialGate`, `e2e.TestNoCredentialNoRecovery`, `e2e.TestVaultctlSmoke` |
| 3.5.3 | Unlock window: memory only; ends at expiry, `credential.lock`, rotation, delete and vault lock | `credential.TestUnlockWindow` |
| 3.5.5, 3.4 | Rotation: new credential key, `ik`/`kem` rotated in the same flush; nothing changes if the identity rotation fails | `credential.TestRotateRotatesIdentity`, `e2e.TestCredentialFlow` |
| 3.5.5 | Create once (`exists`); delete destroys the CEK, the latest blob and the UTKs and restricts the vault again | `credential.TestCreateOnce`, `credential.TestDelete` |
| 10.6 | Roles: apps only, except `credential.version` and `credential.secret.list` (apps and desktops); agents and peers never | `credential.TestAuthorizationBySenderKind`, `e2e.TestCredentialFlow` |
| 10.1 | `version` on shared objects; `conflict` on a stale version; an error changes no state | `secrets.TestPutGetListDelete`, `profile.TestSetSharesOnlySharedFields`, `vault.TestSettings`, `e2e.TestProfileSecretsAuditFeed` |
| 10.1 | `sync.event` kinds to the other owner devices, without values | `credential.TestCreateOnce`, `secrets.TestPutGetListDelete`, `profile.TestSetSharesOnlySharedFields`, `feed.TestItemsAndSync`, `e2e.TestCredentialFlow` |
| 10.7 | Secrets: create/replace, limits, roles, list without values | `secrets.TestAuthorization`, `secrets.TestPutGetListDelete`, `secrets.TestBadBodies`, `secrets.TestLimit`, `secrets.FuzzParsePut` |
| 6.2, 6.4 | A vault's `hs.init` profile and invite hint carry only its display name | `vault.TestHandshakeProfile`, `e2e.TestProfileSecretsAuditFeed` |
| 9.3, 10.8 | `profile.update` on activation and when the shared view changes; only shared fields; private changes stay local | `profile.TestSetSharesOnlySharedFields`, `e2e.TestProfileSecretsAuditFeed` |
| 10.8 | A peer's `profile.update`: strict, highest version wins, stored as the connection's profile, `connection.event{profile}` | `profile.TestUpdateFromPeer`, `profile.FuzzParseUpdate`, `e2e.TestProfileSecretsAuditFeed` |
| 10.8 | `profile.set` validation (keys, sizes, lists name existing fields, JPEG/PNG photo) | `profile.TestSetBad`, `profile.FuzzParseSet` |
| 10.8 | Settings keys, ranges, `app.*`, roles; the in-person auto-approval flag is the runtime's | `vault.TestSettings`, `vault.FuzzApplySettings` |
| 10.9 | Audit: hash chain over the fixed encoding, `head`, per-connection and kind filters, paging, retention and cap | `audit.TestChainAndList`, `audit.TestRetention`, `audit.FuzzParseQuery`, `e2e.TestProfileSecretsAuditFeed` |
| 10.9 | Audit holds no content (message text) | `e2e.TestProfileSecretsAuditFeed` |
| 10.9 | Runtime drops, unlock, lock and identity rotation reach the audit log | `vault.TestActivitySinks` |
| 10.9 | Feed: items from activity, `feed.event` to every owner device, status changes synced, catch-up by `after_seq` with tombstones, retention and cap | `feed.TestItemsAndSync`, `feed.TestRetention`, `feed.FuzzParseList`, `feed.FuzzParseUpdate` |
| 10.9 | `guide.sync`: new and higher versions only, idempotent | `feed.TestGuides`, `feed.FuzzParseGuides`, `e2e.TestVaultctlSmoke` |
| 10.6–10.9 | Roles of audit, feed, profile and secrets types | `audit.TestAuthorizationAndBadBodies`, `feed.TestAuthorizationAndBadBodies`, `profile.TestAuthorization`, `secrets.TestAuthorization` |
| 13.6 | New body parsers are fuzzed | the `Fuzz*` targets above (`make fuzz`) |
| 13.6 | Feature code keeps no package-level mutable state; the test harness is not linked into release packages | `features/all` (per-vault instances), `make check-tcb` (`featuretest`) |

## Recovery, backup and audit immutability (§3.5.6, §10.9, §11.11; 0.4.1)

| § | Requirement | Test(s) |
|---|---|---|
| 11.11.1 | A request locks the running vault with `vault.locking{reason: recovery}`; the record lives in the sealed header (no DEK) | `e2e.TestRecoveryCancel`, `e2e.TestHostRecovery` (through the parent and a vault process) |
| 11.11.2 | Code: 160 bits, Crockford base32, single use, only its hash in the header (never the code) | `vault.TestRecoveryHeaderOps`, `vault.TestRecoveryCode`, `e2e.TestRecoveryFlow` (`used`) |
| 11.11.2 | Valid from request + 24 h for 24 h, enforced by the enclave clock | `vault.TestRecoveryHeaderOps` (early), `vault.TestRecoveryExpiryAndReplace`, `e2e.TestRecoveryFlow` (`too_early`), `e2e.TestRecoveryExpiry` |
| 11.11.2 | Five wrong codes void the recovery | `vault.TestRecoveryCodeAttempts`, `e2e.TestRecoveryFlow` (`bad_code`) |
| 11.11.2 | Sealed to the browser's P-256 key, 5,252 bytes, bound to vault and recovery ids; QR payload | `altchan.TestSealRecoveryCode`, `altchan.TestRecoveryQR`, `altchan.FuzzOpenRecoveryCode`, `altchan.FuzzParseRecoveryQR` |
| 11.11.1 | A newer request replaces an older one | `vault.TestRecoveryExpiryAndReplace` |
| 11.11.3 | Register: binding, order of checks, attestation only after the code, then an unlock key | `vault.TestRecoveryHeaderOps`, `e2e.TestRecoveryFlow`, `altchan.FuzzParseRecoveryRegister` |
| 11.11.4 | Other apps' unlocks refused with `recovery_pending` (before the PIN); cancel by the API, by an owner unlock with `cancel_recovery` (13th signing line); cancel removes the record and the key | `e2e.TestRecoveryCancel`, `e2e.TestHostRecovery`, `vault.TestRecoveryHeaderOps`, `altchan.TestUnlockSigningStringCancel` |
| 11.11.5 | PIN under the enclave backoff; `vault_bundle` for the recovered app; first handshake with ctx = recovery id | `e2e.TestRecoveryFlow` |
| 11.11.5 | Recovering device restricted until `credential.recover`; password under the credential backoff; the CEK rotates (lost copies dead); then an ordinary app | `credential.TestRecover`, `credential.TestRecoverBackoff`, `e2e.TestRecoveryFlow` |
| 11.11.5 | Backup off: the member supplies the blob (`credential_required` without it); no credential: refused at the request (`no_credential`, sealed to the browser) and at `credential.recover` | `credential.TestRecoverBackupOff`, `credential.TestRecover`, `e2e.TestRecoveryBackupOff`, `e2e.TestNoCredentialNoRecovery`, `vault.TestRecoveryHeaderOps` |
| 11.11.6 | Steps taken while locked reach the audit log at unlock | `e2e.TestRecoveryFlow` (`recovery.*` in `audit.list`) |
| 11.5 | Queue ops `recovery` (with `browser_key`), `recovery_cancel`, `recovery_register` | `enclave.TestQueueRecoveryOps`, `enclave.FuzzParseQueueMessage` |
| 3.5.6 | `credential.backup` on by default; off: the latest blob kept only until confirmed, an acknowledged copy dropped at once | `credential.TestLatestBlobKeptUntilAck`, `vault.TestSettings` |
| 10.9 | Append-only, fixed retention (no setting), chain links across pruning | `audit.TestRetention`, `vault.TestSettings` (`audit.retention_days` refused) |
| 10.9 | Anchor check with `after_seq` | `audit.TestAfterSeqExtendsAnchor` |
| 10.9 | `drop.*` bounded per principal and kind; `drop.suppressed` | `audit.TestDropThrottle` |

## V4 batch 2: connections, calls, device and agent sessions (§6.8, §7.4, §8.5, §9.1, §10.1, §10.3, §10.4, §10.10; 0.5.0)

Runtime rules (access sessions, approvals, the block list, connection
metadata) are tested in `vault` with in-process devices; the features in
their packages through `internal/featuretest`; the flows through the real
relay in `e2e.TestBlockRefusesPeer`, `e2e.TestCallSignalling`,
`e2e.TestDesktopSession`, `e2e.TestConnectionAuthenticate` and
`e2e.TestVaultctlSmoke` (vaultctl's session commands).

| § | Requirement | Test(s) |
|---|---|---|
| 6.8 | A desktop or agent without an access session: `session_required` (requests) or dropped and audited (events), except the listed types | `vault.TestAccessSessions`, `e2e.TestDesktopSession`, `e2e.TestVaultctlSmoke` |
| 6.8 | Only desktops and agents request sessions; only apps approve, deny or decide; lengths 60 s–24 h; a newer request replaces an older one; requests expire after 10 min | `vault.TestAccessSessions` |
| 6.8 | Grant with the pairing approval (`session_seconds`); grant, end (by an app or the device itself), expiry; the device is told; `sync.event{device.session}` | `vault.TestAccessSessions`, `e2e.TestPairConnectMessage`, `e2e.TestDesktopSession` |
| 6.8 | Step-up types from a desktop are held for an app: `approval.pending` to apps, `approval.waiting` to the requester, executed on approval as the requester's, `denied`, `approval_timeout` after 5 min | `vault.TestAccessSessions`, `vault.TestBlocks` (`block.remove`), `e2e.TestDesktopSession` (`secret.get`) |
| 6.8 | Agents: nothing beyond their listed types without LEASH; the policy may allow or refer an owner type, never an app-only type | `vault.TestAgentPolicyHook`, `e2e.TestDesktopSession` |
| 7.4, 6.8 | Unlinking ends the device's access session, held requests and pending request | `vault.TestAccessSessions` |
| 9.1 | Fan-out reaches desktops only within their access session | `vault.TestAccessSessions`, `e2e.TestPairConnectMessage` (desktop with a session gets `message.new`) |
| 7.4, 10.4 | Block: the connection removed (tokens denylisted by jti, peer notified best effort), a block entry on its `ik` and relay key; refused deposits mark the peer stale; nothing reaches the owner | `vault.TestBlocks`, `e2e.TestBlockRefusesPeer` |
| 10.4 | A blocked identity's `hs.init` is dropped (`drop.blocked`), even from a new relay key; its invitation is answered `blocked`; a pending request can be blocked; `exists`, `not_found`, bad bodies; after unblock a new connection works | `vault.TestBlocks`, `e2e.TestBlockRefusesPeer` |
| 7.4, 6.7 | Removal denylists every token issued to the peer by jti (including handshakes in flight), not its relay key; the removed peer's deposits are refused; a new invitation and approval reconnect the same peer (same relay key); a fresh connection replaces a stale record | `vault.TestBlocks`, `vault.TestReconnectAfterRemoval`, `e2e.TestRevokeConnection` |
| 3.5.5, 10.4 | `credential.rotate` signs a rotation statement with the old and the new credential key; delivered to connections that pinned the old key; followed chains move the pin (`connection.authenticate.key`, then `key_changed: false`); missed deliveries caught up in the response's `rotations`; forged, unsigned, broken or overlong chains rejected and audited, then `key_changed: true` | `credwire.TestKeyRotationChain`, `credwire.FuzzParseKeyRotation`, `connauth.TestKeyRotationFollowed`, `connauth.FuzzParseRotations`, `e2e.TestConnectionAuthenticate` |
| 10.10 | Desktops within an access session place and answer calls (no per-call approval); without a session no ringing and `session_required`; first answer wins across app and desktop, late answers refused | `e2e.TestDesktopCalls` |
| 10.10 | Key-exchange shares: signed by the device, checked against its paired record and vouched for by its vault; checked by the peer vault under the connection's pinned `ik` and by the peer device under `peer_ik`; a swapped `ek` or `enc` is refused (no ringing; answer not passed on) and audited | `calls.TestSwappedShares`, `e2e.TestDesktopCalls`, `e2e.TestCallSignalling` |
| 10.4 | `connection.update`: versioned (`conflict`), field limits, in the listings, never sent to the peer; `sync.event{connection.changed}` | `vault.TestConnectionUpdate`, `vault.FuzzParseMetaUpdate` |
| 10.4 | Removal or blocking tells features (`ConnectionRemovedObserver`): calls end, authentication state dropped | `vault.TestBlocks`, `calls.TestMissedDeclineAndAuthority`, `connauth.TestAuthenticate` |
| 10.4 | Member authentication: signed with the credential key only within the unlock window (`credential_locked`), only by apps; the signed bytes bind both vaults' `ik`, nonce, request id and context; verified and pinned by the requester; key change reported; denial; replay of a response ignored; limits and expiry | `connauth.TestAuthenticate`, `connauth.TestLimitsAndRoles`, `e2e.TestConnectionAuthenticate` |
| 10.10 | Offer with `exp` (45 s; refused without one or more than 90 s ahead), idempotent by `call_id`; busy (one call at a time); missed calls in the feed | `calls.TestCallFlow`, `calls.TestBusy`, `calls.TestMissedDeclineAndAuthority`, `e2e.TestCallSignalling` |
| 10.10 | Each vault signs the ICE configuration for its own devices; devices verify signature, call id, expiry and canonical form | `callwire.TestICEConfig`, `calls.TestCallFlow`, `e2e.TestCallSignalling` |
| 10.10 | The media key is agreed device to device (MLKEM768X25519 bound to `call_id`); vaults relay `ek`/`enc` only | `callwire.TestMediaKeyAgreement`, `calls.TestCallFlow`, `e2e.TestCallSignalling` |
| 10.10 | Answer from the first device (`answered_elsewhere` to the others, `unavailable` to a late one); answer and ICE to the call's device only; authority per connection and device | `calls.TestCallFlow`, `calls.TestMissedDeclineAndAuthority`, `e2e.TestCallSignalling` |
| 8.5, 10.10 | `call.ice` and `call.ringing` are ephemeral (`exp`) and forwarded memory-only, never in vault state | `calls.TestCallFlow`, `e2e.TestCallSignalling` |
| 10.10 | Roles: apps and desktops; peers offer; never agents | `calls.TestAuthorization` |
| 10.10 | coturn `use-auth-secret` credentials; no servers without a calling service | `calls.TestCoturnIssuer` |
| 10.1 | New error codes and `sync.event` kinds | the tests above |
| 10.9 | Batch-2 audit and feed kinds (no SDP, keys or content) | `calls.TestCallFlow`, `connauth.TestAuthenticate`, `e2e.TestCallSignalling`, `e2e.TestDesktopSession` |
| 13.6 | New parsers fuzzed | `vault.FuzzParseMetaUpdate`, `vault.FuzzDeviceMessage` (every registered type), `callwire.FuzzParseICEConfig`, `callwire.FuzzAccept`, `calls.FuzzParse*`, `connauth.FuzzParse*` |
| 13.6 | No package-level mutable state in feature code; the vault's `ik` signs only ICE configurations for features (`Host.SignICEConfig` parses first) | `features/all` (per-vault instances), `calls.TestCallFlow` |

## V4 batch 3: LEASH, grants, critical-secret use, shared actions (§6.7, §6.8, §9.1, §10.1, §10.6, §10.7, §10.11–§10.14, §13.5; 0.6.0)

Runtime rules (the policy for `agent.request`, the re-check on approval,
initial grants at pairing) are tested in `vault` with in-process devices;
the features in their packages through `internal/featuretest`; the flows
through the real relay in `e2e.TestLeashAgent`, `e2e.TestGrantShareAndRevoke`,
`e2e.TestCriticalSecretUse`, `e2e.TestSharedAction` and
`e2e.TestVaultctlBatch3` (vaultctl's batch-3 commands).

| § | Requirement | Test(s) |
|---|---|---|
| 6.8, 10.11 | `agent.request` is decided by the policy for every agent request (refuse `forbidden`, allow, refer to an app); no policy without an access session (`session_required`); other principals never reach it | `vault.TestAgentPolicyType`, `leash.TestAuthorization`, `e2e.TestLeashAgent` |
| 6.8, 10.11 | A referred request runs on approval only while a grant covers it (otherwise `forbidden`) | `vault.TestAgentPolicyType` |
| 6.7, 10.3 | `device.pair.approve{grants}` only for agents, validated at the approval (never signed), installed when the pairing completes after `device.paired`, then `leash.grant.updated` | `vault.TestPairingGrants`, `leash.TestPairingUnlinkRemoval`, `e2e.TestLeashAgent` |
| 10.11 | Scopes: the three LEASH operations and the nine delegable owner types only; never app-only, credential, device, settings, invitation, grant or approval types | `leash.TestIssueValidation`, `leash.TestDecisions`, `e2e.TestLeashAgent` (`settings.get`) |
| 10.11 | Restrictions (`connections` only for connection-scoped types, `secrets` only for `secrets.*`; a request without the member never matches; the catalog filtered), `auto` `secrets.get` needs `secrets`, limits only on `auto`, expiry in the future and ≤ 365 days, at most 32 grants, versions and `conflict` | `leash.TestIssueValidation`, `leash.TestDecisions`, `leash.TestAgentRequest`, `leash.TestReplaceListNotify`, `leash.FuzzParseSpec` |
| 10.11 | Decisions: none → refuse (`drop.leash_refused`); `auto` within both windows → allow (`leash.allowed`); past a limit → refer, `leash.rate_limited` once per window (high-priority feed item); a new window allows again | `leash.TestDecisions` |
| 10.11 | `agent.request`: only cataloged vault-held secrets the grants name (a private one is `not_found`); `secret.get` returns the value (`leash.secret.read`); `secret.use` returns HMAC-SHA-256, never the value; bad bodies `bad_request` | `leash.TestAgentRequest`, `leash.FuzzParseRequest`, `e2e.TestLeashAgent` |
| 10.11 | Revocation at once (agent told, `sync.event{leash.grant.revoked}`); unlink revokes all (§7.4); removing a connection narrows or revokes; expired grants dropped | `leash.TestAgentRequest`, `leash.TestPairingUnlinkRemoval`, `leash.TestExpiry`, `e2e.TestLeashAgent` |
| 10.11 | Signed delegation: only within the unlock window (`credential_locked`), canonical bytes, Ed25519 by the credential key, `exp` ≤ 24 h; verifiers check form, signature and expiry | `leashwire.TestDelegationRoundTrip`, `leashwire.TestDelegationStrict`, `leashwire.FuzzParseDelegation`, `leash.TestSignedDelegation`, `e2e.TestLeashAgent` |
| 9.1 | Agents get no fan-out, only responses, §6.8 messages and their own `leash.grant.updated` within their session | `leash.TestReplaceListNotify`, `e2e.TestLeashAgent` |
| 10.7, 10.12 | `discoverability` takes effect: only `cataloged` secrets are listed (metadata only), granted, or read and used by agents; turning one private stops later fetches (`unavailable`) | `leash.TestAgentRequest`, `grants.TestCatalog`, `grants.TestDenyPartialAndUnavailable`, `e2e.TestGrantShareAndRevoke`, `e2e.TestVaultctlBatch3` |
| 10.12 | Ask, decide, fetch and revoke as events correlated by `request_id`/`fetch_id`; `grant.pending` to apps and desktops; `grant.event` granted, denied, revoked | `grants.TestShareFetchRevoke`, `grants.TestDenyPartialAndUnavailable`, `e2e.TestGrantShareAndRevoke` |
| 10.12 | Roles: device types from apps and desktops; `data.*` only from connections; agents never; `grant.decide` a desktop step-up type | `grants.TestAuthorization` |
| 10.12 | Only available items granted (existing fields, cataloged secrets); none → `bad_request`; partial `items`; the decision may set `uses` and `expires_in` | `grants.TestDenyPartialAndUnavailable`, `e2e.TestGrantShareAndRevoke` |
| 10.12 | Values sealed to the fetching device's one-time `reply_key`, bound to grant and fetch; the asking vault never holds plaintext; `grant.value` only to the fetching device | `sharewire.TestSealValue`, `sharewire.FuzzOpenValue`, `grants.TestShareFetchRevoke`, `e2e.TestGrantShareAndRevoke` |
| 10.12 | Fetch refusals `not_found`, `revoked`, `expired`, `exhausted`, `unavailable` (audited); uses counted; a repeated `fetch_id` answered again without a use | `grants.TestShareFetchRevoke`, `grants.TestExpiry`, `grants.TestDenyPartialAndUnavailable` |
| 10.12 | Repeated `request_id` ignored (another connection's dropped, `drop.grant_duplicate`); at most 16 pending per connection (`drop.grant_limit`); undecided after 7 days → denied; fetches forgotten after 10 min; limits on active grants | `grants.TestIdempotencyAndLimits`, `grants.TestExpiry` |
| 10.12 | Either side revokes, the other is told; removing or blocking a connection drops everything of it without notice | `grants.TestShareFetchRevoke`, `grants.TestRelinquishAndRemoval` |
| 10.12 | Catalog: cataloged vault-held secrets and cataloged critical secrets (`critical: true`), metadata only, to the asking device | `grants.TestCatalog`, `e2e.TestGrantShareAndRevoke` |
| 10.12 | Malformed peer messages dropped and audited, never answered; state survives a flush and unlock | `grants.TestBadBodies`, `grants.TestRoundTrip`, `grants.FuzzPeerMessage` |
| 10.6, 10.13 | `credential.secret.catalog` (app only, no password) lists a critical secret's metadata; `cataloged` in `credential.secret.list`; `sync.event{credential.secret.cataloged}` | `critical.TestRefusals`, `e2e.TestCriticalSecretUse`, `e2e.TestVaultctlBatch3` |
| 10.13 | Roles: request, deny, list from apps and desktops; approve only from apps; `critical-secret.use` and `.result` only from connections | `critical.TestAuthorizationAndBadBodies`, `critical.TestConsent` |
| 3.5.4, 10.13 | Consent per use: the UTK-sealed password bound to `request_id` and `payload_sha256` (constant time); a mismatch is `bad_request` with the UTK spent and nothing signed | `critical.TestConsent` |
| 3.5.3, 10.13 | Each use opens and rotates the credential (the old blob `stale_credential`); `bad_password` and `backoff` keep the request pending; nothing retained | `critical.TestUseFlow`, `critical.TestConsent`, `e2e.TestCriticalSecretUse` |
| 10.13 | `sign` over the payload; `auth` domain-separated over both vaults' `ik`, the request id and the payload; `public_key`; not a 32-byte seed → `unsuitable`; deleted since → `unavailable` | `critical.TestUseFlow`, `critical.TestRefusals`, `sharewire.TestAuthMessage`, `e2e.TestCriticalSecretUse` |
| 10.13 | Only cataloged critical secrets (others `unavailable` without asking, private and unknown not told apart); at most 8 pending per connection; `expired` after 24 h; repeated `request_id` ignored; denial | `critical.TestRefusals`, `critical.TestUseFlow` |
| 10.13 | The asking vault accepts results only for its own pending request from that connection, verifies the signature (`drop.critical_signature`), forwards to apps and desktops | `critical.TestForgedResultDropped`, `critical.TestUseFlow`, `e2e.TestCriticalSecretUse` |
| 10.13, 7.4 | Removing a connection drops its requests without notice | `critical.TestRefusals` |
| 10.14 | Roles: apps and desktops define, delete, list, invoke, respond; connections send `action.offered`, `action.invocation`, `action.result`; agents only through LEASH; `action.define` a desktop step-up type; no type is both a request and an event | `actions.TestAuthorization` |
| 10.14 | Definitions: `respond` needs `ask` and no result; `fixed` a result object ≤ 16 KiB; at most 64; allowlist of distinct ids; versioned replacement (`conflict`); delete | `actions.TestDefineReplaceDelete`, `actions.TestBadBodies` |
| 10.14 | Complete offered list to each affected active connection after every change (empty when none remain); never the fixed result; the receiver keeps it and tells its devices (`sync.event{action.offers}`) | `actions.TestDefineReplaceDelete`, `e2e.TestSharedAction` |
| 10.14 | Invoking needs an offer (`not_found`); `respond` answered by the member; deny; `fixed` + `ask` approved returns the fixed result; `fixed` + `auto` answered at once | `actions.TestInvokeRespond`, `actions.TestDenyAndFixedAsk`, `actions.TestFixedAutoAndUnavailable`, `e2e.TestSharedAction` |
| 10.14 | `unavailable` for an unknown action, one not offered to that connection, another version, a 9th pending invocation, or after a deletion or redefinition stops the offer | `actions.TestFixedAutoAndUnavailable`, `actions.TestPendingLimitExpiryIdempotency`, `actions.TestRedefineDropsPending` |
| 10.14 | `expired` after 24 h; a repeated `invocation_id` ignored; late or foreign results dropped; state survives a flush | `actions.TestPendingLimitExpiryIdempotency`, `actions.TestInvokeRespond` |
| 10.14, 7.4 | Removing a connection drops it from allowlists, its offers and invocations both ways | `actions.TestConnectionRemoved` |
| 10.1, 10.9 | Batch-3 `sync.event`, audit and feed kinds (no values, payloads or signatures in the log) | `leash.TestReplaceListNotify`, `grants.TestShareFetchRevoke`, `critical.TestUseFlow`, `actions.TestInvokeRespond`, `e2e.TestLeashAgent`, `e2e.TestCriticalSecretUse`, `e2e.TestSharedAction` |
| 13.6 | New parsers fuzzed | `leashwire.FuzzParseDelegation`, `sharewire.FuzzOpenValue`, `leash.Fuzz*`, `grants.Fuzz*`, `critical.Fuzz*`, `actions.Fuzz*` |
| 13.6 | No package-level mutable state in feature code (per-vault instances in `features/all`) | `features/all` |
