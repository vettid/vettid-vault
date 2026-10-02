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

## V3a alternate channel, attestation and release updates (§11, §12, §13)

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
| 11.3 | A confirmed vault MUST NOT be replaced (vault_exists); a provisional one may be after 24 h | `e2e.TestAltchanEnrollUnlock`, `enclave.TestProvisionalReplacement` |
| 11.3 | vault.enrolled attestation: nonce, user_data over the bundle, PCRs | `enclave.TestEnrolledAttestationChecked`, `e2e.TestAltchanEnrollUnlock` |
| 11.3 | First app's handshake, provisional window | `e2e.TestAltchanEnrollUnlock`, `e2e.TestPairConnectMessage` |
| 11.4 | Unlock order: header, unlock key + sig, device assertion, backoff, rollback, manifest, DEK | `enclave.TestBadPINAndBackoff`, `enclave.TestRollbackRefused`, `enclave.TestManifestRefused`, `enclave.TestDeviceAttestationRefused` |
| 11.4 | Results sealed to the device's kem; unknown device / bad signature dropped with a same-size answer | `enclave.TestUnknownDeviceDropped`, `enclave.TestUniformSizes` |
| 11.4, 13.2 | App MUST warn on state_rollback | `client.OpenUnlockResult` returns the code; `vaultctl altchan-unlock` prints the warning |
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
