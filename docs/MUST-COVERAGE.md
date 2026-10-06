# VAULT-MESSAGING §4–§6 requirements → tests

(Updated for VAULT-MESSAGING 0.10.0: manifest by hash, `removed` and
`ends_at`, the retirement key-policy delta, per-channel release constants;
for 0.10.2 and 0.10.3: connection requests, the SAS commitment, the
handshake before approval, request tokens; for 0.10.5:
`connection.declined` and `device.pair.rejected`; for 0.10.6: the
recovery marker, `credential_backup` and the lock state; for 0.12.0:
LEASH delegations and status statements in the LEASH paper's §3.5 format;
for 0.13.0: the daily owner check and the hold; and for 0.15.0:
enrollment codes, app keys and the account snapshot.)

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
| 6.2 | 0.10.3: `sas_commit` (hs.init), `sas_nonce` (hs.resp n_R, hs.fin n_I), 32 bytes each, exactly for app, desktop, agent and connection, absent for rekey and reconnect; a connection handshake carries a request token and no `reconnect_token` | `handshake.TestInitFieldRules`, `handshake.TestRespFieldRules`, `handshake.TestNoSASForRekeyAndReconnect`, `handshake.FuzzParseFin`, `vectors.TestVectors` (handshake) |
| 6.3 | Key schedule, th1/th, kids, rk, epoch_id, SAS | `vectors.TestVectors` (handshake), `handshake.TestSASBothSides` |
| 6.3 | 0.10.3: `sas_commit` = SHA-256(label ‖ n_I); `sas` from prk, th, n_I and n_R; the initiator knows it after sig_R, the responder after sig_I and the commitment; one hs.resp per hs.init | `handshake.TestSASBothSides`, `handshake.TestSASDependsOnBothNonces`, `vectors.TestVectors` (handshake) |
| 6.3 | 0.10.3: an hs.fin whose sig_I verifies but whose n_I does not open the commitment aborts the handshake (`drop.sas_commit_mismatch`); its request is dropped, never shown, the request token denylisted | `handshake.TestSASCommitMismatchAborts`, `vault.TestSASCommitMismatch` |
| 6.3 | Session kids per direction (i2r: recipient kid_i2r, sender kid_r2i) | `handshake.TestSessionDirectionKids`, `vectors.TestVectors` (hs.fin) |
| 6.3 | I MUST verify sig_R before using any epoch key, MUST abort on failure | `handshake.TestMustVerifySigRAndAbort`, `handshake.TestJunkDoesNotCancelHandshake` |
| 6.3 | Abort only once a message decrypted under eph; junk is dropped | `handshake.TestJunkDoesNotCancelHandshake`, `handshake.TestMustVerifySigRAndAbort` |
| 6.3 | R activates the epoch only after sig_I verifies | `handshake.TestMustActivateOnlyAfterSigI` |
| 6.3 | Collect `sender` MUST equal from.relay.pk (hs.init) and the record (later) | `handshake.TestMustCheckCollectSender`, `handshake.TestRekeyRequiresRecordIdentity` |
| 6.3 | (Before 0.10.3: SAS depended only on hs.init; replaced by the commitment above) | — |
| 6.4 | Invite TTL MUST be ≤ both relay limits; app MUST NOT offer more | `invite.TestInviteTTL` |
| 6.4 | Remote invites: auto-approval MUST NOT apply | `invite.TestAutoApproval` |
| 6.4 | Bundle encryption; MUST check `h` before decrypting; MUST reject wrong `kind`, `exp` ≠ `e`, expired | `invite.TestInviteFlow`, `invite.TestBundleCommitment`, `invite.TestBundleChecks`, `invite.TestQRStrict`, `vectors.TestVectors` (invite) |
| 6.4 | Single use per invite_id; reject expired, used or revoked invites | `vault.TestInviteSingleUse`, `vault.TestInviteCancelled`, `vault.TestInviteExpiry`, `invite.TestBundleChecks` |
| 6.4 | Remote invites stay pending; auto-approval MUST NOT apply; 0.10.3: hs.resp at once, no `connection.approved` while pending; in-person auto-approval approves at hs.fin and still shows the code | `vault.TestRemoteInviteStaysPending`, `e2e.TestPairConnectMessage` |
| 6.4 | Pending connection requests dropped 7 days after hs.init (`sync.event{connection.request, expired}`); approved ones kept 16 days | `vault.TestPendingConnectionExpires` |
| 6.4 | 0.10.2/0.10.3: both members see the SAS (`connection.request.pending`, `connection.request.outgoing`); each approves its side; `connection.approved{token, reconnect_token}` both ways; active with both approvals, in either order; `connection.event{added, pending_id}`; `connection.request.list` | `vault.TestConnectionRequestBothApprove`, `e2e.TestPairConnectMessage`, `e2e.TestIntroductionAccepted`, `integration.TestV3Exit` |
| 6.4 | 0.10.3: approving while the SAS is unknown is `bad_request`; before activation only `connection.approved` is taken (else `drop.unapproved_peer`, or left unacked after the member's approval) | `vault.TestConnectionRequestBothApprove`, `vault.TestPreActivationAndRequestToken` |
| 6.4 | 0.10.2: `exists{connection_id}` before any hs.init for a connected or requested vault; the inviter's drop by sender or `from.ik` (`drop.hs_init_from_known_peer`) | `vault.TestAcceptExists`, `vault.TestInviterDropsKnownIdentity`, `e2e.TestBlockRefusesPeer` |
| 6.4 | A decline denylists the request token (0.10.2; since 0.10.5 it is also sent, below); an outgoing request fails after 8 days (`connection.event{failed}`); at most 256 requests each way | `vault.TestDeclineRequest`, `vault.TestOutgoingRequestExpires`, `e2e.TestBlockRefusesPeer` |
| 6.4, 7.4 | 0.10.5: the member's decline sends `connection.declined{}` under the handshake's epoch on the request token the **peer** issued (also after the peer's `connection.approved` replaced it), queued first in the flush that drops the request; the decliner denylists only its own tokens | `vault.TestDeclineSentInviterToAccepter`, `vault.TestDeclineSentAccepterToInviter`, `vault.TestDeclineAfterPeerApproval`, `vault.TestDeclineRequest` |
| 6.4, 10.4 | 0.10.5: `block.add{pending_id}` sends `connection.declined` too, indistinguishable from a decline | `vault.TestBlockPendingSendsDecline` |
| 6.4 | 0.10.5: nothing is sent by an accepter in `waiting`, for an `hs.init` without `hs.fin`, or at expiry | `vault.TestDeclineWaitingSendsNothing`, `vault.TestExpirySendsNoDecline` |
| 6.4, 10.1, 10.4, 10.9 | 0.10.5: the receiver, whether or not its member approved, ends the request: `sync.event{connection.request, state: peer_declined}` in both directions, `connection.event{failed, reason: declined}` on the accepter's side, every token it issued denylisted (request, standing, reconnect), the slot freed, `exists` cleared, audit and feed `connection.request.peer_declined` | `vault.TestDeclineSentInviterToAccepter`, `vault.TestDeclineSentAccepterToInviter`, `vault.TestDeclineAfterPeerApproval`, `e2e.TestConnectionDeclineSent`, `e2e.TestVaultctlDecline`, `integration.TestV3Exit` |
| 6.4 | 0.10.5: a late or duplicate `connection.declined` finds no request and is dropped and audited | `vault.TestDeclineSentInviterToAccepter` |
| 6.4 | 0.10.5: one that reaches a connection already active (the receiver's approval completed it while the decline was in flight) is handled as `connection.removed` (no notice back; `connection.event{removed}`), audited `connection.request.peer_declined` | `vault.TestDeclineCrossingActivation` |
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
| 6.7 | 0.10.3: hs.resp at once with a request token; `device.pair.pending{sas}` after hs.fin; nothing but the handshake before approval (`drop.unapproved_peer`); the approval activates and sends `device.paired{token}`; drop after 10 min and denylist the open and request tokens | `vault.TestPairingHandshakeThenApproval`, `vault.TestInviteExpiry`, `e2e.TestPairConnectMessage` |
| 6.7, 6.7.1 | 0.10.5: the owner's `device.pair.reject` or `device.transfer.reject` after `hs.fin` sends `device.pair.rejected{}` under the handshake's epoch on the token the new device issued in `hs.init`, before the drop; nothing before `hs.fin`, nor for an expiry, a clone alarm or a recovery; retries end with the pairing's 10 minutes | `vault.TestPairRejectedSent`, `vault.TestTransferRejectedSent`, `vault.TestOutboxNotAfter` |
| 6.7 | 0.10.5: the new device stops waiting on `device.pair.rejected`, drops its handshake state and request token (Go client: `ErrPairRejected`; `vaultctl pair` reports "rejected on your phone") | `e2e.TestPairingRejectSent`, `e2e.TestTransfer`, `e2e.TestVaultctlDecline` |
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
| 7.1 | 0.10.3: request tokens (8 / 64 KiB; ≤ 16 d, a device ≤ 10 min) carry only hs.resp, hs.fin, `connection.approved` and (0.10.5) `connection.declined`, the last also once the connection is active (else `drop.request_token_misuse`); `relay.token.refresh` on one is `forbidden` | `vault.TestPairingHandshakeThenApproval`, `vault.TestPreActivationAndRequestToken`, `vault.TestDeclineCrossingActivation` |
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
| 11.3 | device_attest REQUIRED; manifest_sha256 and manifest_serial REQUIRED (0.10.0; the host-supplied document verified against them, own active entry, own key checked before the first seal, else release_key) | `enclave.TestDeviceAttestationRefused`, `enclave.TestSealKeyPolicyRefused`, `enclave.TestManifestByHash` (enrollment), `altchan.TestRequestRoundTrip` |
| 11.3 | A confirmed vault MUST NOT be replaced (vault_exists); a provisional one may be after 24 h; re-enrollment with the member's existing vault_id (refused if confirmed, < 24 h or sealed to another release; otherwise replaced) | `e2e.TestAltchanEnrollUnlock`, `enclave.TestProvisionalReplacement`, `enclave.TestReenrollSameVaultID` |
| 11.3 | `vault.enroll.result` in the response slot, sealed to app.kem, 4,096 bytes, `re` = request_id | `enclave.TestEnrollUnlock`, `altchan.TestSealOpen` |
| 11.3 | vault.enrolled attestation: nonce, user_data over the bundle, PCRs | `enclave.TestEnrolledAttestationChecked`, `e2e.TestAltchanEnrollUnlock` |
| 11.3 | First app's handshake, provisional window | `e2e.TestAltchanEnrollUnlock`, `e2e.TestPairConnectMessage` |
| 11.4 | Unlock order: header, unlock key + sig, device assertion, backoff, rollback, manifest, DEK | `enclave.TestBadPINAndBackoff`, `enclave.TestRollbackRefused`, `enclave.TestManifestRefused`, `enclave.TestDeviceAttestationRefused` |
| 11.4 | Results sealed to the device's kem; unknown device / bad signature dropped with a same-size answer | `enclave.TestUnknownDeviceDropped`, `enclave.TestUniformSizes` |
| 11.4, 13.2 | App MUST warn on state_rollback | `client.OpenUnlockResult` returns the code; `vaultctl altchan-unlock` prints the warning |
| 11.1, 11.2 | `instance_id` is `[A-Za-z0-9_-]{1,48}` (configuration and descriptors) | `enclave.TestInstanceIDValidated`, `altchan.TestDescriptor`, `altchan.TestValidInstanceID` |
| 11.5 | Queue message: `etk_kid` and `envelope` absent for lock/delete; `manifest_sha256` present exactly for enroll and unlock (0.10.0); response `{v, request_id, status: done\|etk_unknown, envelope?}` | `enclave.TestQueueMessage`, `enclave.TestETKLifecycle` (`etk_unknown` without envelope), `enclave.FuzzParseQueueMessage` |
| 11.5, 11.10.4 | Manifest by hash (0.10.0, M1): the enclave verifies the host-supplied document in order (present, served format ≤ 90,112 bytes, SHA-256 = manifest_sha256, signature under a pinned key, strict format, serial = manifest_serial, serial ≥ the header's, own entry); any failure (withheld, another or corrupt document) is `manifest`, not a PIN failure; the unlock signing string is unchanged | `manifest.TestVerifyByHash`, `manifest.FuzzVerifyByHash`, `enclave.TestManifestByHash`, `enclave.FuzzProcessBody` (fuzzed document), `altchan.TestUnlockSigningString`, `vectors.TestVectors` (altchan 0.10.0) |
| 11.10.1 | Manifest bytes ≤ 65,536 (30 realistic entries fit); served document ≤ 90,112 | `manifest.TestStatusesEndsAtAndSize` |
| 11.6 | Replayed request_id refused while its ETK lives; destroyed ETK → etk_unknown | `enclave.TestReplayRefused`, `enclave.TestETKLifecycle`, `e2e.TestAltchanEnrollUnlock` |
| 11.7 | Android: chain to a pinned root, challenge, TEE/StrongBox, RootOfTrust locked + Verified, package and signer digests, signing-only generated P-256 key; status list ≤ 24 h at enrollment and pairing, ≤ 7 d at unlock | `devattest.TestAndroidHappyPath`, `devattest.TestAndroidRejects`, `enclave.TestDeviceAttestationRefused` |
| 11.7 | iOS: App Attest chain, nonce, key id, App ID, production aaguid, counter 0; assertions with increasing counters | `devattest.TestIOS`, `enclave.TestBadPINAndBackoff` (iOS app) |
| 11.7, 6.7 | App pairing carries device_attest; binding into the unlock keys | `vault.TestPairingDeviceAttestation`, `e2e.TestAltchanEnrollUnlock` (paired iOS app unlocks) |
| 11.7 | Vendor roots pinned (and the test roots never accepted by them) | `pins.TestFingerprints`, `pins.TestRootsValid`, `devattest.TestAndroidRejects` ("google roots"), `devattest.TestIOS` ("apple root"), `nitro.TestVerifyRejects` ("aws root") |
| 11.8 | Backoff after 3 failures (30 s …), reset on success, never wipe; manifest failures not counted | `enclave.TestBadPINAndBackoff`, `enclave.TestManifestRefused`, `vault.TestBadPINBackoff` |
| 11.10.1 | Manifest: strict format, ECDSA P-256 over the exact bytes under a pinned key, key_id; serial lower than seen MUST be refused (apps and enclave); no debug PCRs | `manifest.TestSpecVector`, `manifest.TestVerify`, `manifest.TestParseRejects`, `client.TestVerifyManifestSerial`, `enclave.TestManifestRefused`, `vectors.TestReleaseVectors` |
| 11.10.1 | Statuses fixed at release 1 (`active`, `deprecated`, `retired`, `removed`), unknown ones refused; optional `ends_at` (whole-second RFC 3339, after `published_at`), validated wherever present | `manifest.TestStatusesEndsAtAndSize`, `manifest.TestParseRejects`, `vectors.TestReleaseVectors` (manifest_0_10_0) |
| 11.10.4–5 | `removed`: never a move target (`target`), never enrolled into (apps), but a running release whose own entry is removed still unlocks and moves on (rescue); `release_status` reports it | `enclave.TestRemovedRelease` |
| 11.10.3 | Approval string, signed by the device attestation key; bound to the request; iOS counter increases | `altchan.TestApprovalSigningString`, `vectors.TestReleaseVectors`, `enclave.TestReleaseMove` (iOS) |
| 11.10.4 | Move sequencing: checks in order (target, downgrade, approval, seal_key, pending), record the move, seal to N+1 create-only, lock, report moved | `enclave.TestReleaseMove`, `enclave.TestSealKeyPolicyRefused`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.4 | Pending move completed without a new approval after a step-7 failure; a different target does not change it | `enclave.TestPendingMoveCompletes` |
| 11.10.4 | Confirmation at N+1 deletes header/N; N MUST refuse a vault that left (wrong_release); N cannot open N+1's header | `enclave.TestReleaseMove`, `enclave.TestWrongReleaseRefused` |
| 11.10.4 | Abandoning an unconfirmed move | `enclave.TestAbandonMove`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.4 | Forward only: equal or lower releases refused (downgrade) | `enclave.TestReleaseMove`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.7 | Key identity, metadata, no grants, policy shape, Deny ignored, actions, attestation condition, principals; the passing example and every must-fail variant | `keypolicy.TestExamplePasses`, `keypolicy.TestMustFailVariants`, `keypolicy.TestMoreRefusals`, `keypolicy.FuzzCheckPolicy`, `keypolicy.FuzzPolicyDocument` |
| 11.10.7 | Check before the first seal under a key (enrollment: release_key; move: seal_key); record seal_key_verified | `enclave.TestSealKeyPolicyRefused`, `e2e.TestAltchanReleaseUpdates` |
| 11.10.7 | Retirement delta (0.10.0): only the pinned retirement principal, in statements of retirement actions only, may `ScheduleKeyDeletion` (with `NumericEquals` on the pinned window, required) and `CancelKeyDeletion` / `EnableKey`; exact principal and `kms:CallerAccount`; never in a `Decrypt`/`GenerateDataKey` statement; unpinned images refuse the actions; check 2 refuses a key pending deletion or disabled; every new must-fail variant | `keypolicy.TestExamplePasses` (0.10.0 example), `keypolicy.TestRetirementMustFailVariants`, `keypolicy.TestRetirementPinned`, `keypolicy.TestWindowValue`, `keypolicy.FuzzPolicyDocument`, `enclave.TestRetirementPinnedInImage`, every enclave and e2e test (the test release keys carry the retirement statements) |
| 11.10.8 | Per-channel release constants: one channel per build (build tag), embedded from the committed file, the same file as the source; release builds refuse placeholders or missing values; an incomplete file pins nothing (fail closed); no `-ldflags -X` | `releasecfg.TestCommittedFiles`, `releasecfg.TestEmbedded` (`make channels`, per tag), `releasecfg.TestRefusals`, `releasecfg.TestCompletePasses`, `releasecfg.FuzzParse`, `make check-tcb`, CI "release gate refuses placeholders" |
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
| 11.5 | Parent supplies the manifest document an enroll or unlock names (`manifests/<sha256>.json`; none if missing, too large or not that manifest; never for other ops) with the unchanged queue message (0.10.0) | `parent.TestManifestDocument`, `e2e.TestHostStack`, `integration.TestV3Exit` (documents read from the LocalStack bucket) |
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
in `e2e.TestCredentialFlow`, `e2e.TestProfileItemsAuditFeed` and
`e2e.TestVaultctlSmoke` (vaultctl's feature commands).

| § | Requirement | Test(s) |
|---|---|---|
| 3.5.1, 3.5.2 | Blob: HPKE to the CEK over a password layer (Argon2id + HKDF), header as AAD, bound to `vault_id`; refuse KDF parameters below t=1, m=8 MiB | `credential.TestBlobLayers`, `credential.FuzzOpen` |
| 3.5.2, 10.6 | Strict plaintext, request envelopes and UTK payloads: item-key entries (`item_id`, `gen`, 32-byte `key`), ≤ 1,000 entries within the 131,072-byte plaintext (`limit`), versions agree | `credential.FuzzParseInner`, `credential.FuzzParseEnvelope`, `credential.FuzzParsePayload`, `credential.FuzzParseOpPayload`, `credential.TestInnerLimit`, `credential.TestBadBodies` |
| 3.5.3 | Every use carries the blob and the password; every use rotates the CEK and destroys the old one, so the previous blob is undecryptable (not only refused) | `credential.TestCEKRotatesOnEveryUse`, `e2e.TestCredentialFlow` |
| 3.5.3 | Wrong password: `bad_password`, counted, audited; backoff after 5 failures; success resets | `credential.TestBadPasswordAndBackoff`, `e2e.TestCredentialFlow` |
| 3.5.3 | No plaintext, password or critical value in vault state | `credential.TestOperateAndReplyKey`, `items.TestCriticalItems`, `items.TestSensitivityChanges` |
| 3.5.3 | A lost response never loses the credential: the latest blob is kept until `credential.ack` (even with backup off) and fetched with `credential.get`; responses are cached | `credential.TestLatestBlobKeptUntilAck` |
| 3.5.4 | UTK pool of 20, refill by 10 under 10, expiry, single use (`utk_invalid` on reuse), bound to the device, the type and the request id | `credential.TestUTKPool`, `credwire.TestPayloadBinding`, `credwire.FuzzOpenPayload`, `e2e.TestCredentialFlow` (reuse refused, replenishment through the relay) |
| 3.5.4 | Critical values return sealed to a one-time reply key carried in the UTK payload; nothing secret in the clear in the response | `credential.TestOperateAndReplyKey`, `items.TestCriticalItems`, `credwire.TestValue` |
| 8.2 | A volatile response is neither cached nor written to state; a retransmission is executed again (runtime rule; no type of 0.4.1 needs it) | `vault.TestVolatileResponses` |
| 3.5.7 | A vault without a credential answers `credential_required` except to the listed types, stays provisional, records `has_credential` | `vault.TestCredentialGate`, `e2e.TestNoCredentialNoRecovery`, `e2e.TestVaultctlSmoke` |
| 3.5.3 | Unlock window: memory only; ends at expiry, `credential.lock`, rotation, delete and vault lock | `credential.TestUnlockWindow` |
| 3.5.5, 3.4 | Rotation: new credential key, `ik`/`kem` rotated in the same flush; nothing changes if the identity rotation fails | `credential.TestRotateRotatesIdentity`, `e2e.TestCredentialFlow` |
| 3.5.5 | Create once (`exists`); 0.15.2: no `credential.delete` (`unsupported_type`), a credential is replaced only by `credential.reset` (or deleted with the vault) | `credential.TestCreateOnce`, `credential.TestHolderReset` |
| 10.6 | Roles: apps only, except `credential.version` (apps and desktops); agents and peers never; `credential.secret.*` gone (0.7.0); another feature's operation (`Operate`) app-only | `credential.TestAuthorizationBySenderKind`, `e2e.TestCredentialFlow` |
| 10.1 | `version` on shared objects; `conflict` on a stale version; an error changes no state | `items.TestItemsCRUD`, `items.TestTags`, `items.TestProfile`, `vault.TestSettings`, `e2e.TestProfileItemsAuditFeed` |
| 10.1 | `sync.event` kinds to the other owner devices, without values | `credential.TestCreateOnce`, `items.TestItemsCRUD`, `feed.TestItemsAndSync`, `e2e.TestCredentialFlow` |
| 10.7 | Items (0.7.0, replacing secrets): see the V4 items section | `items.*`, `itemspec.*` |
| 6.2, 6.4 | A vault's `hs.init` profile and invite hint carry only its display name | `vault.TestHandshakeProfile`, `e2e.TestProfileItemsAuditFeed` |
| 9.3, 10.8 | `profile.update` on activation and when the shared view changes (name, photo, `@profile` items, 0.7.0); private changes stay local | `items.TestProfile`, `items.TestTagsNeverInPeerMessages`, `e2e.TestProfileItemsAuditFeed` |
| 10.8 | A peer's `profile.update`: strict, highest version wins, stored as the connection's profile, `connection.event{profile}` | `items.TestProfile`, `items.FuzzItemTypes`, `e2e.TestProfileItemsAuditFeed` |
| 10.8 | `profile.set` validation (sizes, JPEG/PNG photo); the shared profile's limits (32 `@profile` items, 196,608 bytes) | `items.TestProfile` |
| 10.8 | Settings keys, ranges, `app.*`, roles; the in-person auto-approval flag is the runtime's | `vault.TestSettings`, `vault.FuzzApplySettings` |
| 10.9 | Audit: hash chain over the fixed encoding, `head`, per-connection and kind filters, paging, retention and cap | `audit.TestChainAndList`, `audit.TestRetention`, `audit.FuzzParseQuery`, `e2e.TestProfileItemsAuditFeed` |
| 10.9 | Audit holds no content (message text) | `e2e.TestProfileItemsAuditFeed` |
| 10.9 | Runtime drops, unlock, lock and identity rotation reach the audit log | `vault.TestActivitySinks` |
| 10.9 | Feed: items from activity, `feed.event` to every owner device, status changes synced, catch-up by `after_seq` with tombstones, retention and cap | `feed.TestItemsAndSync`, `feed.TestRetention`, `feed.FuzzParseList`, `feed.FuzzParseUpdate` |
| 10.9 | `guide.sync`: new and higher versions only, idempotent | `feed.TestGuides`, `feed.FuzzParseGuides`, `e2e.TestVaultctlSmoke` |
| 10.6–10.9 | Roles of audit, feed, profile and item types | `audit.TestAuthorizationAndBadBodies`, `feed.TestAuthorizationAndBadBodies`, `items.TestAuthorization` |
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
| 11.11.5 | No credential: refused at the request (`no_credential`, sealed to the browser) and at `credential.recover`; superseded for the backup off by the 0.16.0 section | `credential.TestRecover`, `e2e.TestNoCredentialNoRecovery`, `vault.TestRecoveryHeaderOps` |
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
| 6.8 | Step-up types from a desktop are held for an app: `approval.pending` to apps, `approval.waiting` to the requester, executed on approval as the requester's, `denied`, `approval_timeout` after 5 min | `vault.TestAccessSessions`, `vault.TestBlocks` (`block.remove`), `e2e.TestDesktopSession` (`item.reveal`) |
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
through the real relay in `e2e.TestLeashAgent`, `e2e.TestGrantRequestAndRevoke`,
`e2e.TestCriticalSecretUse`, `e2e.TestSharedAction` and
`e2e.TestVaultctlBatch3` (vaultctl's batch-3 commands).

| § | Requirement | Test(s) |
|---|---|---|
| 6.8, 10.11 | `agent.request` is decided by the policy for every agent request (refuse `forbidden`, allow, refer to an app); no policy without an access session (`session_required`); other principals never reach it | `vault.TestAgentPolicyType`, `leash.TestAuthorization`, `e2e.TestLeashAgent` |
| 6.8, 10.11 | A referred request runs on approval only while a grant covers it (otherwise `forbidden`) | `vault.TestAgentPolicyType` |
| 6.7, 10.3 | `device.pair.approve{grants}` only for agents, validated and signed at the approval for the agent's `ik` (`credential_locked` outside the unlock window), installed when the pairing completes after `device.paired`, then `leash.grant.updated` | `vault.TestPairingGrants`, `leash.TestPairingUnlinkRemoval`, `e2e.TestLeashAgent`, `e2e.TestVaultctlBatch3` |
| 10.11 | Scopes: the three LEASH operations and the nine delegable owner types only; never app-only, credential, device, settings, invitation, grant or approval types | `leash.TestIssueValidation`, `leash.TestDecisions`, `e2e.TestLeashAgent` (`settings.get`) |
| 10.11 | Restrictions (`connections` only for connection-scoped types; a request without the member never matches), limits only on `auto` (and `items.read`), expiry in the future and ≤ 365 days, at most 32 grants, versions and `conflict`; `items.read` only through share rules (0.7.0) | `leash.TestIssueValidation`, `leash.TestDecisions`, `leash.TestAgentRequest`, `leash.TestReplaceListNotify`, `leash.FuzzParseSpec` |
| 10.11 | Decisions: none → refuse; `auto` within both windows → allow; past a limit → refer, `leash.rate_limited` once per window (high-priority feed item); a new window allows again | `leash.TestDecisions` |
| 10.11 | Anti-spam: per agent and scope, a cooldown after each refusal (1 s doubling to 5 min) in which requests are throttled unexamined, ended by a covered request, an hour or a new grant of the scope; at most 20 referrals per agent and hour (`leash.referrals_limited` once); 30 refusals in an hour suspend the agent (grants paused, agent told, owner feed and `sync.event`, not covered on approval) until an app resumes it | `leash.TestSpamControls`, `e2e.TestLeashAgent` |
| 10.9, 10.11 | Agent activity summarised: per agent and hour the first allowed, refused, read and used event written singly, the rest in one `<kind>.summary` (`ref` = count) when the window ends, at suspension or at unlink; throttled requests only summarised | `leash.TestAuditSummaries`, `e2e.TestLeashAgent` |
| 10.11 | `agent.request` (0.7.0): only items the agent's rules include (others refused like an uncovered request); `item.get` returns the content (`leash.item.read`); `item.use` returns HMAC-SHA-256, never the value; an `address` field not usable; bad bodies `bad_request` | `leash.TestAgentRequest`, `leash.FuzzParseRequest`, `items.TestAgentRules`, `e2e.TestLeashAgent` |
| 10.11 | Revocation at once (agent told, `sync.event{leash.grant.revoked}`), honoured for referred requests; unlink revokes all (§7.4); removing a connection revokes the grants that name it; expired grants dropped | `leash.TestAgentRequest`, `leash.TestPairingUnlinkRemoval`, `leash.TestExpiry`, `vault.TestAgentPolicyType`, `e2e.TestLeashAgent` |
| 10.11 | Every grant a delegation: issuing or replacing only by an app within the unlock window (`credential_locked`); 0.12.0: JCS bytes with exactly LEASH §3.5's members (`iss` = credential key, `sub` = agent `ik`, `status_issuer`, `scope` object, `limits` for every `auto` and `items.read` grant, a fresh 16-byte `nonce` per signature, `exp` = the grant's expiry or none); `sig` = Ed25519 over `leash/v1/delegation` ‖ bytes; the grant object carries `sig`, no `key`; standard base64 with padding; unknown members rejected; 0.6.0-format delegations not served (decision 8) | `leashwire.TestSpecVectors`, `vectors.TestLeashVectors`, `leashwire.TestDelegationRoundTrip`, `leashwire.TestDelegationStrict`, `leashwire.TestItemsDelegation`, `leashwire.FuzzParseDelegation`, `leash.TestSignedDelegation`, `leash.TestOldFormatDelegationNotServed`, `leash.TestPairingUnlinkRemoval`, `items.TestAgentRules`, `e2e.TestLeashAgent`, `e2e.TestVaultctlBatch3` |
| 10.11 | Status statements: signed by the vault's `ik` without the credential, `not_after` = `issued_at` + `status_ttl` (60–3,600 s, default 900) and never past `exp`; only for grants in force (revoked → none, the old one lapses; suspended → none; another agent's or unknown → `not_found`); in `leash.grant.updated` and `leash.status.get`; the client refreshes before expiry | `leash.TestStatusStatements`, `e2e.TestLeashStatus` |
| 10.11 | A relying party verifies offline (0.12.0, steps 1–5 in order): `sig` under `iss`, a key it trusts; `now` before `exp`; `status_sig` (`leash/v1/status`) under `status_issuer` or the end of a valid rotation chain (≤ 32); the statement names this delegation (SHA-256, `grant_id`); `issued_at` − 60 s ≤ `now` ≤ `not_after` + 60 s (revocation bound `status_ttl` + 60 s); stricter: unknown members, `status_ttl` outside 60–3,600, a statement longer than `status_ttl`, no statement — all rejected; no `iat` check | `leashwire.TestStatusStatements`, `leashwire.TestSpecVectors`, `vectors.TestLeashVectors`, `leashwire.FuzzParseStatus`, `e2e.TestLeashStatus` |
| 10.11, 12.1 | A locked vault issues no statements (fail closed) | `e2e.TestLeashStatus` |
| 9.1 | Agents get no fan-out, only responses, §6.8 messages and their own `leash.grant.updated` within their session | `leash.TestReplaceListNotify`, `e2e.TestLeashAgent` |
| 10.7, 10.12 | (0.7.0: `discoverability` replaced by share rules and per-connection catalogs; see the V4 items section) | `items.TestCatalogIsolation`, `grants.TestCatalog` |
| 10.12 | Ask, decide, fetch and revoke as events correlated by `request_id`/`fetch_id`; `grant.pending` to apps and desktops; `grant.event` granted, denied, revoked | `grants.TestShareFetchRevoke`, `grants.TestDenyPartialAndUnavailable`, `e2e.TestGrantRequestAndRevoke` |
| 10.12 | Roles: device types from apps and desktops; `data.*` only from connections; agents never; `grant.decide` a desktop step-up type | `grants.TestAuthorization` |
| 10.12 | Only available items granted (readable items with the requested fields; never critical); none → `bad_request`; partial `items`; category entries only through answers; the decision may set `uses` and `expires_in` | `grants.TestDenyPartialAndUnavailable`, `grants.TestCategoryAnswer`, `e2e.TestGrantRequestAndRevoke` |
| 10.12 | Values sealed to the fetching device's one-time `reply_key`, bound to grant and fetch; the asking vault never holds plaintext; `grant.value` only to the fetching device | `sharewire.TestSealValue`, `sharewire.FuzzOpenValue`, `grants.TestShareFetchRevoke`, `e2e.TestGrantRequestAndRevoke` |
| 10.12 | Fetch refusals `not_found`, `revoked`, `expired`, `exhausted`, `unavailable` (audited); uses counted; a repeated `fetch_id` answered again without a use | `grants.TestShareFetchRevoke`, `grants.TestExpiry`, `grants.TestDenyPartialAndUnavailable` |
| 10.12 | Repeated `request_id` ignored (another connection's dropped, `drop.grant_duplicate`); at most 16 pending per connection (`drop.grant_limit`); undecided after 7 days → denied; fetches forgotten after 10 min; limits on active grants | `grants.TestIdempotencyAndLimits`, `grants.TestExpiry` |
| 10.12 | Either side revokes, the other is told; removing or blocking a connection drops everything of it without notice | `grants.TestShareFetchRevoke`, `grants.TestRelinquishAndRemoval` |
| 10.12 | Catalog (0.7.0): per connection, its active grants and the critical items its rules make usable, metadata only, to the asking device | `grants.TestCatalog`, `grants.TestRuleGrants`, `items.TestCatalogIsolation`, `e2e.TestItemsShareRules` |
| 10.12 | Malformed peer messages dropped and audited, never answered; state survives a flush and unlock | `grants.TestBadBodies`, `grants.TestRoundTrip`, `grants.FuzzPeerMessage` |
| 10.6, 10.13 | (0.7.0: `credential.secret.catalog` replaced by share rules that make a critical item usable) | `items.TestCriticalUseThroughRule`, `e2e.TestCriticalSecretUse` |
| 10.13 | Roles: request, deny, list from apps and desktops; approve only from apps; `critical-secret.use` and `.result` only from connections | `critical.TestAuthorizationAndBadBodies`, `critical.TestConsent` |
| 3.5.4, 10.13 | Consent per use: the UTK-sealed password bound to `request_id` and `payload_sha256` (constant time); a mismatch is `bad_request` with the UTK spent and nothing signed | `critical.TestConsent` |
| 3.5.3, 10.13 | Each use opens and rotates the credential (the old blob `stale_credential`); `bad_password` and `backoff` keep the request pending; nothing retained | `critical.TestUseFlow`, `critical.TestConsent`, `e2e.TestCriticalSecretUse` |
| 10.13 | `sign` over the payload; `auth` domain-separated over both vaults' `ik`, the request id and the payload; `public_key`; not a 32-byte seed → `unsuitable`; deleted since → `unavailable` | `critical.TestUseFlow`, `critical.TestRefusals`, `sharewire.TestAuthMessage`, `e2e.TestCriticalSecretUse` |
| 10.13 | Only critical items a rule of that connection makes usable, and their fields (others `unavailable` without asking, not told apart from unknown); at most 8 pending per connection; `expired` after 24 h; repeated `request_id` ignored; denial | `critical.TestRefusals`, `critical.TestUseFlow`, `items.TestCriticalUseThroughRule` |
| 10.13 | The asking vault accepts results only for its own pending request from that connection, verifies the signature (`drop.critical_signature`), forwards to apps and desktops | `critical.TestForgedResultDropped`, `critical.TestUseFlow`, `e2e.TestCriticalSecretUse` |
| 10.13, 7.4 | Removing a connection drops its requests without notice | `critical.TestRefusals` |
| 10.14 | Catalog v1 (5 actions, ids, versions, sensitivities, JSON Schema documents in `action.list`); every action starts `default-deny` | `actions.TestCatalogAndConfigure` |
| 10.14 | Roles: apps and desktops list, configure, invoke and respond; connections only `action.offered`, `.invocation`, `.result`; agents only through LEASH; `action.configure` a desktop step-up type; no type both a request and an event | `actions.TestAuthorization` |
| 10.14 | Modes: `default-deny` (not offered, `unavailable`), `allowlist` (at once, listed connections only), `prompt-each-time` (held, `action.pending`, approve or deny), `default-allow`; sensitive never `default-allow`; critical never `default-allow` or `allowlist`; versioned configuration (`conflict`) | `actions.TestModes`, `actions.TestCatalogAndConfigure`, `e2e.TestSharedAction` |
| 10.14 | Critical actions approved only by an app within the unlock window (desktop `forbidden`, closed window `credential_locked`, the invocation stays pending); wallet actions `unavailable` until the wallet | `actions.TestCritical`, `e2e.TestSharedAction` |
| 10.14, 10.12 | `items.share` (catalog version 2, replacing `profile.fields.read` and `secrets.share`) makes a one-use 10-minute grant of a configured, readable item (optionally some fields) only; the invoking vault records it and its device fetches the content sealed to it | `actions.TestSharingThroughGrants`, `e2e.TestSharedAction` |
| 10.14 | `audit.recent`: only that connection's entries, kind, time and direction, no `ref`, no `drop.*` | `actions.TestModes` |
| 10.14 | Offers after each configuration change and when a connection becomes active; the receiver keeps them (`sync.event{action.offers}`); malformed messages dropped and audited | `actions.TestOffers` |
| 10.14 | Limits: 8 pending, 60 per hour per connection, `expired` after 24 h, repeated ids ignored, other version, not offered, unknown or bad parameters `unavailable`; foreign or unknown results dropped | `actions.TestLimitsExpiryIdempotency`, `actions.TestBadBodies` |
| 10.14, 7.4 | Removing a connection drops it from configurations, offers and invocations; state survives a flush | `actions.TestConnectionRemovedAndRoundTrip` |
| 10.15 | Only the member's devices start, cancel, list, accept or decline introductions (`intro.create`, `intro.accept` step-up for desktops); connections send only the V↔V types; agents none; no type asks to be introduced or lists the member's connections | `intro.TestAuthorization`, `e2e.TestConnectionsCannotProbe` |
| 10.15 | Both accept → `intro.connect` (C's `ik` as B has it) → A's invitation bound to it → `intro.invite` → `intro.link` → C accepts once; `connection.request.pending{introduced_by}`; A approves with the SAS; A and C connect | `intro.TestBothAccept`, `vault.TestIntroInvite`, `e2e.TestIntroductionAccepted` |
| 10.15 | An `hs.init` on an introduction's invitation from another identity is dropped (`drop.intro_mismatch`); the invitation stays usable for the bound identity | `vault.TestIntroInvite` |
| 10.15 | Decline, cancel or expiry: `intro.closed` without a reason; no invitation; neither party learns the other's key, link or answer | `intro.TestDecline`, `intro.TestCancelAndExpiry`, `e2e.TestIntroductionDeclined` |
| 10.15 | Authority: messages from the wrong party, for unknown ids or before acceptance dropped (`drop.intro`); limits (one per pair, 16 open; 4 per introducer and 16 offers received); idempotency; bad bodies | `intro.TestWrongParty`, `intro.TestBadPeerBodies`, `intro.TestLimitsAndIdempotency`, `intro.FuzzPeerMessage` |
| 10.15, 7.4 | Removing a connection closes its introductions and drops offers from it | `intro.TestConnectionRemoved` |
| 10.1, 10.9 | Batch-3 `sync.event`, audit and feed kinds (no values, payloads or signatures in the log) | `leash.TestReplaceListNotify`, `grants.TestShareFetchRevoke`, `critical.TestUseFlow`, `actions.TestModes`, `e2e.TestLeashAgent`, `e2e.TestCriticalSecretUse`, `e2e.TestSharedAction` |
| 13.6 | New parsers fuzzed | `leashwire.FuzzParseDelegation`, `sharewire.FuzzOpenValue`, `leash.Fuzz*`, `grants.Fuzz*`, `critical.Fuzz*`, `actions.Fuzz*`, `intro.Fuzz*` |
| 13.6 | No package-level mutable state in feature code (per-vault instances in `features/all`) | `features/all` |

## V4 items: items, tags, share rules (§3.5.2, §3.5.4, §6.8, §10.6–§10.8, §10.11–§10.14, §13.5; 0.7.0)

Unit tests drive the whole feature set (`features/all`) on the fake host
(`items` tests), or one feature with fakes (`grants`, `leash`,
`critical`). The flows run through the real relay in
`e2e.TestItemsShareRules`, `e2e.TestGrantRequestAndRevoke`,
`e2e.TestCriticalSecretUse`, `e2e.TestProfileItemsAuditFeed`,
`e2e.TestLeashAgent`, `e2e.TestLeashStatus`, `e2e.TestSharedAction`,
`e2e.TestVaultctlSmoke` and `e2e.TestVaultctlBatch3`.

| § | Requirement | Test(s) |
|---|---|---|
| 10.7 | Roles: item, tag, profile and share types from apps and desktops only (agents and connections `forbidden`); step-up types held for desktops; `profile.update` only from connections | `items.TestAuthorization` |
| 6.8, 10.7, 10.12 | App-only forms of step-up types (critical items, agent rules) refused to a desktop at once, never held | `items.TestAuthorization` (`AppOnly`), `e2e.TestCredentialFlow` |
| 10.7 | Fields: kinds and value shapes (text, multiline, number, date, email, phone, url, password, otp, address; `file` refused), canonical encodings, control characters, labels; vault-assigned field ids never reused; names, categories, templates, notes | `itemspec.TestParseValue`, `itemspec.TestContentAndFieldIDs`, `itemspec.FuzzParseValue`, `itemspec.FuzzParseContent`, `items.TestItemsCRUD` |
| 10.7 | Create and replace with versions (`conflict`); sensitivity kept on replace; tags left as they are when absent; `item.get` without `secret` or `critical` values; `item.reveal` audited, field subsets; `item.list` filters (tags any/all, category, sensitivity), metadata only, paged (`next`, 131,072 bytes); delete | `items.TestItemsCRUD` |
| 10.7 | Limits: 64 fields, 16 KiB per value, 64 KiB per item, 2,000 items | `items.TestLimits`, `itemspec.TestParseValue` |
| 10.7, 3.5.3 | Critical items: credential operations (UTK spent, password, CEK rotated, old blob stale), content and item id sealed to the UTK, no plaintext values in DEK state, reveal sealed to the reply key, consent bound to the item, UTK single use, `bad_password`, 12,288-byte limit, delete needs the password; `credential.reset` takes them (0.15.2) | `items.TestCriticalItems`, `items.TestSensitivityChanges`, `credential.TestOperateAndReplyKey`, `e2e.TestCredentialFlow` |
| 3.5.2, 10.7 | Envelope encryption: values encrypted (XChaCha20-Poly1305, AAD binding vault, item, key generation, field ids) under a per-item key held only in the credential; DEK state alone (ciphertext, CEK, blob) does not open them without the password; a key is re-generated at every use of its item and for every item at `credential.rotate` (old keys and old blobs no longer open anything); reveal, use and moves still work | `items.TestEnvelopeEncryption`, `items.FuzzParseValues`, `credential.FuzzParseInner` |
| 10.7, 3.5.2 | Capacity beyond the old credential bound: 200 critical items in one vault (limit 1,000), each still opens | `items.TestCriticalCapacity`, `credential.TestInnerLimit` |
| 3.5.6, 11.11 | A recovery restores the critical items (the vault's blob holds the keys, DEK state the ciphertext) and re-keys them | `e2e.TestRecoveryFlow` (reveal after `credential.recover`) |
| 10.7 | Sensitivity: `data` ↔ `secret` metadata only; to and from `critical` a credential operation moving the values inside the vault; `@profile` only on `data` items | `items.TestSensitivityChanges` |
| 10.8 | Tags: normalisation (lowercase, trimmed, spaces collapsed, `[a-z0-9][a-z0-9 _-]{0,31}`), reserved `@profile`, at most 16, deduplicated and sorted | `itemspec.TestNormalizeTag`, `itemspec.TestParseTags`, `itemspec.FuzzNormalizeTag`, `items.TestItemsCRUD` |
| 10.8 | Tag registry: `tag.set` (color, icon, description; versions), `tag.list` (items and rules per tag; paged), `tag.delete` (`in_use` when a rule names it; `dry_run`), `tag.merge` (items and connection rules rewritten, newly matching items shared or asked, `dry_run` preview with `shares`; `in_use` for an agent rule) | `items.TestTags`, `items.TestAgentRules`, `items.TestPaging` |
| 10.8 | Tag names never in a message to a connection (`data.shared`, `data.decided`, `data.catalog`, `profile.update`, critical-item use), nor in shared content | `items.TestTagsNeverInPeerMessages`, `items.TestCatalogIsolation`, `grants.TestShareFetchRevoke`, `itemspec.TestEncodings`, `e2e.TestItemsShareRules` |
| 10.8, 9.3 | Profile: name and photo plus `data` items tagged `@profile`; `profile.update` when that view changes (not for private items), with its own counter; at most 32 `@profile` items; peers' updates strict | `items.TestProfile`, `e2e.TestProfileItemsAuditFeed` |
| 10.12 | Share rules: terms (tags 1–16, not reserved; `any`/`all`; `read`; `ask` default/`auto`; uses; expiry; `include_existing`), subjects (active connection or paired agent; immutable), versions, limits (64 per subject, 512, 4,096 pending), agent-only members | `itemspec.TestTermsAndMatching`, `itemspec.FuzzParseTerms`, `items.TestShareAuto`, `items.TestPendingAndRuleLimits`, `items.FuzzItemTypes` |
| 10.12 | Ask mode: preview (`dry_run`), `share.pending` to apps and desktops, nothing shared before approval, `share.decide` approve and decline, declines remembered until a re-tag, a new tagged item asked | `items.TestShareAsk`, `e2e.TestItemsShareRules` |
| 10.12 | Auto mode: included at once (`data.shared`), `include_existing: false`, ask → auto includes the pending, `match: all`, rule `uses` counted per item | `items.TestShareAuto`, `e2e.TestItemsShareRules` |
| 10.12 | Withdrawal at once: tag removed, rule deleted or expired (grant revoked, `data.revoked`, fetch `revoked`); audit `share.*` | `items.TestShareAsk`, `items.TestRuleExpiry`, `e2e.TestItemsShareRules` |
| 10.12 | Per-connection catalog: each connection sees only its grants and usable critical items, never tags; critical items never granted (rule or one-off), only usable | `items.TestCatalogIsolation`, `items.TestCriticalUseThroughRule`, `grants.TestRuleGrants`, `e2e.TestItemsShareRules` |
| 10.12 | Grants of items: `{kind: item, ref, fields?}`, descriptors (name, category, labels; no tags or values), `data.shared` recorded once, content sealed (restricted to the granted fields), rule grants without use limit or expiry, one-off requests by category answered by the member | `grants.TestShareFetchRevoke`, `grants.TestRuleGrants`, `grants.TestCategoryAnswer`, `grants.FuzzParseShared`, `grants.FuzzParseDecided`, `grants.FuzzParseCatalog`, `e2e.TestGrantRequestAndRevoke` |
| 10.11 | Agent rules: `items.read` grants, signed only in the unlock window from an app, delegation carries tags, match, access, uses, per_hour, per_day; delivered to the agent; never include a critical item; ask mode pending until approved; reads within the rule's limits (then referred); uses counted; `leash.grant.issue` and pairing refuse `items.read`; revoke deletes the rule; unlink drops it | `items.TestAgentRules`, `leash.TestAgentRules`, `leash.TestAgentRequest`, `leashwire.TestItemsDelegation`, `e2e.TestLeashAgent`, `e2e.TestLeashStatus` |
| 10.13 | Critical-item use through a rule: usable, never readable; each use with the password; `unsuitable` for a non-seed field; unusable after the rule is deleted | `items.TestCriticalUseThroughRule`, `critical.TestUseFlow`, `e2e.TestCriticalSecretUse` |
| 7.4 | Removing a connection removes its rules; unlinking an agent its rules and inclusions | `items.TestConnectionRemoved`, `items.TestAgentRules` |
| 10.1, 10.9 | `sync.event` kinds (`item.*`, `tag.changed`, `share.*`), audit kinds (`item.*`, `tag.changed`, `share.*`, `leash.item.*`), feed items (`share.pending`, `grant.shared`, critical `item.revealed`) | `items.TestItemsCRUD`, `items.TestShareAsk`, `e2e.TestCredentialFlow`, `e2e.TestItemsShareRules`, `e2e.TestLeashAgent` |
| 13.6 | New parsers fuzzed | `itemspec.Fuzz*`, `items.FuzzItemTypes`, `credential.FuzzParseOpPayload`, `grants.FuzzParseShared`, `leashwire.FuzzParseDelegation` (items seed) |
| — | The shared template registry (`docs/item-templates.json`) describes items the vault accepts | `itemspec.TestTemplateRegistry` |

## V4 batch 4: location, wallet, presence (§9.2, §10.14, §10.16–§10.18, §13.5; 0.8.0)

Unit tests drive each feature on the fake host (`location`, `presence`)
or the credential, items, wallet and actions features together
(`wallet`); `btc` covers the Bitcoin code with published vectors and
synthetic regtest PSBTs (no real funds). The flows run through the real
relay in `e2e.TestLocationShare`, `e2e.TestPresencePing`,
`e2e.TestLocationHistory`, `e2e.TestWallet`, `e2e.TestWalletTaproot`,
`e2e.TestSharedAction` and `e2e.TestVaultctlBatch4`.

| § | Requirement | Test(s) |
|---|---|---|
| 10.16 | Roles: share control from apps and desktops (start step-up for desktops), samples from devices and connections, peer events only from connections | `location.TestStartValidation`, `e2e.TestLocationShare` |
| 10.16 | Start: modes, durations, intervals, precision, one outgoing share per connection (replace stops the old), limits; once-shares end after one sample | `location.TestStartValidation`, `location.TestOnceAndReplace`, `location.FuzzParseStart` |
| 10.16 | Samples: ranges, `at` window, precision applied by the sending vault (exact, approximate, city; altitude, speed and heading dropped), cadence, forwarded from memory only (never in the sender's state) | `location.TestContinuousShare`, `location.TestReduce`, `location.TestSampleValidation`, `location.FuzzParseSample`, `e2e.TestLocationShare` |
| 10.16 | Receiving: only from the sharing connection for an active share, rate limits, `exp` bound, latest sample and trail only if allowed, everything deleted at stop or expiry; either side stops | `location.TestReceive`, `location.TestIncomingExpiryAndStop`, `location.FuzzParseShared`, `location.FuzzParseShareID` |
| 10.16 | Default precision `approximate` | `location.TestDefaultPrecisionApproximate`, `e2e.TestLocationHistory` |
| 10.16 | The member's log: off by default, recorded from devices at the member's cadence only when enabled, owner devices only (desktops step-up; agents and connections never), paged, deleted by range and when turned off, retention, thinning and the 5,000-point cap; shared only as a snapshot through an active share, at its precision; kept by the receiver with that share, only from its connection | `location.TestHistoryLog`, `location.TestHistoryCompaction`, `location.FuzzParseRange`, `location.FuzzParseSnapshot`, `e2e.TestLocationHistory` |
| 10.16 | Requests: rate limited both ways, pending to apps and desktops, feed item | `location.TestRequests`, `location.FuzzParseRequest`, `location.FuzzParseGet` |
| 7.4, 10.16 | Removing a connection drops its shares and requests | `location.TestConnectionRemoved` |
| 9.2, 10.17 | Presence: on-demand ping only, one ping per connection per minute, pong only within `exp`, result to the asking device | `presence.TestQueryPingPong`, `presence.TestQueryErrors`, `presence.FuzzParseQuery`, `presence.FuzzParsePing`, `presence.FuzzParsePong`, `e2e.TestPresencePing` |
| 9.2, 10.17 | Policy: versioned; `invisible`, `share: none` and per-connection `except` answer nothing (indistinguishable from a locked vault); one answer per peer per minute; `last_active` rounded to 5 minutes | `presence.TestPolicy`, `presence.FuzzParseSet`, `e2e.TestPresencePing` |
| 10.18 | BIP39 (wordlist hash, vectors, checksum, normalisation, ASCII passphrase), BIP84 and BIP86 (vectors: fingerprint, account key, receive and change addresses), networks and their encodings | `btc.TestWordlist`, `btc.TestBIP39Vectors`, `btc.TestBIP84Vectors`, `btc.TestBIP86Vectors`, `btc.TestCheckAddress`, `btc.FuzzNormalizeMnemonic`, `btc.FuzzCheckAddress` |
| 10.18 | The recovery phrase is a critical item (credential operation, envelope-encrypted, revealed only sealed to a reply key; never in `item.get` or wallet responses); generated or imported; networks allowed per release | `wallet.TestCreateGeneratedAndReveal`, `wallet.FuzzParseCreate`, `wallet.FuzzParseImport`, `e2e.TestWallet`, `e2e.TestVaultctlBatch4` |
| 10.18 | The wallet owns its item: `item.put` and `item.sensitivity` refused `in_use`; tags free; `item.delete` (or, since 0.15.2, `credential.reset`) deletes the wallet | `wallet.TestAddressesAndGuard` |
| 10.18 | Roles: create and sign app only; agents nothing; addresses issued from the account key without the password; `wallet.address.used` | `wallet.TestAddressesAndGuard` |
| 10.18 | Both accounts per wallet; new wallets receive on P2TR; the app chooses the receiving account for an imported phrase (`address_type`, `wallet.update`); addresses of either type; `request-address` on the receiving account | `wallet.TestTaproot`, `wallet.TestCreateGeneratedAndReveal`, `wallet.FuzzParseUpdate`, `e2e.TestWalletTaproot`, `e2e.TestWallet` |
| 10.18 | Taproot spends: taproot BIP32 derivations re-derived (x-only key, internal key, script), no leaf hashes, script paths or merkle roots, previous transactions still required, BIP340 key-path signatures (SIGHASH_DEFAULT or ALL) checked by the script engine, taproot change; mixed P2WPKH and P2TR inputs | `btc.TestSignTaprootAndMixed`, `btc.FuzzInspect` (taproot seed), `wallet.TestTaproot`, `e2e.TestWalletTaproot`, `e2e.TestWallet` (mixed spend) |
| 10.18 | PSBT policy before signing: own inputs re-derived, full previous transactions (txid match), witness UTXO consistent, SIGHASH_ALL, no finalised inputs, standard outputs of the network, dust, change re-derived, fee positive and ≤ 1,000 sat/vB | `btc.TestInspectRefusals`, `btc.FuzzInspect` |
| 10.18, 3.5.3 | Spending: app within the unlock window (`credential_locked`), password bound to the wallet and the PSBT's hash, the item re-keyed and the CEK rotated, signatures checked by the script engine, history and change index | `wallet.TestSign`, `btc.TestSignRegtest`, `e2e.TestWallet`, `e2e.TestVaultctlBatch4` |
| 10.18 | Chain access: none in the vault by default (`wallet.balance` and `broadcast` `unavailable`); a `ChainSource` plugs in | `wallet.TestAddressesAndGuard`, `wallet.TestSign` (fake source) |
| 10.14, 10.18 | `wallet.request-address`: the configured wallet (exactly one), the connection's address kept until used, audited | `wallet.TestActions`, `e2e.TestWallet` |
| 10.14, 10.18 | `wallet.request-payment`: critical (prompt only), app in the unlock window, the PSBT must pay exactly the amount to the address (network checked) and nothing to others, consent bound to the invocation; a refused approval leaves it pending; the txid to the connection | `wallet.TestActions`, `wallet.TestPayAddressNetwork`, `actions.TestCritical`, `actions.FuzzParseParams`, `e2e.TestWallet` |
| 13.6 | Bitcoin libraries only in the vault process and clients (not the supervisor); new parsers fuzzed | `make check-tcb`, `btc.Fuzz*`, `wallet.Fuzz*`, `location.Fuzz*`, `presence.Fuzz*` |

## One app per vault: clone alarm, transfer, recovery replaces the app, GrapheneOS, deletion (§3.5.3, §3.5.6, §3.5.9, §6.7, §6.7.1, §11.5, §11.7, §11.11.5, §12.5, §13.7; 0.9.0)

Owner decisions of 2026-10-03 (PROTEAN-CREDENTIAL §4). Unit tests drive
the credential feature on the fake host (`credential`), the runtime's
transfer, PIN check, app replacement and alarm report (`vault`), the
parent's alarm write (`parent`, LocalStack in `make integration`) and the
attestation policy (`devattest`, `pins`). The flows run through the real
relay in `e2e.TestSecondAppRefused`, `e2e.TestCloneAlarm`,
`e2e.TestTransfer`, `e2e.TestRecoveryReplacesApp`,
`e2e.TestRecoveryBackupOffRefused` and `e2e.TestGrapheneOS`.

| § | Requirement | Test(s) |
|---|---|---|
| 6.7 | One app: `device.pair.create{role: app}` answered `one_app`; an app `hs.init` that is not enrollment, recovery or a transfer dropped (`drop.one_app`); the app cannot be unlinked; desktops still pair | `vault.TestOneApp`, `vault.TestPairingDeviceAttestation`, `e2e.TestSecondAppRefused`, `e2e.TestAltchanEnrollUnlock` |
| 3.5.9 | The holder: set by `credential.create`, moved by a transfer or a recovery; `credential.get`, `.ack`, `.alarm.confirm` and `device.transfer.*` holder-only; desktops never fetch the blob | `credential.TestOneHolder`, `credential.TestTransfer`, `credential.TestRecover`, `e2e.TestSecondAppRefused` |
| 3.5.3, 3.5.9 | The holder's own retry of the previous, unconfirmed version is `stale_credential` (no alarm) and fetches the latest; every other mismatch is a clone: another app's blob, an older version, the previous version after the ack, the current version with other bytes, a version above the current | `credential.TestCloneAlarmFreezeConfirmRotate`, `credential.TestCloneVariants`, `credential.TestOneHolder`, `credential.TestTransferAbortKeepsHolder` |
| 3.5.9 | On a clone: refused `credential_frozen`, nothing opened or returned; `credential.alarm` to the holder; urgent feed item; `sync.event credential.alarm` to the owner's devices; audit `credential.clone_detected`; one host alarm per alarm, after the flush; the unlock window ends; an open transfer is aborted | `credential.TestCloneAlarmFreezeConfirmRotate`, `credential.TestOneHolder`, `credential.TestTransferAbortKeepsHolder`, `vault.TestAlarmReportedAfterFlush`, `e2e.TestCloneAlarm` |
| 3.5.9 | Freeze: every credential operation (critical items, other features' operations, `credential.unlock`, `device.transfer.create`) refused before the UTK is spent; UTKs, version, lock and confirm still answer; messaging and other features keep working; a second clone opens no new alarm | `credential.TestCloneAlarmFreezeConfirmRotate`, `e2e.TestCloneAlarm` |
| 3.5.9 | Confirm (holder only, this alarm, `mine` required) → `rotation_required`; only `credential.rotate` (and get/ack) until it succeeds; the forced rotation (new credential key, CEK, item keys, `ik`/`kem`) resolves the alarm; every older copy is dead and, presented, a new alarm | `credential.TestCloneAlarmFreezeConfirmRotate`, `e2e.TestCloneAlarm` |
| 3.5.9, 11.11.5 | A recovery during an alarm hands over and leaves `rotation_required` | `credential.TestRecoverDuringAlarm` |
| 11.5 | Host alarm `alarm.credential_clone`: content-free lifecycle event, accepted by the parent's parser (other alarm kinds refused), written as `alarm {kind, alarm_id (ULID), at}` + `alarm_pending` whoever holds the lease, nothing for a missing row | `parent.TestParseAlarmEvent`, `parent.TestAlarmULID`, `parent.TestRequestsAndLeases` (memory tables), `parent.TestAWSBackend` (LocalStack) |
| 6.7.1 | Transfer: holder-only create, one at a time (`exists`), QR `p` / kind `app`; the new app's `hs.init` needs device attestation; pending only to the old app; `device.pair.approve` cannot approve it | `vault.TestTransferRuntime`, `vault.TestPairingDeviceAttestation`, `credential.TestTransfer`, `e2e.TestTransfer` |
| 6.7.1 | Approval: UTK-sealed PIN and password; PIN against the DEK under the unlock backoff (`bad_pin`, `backoff`, `vault.pin_failed`), then the password (`bad_password`); the CEK rotates (old copy dead, nobody gets the new blob); 0.10.3: `{}`, the transfer completes at once (`transfer_pending` retired) | `credential.TestTransfer`, `vault.TestVerifyPIN`, `e2e.TestTransfer` |
| 6.7.1 | Completion at the approval (0.10.3; was at `hs.fin`) in one flush, after the approval's response: the new app is the holder and the only unlock key; the old app removed (relay key denylisted, `device.unlinked{transferred}`, UTK pool gone); `device.paired{transfer, credential_version}`; `device.transferred` audit, feed and sync; desktops kept; the critical items open on the new app; the old app cannot unlock | `vault.TestTransferRuntime`, `credential.TestTransfer`, `e2e.TestTransfer` |
| 6.7.1 | Aborts: reject before the approval (also after failed attempts), expiry before or after the scan, a commitment mismatch (`failed`), an alarm; audited and announced with a reason | `vault.TestTransferExpiry`, `credential.TestTransferAbortKeepsHolder`, `e2e.TestTransfer` |
| 11.11.5 | Recovery replaces the app: the recovered app is the holder, every other app removed (`device.replaced`), desktops and agents kept and working, the old app's unlock key revoked and its copy a clone | `vault.TestRecoveryReplacesApps`, `credential.TestRecover`, `e2e.TestRecoveryReplacesApp`, `e2e.TestRecoveryFlow` |
| 3.5.6, 11.11.5 | (0.9.0 backup-off reset by the recovering app: removed in 0.16.0, see below) | — |
| 11.7 | GrapheneOS: `SelfSigned` accepted only with a pinned `verifiedBootKey` (the release's 21 GrapheneOS fingerprints; the test policy's own key), still locked; `Unverified` and `Failed` refused whatever the key; another self-signed OS refused; enrollment and unlock with an allowed key | `devattest.TestAndroidRejects`, `pins.TestGrapheneOSBootKeys`, `devattest.FuzzKeyDescription`, `e2e.TestGrapheneOS` |
| 11.11.5 | (0.9.0 backup-off "access only" recovery: removed in 0.16.0, see below) | — |
| 3.5.9 | A credential without a holder never adopts an app: the vault is restricted to the recovery path and deletion | `credential.TestNoHolderNoAdoption` |
| 13.7 | A vault reports only to its owner: the alarm only to the owner's app (checked as a paired app), sync events only to owner devices, nothing to a connection; to the host only content-free events | `credential.TestOneHolder`, `e2e.TestCloneAlarm` (the connection's app hears nothing), `vault.TestAlarmReportedAfterFlush` |
| 12.5 | `vault.delete`: the exact phrase, the PIN (unlock backoff) and the password from the holder; refused during an alarm; the enrolling app before a credential exists with the PIN; a recovering app `forbidden` (0.16.0); nothing returned | `credential.TestVaultDelete`, `credential.TestVaultDeleteDuringAlarmAndRecovery`, `e2e.TestVaultDelete` |
| 12.5 | Deletion: marked in the request's flush (state and header), credential and keys destroyed, connections told (`connection.removed`), devices told (`device.unlinked{vault_deleted}`), every issued token revoked by jti and every peer key by sub, claims deleted, outbox drained, keys zeroized, state and headers (own last) and the member index erased, `deleted` reported; the member enrolls afresh; deposits refused | `vault.TestDeleteRuntime`, `vault.TestEraseStoredIdempotent`, `e2e.TestVaultDelete` |
| 12.5 | Relay mailbox (0.9.1): deleted at the relay after the marking flush and before the drain (host deletion too); the queued revocations and claim deletions dropped as moot; on a relay before 0.5.0 (`not_found`) they are delivered instead; afterwards deposits into the vault's mailbox get `mailbox_unknown` | `vault.TestDeleteRuntime` (0.5 and 0.4 relays), `vault.TestDeleteByHost`, `e2e.TestVaultDelete` |
| 12.5 | Crash safety: a crash after the mark or in the middle of erasing converges to deleted at the next unlock; a marked header never opens | `vault.TestDeleteCrashConverges` |
| 12.5, 11.5 | The host's deletion (account cancellation) with the same semantics on a running vault, erasing otherwise; the parent records `deleted` and the `vault_deleted` notice whatever the lease | `vault.TestDeleteByHost`, `parent.TestAWSBackend` (LocalStack) |
| 13.6 | New parsers fuzzed | `credential.FuzzOneAppBodies` (with `vault.delete`), `credential.FuzzParsePayload` (`pin`, `vault.delete`), `credential.FuzzParseEnvelope` (transfer), `devattest.FuzzKeyDescription` (GrapheneOS seed) |

## V5 W2: release build, key check, manifest tooling, compatibility (§11.10.1, §11.10.7, §11.10.8; VAULT-RELEASES §3.4, §5–§7, §11.3)

| § | Requirement | Test(s) |
|---|---|---|
| 11.10.8 | A release build refuses a channel file with a placeholder or a missing value: the release workflow's `gate` refuses `prod`/`staging` tags and dispatches, and a tag's release number must equal the file's | `.github/workflows/release.yml` (`gate`), `vaultctl.TestKeycheckExitStatus` (committed files refused), CI "release gate refuses placeholders" |
| 11.10.1 | Every release image embeds its own release number, covered by PCR0; the image is reproducible from its tag (VAULT-RELEASES §5.1): two clean builds give identical binaries, identical measured EIF sections and identical PCR0/1/2, recomputed from the EIF | `.github/workflows/release.yml` (`build` ×2, `compare`), `eif.TestPCRs`, `eif.TestCompare`, `eif.TestParseRefuses`, `eif.FuzzParse`, `scripts.TestEIFToolchain` |
| 11.10.1 | Publisher side: canonical manifest bytes (member order, sorted, no candidates), `serial` above the published one, statuses only forward, no PCR or key changed, nothing dropped before `removed`; signed only by a pinned key (KMS key A, or key B's imported signature), verified before it is written | `manifesttool.TestRender`, `manifesttool.TestCheckSuccessor`, `manifesttool.TestSignFileAndImport`, `manifesttool.TestKMSSigner`, `vaultctl.TestManifestCommands` |
| 11.10.7 | The same check on a live key before it is named in a manifest (VAULT-RELEASES §6.2, layer 2): the enclave's KMS client and `keypolicy`, the channel's pinned constants; exit status = the failing check | `keycheck.TestRecordedFixtures`, `keycheck.TestFetchAndRecord`, `keycheck.TestLoadManifestSigned`, `vaultctl.TestKeycheckExitStatus` |
| 11.10.1–4 | Move-only contract (VAULT-RELEASES §3.4): a previous release's parent and enclave against this tree's client, member API stand-in and release; deprecated and retired releases still unlock and move; frozen vectors of live releases still derived | `integration.TestCompatMoveOnly` (`scripts/compat-matrix.sh`), `vectors.TestFrozenReleaseVectors` |

## Recovery and lock-state gaps (§11.5, §11.11.3, §11.11.5, §11.11.7; 0.10.6)

| § | Requirement | Test(s) |
|---|---|---|
| 11.5, 11.11.3 | The enclave's answer to a `recovery_register` whose sealed result is `{"ok": true}` carries the clear marker `code: "recovery_registered"` after the envelope; no other answer (a refusal, random bytes, another op) carries it; the vault process reports it to the supervisor with Open's answer (vaultipc 3) | `enclave.TestResponseCode`, `e2e.TestRecoveryFlow` and every `register` (marker exactly on `ok`), `e2e.TestHostRecovery` (through a vault process and the parent) |
| 11.5 | The parent copies the marker into the response slot's `code`, with the envelope, only for `recovery_register`; never without an envelope or for another value | `parent.TestRecoveryRegisteredMarker`, `e2e.TestHostRecovery` |
| 11.11.7 | Member API stand-in as vault.ts: the register slot names its `recovery_id`, the marker makes the recovery `registered` (no `sealed_code`, still active and cancellable, `409 recovery_not_available` for a new register); cancel answers `{cancelled}`; status reports `unlocked` only under a live lease | `devstack.TestDevStackLocalStack` (`vaultctl api-recover`, LocalStack) |
| 11.11.5 | The registered app's unlock result carries `credential_backup` after `vault_bundle`, always `true` since 0.16.0; no other app's result carries it | `altchan.TestSealOpen`, `e2e.TestRecoveryReplacesApp`, `e2e.TestRecoveryCancel` (absent for an owner app), `devstack.TestDevStackLocalStack` |
| 11.5 | A stopped vault is locked: the lease release on a stopped vault turns `unlocked` into `locked`; the vault process delivers its lifecycle `locked` before it exits (both since vettid-vault #31) | `parent.TestAWSBackend` (LocalStack), `hostproto.TestFlushBeforeClose`, `e2e.TestHostStack` |

## Enrollment codes, app keys and account status (§6.2, §6.7.1, §11.3, §11.5, §11.11, §11.12, §11.13, §13.7; 0.15.0)

Owner decision of 2026-10-05, approved 2026-10-06 (ENROLLMENT-CODES.md,
MEMBER-API 2.0.0). The enclave records and reports the app key; it never
checks app-key signatures (§11.12.2), which the member API stand-in
(`internal/memberapitest`) checks as the member API does. `appkey.json`
holds the vectors §15 item 20 asks for (not printed in §16).

| § | Requirement | Test(s) |
|---|---|---|
| 11.12.2 | App key: standard base64 of the canonical SPKI DER of a P-256 key; `akid` = hex(SHA-256(SPKI)[0:16]); signing string `"vettid/member-api/app/1" \n METHOD \n path \n query \n vault_id \n akid \n ts \n nonce \n hex(SHA-256(body))`; `X-VettID-App` header strictly parsed; ECDSA P-256 | `altchan.TestParseAppKey`, `altchan.TestAppRequestSigning`, `altchan.FuzzParseAppHeader`, `vectors.TestAppKeyVectors` |
| 11.12.1 | Setup code: 31-symbol alphabet without 0, 1, I, L, O; 8 symbols by rejection sampling (bytes ≥ 248 discarded); normalization (spaces, hyphens, upper case); 16-byte QR secret, 22 characters base64url; QR `{"v":1,"t":"e","api","s"}`; `api` an origin; MACs as specified | `altchan.TestSetupCode`, `altchan.TestEnrollQR`, `altchan.FuzzParseEnrollQR`, `vectors.TestAppKeyVectors` |
| 11.11.2 | Recovery QR gains `api` (after `t`) | `altchan.TestEnrollQR`, `vectors.TestAppKeyVectors` |
| 11.3, 11.11.3 | `app.api_key` REQUIRED in `vault.enroll` and `vault.recovery.register` | `altchan.TestRequestRoundTrip`, `altchan.FuzzParseRecoveryRegister` |
| 11.3, 11.5, 11.11.3 | The sealed `app.api_key` must equal the queue message's `app_key` (REQUIRED for enroll and recovery_register, absent otherwise): a mismatch is answered with random bytes | `enclave.TestEnrollAppKey`, `enclave.TestQueueAppKeyAndAccount` |
| 6.2 | hs.init `api_key` only for purpose app; REQUIRED in a transfer's hs.init (otherwise dropped like a failed attestation), absent otherwise | `handshake.TestInitFieldRules`, `handshake.TestInitAPIKey`, `vault.TestTransferNeedsAPIKey` |
| 11.3, 6.7.1, 11.11.5 | The header keeps the app key and `app_key_seq` (1 at enrollment; + 1 when a transfer or a recovery replaces the app) | `enclave.TestEnrollAppKey`, `vault.TestTransferRuntime`, `vault.TestRecoveryAppKey` |
| 11.5 | `enrolled`, `unlocked` and `locked` carry `app_key` and `app_key_seq`; the event `app_key` is reported after the flush that stored the header; the vault process, supervisor and parent carry them (vaultipc 4) | `enclave.TestEnrollAppKey`, `vault.TestTransferRuntime`, `parent.TestParseLifecycleAppKey`, `integration.TestV3Exit` |
| 11.5 | The parent writes `app_key = {key, kid, seq}` whatever the lease, only when `seq` is higher (`enrolled`: always) | `parent.TestAppKeyWrite` (memory), `parent.TestAWSBackend` (LocalStack), `integration.TestV3Exit` |
| 11.5, 11.13 | Queue op `account` (no envelope, no lease, answered `done`) and `account` in unlock (OPTIONAL); to the running vault process, dropped without one | `enclave.TestQueueAppKeyAndAccount`, `enclave.TestAccountOp`, `integration.TestV3Exit` |
| 11.13 | Snapshot parsed strictly (unknown members ignored, wrong types refused, over 2 KiB refused); kept only if `as_of` is later; `version` + 1 and `received_at`; `sync.event{account.changed, version}` to the app and desktops, never agents or connections; `account.get` `{account \| null, version, received_at}` | `vault.TestParseAccountSnapshot`, `vault.TestAccountInVault`, `enclave.TestAccountOp`, `integration.TestV3Exit` |
| 11.12.1, 11.12.2, 11.11.7 | Member API stand-in: setup code issue, QR and typed redeem (one `404 invalid_code`), pending key, signed requests with the key matrix (session no longer reaches enclave, enroll, unlock or register), recovery claim and recovering key, slots polled by their own key | `integration.TestV3Exit`, `devstack.TestDevStackLocalStack`, `e2e.*` through `vaultctl api-*` |

## Daily owner check and the hold (§3.5.3, §3.6, §6.7.1, §6.8, §9.1, §10.1, §10.2, §10.8–§10.11, §10.17, §11.11.5, §12.3; 0.13.0)

Owner decisions of 2026-10-05 and 2026-10-06 (§15 item 22). The runtime
keeps the record and the hold (`vault`, with a stand-in credential
feature), the credential feature runs the check (`credential`, on the
fake host), and calls, presence and LEASH apply their gates (`calls`,
`presence`, `leash`). `e2e.TestOwnerCheckHeldVault` runs a held vault
through the real relay with an injectable owner-check clock
(`vault.Options.OwnerCheckClock`).

The message type is `vault.owner-check` (owner decision of 2026-10-06,
VAULT-MESSAGING 0.15.2): 0.13.0's `vault.owner_check` broke §5.3's type
grammar.

| § | Requirement | Test(s) |
|---|---|---|
| 3.6.1 | The check, in order: alarm refusal before the UTK is spent; the UTK; a bad hold change is `bad_request` before the PIN (not a failed check); the blob (`stale_credential` for the holder's retry, the clone rule); the PIN under the §11.8 backoff (`bad_pin`, a failed check, the password not tried); the password backoff and the password (`bad_password`, a failed check); on success the CEK rotates and the answer is `{credential, version, utks, deadline, interval_seconds, hold, hold_off_until?}`; holder only (`forbidden`) | `credential.TestOwnerCheck`, `credential.TestOwnerCheckDuringAlarm`, `e2e.TestOwnerCheckHeldVault` |
| 3.6.1 | The record `{last_at, deadline, failures}` in DEK state, on the vault's clock; a success sets `last_at` = now, `deadline` = now + interval, `failures` = 0, audits `owner_check.passed` and sends the other devices `sync.event{owner_check, deadline}` | `vault.TestOwnerCheckHold`, `vault.TestOwnerCheckTenFailuresLock` |
| 3.6.1 | What starts the clock: every new credential starts it fresh (owner decision of 2026-10-06): the first `credential.create` (at enrollment); the holder's `credential.reset` (0.15.2); a completed recovery (`credential.recover`, `credential.reset`); a transfer's approval (its wrong entries are failed checks); a vault from before 0.13.0 at its first start, if it has a credential. A vault without a credential is never gated | `vault.TestOwnerCheckClockStart`, `credential.TestOwnerCheckClockStarters`, `credential.TestTransferApprovalIsCheck`, `credential.TestOwnerCheck` |
| 3.6.2 | `owner_check.interval_seconds` 3,600–86,400 (default 86,400, else `bad_request`); app only (a desktop's `settings.set` naming any owner-check key `forbidden` at once, never held); shorter applies at once (and may hold at once), longer from the next check | `vault.TestOwnerCheckSettings` |
| 3.6.3 | The app gate: past the deadline the holder may send only its row of the allow list, whatever the hold switch; requests answered `owner_check_required`, other messages dropped and audited `drop.owner_check`; with the hold on, desktops and agents only theirs; a recovering app its own set; the transport types for any device; the alarm's path, an open transfer and a call answered before the deadline | `vault.TestOwnerCheckHold`, `vault.TestOwnerCheckDue`, `vault.TestHoldAllowList`, `e2e.TestOwnerCheckHeldVault` |
| 3.6.3 | Entering the hold (one flush): the unlock window ends, held approvals answered `owner_check_required`, access-session requests dropped, a ringing call stops ringing on the devices only (`call.end{unavailable}`), audit `owner_check.held`, `vault.held` to the app and desktops in a session | `vault.TestOwnerCheckHold`, `credential.TestHoldEndsUnlockWindow`, `calls.TestCallsWhileHeld` |
| 3.6.3, 9.1 | Fan-out stops except `vault.held`, `vault.locking`, the clone alarm (with its `sync.event` and feed item), `device.transfer.pending`, `device.unlinked`, the token, address, rotation and call messages; with the hold off only the app's fan-out stops (it still rings); `vault.held{deadline, waiting{messages, requests, calls, other}}` counts what would have made a feed item since the deadline, at the start and on count changes at most every 10 minutes per device | `vault.TestOwnerCheckHold`, `vault.TestOwnerCheckDue`, `vault.TestHoldAllowList`, `e2e.TestOwnerCheckHeldVault` |
| 3.6.3, 10.10 | Held: an offer rings no device and is not answered (not even `busy`), a missed call is recorded and counted; the hold off: it rings | `calls.TestCallsWhileHeld` |
| 3.6.3, 10.17 | Held: pings are not answered; the hold off: they are | `presence.TestHeldVaultDoesNotAnswer` |
| 3.6.3, 10.11 | Held: no status statement issued or renewed, grants kept, `leash.status.get` `owner_check_required`; after the check agents in a session get `leash.grant.updated` with fresh statements; the hold off: statements renew | `leash.TestStatusWhileHeld`, `e2e.TestOwnerCheckHeldVault` |
| 3.6.3, 6.4 | Held: in-person auto-approval does not apply (the request waits) | `vault.TestHeldRequestNotAutoApproved` |
| 3.6.4 | Failed checks: `owner_check.failed` (audit and feed, `high`, `ref` = `pin`/`password`) besides `vault.pin_failed` / `credential.password_failed`; `failures` survives locks; the tenth consecutive failure audits `owner_check.locked` (`ref` = the count, feed `urgent`), answers, sends `vault.locking{reason: "owner_check"}` and locks as an owner request | `vault.TestOwnerCheckTenFailuresLock`, `credential.TestOwnerCheck` |
| 3.6.7 | The hold switch: off only within a successful check (`hold: false`, `hold_off_until` in the future and ≤ 30 days, only with `hold: false`); `settings.set` naming `hold: false` or `hold_off_until` is `owner_check_required`; on by `settings.set` or a check, clearing `hold_off_until`; back on by itself at `hold_off_until` (held at once past the deadline); every change audited and a feed item (`owner_check.hold_changed`, `on`, `off`, `off_until:<ts>`, `on:expired`) with `sync.event{settings.changed}`; `vault.status` reports `hold`, `hold_off_until` and `state` `due` | `vault.TestOwnerCheckSettings`, `vault.TestOwnerCheckDue`, `credential.TestOwnerCheck`, `credential.TestHoldChangeParse` |
| 10.2 | `vault.status.owner_check`: `{state, deadline, interval_seconds, failures, hold, hold_off_until?}` to apps and desktops, `{state}` to agents (`deadline` absent before the clock starts) | `vault.TestOwnerCheckHold`, `vault.TestOwnerCheckDue` |
| 11.13, 3.6.3 | 0.15.0 with the hold: the op `account` is stored while held, `account.get` is not on the allow list, `sync.event{account.changed}` waits for the check | `vault.TestHeldAccountSnapshot`, `vault.TestHoldAllowList` |
| 13.6 | New parsers fuzzed | `credential.FuzzParsePayload` (owner-check seeds) |

## No standalone credential deletion; the holder's reset (§3.5.5, §3.5.7, §3.6.1, §10.6, §15 item 23; 0.15.2)

| § | Requirement | Test(s) |
|---|---|---|
| 3.5.5, 10.6 | `credential.delete` removed: answered `unsupported_type`; `credential.deleted` sync and audit kinds no longer emitted; a credential is deleted only by `vault.delete` | `credential.TestHolderReset`, `credential.TestVaultDelete` |
| 3.5.5, 10.6, 3.6.1, 3.6.4 | The holder's `credential.reset{credential, utk_id, sealed{pin, password, new_password}}`: the blob, the PIN and the current password verified as in an owner check (same backoffs; `bad_pin` / `bad_password` are failed checks); then in one flush the credential and every critical item destroyed and version 1 of a new credential (new key, no rotation statement) under `new_password`; the clock starts fresh; refused to another app and during an alarm; the recovering app's form removed in 0.16.0 | `credential.TestHolderReset`, `credential.TestBackupCopyAndRecoveringApp`, `items.TestCriticalItems`, `e2e.TestConnectionAuthenticate` |
| 3.6.3 | The holder's reset is not on the hold's allow list (refused while held) | `vault.TestHoldAllowList` |

## No recovery with the credential backup off (§3.3, §3.5.6, §10.2, §11.4, §11.5, §11.11.1–§11.11.5, §13.7, §15 item 24; 0.16.0)

| § | Requirement | Test(s) |
|---|---|---|
| 3.3, 3.5.6 | The sealed header's `credential_backup`: the vault has a backup copy when the setting is on and the latest blob it keeps was sealed with it on (none after turning it on until the next use); written at every header write | `credential.TestBackupCopyAndRecoveringApp`, `vault.TestCredentialBackupBit`, `vault.TestHeaderContents` |
| 11.5, 13.7 | One content-free bit to the host: `credential_backup` on `enrolled`, `unlocked`, `locked` and the event `credential_backup` after the flush that changed it (vaultipc 5, 8-field lifecycle frames); the parent writes it under the lease rule; it copies the slot code `recovery_unavailable` for `recovery` only | `vault.TestCredentialBackupBit`, `parent.TestParseLifecycleBackup`, `parent.TestCredentialBackupWrite`, `parent.TestRecoveryRegisteredMarker`, `parent.TestAWSBackend` (LocalStack), `integration.TestV3Exit`, `e2e.TestRecoveryBackupOffRefused` |
| 11.11.1, 11.11.2 | A recovery request for a vault without a credential or without a backup copy is refused, sealed to the browser key (`no_credential` / `no_backup`), with the clear marker `recovery_unavailable`, **before** the vault is locked (a running vault decides from its own state) and with nothing recorded; a header from before 0.16.0 counts as having a copy | `vault.TestRecoveryNoBackup`, `e2e.TestRecoveryBackupOffRefused`, `e2e.TestNoCredentialNoRecovery`, `vectors.TestRecoveryVectors` (`no_backup`) |
| 11.11.3 | A register for a vault without a backup copy: `no_backup`, the recovery removed | `vault.TestRecoveryNoBackup` |
| 11.4, 11.11.5 | The registered app's unlock of a vault without a backup copy: `no_backup`, no token, no bundle; the recovery and its unlock key removed, the vault locked again | `vault.TestRecoveryUnlockNoBackup` |
| 11.11.5, 10.2 | The recovering app may send only `credential.utk.get`, `credential.recover`, `vault.status` (reduced to `{vault_id, state_seq, header_seq}`) and the token and address types; no `credential.reset`, no `vault.delete`, no `credential_lost`; no fan-out until `credential.recover` succeeds | `vault.TestRecoveringStatusReduced`, `credential.TestBackupCopyAndRecoveringApp`, `credential.TestVaultDeleteDuringAlarmAndRecovery` |
| 16 | `recovery.json` gains the `no_backup` refusal (eph 32 × 0x28, nonce 12 × 0x29) | `vectors.TestRecoveryVectors`, `vectors.TestVectorsUpToDate` |
| 11.11.7 | Member API stand-in: `409 recovery_unavailable` (`reason: no_backup`) when the row's bit is false | code review (`internal/memberapitest`) |
