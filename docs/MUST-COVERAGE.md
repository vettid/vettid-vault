# VAULT-MESSAGING §4–§6 requirements → tests

(Updated for VAULT-MESSAGING 0.10.0: manifest by hash, `removed` and
`ends_at`, the retirement key-policy delta, per-channel release constants;
for 0.10.2 and 0.10.3: connection requests, the SAS commitment, the
handshake before approval, request tokens; for 0.10.5:
`connection.declined` and `device.pair.rejected`; for 0.10.6: the
recovery marker, `credential_backup` and the lock state; for 0.12.0:
LEASH delegations and status statements in the LEASH paper's §3.5 format;
for 0.13.0: the daily owner check and the hold; for 0.15.0:
enrollment codes, app keys and the account snapshot; and for 0.18.0: the
shared profile's core and the name change from the app; for 0.19.0:
the held counts in `vault.status`, the worst-case profile size and the
0.18.0 errata; for 0.20.0: the full email in the account snapshot and
the audit search; and for 0.21.0: kept values on item edits, the item's
size, dry runs, named limits, share.pending.list and
share.decide{include, decline}, grant labels and names, and suitability
before the password; for 0.21.1: the 0.21.0 errata; for 0.22.0:
History export, `audit.export`; and for 0.23.0: a connection's asks
(no approval fatigue), rate limits on connection rules, overlapping
rules (ask wins), the 0.22.0 errata and the month hint; for 0.23.1: the
0.23.0 errata; for 0.23.2: the device on `vault.unlocked` and
`vault.locked`; for 0.26.0: the feature allowlist and the per-channel
Android package; for 0.27.0: the per-vault signer binding; and for 0.27.2: the collect
loop's waits and the shared HTTP/2 connections (§12.2, §12.2.1); for
0.32.0 (the rules for every message, not release A): `response_too_large`,
volatile `message.list` and `message.get`, and `message.list` pages; for
0.32.0 release A: message attachments (with VAULT-HOST-PROTOCOL 0.1.9
P15 and RELAY-PROTOCOL 0.9.2–0.9.4's blob API); for 0.34.0 release R:
`attempt_used` and the release capabilities; for 0.40.0: the bound on
`device.session.request`; for 0.43.0: the staging time scale; and,
ahead of its spec text, a connected but silent parent (§12.3,
VAULT-HOST-PROTOCOL §13 point 1).)

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
| 8.3 | "Devices apply the same rule to their local storage" (reference client, `client.Config.Persist`): a collected batch is saved after it is handled and before any of it is acknowledged; its deposits go out after the save; a save error leaves the batch unacknowledged; a crash before the save loses nothing, one after it replays without effect | `client.TestPersistBeforeAck`, `client.TestPersistErrorLeavesBatchUnacked`, `client.TestCrashBeforePersistLosesNothing`, `client.TestCrashAfterPersistReplaysHarmlessly`, `client.TestCrashBeforeAckDepositsAgain`, `client.TestPersistOutboxRetry`, `client.TestPersistNilUnchanged` |
| 8.4 | Reject `ts` > 5 min ahead and, for durable types, > 16 d old | `vault.TestTimestampWindow`, `envelope.TestInnerCheckTime` |
| 8.5 | Ephemeral types: `exp` required, acked after handling, in-memory dedupe | `vault.TestEphemeralClass` |
| 8.6 | Error table: token_revoked / mailbox_unknown terminal, token_expired → reconnect | `vault.TestDepositErrors`, `e2e.TestRevokeConnection`, `e2e.TestReconnectAfterExpiry` |
| 8.6 | "An owner device refused by its own vault" (reference client): `token_revoked` on a deposit to its vault's mailbox stops all sending to it (`client.ErrRefused`, `Refused`), erases nothing, keeps collecting (a `device.unlinked` is still read), and the batch is acknowledged anyway; the outbox backs off on 429 and transient errors (full jitter, 0.25 s doubling, 30 s cap, `retry_after` honoured) | `client.TestPersistTokenRevoked`, `client.TestNoPersistTokenRevoked`, `client.TestOutboxBackoff` |
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
| 11.7 | Android: chain to a pinned root, challenge, TEE/StrongBox, RootOfTrust locked + Verified, package and signer digests, signing-only generated P-256 key; status list ≤ 24 h at enrollment and pairing, ≤ 7 d at unlock | `devattest.TestAndroidHappyPath`, `devattest.TestAndroidRejects`, `enclave.TestDeviceAttestationRefused`, and the chain rules below ("Key attestation chain rules") |
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
| 12.4 | The channel is scoped to the vault: its objects, its member's index, index written only with its own vault id by an enrollment while it opens and deleted only while it names its own vault, previous vault's state and header read-only while an enrollment opens, relay requests under its own key, namespace KMS keys, no arbitrary attestation | `supervisor.TestChannelScope`, `supervisor.TestChannelIndexHonestCalls`, `e2e.TestHostMemberIndex` |
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
| 8.2 | A volatile response is neither cached nor written to state; a retransmission is executed again (runtime rule; used since 0.32.0 by `message.list` and `message.get`) | `vault.TestVolatileResponses` |
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
| 6.8 | (0.40.0) At most one accepted `device.session.request` per desktop or agent every 10 minutes, counted from the last accepted one whether it was approved, denied, replaced or dropped; one within that time is answered `too_soon {allowed_after}`, reaches no app (no `device.session.pending`, no feed item), does not replace the pending request and does not move the window; per device; kept in the device's record across a lock and unlock | `vault.TestAccessRequestBound`, `vault.TestAccessRequestBoundPersists` |
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
| 10.16 | (0.35.0) A request that closes, answered by a share (only of its own connection) or expired at the sweep, sends `sync.event{location.request.closed, request_id, reason}` | `location.TestRequests` |
| 7.4, 10.16 | Removing a connection drops its shares and requests | `location.TestConnectionRemoved` |
| 9.2, 10.17 | Presence: on-demand ping only, one ping per connection per minute, pong only within `exp`, result to the asking device | `presence.TestQueryPingPong`, `presence.TestQueryErrors`, `presence.FuzzParseQuery`, `presence.FuzzParsePing`, `presence.FuzzParsePong`, `e2e.TestPresencePing` |
| 9.2, 10.17 | Policy: versioned; `invisible`, `share: none` and per-connection `except` answer nothing (indistinguishable from a locked vault); one answer per peer per minute; `last_active` rounded to 5 minutes | `presence.TestPolicy`, `presence.FuzzParseSet`, `e2e.TestPresencePing` |
| 10.18 | BIP39 (wordlist hash, vectors, checksum, normalisation, ASCII passphrase), BIP84 and BIP86 (vectors: fingerprint, account key, receive and change addresses), networks and their encodings | `btc.TestWordlist`, `btc.TestBIP39Vectors`, `btc.TestBIP84Vectors`, `btc.TestBIP86Vectors`, `btc.TestCheckAddress`, `btc.FuzzNormalizeMnemonic`, `btc.FuzzCheckAddress` |
| 10.18 | The recovery phrase is a critical item (credential operation, envelope-encrypted, revealed only sealed to a reply key; never in `item.get` or wallet responses); generated or imported; networks allowed per release | `wallet.TestCreateGeneratedAndReveal`, `wallet.FuzzParseCreate`, `wallet.FuzzParseImport`, `e2e.TestWallet`, `e2e.TestVaultctlBatch4` |
| 10.18 | (0.35.0) `testnet4` is a network name of its own (testnet3's encodings, coin type 1); releases accept `mainnet`, `testnet`, `testnet4` and `signet`; `wallet.request-address` may report it | `wallet.TestTestnet4`, `btc.TestLookupTestnet4` |
| 10.18 | (0.35.0) `wallet.update` moves an account's `next_receive`/`next_change` forward only, from the app only (a desktop `forbidden`) (lower is `bad_request`, the same value a no-op), with or without `address_type`, versioned, all or nothing; skipped addresses are not recorded | `wallet.TestUpdateNextIndices`, `wallet.FuzzParseUpdate` |
| 10.18 | `<wallet>` carries its item's `tags` (given at `wallet.create` under the item rules, changed by `item.tag`; `[]` without any); the wallet keeps no copy and its version does not change with them | `wallet.TestWalletTags` |
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
| 10.17, 10.1, 7.4 | (0.35.0) Removing a connection that is in `except` is a policy change: a new version and `presence.changed`; a `presence.set` with the old version is `conflict`; removing one that is not changes nothing | `presence.TestPolicy` |
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
| 3.6.3, 10.16 | (0.35.0) `location.share.stop` is on the hold's allow list for the app (due or held) and for desktops while held, never for agents; starting a share and the other `location.*` requests are not; stopping while held tells the connection | `vault.TestHoldAllowList`, `e2e.TestOwnerCheckHeldStopsLocationShare` |
| 3.6.3, 10.16 | While held, `sync.event{location.share.changed}` and `{location.request.closed}` and the location device events are withheld from the app, desktops and agents; a stop made while held reaches the connection but not the desktop | `vault.TestHoldAllowList`, `e2e.TestOwnerCheckHeldWithholdsLocationSyncEvents` |

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

## A transferred app's `user_guid`; `backoff` carries `retry_after` (§3.6.1, §6.7.1, §10.1, §10.3, §15 item 25; 0.17.0)

| § | Requirement | Test(s) |
|---|---|---|
| 6.7.1, 10.3 | A transfer's `device.paired` carries the member's `user_guid` from the sealed header (a plain pairing's does not); the reference client stores it (1–128 printable ASCII) and the new app unlocks with it | `vault.TestTransferRuntime`, `e2e.TestTransfer` |
| 10.1, 3.6.1 | A `backoff` error's body is `{retry_after}`: whole seconds, rounded up, at least 1, until the PIN backoff (§11.8) or the password backoff (§3.5.3) that refused the request ends | `vault.TestVerifyPIN`, `credential.TestOwnerCheckBackoffRetryAfter` |

## The shared profile's core; names change only in the app (§6.2, §9.3, §10.4, §10.8, §10.9, §11.5, §11.13, §16, §15 item 26; 0.18.0)

| § | Requirement | Test(s) |
|---|---|---|
| 11.13 | The snapshot's `first_name`, `last_name` (strings of 1–160 bytes without C0, C1, U+2028, U+2029) and `name_change {allowed_after, last}` are required (still `v: 1`); a snapshot without them is refused and the stored one kept | `vault.TestParseAccountSnapshot`, `vault.FuzzParseAccountSnapshot`, `vault.TestAccountInVault` |
| 11.5, 11.3 | `account` is REQUIRED in `enroll`: without a well-formed one the enrollment is answered `bad_request`; the vault stores it with its first flush | `enclave.TestEnrollNeedsAccount`, `e2e.TestHostStack` |
| 10.8 | Every `profile.update` carries the core `{first_name, last_name, ik}` before the optional `name`, `photo` and `items`; `profile.get` returns it; `profile.set` naming a core member is `bad_request`; the display name is optional (absent by default) | `items.TestProfileCore`, `items.TestProfile`, `e2e.TestProfileCoreNamesAndRotation` |
| 10.8 | Sent on activation (§9.3), on a change of the extras, when a stored snapshot's names differ from the ones last sent (not for the same names again), once when a vault first stores names, and after an `ik` rotation only in the epoch under the new `ik` (after `identity.rotate`; the connection's update waits while its epoch predates the rotation) | `items.TestProfileCore`, `vault.TestRotationPending`, `e2e.TestProfileCoreNamesAndRotation` |
| 10.8 | No update without the complete core: none is sent and `profile.core_missing` is audited | `items.TestProfileCore` |
| 10.8, 10.9 | Receiving: strict parse, then the version check, then `drop.profile_malformed` for a missing or invalid core member, an earlier `ik` of the peer's chain ignored without an audit entry, any other `ik` `drop.profile_ik_mismatch` (`ref` = the connection id); a dropped update changes nothing and tells no device | `items.TestProfileReceiveCore`, `items.FuzzParseUpdate` |
| 6.2 | A vault's connection `hs.init` profile is `{first_name, last_name, name?}`; one without both names is dropped (`drop.profile_malformed`) and the invitation stays usable; a vault without names sends no `hs.init` (`profile.core_missing`) | `vault.TestHandshakeProfile`, `vault.TestHandshakeProfileRequired`, `vault.TestAcceptWithoutNames` |
| 10.4 | A connection's `name` is the display name of its kept profile (absent without one); `profile` is the peer's kept update | `e2e.TestProfileCoreNamesAndRotation` |
| 10.8 | (0.19.0 erratum: the names are checked before the blob, the PIN and the password, step 3 before step 4) `account.name.set`: the holder's only (`forbidden` otherwise), refused during an alarm and while held; `too_soon {allowed_after}` while the snapshot's `allowed_after` lies ahead (nothing counted); the PIN and the password as the owner check (the same failed checks), the CEK rotates, not an owner check (the deadline does not move); the registration rule on the trimmed names (`bad_request`, also for the current names); answer `{credential, version, utks, request}` | `credential.TestAccountNameSet`, `credential.TestAccountNameSetDuringAlarm`, `vault.TestNormalizeRequestedName`, `vault.TestHoldAllowList` |
| 10.8, 11.5 | The request gets the next `seq`, is stored `pending` (replacing one still pending), audited `account.name_requested` (`ref` = `seq`, no names), announced `sync.event{account.changed}`, and reported as the host event `account_name {seq, first_name, last_name}` after the flush that stored it | `vault.TestNameRequest`, `vault.TestNameRequestNotReportedWithoutFlush` |
| 10.8, 11.13 | A stored snapshot's `name_change.last` with the pending `seq` sets its state and reason (`account.name_applied` / `account.name_refused`); a higher `seq` refuses it with `account`; `account.get` returns `name_request` | `vault.TestNameRequest`, `e2e.TestProfileCoreNamesAndRotation`, `integration.TestV3Exit` |
| 11.5 | The lifecycle frame's name fields (vaultipc 6, 11 fields: `name_seq`, `first_name`, `last_name`); the parent writes `name_change = {seq, first_name, last_name, at}` and `name_change_pending = true` whatever the lease, when `seq` is higher than the row's | `enclave.TestLifecycleNameFields`, `parent.TestParseLifecycleName`, `parent.TestNameChangeWrite`, `parent.TestAWSBackend` (LocalStack), `e2e.TestHostStack`, `integration.TestV3Exit` |
| 16 | The `ik` fingerprint: SHA-256("vettid/vms/2/ik-fp" ‖ ik), shown as its first 16 bytes in 8 groups of 4 lowercase hex digits; the §16 vector in `keys.json` (`ik_fingerprint`) | `vectors.TestVectors` (ik_fingerprint), `vectors.TestVectorsUpToDate`, `suite.TestLabelsEmbedSuite` |
| 11.5 | Member API stand-in: the snapshot's names and `name_change`, `account` in `enroll`, the vault-names job (claim, `invalid` / `too_soon`, the result, the push) | `integration.TestV3Exit` |
| 6.6, 8.6 | (Found with 0.18.0's activation updates.) A deposit waiting for a fresh standing token holds back only later deposits on the standing token, not the reconnect's `hs.init` that brings it | `vault.TestAwaitTokenDoesNotBlockReconnect`, `e2e.TestReconnectAfterExpiry` |

## Held counts in `vault.status`; the worst-case profile size; 0.18.0 errata (§3.6.3, §10.1, §10.2, §10.4, §10.8, §11.5, §11.13, §15 item 27; 0.19.0)

| § | Requirement | Test(s) |
|---|---|---|
| 10.2, 3.6.3 | `vault.status`'s `owner_check.waiting {messages, requests, calls, other}` while `due` or `held`, for the devices that get `vault.held` (the app; a desktop with an access session only while `held`); absent for agents, for a desktop while `due`, and once the check succeeded | `vault.TestOwnerCheckHold`, `vault.TestOwnerCheckDue` |
| 3.6.3 | The first count change after the hold's start notice is sent at once; later changes at most once per 10 minutes from that notice, with the latest counts | `vault.TestOwnerCheckHold` |
| 10.8 | Whenever the display name, the photo or the `@profile` items change, the `profile.update` size is checked with each name counted as a 322-byte JSON string (160 bytes, only `"` and `\` escaped: the encoder writes names as raw UTF-8), refused with `limit` over 196,608 bytes | `items.TestProfileSizeWorstCaseNames` |
| 10.8, 11.5 | A still-pending name request is reported again (`account_name`) with every `unlocked` report; a settled one is not; the parent treats the failed `seq` condition as done | `vault.TestNameRequestReReportedOnUnlock`, `parent.TestNameChangeWrite` |
| 10.8 | The names are trimmed of U+0020 only; other white space at either end fails the pattern | `vault.TestNormalizeRequestedName` |
| 11.13 | `name_change.last.status` is `applied` or `refused` (any other refuses the snapshot); `reason` is kept only with `refused` | `vault.TestParseAccountSnapshot` |
| 10.4, 10.8 | A vault without names answers `connection.invite.accept` with `internal`, sends no `hs.init` and audits `profile.core_missing` | `vault.TestAcceptWithoutNames` |
| 10.1, 10.2 | `sync.event{account.changed}` for a name request alone repeats the stored snapshot's `version` | `vault.TestNameRequest` |

## The full email in the snapshot; audit search in the vault (§10.2, §10.9, §11.13, §13.7, §15 item 28; 0.20.0)

| § | Requirement | Test(s) |
|---|---|---|
| 11.13 | The snapshot's `email` is required (still `v: 1`): a string of 3–1,016 bytes with an `@`, without control characters (C0, DEL, C1); a snapshot without it, or with a bad one, is refused and the stored one kept; an `email_hint` is an unknown member and ignored, whatever its type | `vault.TestAccountSnapshotEmail`, `vault.TestParseAccountSnapshot`, `vault.FuzzParseAccountSnapshot` |
| 11.13, 10.2 | `account.get` returns the snapshot with the full `email` to the app and desktops (stored as received); agents may not ask | `vault.TestAccountInVault`, `e2e.TestEmailStaysWithTheMember`, `e2e.TestHostStack`, `integration.TestV3Exit` |
| 11.13, 13.7 | The email (or a hint or its domain) is in no `profile.update` (on activation, after a name change), no `hs.init` profile, no invitation, no feed item, no audit entry, nothing a connection lists, and no lifecycle event or host audit entry | `e2e.TestEmailStaysWithTheMember` |
| 11.11.7, 11.12.1 | The redeem and recovery-claim answers keep the masked `email_hint` (member API; the stand-in and the client unchanged) | `integration.TestV3Exit`, `vectors.TestAppKeyVectors` (`email_hint`) |
| 11.5 | Member API stand-in: the snapshot carries `email` (trimmed and lower-cased), not `email_hint` | `integration.TestV3Exit` |
| 10.9 | `q` matches, case-insensitively (`strings.ToLower`, per field): the `kind`, the `kind` with `.`, `_`, `-` as spaces; the entry's connection's current `name`, `alias`, profile `first_name`, `last_name`, display name and "First Last"; its device's current name (as `device.list`, any state); for `item.*`, `share.included`/`declined`/`withdrawn`, `wallet.created`/`deleted`/`address_issued`, the item's current name (critical items included) | `audit.TestSearchFields`, `vault.TestSearchNamesFromManager`, `e2e.TestAuditSearch` |
| 10.9 | Never searched: field labels or values, tags, notes, the profile's other members, ids, refs that are not item ids; no match across two fields; a removed connection, unlinked device or deleted item adds no text; names are those held when the vault answers; the entries (and `hash`) are unchanged | `audit.TestSearchNeverSearched`, `e2e.TestAuditSearch` |
| 10.9 | With `q`, at most 2,000 entries that pass the other filters (`connection_id`, `kinds`, `since`, `until`, the cursor) are evaluated; a budget run out before `limit` matches answers the matches so far (possibly none), `partial: true` and `next_before_seq` / `next_after_seq` = the last evaluated `seq`; with `limit` matches and entries left the cursor is the last returned, without `partial`; no cursor is the end; without `q` no budget | `audit.TestSearchBudget`, `e2e.TestAuditSearch` (`client.AuditSearchAll`) |
| 10.9 | `since` inclusive, `until` exclusive, RFC 3339 with any offset, compared in Unix milliseconds; either alone; a filter, not a cursor (an `at` that steps back is still filtered) | `audit.TestSinceUntil`, `e2e.TestAuditSearch` |
| 10.9 | `bad_request` for a `q` that is empty, over 128 bytes, only white space or with a control character (C0, DEL, C1) or not a string; a `since` / `until` that is not an RFC 3339 time; `since` ≥ `until`; the same on `connection.audit.list`; `kinds` still 1–16 prefixes; agents and connections still `forbidden` | `audit.TestSearchErrors`, `audit.FuzzValidQ`, `audit.FuzzParseQuery` |

## Kept values, size, dry runs, named limits, sharing and suitability (§10.1, §10.7, §10.8, §10.9, §10.12, §10.13, §11.13, §15 item 29; 0.21.0)

| § | Requirement | Test(s) |
|---|---|---|
| 10.7 | An `item.put` replacing an item of any sensitivity keeps the stored value of a field sent with its `field_id` and without `value`; its `kind` MUST be the stored one (`bad_request` otherwise); its label and position may change; a field left out is removed | `items.TestKeptValuesDataSecret`, `items.TestKeptValuesCritical`, `itemspec.TestApplyKept`, `e2e.TestKeptValuesAndDryRun` |
| 10.7 | `keep_notes: true` keeps the notes (in the sealed `item` for a critical item, in the request otherwise); `notes` with `keep_notes` is `bad_request`; neither removes the notes; a new field, and every field of a new item, needs a `value`; `keep_notes` on a new item is `bad_request` | `items.TestKeptValuesDataSecret`, `items.TestKeptValuesCritical`, `itemspec.TestParseContentKept` |
| 10.7 | A secret edit reads the kept values from DEK state: no `item.reveal`, recorded as `item.updated`, never `item.revealed`; no kept value leaves the vault | `items.TestKeptValuesDataSecret`, `e2e.TestKeptValuesAndDryRun` |
| 10.7 | A critical edit is one credential operation: the vault opens the stored values with the current key, merges, checks the merged item (shapes, 64 fields, 12,288 bytes with the kept values), seals under the next generation and wipes the plaintext it opened | `items.TestKeptValuesCritical` (generation, wiped buffers, limit with `size`), `e2e.TestKeptValuesAndDryRun` |
| 10.7 | The size is the content encoding without `item_id`, `version`, `created_at`, `updated_at` and `field_id`s, members in order, `template`/`notes` only when set, `tags`/`fields` always, the address member order, Go's escapes without HTML escaping | `itemspec.TestSizeEncoding`, `items.TestItemSize` |
| 10.7 | `item.get` returns `size` for every sensitivity; recorded for a critical item whenever its values are written or opened (a reveal, a use, a re-key; kept across tag changes), absent until then for an item written earlier; not in `item.list`, never sent to a connection | `items.TestItemSize`, `itemspec.TestSizeEncoding`, `e2e.TestKeptValuesAndDryRun` |
| 10.7 | `file` stays reserved: refused with `bad_request` | `itemspec.TestParseContentKept` |
| 10.7 | `item.put{dry_run}` and `item.tag{dry_run}` answer `{version?, shares: [{rule_id, subject, mode, usable?}], withdrawals: [{rule_id, subject, state}]}` sorted by `rule_id`, planned as the real request; content members ignored; `credential`/`utk_id`/`sealed` refused; `bad_request`, `not_found`, `conflict` and the `share_pending`, `grants_given`, `profile_items` limits; nothing recorded or sent | `items.TestDryRun`, `items.TestDryRunSharingLimits`, `e2e.TestKeptValuesAndDryRun` |
| 10.7, 6.8 | A dry run needs no step-up from a desktop (`vault.ReadOnlyForms`); critical items stay app-only (`forbidden`) | `vault.TestReadOnlyFormsAndHeldLimit`, `items.TestDryRun`, `e2e.TestKeptValuesAndDryRun` |
| 10.1 | Every `limit` error carries `{limit, max, size?}` (`size` only for a size limit), with the names of the §10.1 table | `vault.TestLimitBody`, `vault.TestReadOnlyFormsAndHeldLimit` (`held_approvals`), `items.TestKeptValuesDataSecret` (`item_size`), `items.TestDryRun` (`profile_items`), `items.TestDryRunSharingLimits` (`share_rules_subject`, `share_pending`), `items.TestShareDecideBothAtomic` (`grants_given`), `items.TestProfileSizeWorstCaseNames` (`profile_size`), `grants.TestLimitNames` (`catalog_requests`, `grant_requests`), `critical.TestOutgoingLimit` (`critical_use_requests`), `e2e.TestKeptValuesAndDryRun` (`client.LimitOf`) |
| 10.12 | `share.pending.list{rule_id? \| connection_id? \| agent_id?, after?, limit?}` answers `{pending: [{rule_id, subject, item_id, name, category, sensitivity, at}], next?}`, sorted by rule then item, paged with an opaque cursor; at most one filter | `items.TestSharePendingList`, `e2e.TestSharingAndSuitability` |
| 10.12 | `share.decide{rule_id, include?, decline?}`: 1–500 ids together, no overlap, not mixed with `items`/`approve`; one change, one response, one `share.decided`, nothing on an error; the old form stays valid | `items.TestShareDecideBoth`, `items.TestShareDecideBothAtomic`, `e2e.TestSharingAndSuitability` |
| 10.12 | A received grant in `grant.list` carries the descriptor's `labels` as received (not refreshed); a given grant none | `grants.TestReceivedLabels`, `e2e.TestSharingAndSuitability` |
| 10.12 | An available `item` entry of `grant.pending` and of `grant.list`'s `pending` (which carries `available`) has the item's `name`, `category` and the requested fields' `labels` in the item's order; unavailable and `category` entries none; `requested` entries exactly as sent, `state` `pending`/`granted`/`denied` | `grants.TestPendingEntryDetails`, `e2e.TestSharingAndSuitability` |
| 10.13 | Suitable is a `password`, `text` or `multiline` field of an item that is not a wallet's; any other request is answered `unsuitable` at once: no member, no credential operation, audited (`requested`, `denied`), no `.pending`, no feed item, not in `.list`; a suitable field without a seed is found at the use | `critical.TestSuitability`, `e2e.TestSharingAndSuitability` |
| 10.13 | `.pending`, `.list` and `.get` carry the field's `kind`; at most 64 outstanding outgoing requests (`critical_use_requests`) | `critical.TestSuitability`, `critical.TestOutgoingLimit`, `e2e.TestSharingAndSuitability` |
| 10.9 | The budget runs out when a 2,001st entry would be evaluated: `limit` matches by the 2,000th is not `partial`; `since` ≥ `until` in Unix milliseconds; `connection.audit.list` takes `after_seq` (unchanged behaviour, stated) | `audit.TestSearchBudgetEdge`, `audit.TestSearchBudget`, `audit.TestSearchErrors` |
| 11.13, 10.8 | The snapshot's `email` excludes C0, DEL, C1, U+2028 and U+2029; names (snapshot, `account.name.set`, the profile receiver) exclude DEL too | `vault.TestAccountControlSet`, `vault.TestParseAccountSnapshot` |

## 0.21.0 errata (§10.1, §10.7, §10.13, §15 item 29.7; 0.21.1)

| § | Requirement | Test(s) |
|---|---|---|
| 10.7, 6.8 | A dry run follows the access rule of the call it previews but never needs step-up: a desktop's dry run of `item.tag` on a critical item is answered at once (not an app-only form; the real `item.tag` is a step-up request); a dry run of `item.put` for a critical item is `forbidden` from a desktop | `items.TestDryRunErrata`, `items.TestDryRun`, `vault.TestReadOnlyFormsAndHeldLimit` |
| 10.7 | `item.put`'s dry run requires `version` together with `item_id` (`bad_request` with only one) | `items.TestDryRunErrata`, `items.TestDryRun` |
| 10.7, 10.1 | More than 64 fields is `bad_request` for every sensitivity, critical included, never a `limit`; 64 is accepted | `items.TestFieldCountEveryCritical`, `items.TestLimits` |
| 10.7 | A move to `critical` checks the 12,288-byte size on the item as it will be stored, with `"sensitivity":"critical"` (`limit` `item_size` with that `size`; nothing moves) | `items.TestMoveToCriticalSize` |
| 10.13 | A request recorded before 0.21.0 has no `kind`: `.list` and `.get` omit it (and the state keeps none) while the field is not usable; the vault fills in the current kind once it is; the request still expires 24 h after it arrived | `critical.TestKindAbsentBefore021` |
| 10.13 | An incoming use is checked usable (`unavailable`), then suitable (`unsuitable`), then against the 8 pending per connection (`unavailable`): an unsuitable request is `unsuitable` even at the cap | `critical.TestCheckOrder` |

## History export (§3.5.4, §3.5.9, §10, §10.9, §10.11, §15 item 30; 0.22.0)

| § | Requirement | Test(s) |
|---|---|---|
| 10.9, 3.5.9 | `audit.export` is the holder's app only: a desktop is answered `forbidden` at once (never held for approval); an agent, a recovering app, another app and a connection `forbidden`; without the credential feature `forbidden` | `audit.TestExportHolderOnly`, `credential.TestSpendPINForExport`, `e2e.TestAuditExport` |
| 10.11 | No `audit.*` type is delegable (app-only types are never delegated; not a LEASH scope) | `leash.TestAuditNeverDelegable`, `e2e.TestAuditExport` (agent) |
| 10.9, 3.6.3 | While the app is gated (past the owner check's deadline) the preview and the export are `owner_check_required` | `e2e.TestAuditExportHeld` |
| 10.9, 3.5.9 | While a clone alarm is open the preview and the export are refused with the alarm's freeze code (`credential_frozen`, `rotation_required`) after the sender and holder check and before anything else (even a malformed body; 0.23.0 errata) and without spending the UTK | `audit.TestExportCheckOrder`, `credential.TestSpendPINForExport` |
| 10.9 | The preview (`dry_run: true`) takes `audit.list`'s filters (`connection_id`, `kinds`, `q`, `since`, `until`) with their `bad_request` rules; `before_seq`, `after_seq`, `limit`, `utk_id`, `sealed` and `upto_seq` are `bad_request`; `format`, if present, `csv` or `json`; it answers `{count, more, upto_seq, upto_hash, oldest_seq?, newest_seq?, oldest_at?, newest_at?}` (the range only with `count` > 0; `upto_seq`/`upto_hash` the log's newest entry), spends nothing and writes no entry | `audit.TestExportPreviewFilters`, `e2e.TestAuditExport` |
| 10.9 | `q` is evaluated over the whole log without the 2,000-entry budget (the count is exact); at most 10,000 entries newest first, `more` beyond | `audit.TestExportWholeLogAndCap` |
| 10.9, 3.5.4 | The export carries `utk_id` and `sealed` = `{pin}` alone, bound to `audit.export` and the request id; single-use; no blob, password or CEK rotation; the answer has no `utks` or `credential` | `credential.TestSpendPINForExport`, `e2e.TestAuditExport` (`client.AuditExport`) |
| 10.9 | The export's order: the alarm, the UTK (`utk_invalid`), the shape (`bad_request`: a bad filter, `format` absent or not `csv`/`json`, a PIN not 6–32 digits, `upto_seq` not an integer 1…newest seq; the UTK spent), `not_found` when nothing matches with `seq` ≤ `upto_seq` (the PIN not tried), the §11.8 backoff (`backoff` with `retry_after`), the PIN | `audit.TestExportCheckOrder`, `credential.TestSpendPINForExport`, `e2e.TestAuditExport` |
| 10.9 | A wrong PIN is `bad_pin`, audited `vault.pin_failed` and counted in the §11.8 PIN backoff only: the owner check's `failures` stay 0, no `owner_check.failed` entry, no feed item; three failures start the backoff | `audit.TestExportCheckOrder`, `e2e.TestAuditExport` |
| 10.9 | The right PIN, in one flush, resets the PIN backoff, appends exactly one `audit.exported` (`device_id` = the app, no `connection_id`) and answers the preview's members for the entries with `seq` ≤ `upto_seq`, plus `entry_seq`; no feed item; not an owner check | `audit.TestExportCheckOrder`, `e2e.TestAuditExport` |
| 10.9 | `audit.exported`'s `ref`: `format=…;count=…;seqs=<oldest>-<newest>;filters=<none\|connection,kinds,q,dates>[;since=<ts>][;until=<ts>]`, times in UTC `ts` format, naming no connection, kind prefix or search text | `audit.TestExportSummary`, `e2e.TestAuditExport` |
| 10.9 | `upto_seq` bounds the export: entries written after the preview (`audit.exported` among them) are not counted; `upto_hash` is the hash of `upto_seq`'s entry; an unfiltered export read with `audit.list` from `before_seq` = `upto_seq` + 1 is one chain ending at `upto_hash` | `audit.TestExportUptoBound`, `e2e.TestAuditExport` (`client.AuditExportEntries`) |

## Asks, connection rule rate limits, overlapping rules, 0.22.0 errata (§6.3, §10.4.1, §10.7, §10.9, §10.11, §10.12, §15 item 31; 0.23.0)

| § | Requirement | Test(s) |
|---|---|---|
| 10.4.1 | An ask (grant request, critical-item use, prompt-each-time invocation, authentication challenge, introduction offer, location request) is checked after its type's own checks, and suppressed at the first of: muted, paused, cooldown, pending (8, all kinds together), rate (5 per fixed 24 h window from the first ask that reached the member; suppressed asks do not count) | `vault.TestAskCheckOrder`, `vault.TestAskPendingCap`, `vault.TestAskRateWindow`, `vault.TestAskHeldAnswerSent` (other features' pending, the source not asked), `items.TestAsksPendingRatePause`, `items.TestAsksEveryKind` |
| 10.4.1 | The cooldown: 7 days after a decline of the same ask (a grant entry's kind and ref, a use's item_id and field_id, an action_id, any challenge, any offer from the introducer); a grant request with some entries in cooldown reaches the member without them, all of them: suppressed; at most 64 cooldowns, the oldest dropped; location requests have none | `vault.TestAskCooldown`, `items.TestAsksGrantPartialCooldown`, `items.TestAsksEveryKind`, `e2e.TestConnectionAsksE2E` |
| 10.4.1 | A decline is an explicit refusal of a whole ask (`grant.decide{approve: false}`, `critical-secret-use.deny`, `action.respond{approve: false}`, `connection.authenticate.deny`, `intro.decline`); a partial approval is not; the third decline within 30 days of the first of three (sliding) pauses the asks, once: one high-priority feed item and audit entry `connection.asks_paused`, `sync.event{connection.changed}` | `vault.TestAskPauseResume`, `vault.TestAsksTypes`, `items.TestAsksPendingRatePause`, `items.TestAsksGrantPartialCooldown` |
| 10.4.1 | No oracle: a suppressed ask is answered exactly as the member's decline of its kind (same type and members; none for a location request), never at once: after a uniform 1–20 minute delay, at most until 1 minute before the ask's exp; at most 16 held per connection (beyond: no answer); a repeat of a held ask is ignored; housekeeping sends it when due | `vault.TestAskHeldAnswers`, `vault.TestAskHeldAnswerSent`, `items.TestAsksEveryKind` (byte-identical to the decline, per kind), `e2e.TestConnectionAsksE2E` |
| 10.4.1 | `connection.asks.mute{connection_id, muted}` and `connection.asks.resume{connection_id}` answer `{}` or `not_found`, app and desktop without step-up, not delegable; resume ends a pause and clears decline times and cooldowns (0.23.1: always, audited even without a pause; below); unmuting does not resume; `<connection>.asks {muted, paused, paused_at?, cooldowns}`; changes audited (`connection.asks_muted`, `_unmuted`, `_resumed`) with `sync.event{connection.changed}` | `vault.TestAsksTypes`, `leash.TestAsksNeverDelegable`, `e2e.TestConnectionAsksE2E`, `e2e.TestVaultctlSmoke` |
| 10.4.1 | Every suppressed ask is audited `drop.ask_muted`, `_paused`, `_cooldown`, `_pending` or `_rate` (connection_id, ref = the ask's id), a removed grant entry `drop.ask_cooldown`; no feed item, no `.pending` | `vault.TestAskCheckOrder`, `items.TestAsksEveryKind`, `items.TestAsksGrantPartialCooldown` |
| 10.4.1, 10.9 | Batching: asks of one connection within 10 minutes of the first are one feed item (the first's), updated with a new seq and the same item_id, `count` from 2 (`sync.event{feed.updated}`); the per-type `.pending` events are still sent; a new batch after 10 minutes | `items.TestAsksBatching` |
| 10.12 | A connection rule takes `per_hour` (1–3,600) and `per_day` (1–86,400), optional, no default (`status_ttl` stays agent-only); shown on the rule, as `limits` on given grants (the rule's current) and descriptors (at issue), on received grants as received | `items.TestShareAuto`, `items.TestConnRuleRateLimits`, `grants.TestRateLimitedFetch`, `grants.TestRateLimitedWire`, `e2e.TestRuleLimitsAndOverlapE2E` |
| 10.12 | The connection's answered fetches of the rule's items count in total, in fixed windows from the first counted fetch (1 h, 24 h), kept across a replacement (a lowered limit applies at once); a refused fetch counts nothing; past a limit `data.value{error: "rate_limited", retry_after}` (whole seconds, rounded up, ≥ 1, until every full window ends), checked after the other refusals, no use counted, audited `drop.grant_rate_limited`, at most one normal `share.rate_limited` feed item per rule per 24 h, the member not asked; `grant.value` passes `retry_after` on; a one-off grant has no rate limit | `items.TestConnRuleRateLimits`, `grants.TestRateLimitedFetch`, `grants.TestRateLimitedWire`, `e2e.TestRuleLimitsAndOverlapE2E` |
| 10.12 | Overlapping rules: an item gaining an auto rule while an ask rule of the same subject covers it (and does not include it) is pending there with `ask_rule_id` (the lowest); evaluated on item creation and tag changes, a move across critical, a rule's creation, replacement (ask → auto includes only what no other ask rule holds, in every rule where pending) and deletion or expiry (held items stay pending, `ask_rule_id` dropped or another named), `tag.merge`; rules of other subjects are unaffected | `items.TestOverlapAskWins`, `items.TestOverlapPlanning` |
| 10.12 | One answer per item and subject: an inclusion includes the item in every rule of the subject where it is pending; a decline declines it in every rule where it is pending or included, withdrawing it (`data.revoked`); one `share.decided` per rule | `items.TestOverlapAskWins`, `items.TestOverlapPlanning`, `e2e.TestRuleLimitsAndOverlapE2E` |
| 10.12 | No silent withdrawal: an included item stays shared when an ask rule starts covering it; gaining the ask rule asks (`shared: true`); `include_existing: false` asks nothing | `items.TestOverlapAskWins` |
| 10.12 | `uses` across the rule grants of an item: a fetch counts one use on each that has uses, is `exhausted` if any is spent, the last use of one spends all (`used`, in the same flush), `uses_left` (and the catalog's) is the least; rate limits count in every including rule | `items.TestOverlapUsesAndRates`, `grants.TestRuleGrantsUsesTogether` |
| 10.12, 10.7 | `share.rule.set{dry_run}` entries carry `outcome` (`include` or `ask`) when the state would change, and `ask_rule_id`; `item.put`/`item.tag` dry-run `shares` carry `ask_rule_id`; `share.pending` items and `share.pending.list` entries carry `ask_rule_id` and `shared` | `items.TestOverlapPlanning`, `items.TestOverlapItemDryRun`, `items.TestOverlapAskWins`, `e2e.TestRuleLimitsAndOverlapE2E` |
| 10.11 | Agents: ask wins over an agent's auto rule; `item.get`/`item.use` is allowed only within every including rule's windows (counted on each), referred otherwise; a read counts one use in every including rule with uses, and with none left in one the item is included in none (catalog too) | `items.TestOverlapAgents` |
| 10.9 | `audit.export`'s order (errata): the sender and the holder (`forbidden`) before the clone alarm; the alarm before any body check; then `bad_request` at once, the UTK unspent, for a body that is not an object, a non-boolean `dry_run`, a preview with `utk_id`/`sealed`/`upto_seq`, an export without a readable `utk_id` and `sealed`; then the export's steps (the spend first) | `audit.TestExportErrataOrder`, `audit.TestExportCheckOrder` |
| 10.9 | The empty-log preview answers `count` 0, `upto_seq` 0 and `upto_hash` 32 zero bytes; an export of it is `bad_request` | `audit.TestExportEmptyLog` |
| 6.3, 6.5 | A message of the new epoch that reaches the vault, as responder, before `hs.fin` is left unacked (not processed, dropped or deduplicated) and taken on redelivery after `hs.fin` | `vault.TestNewEpochBeforeFinUnacked` |
| 10.7 | Registry version 3: `payment_card`'s Expires carries `"format": "month"` (the only hint, on a `date` field); `YYYY-MM` is a date value; no template carries a reserved tag | `itemspec.TestTemplateRegistry` |

## 0.23.0 errata (§10.4.1, §10.8, §10.12, §10.16, §15 item 31.13; 0.23.1)

| § | Requirement | Test(s) |
|---|---|---|
| 10.8, 10.12 | `tag.merge`'s `shares` (dry run and real) carry `ask_rule_id` on an `auto` entry that an `ask` rule of the subject holds, as `item.put`'s and `item.tag`'s dry runs do | `items.TestMergeSharesAskRuleID` |
| 10.4.1 | A suppressed ask's answer is due at min(the random 1–20 minute delay, exp − 1 minute), never earlier than now; held answers are kept in DEK state, and one due while the vault is locked is sent at the first housekeeping after unlock | `vault.TestHeldAnswerDueClamp`, `vault.TestAskHeldAnswers`, `vault.TestHeldAnswerAfterUnlock` |
| 10.4.1 | An ask that joins a batch whose feed item is read or archived updates its `count` and `seq` and keeps its status; a deleted item ends the batch and the ask starts a new one | `items.TestBatchReadArchivedDeleted` |
| 10.12 | A rule's windows count only fetches through the rule grants of the item; a fetch through a one-off (or shared-action) grant is neither counted nor refused by them | `grants.TestOneOffFetchNotInRuleWindows`, `grants.TestRateLimitedFetch` |
| 10.12 | A repeated `fetch_id` is answered again, uncounted, even while a window is full | `items.TestRuleWindowsWithoutLimits` |
| 10.12 | The windows count a rule's fetches even without limits, so a limit set later applies to the open window | `items.TestRuleWindowsWithoutLimits` |
| 10.4.1 | (Owner decision of 2026-10-09.) `connection.asks.resume` always clears the connection's decline times and cooldowns and ends a pause if any; it is audited `connection.asks_resumed` and sends `sync.event{connection.changed}` even when nothing was paused | `vault.TestResumeAlwaysClears`, `vault.TestAskPauseResume`, `vault.TestAsksTypes` |
| 10.4.1, 10.16 | Each grant entry removed for a cooldown is audited `drop.ask_cooldown` on its own, also when the reduced request is then suppressed; a suppressed location request does not use location's one-per-10-minutes allowance | `vault.TestCooledEntriesAuditedWhenSuppressed`, `vault.TestAskCooldown`, `items.TestSuppressedLocationKeepsAllowance` |
| 10.12 | `retry_after` is at most 86,400: the vault clamps what it sends, and a received `data.value` with more is malformed | `grants.TestRetryAfterMax` |
| 10.12 | A received `limits: {}` means no limits | `grants.TestEmptyLimitsMeanNone`, `grants.TestRateLimitedWire` |
| 10.4.1 | Ask-state changes send `sync.event{kind: "connection.changed", connection_id, version}` to every owner device | `vault.TestResumeAlwaysClears`, `vault.TestAsksTypes` |

## The device on vault.unlocked and vault.locked (§10.9, §15 item 31.14; 0.23.2)

| § | Requirement | Test(s) |
|---|---|---|
| 10.9, 11.4 | `vault.unlocked` carries `device_id`, the device record of the app whose unlock opened the vault | `vault.TestUnlockedNamesDevice` |
| 10.9, 11.10.4 | The confirming unlock at a move's new release names the app as well | `vault.TestUnlockedNamesDeviceOnMoveConfirmation` |
| 10.9 | An unlock without a device (PIN-only, development) has no `device_id` | `vault.TestUnlockedPINOnlyNoDevice` |
| 10.9, 10.2 | `vault.locked` carries `device_id` when an owner device's `vault.lock` locked the vault | `vault.TestLockedNamesRequestingDevice` |
| 10.9, 12.3 | Every other lock has no `device_id`: the host's lock (account site route, lease, memory, restart), a recovery, ten failed owner checks, also with a device's `vault.lock` in the same batch | `vault.TestLockedByHostNoDevice`, `vault.TestLockedByOwnerCheckNoDevice` |
| 10.9 | Entries with `device_id` are found by the device's name, whatever their kind | `audit.TestSearchFields` (entry 13, `vault.unlocked`) |

## Push (§3.6.3, §10.1, §10.3, §10.9, §11.10.8, §12.2, §14; 0.24.0; PUSH-GATEWAY 0.5.0)

| § | Requirement | Test(s) |
|---|---|---|
| 14.1 | `push.register` from the holder only: a desktop, an agent or a recovering app is `forbidden` | `vault.TestPushRegisterChecks` |
| 14.1 | Check 2: `platform` fcm or apns; fcm token 1–4,096 printable ASCII, apns 64–200 lowercase hex (even); `app_id` 1–255 of `[A-Za-z0-9][A-Za-z0-9._-]*`; `environment` required for apns, absent for fcm; strict members → `bad_request`, nothing sent | `pushwire.TestValidate`, `vault.TestPushRegisterChecks` |
| 14.1, 11.10.8 | Check 3: a release without a gateway URL answers `unavailable`; the channel files carry their own channel's URL (`push.vettid.org`, `push.staging.vettid.org`), placeholders refused by the release gate | `vault.TestPushRegisterChecks`, `releasecfg.TestCommittedFiles`, `releasecfg.TestRefusals` |
| 14.1 | Check 4: `token_hash` = SHA-256("vettid/vms/2/push-token" ‖ lp(platform) ‖ lp(app_id) ‖ lp(environment) ‖ lp(token)); equal to the stored one and the registration under 30 days old: the push state, no gateway call | `pushwire.TestTokenHash`, `vault.TestPushRegister`, `vault.TestPushRenewal` |
| 14.1, PG 4 (0.5.0) | Renewal: the same token with a registration 30 days old or older registers again through the gateway (a new challenge); the registration in force stays until the renewal is confirmed | `vault.TestPushRenewal` |
| 14.1, 10.1 | Check 5: `limit` (`push_registrations`, 20) when 20 registrations reached the gateway in the rolling 24 h (DEK state); the window rolls | `vault.TestPushRegistrationLimit` |
| 14.1, PG 3, 5.1 | A fresh Ed25519 wake key per registration; `POST /v1/register` signed by it with an attestation whose `public_key` is the wake key and `user_data` the request digest; the supervisor computes the digest and attaches the attestation; the vault process's relay key is refused | `supervisor.TestPushChannel`, `pushtest.TestRegisterRefusals`, `e2e.TestHostPush` |
| 14.1, PG 5.1 (0.5.0) | The gateway's 202 `{pending}`: the vault keeps the pending registration and its wake key (DEK state), replacing and wiping any earlier pending one, answers push state `pending`, audits nothing; the registration in force stays; `device.list` shows no pending registration | `vault.TestPushRegister`, `vault.TestPushConfirm`, `pushwire.TestClientRegisterConfirm` |
| 14.1 (0.5.0) | The same token while its pending registration is under 10 minutes old: that pending state, no gateway call, nothing counted, its code still confirms; after 10 minutes a new challenge | `vault.TestPushPendingReused` |
| 14.1, PG 5.1 (0.5.0) | `push.confirm{code}` from the holder only (`forbidden`, a recovering app included), `code` 1–64 base64url and no other member (`bad_request`), `unavailable` without a gateway; no pending registration → `bad_request` `no_pending_registration`; 10 minutes after the registration → `gateway_error` `challenge_expired`, no gateway call, pending dropped; `POST /v1/confirm {pending, code}` signed by the pending registration's wake key, no attestation; 403 `challenge_invalid` (or another refusal) → `gateway_error` (`challenge_invalid` as message), pending dropped; 429, 5xx, no connection → `gateway_error` (`retry_after` from 429/502), pending kept; not counted toward `push_registrations` | `vault.TestPushConfirm`, `pushwire.TestClientRegisterConfirm` |
| 14.1 | On the confirmation's 201 one flush stores `{wake_sk, wake_blob, token_hash, platform, environment, app_id, registered_at, state}`, replacing and wiping any previous one; audits `push.registered` (`device_id`, `ref` = platform); the token is never stored | `vault.TestPushRegister`, `vault.TestPushConfirm` |
| PG 5.1 (0.5.0) | The supervisor forwards `/v1/confirm` with the same signature check, relay-key refusal and size bound, without an attestation; other paths stay refused | `supervisor.TestPushChannel` |
| PG 5.1, 10.4 (0.5.0) | The stand-in: 202 `{pending}` and a recorded challenge (`/dev/push` `challenges`); `/v1/confirm` refuses a wrong code, another key, a tampered or expired pending registration, a blob as pending and an older challenge's code with the same 403 `challenge_invalid`; a pending registration never wakes | `pushtest.TestConfirm`, `devstack.TestPushControl`, `e2e.TestHostPush` |
| 14.1 | Gateway 400 `platform_invalid`/`app_invalid`/`token_invalid` → `bad_request` (code as message); 403, 429, 5xx, timeout, no connection → `gateway_error` with `retry_after` from a 429 or 502; the previous registration stays | `vault.TestPushRegisterChecks` |
| 14.1 | At most one registration per vault; a rotation replaces key and blob | `vault.TestPushRegister` |
| 14.1 | `push.unregister` erases (wiped) in one flush, audits `push.unregistered{ref: app}`; without one `{}` and no write; a transfer or recovery that removes the app erases it with `ref` `transferred` / `replaced`; both also drop a pending registration | `vault.TestPushUnregister`, `vault.TestPushErasedWithApp`, `vault.TestPushConfirm` |
| 10.3 | `push` on the app's `device.list` entry while registered, with `last_wake_at`/`last_result` after a wake | `vault.TestPushRegister`, `vault.TestPushOutcomes`, `e2e.TestHostPush` |
| 14.2 | Wakes after the relay accepted the deposit of: a new feed item of priority normal/high/urgent that is not a guide, `vault.held`, `credential.alarm`; nothing else (low items, guides, message.new, sync.event, responses); never desktops; none without a registration | `vault.TestPushWakeTriggers`, `vault.TestPushWakeAfterDepositOnly` |
| 14.2 | `vault.locking` wakes before zeroizing (one attempt, ≤ 3 s), not for the app's own `vault.lock` | `vault.TestPushLockWake`, `e2e.TestHostPush` |
| 14.2 | Debounce 5 s merging triggers, one in flight; 30 per rolling hour then one per 10 minutes; exempt triggers skip the cap up to 10 per hour and count toward it | `vault.TestSched*`, `vault.TestPushDebounceMerges` |
| 14.2 | 202: `sent`, `last_wake_at`, a `reseal` replaces the blob at the next flush; 410 `token_gone`, 400 `token_invalid`, 410 `blob_invalid` (also a blob past the gateway's 90 days; a pending registration is kept): erased in one flush, `push.token_gone` audited (`ref` = code), `push.token-needed{reason}` to the app, no wake; 429: wait `retry_after` (≤ 3,600 s), `rate_limited`; 5xx/timeout: retries after 5, 30, 120 s (±20 %), then dropped, `gateway_error`, not audited; no audit or feed entry per wake | `vault.TestPushOutcomes`, `vault.TestPushBlobExpiredKeepsPending`, `vault.TestSchedRetries`, `vault.TestSchedRateLimited` |
| 3.6.3 | While held the holder may send `push.register`/`push.confirm`/`push.unregister`; `push.token-needed` is still delivered; feed items do not wake (not delivered) | `vault.TestPushWhileHeld` |
| 14.3, 12.2 | The enclave reaches only its channel's gateway (egress allowlist, pinned URL); the parent allows the gateway hosts | `supervisor.TestPushChannel`, `e2e.TestHostPush` |
| PG 4, 5.2 | Wake blobs are opaque to the vault (base64url, ≤ 6,144 bytes); a wake is `{wake_blob, class: notify}` signed by the wake key | `pushwire.TestBlobsAndAnswers`, `pushtest.TestRegisterAndWake` |
| PG 15 | The registration request vector (key, body hash, canonical string, signature) | `pushwire.TestVector` |

## Feature allowlist and the per-channel Android package (§5.3, §10, §11.7, §11.10.8, §15 item 34; 0.26.0)

| § | Requirement | Test(s) |
|---|---|---|
| 11.10.8 | `features` in the channel file: zero or more of the seven optional names, each once, ascending. Missing, not an array of strings, a placeholder, an unknown name, an always-registered feature's name, a repeated name, names out of order: malformed (rule 1) | `releasecfg.TestRefusals` (the `features …` rows), `releasecfg.TestFeatureNames`, `releasecfg.FuzzParse`, `cmd/releasecfg.TestCheckCommand` |
| 11.10.8 | A channel's list only grows (rule 2): a name the previous release's file lists and this file lacks is refused; a name added passes; a previous file from before 0.26.0 counts as all seven; the previous file must be the channel's | `releasecfg.TestFeaturesOnlyGrow`, `cmd/releasecfg.TestCheckCommand`; the release workflow's `gate` job runs it against the previous release tag |
| 11.10.8 | The committed files: staging lists all seven and `com.vettid.app.staging`; production lists none and `com.vettid.app` | `releasecfg.TestCommittedFiles`, `releasecfg.TestFeaturesOnlyGrow` (staging after a pre-0.26.0 release), `enclave.TestReleaseConfigAndroidPackage` (per channel build, `make channels`) |
| 11.10.8 | The list is embedded with the rest of the channel file (measured); the image's features come from it and from nothing at run time; an incomplete configuration registers no optional feature | `releasecfg.TestEmbedded`, `enclave.TestReleaseConfigAndroidPackage`, `all.TestSetFollowsTheList` (zero options) |
| 11.10.8 | The names a file may list are exactly the optional features the code registers, each the feature package's own name | `releasecfg_test.TestOptionalFeaturesMatchTheCode`, `all.TestSetFollowsTheList` |
| 11.10.8, 5.3 | Not listed means not registered: the feature is not constructed and none of its types is registered | `all.TestSetFollowsTheList` (per feature: listed alone, and left out of the full list) |
| 11.10.8, 5.3 | Each type of an unregistered feature is an unknown type: `unsupported_type` to an app and to a connection, and a response of such a type is dropped | `vault.TestUnregisteredTypeIsUnknown` (app and connection, request and response), `e2e.TestOptionalFeatureNotRegistered` (every type of each of the seven, real features), `e2e.TestConnectionSendsUnregisteredType`, `e2e.TestHostStackProductionFeatures` |
| 11.10.8 | No `features.<name>` entry is created for an unregistered feature: after enrollment, requests (flushes), a lock and an unlock | `e2e.TestOptionalFeatureNotRegistered`, `e2e.TestNoOptionalFeatures`, `vault.TestUnregisteredFeatureStateCarried` |
| 11.10.8 | With no optional feature at all, the flows the v1 app uses pass | `e2e.TestNoOptionalFeatures`, `e2e.TestHostStackProductionFeatures` |
| 11.10.8 | An entry of an unregistered feature is carried unchanged through load, flush, lock and unlock, and is never read, migrated or deleted | `vault.TestUnregisteredFeatureStateCarried` |
| 11.10.8 | Turning a feature on: a vault without the entry starts the feature empty and gains the entry with a later flush | `vault.TestUnregisteredFeatureStateCarried`, `e2e.TestOptionalFeatureNotRegistered` (the same vault unlocked by an image with the feature) |
| 11.10.8 | Without `leash`: `device.pair.create{role: "agent"}` is `bad_request` as an unknown role is; an agent share rule is `not_found`; desktop pairing stays answered | `vault.TestPairCreateAgentNeedsLeash`, `e2e.TestNoOptionalFeatures`, `e2e.TestHostStackProductionFeatures` |
| 11.10.8 | Without `location`: `settings.set` of a `location.history.*` member is `bad_request` and changes nothing; `settings.get` is unchanged | `vault.TestLocationHistorySettingsNeedLocation`, `e2e.TestNoOptionalFeatures` |
| 11.10.8 | `actions` without `wallet`: the wallet actions answer `unavailable` | `e2e.TestActionsWithoutWallet` |
| 11.10.8 | The development build registers everything unless its test configuration names a list (production's list is run before a production release) | `enclavetest.TestDevFeatures`, `e2e.TestHostStackProductionFeatures`, `devstack.TestParseFlags` |
| 11.10.8, 11.7 | `android_package` is the channel's one value: missing, a placeholder, another channel's value or any other is refused | `releasecfg.TestRefusals` (the `package …` rows), `releasecfg.TestCommittedFiles` |
| 11.7, 11.10.8 | The package of key attestation is the release constant, not a constant in code; a build without complete constants has none (Android attestation fails closed) | `enclave.TestReleaseConfigAndroidPackage` |
| 11.10.8, 11.7 | `ios_app_id` is the channel's one value (0.35.0): missing, a placeholder, another channel's value or any other is refused | `releasecfg.TestRefusals` (the `iOS App ID …` rows), `releasecfg.TestCommittedFiles` |
| 11.7, 11.10.8 | The App ID of App Attest is the release constant, not a constant in code; a build without complete constants has none (iOS attestation fails closed); a release policy has no development App ID and no development environment; each channel accepts its own App ID at attestation and assertion and refuses the other's | `enclave.TestReleaseConfigIOSAppID`, `enclave.TestIOSAppIDPerChannel`, `devattest.TestIOSDevelopmentMembers` |
| 11.7, 11.10.8 | An attestation naming the other channel's package is refused at enrollment, at a transfer's `hs.init` and at a recovery's register; an unlock and a release approval by a binding made under another package pass | `e2e.TestAndroidPackagePerChannel`, `devattest.TestAndroid*` (the package check itself) |
| 11.10.8 | Build: the two channels' images of one commit differ in `releasecfg_sha256` and PCR0, and each rebuilds to the same PCR0 | the `release` workflow (two clean builds per channel, `eifinfo compare` / `match`); not run in `go test` |

## Per-vault signer binding (§6.7.1, §10.3, §10.9, §11.3, §11.4, §11.7, §11.7.1, §11.9, §11.10.8, §11.11.3, §11.11.5, §15 item 35; 0.27.0)

| § | Requirement | Test(s) |
|---|---|---|
| 11.7.1 | An attestation MUST report exactly one signing digest, pinned by the running release: one pinned digest is accepted and recorded; two digests, both pinned, are refused; an unpinned digest is refused | `devattest.TestAndroidSigner`, `devattest.TestAndroidRejects` (other signer, extra signer, no signer), `e2e.TestSignerBoundAtEnrollment` |
| 11.7.1, 11.10.8 | Each pinned signer has a class (`vettid`, `google_play`, `development`), an identifier from the table; the class of each configured signer | `devattest.TestAndroidSigner`, `e2e.TestSignerBoundAtEnrollment` |
| 11.10.8 | `android_signers`: 1 to 4 entries `{digest, class}` with distinct digests; an entry without a class, an unknown class, a duplicate digest, `development` in the production file and the bare-string form are each refused by the release build | `releasecfg.TestAndroidSigners`, `releasecfg.TestRefusals` (bare signer list), `releasecfg.FuzzParse` |
| 11.10.8 | Production pins one entry, VettID's certificate, class `vettid`, with no placeholder; staging pins its signing certificate (`vettid`) and the automation certificate (`development`); the gate refuses production only for its release number | `releasecfg.TestCommittedSigners`, `enclave.TestReleaseConfigAndroidPackage` (per channel build) |
| 11.7, 11.7.1 | Recording: the digest is stored in the device binding in the sealed header at enrollment, at a transfer's `hs.init` and at a recovery's register | `devattest.TestAndroidSigner` (the binding), `e2e.TestSignerBoundAtEnrollment`, `e2e.TestTransferSigner`, `e2e.TestRecoverySigner` |
| 11.3, 11.7.1 | Enrollment binds and audits `device.signer_bound` (`ref` = the class) | `e2e.TestSignerBoundAtEnrollment` |
| 10.3, 11.7.1 | `device.list` carries `signer{class, digest}` on the app's entry only, for an Android app with a recorded signer; not for iOS, a desktop, a recovering app or an unbound vault; the header's binding is the one reported | `vault.TestDeviceListSigner`, `e2e.TestSignerBoundAtEnrollment` |
| 11.4, 11.7.1 | Unlock and a release-update approval with a bound signer the running release pins: unchanged | `e2e.TestSignerBoundAtEnrollment`, the existing unlock and release tests (`enclave.TestEnrollUnlock`, `enclave.TestReleaseMove`, `e2e.TestAltchanReleaseUpdates`) |
| 11.4, 11.7.1, 11.9 | A bound signer the release does not pin (the same vault moved to an image whose configuration omits it): `signer_refused`, sealed and sized as any result, also at the confirming unlock of the move and for an unlock carrying an approval | `e2e.TestSignerRefused`, `vault.TestSignerRefusedAtUnlock`, `devattest.TestAndroidSigner` (CheckSigner) |
| 11.7.1 | The refusal is decided before the PIN and is not a PIN failure: the backoff counters are unchanged (wrong PINs, a running backoff) | `vault.TestSignerRefusedAtUnlock`, `e2e.TestSignerRefused` |
| 11.7.1 | No clone alarm, no host alarm, nothing reported to the host | `vault.TestSignerRefusedAtUnlock`, `e2e.TestSignerRefused` |
| 11.7.1 | One header-log entry per 24 hours; `device.signer_refused` (`ref` = `unpinned` or `unbound`, no `device_id`) in the audit log after a later successful unlock; not in the feed | `vault.TestSignerRefusedAtUnlock`, `e2e.TestSignerRefused`, `e2e.TestUnboundVaultBindsByChain` |
| 11.7.1 | A wrong `device_ik` signature or a wrong assertion never yields `signer_refused` | `vault.TestSignerRefusedAtUnlock`, `e2e.TestSignerRefused` |
| 6.7.1, 11.7.1 | Transfer to the same signer: `device.transfer.pending` carries `signer` and `signer_changed: false`; no `signer` needed in the approval; no `device.signer_changed` | `vault.TestTransferSameSigner`, `e2e.TestTransferSigner` |
| 6.7.1, 11.7.1 | Transfer to another pinned signer: `signer_changed: true`; an approval without `signer`, or with the wrong class, is `signer_unconfirmed` before the UTK is spent or the PIN tried (UTK unspent, PIN backoff untouched, no owner check failed, the transfer stays open) | `credential.TestTransferSignerConfirmation`, `vault.TestTransferChangesSigner`, `e2e.TestTransferSigner` |
| 6.7.1, 11.7.1 | With the confirmation the transfer completes, the binding is the new signer in that flush, and `device.signer_changed` (`device_id` = the new app, `ref` = `<old class>:<new class>`) is audited and put in the feed with priority `high`; neither carries a digest | `vault.TestTransferChangesSigner`, `vault.TestSignerChangedFromUnpinned`, `e2e.TestTransferSigner` |
| 6.7.1, 11.7.1 | Transfer to an unpinned signer: dropped as before (`device.transfer.attestation_failed`) | `e2e.TestTransferSigner` |
| 11.7.1 | `signer_changed` is false when the vault has no recorded signer; the transfer then binds and audits `device.signer_bound` | `vault.TestTransferFromUnboundVault`, `e2e.TestUnboundVaultOnStaging` |
| 11.11.3, 11.11.5, 11.7.1 | Recovery to another pinned signer: the binding is unchanged after register, after a cancel and after an expiry; it moves when `credential.recover` succeeds, audited and in the feed; the old app's key no longer unlocks | `e2e.TestRecoverySigner` |
| 11.7, 11.7.1 | `device_assertion` MAY carry `chain` (1 to 10 certificates); absent stays absent, a malformed one rejects the object, unknown members are ignored; it is not part of the signing string | `altchan.TestDeviceAssertionChain`, `altchan.FuzzParseDeviceAssertion` |
| 11.7.1 | A header written before 0.27.0: with a valid `chain`, bound (challenge and validity not checked again; leaf key and serials must equal the stored ones) and audited `device.signer_bound` | `devattest.TestBindSigner`, `vault.TestSignerBoundAtUnlock`, `e2e.TestUnboundVaultBindsByChain`, `devattest.FuzzBindSigner` |
| 11.7.1 | With a chain naming another package than the channel's, for another key, with other serials, with two digests or with an unpinned digest: `attestation` | `devattest.TestBindSigner`, `e2e.TestUnboundVaultBindsByChain` |
| 11.7.1 | Without a chain: `signer_refused` on a production-channel build, an unbound unlock on a staging-channel build at S10; a bound key ignores `chain` | `devattest.TestBindSigner` (CheckSigner), `e2e.TestUnboundVaultBindsByChain`, `e2e.TestUnboundVaultOnStaging`, `e2e.TestSignerRefused` (a bound key with a chain) |
| 11.7.1 | Staging accepts unbound vaults up to S10 and refuses them from the release after it; no production release accepts them, and no member of a channel file can turn it on | `releasecfg.TestAcceptsUnbound`, `releasecfg.TestCommittedSigners`, `enclave.TestReleaseConfigAndroidPackage` |
| 11.7.1, 11.10.8 | With the staging application id: a vault enrolled under the old package unlocks unbound on S10 without a chain, cannot bind by chain (the chain names the old package), and the transfer to the new build binds it | `e2e.TestUnboundVaultOnStaging`, `e2e.TestUnboundVaultBindsByChain`, `e2e.TestAndroidPackagePerChannel` |
| 15 item 35 | The unlock request fits its 12,288 bytes with a `chain` and a `release_update` together | `enclave.TestUnlockWithChainAndReleaseUpdateFits` (about 8,100 bytes of chain DER fit; more than enrollment or a recovery's register, which carried the chain first) |
| 3.3, 11.10.4 | A vault sealed by the previous staging release (S9: its header and state members only) loads, keeps working, moves to the next release and binds; its optional features' entries are loaded by an image that registers them and carried unchanged by one that does not | `vault.TestVaultSealedByS9`; the `compat` workflow's row runs the previous commit's binaries against this tree |
| 11.7.1 | On real phones (staging): a Pixel on stock Android and one on GrapheneOS enroll and show the expected class; a vault enrolled on the previous staging release binds by `chain` at its first unlock; the attestation of the app as built reports exactly one digest | not in CI: staging release S10 on the test phones |

## Key attestation chain rules, and a refusal on a rolled-back header (§11.4, §11.7, §11.7.1; no spec change)

§11.7 says the enclave "verifies the chain up to a Google hardware
attestation root pinned in the image, then checks the attestation
extension". Verifying signatures alone is not that: a Keystore key that
was itself genuinely attested can sign a further certificate, for any key
and with any extension. `devattest.checkAndroidChain` holds the rules,
the same for an attestation (`VerifyAttest`: enrollment, a transfer's
`hs.init`, a recovery's register) and for a chain re-sent at unlock
(`BindSigner`). The rules were checked against key attestation chains of
real devices (the test data of Google's `android/keyattestation`
verifier: Pixel 2 to Pixel 10, a Sony Xperia 10 III; factory-provisioned
and remotely provisioned; RSA and EC roots), which are not in this
repository; `devattest.TestRealAndroidChains` runs them, and the chains
of the test phones, when they are put in `vms/devattest/testdata/real`.

| § | Requirement | Test(s) |
|---|---|---|
| 11.7 | The attestation extension is read from the leaf, and no other certificate of the chain may carry it: a certificate for another key issued by an attested Keystore key (directly, or through a certificate that claims to be a CA) is refused whatever its extension says, at an attestation and at a bind by chain; so are the attest-key shape (an attested CA above the leaf) and a leaf without the extension above an attested key | `devattest.TestAndroidChainExtendedBelowAttestedKey`, `devattest.TestAndroidChainRules`, `devattest.FuzzAndroidChain`, `devattest.FuzzBindSigner` |
| 11.7 | Every certificate above the device's attestation certificate (`chain[2]` and up) is a CA: basicConstraints cA, and keyCertSign where it has a keyUsage. A non-CA certificate, one without basicConstraints and a CA without keyCertSign are refused there | `devattest.TestAndroidChainRules` |
| 11.7 | No CA certificate has more certificates between it and the leaf than its pathLenConstraint (an intermediate's, the root's) | `devattest.TestAndroidChainRules` |
| 11.7 | Real chain shapes stay accepted: factory-provisioned (root, intermediate, attestation certificate, leaf), remotely provisioned (two intermediates, and the provisioning-information extension 1.3.6.1.4.1.11129.2.1.30 on the attestation certificate), an attestation certificate with pathLen 0, and the older devices' attestation certificate that says cA FALSE with digitalSignature only (so `chain[1]` is not required to be a CA, and the standard library's path validation, which refuses it, is not used) | `devattest.TestAndroidChainRules`, `devattest.TestRealAndroidChains` (skipped without files), the existing `devattest.TestAndroid*`, `e2e` and `integration` tests on the test PKI |
| 11.7 | Unchanged: order (each certificate signed by the next), the last a pinned root by public key and self-signed, 1 to 10 certificates, validity at an attestation and not at a bind by chain. A duplicated or inserted certificate, another root, the pinned key certified by another root are refused; the pinned root repeated at the end still verifies | `devattest.TestAndroidChainRules`, `devattest.TestAndroidRejects`, `devattest.TestBindSigner` |
| 11.7.1 | A vault whose stored binding came from such an extended chain (accepted by a release before this rule) is not bound by that chain: `attestation`; without a chain it is `signer_refused` (`unbound`) on a production build. It is recovered or transferred with a genuine attestation | `devattest.TestAndroidChainExtendedBelowAttestedKey` (BindSigner), `e2e.TestUnboundVaultBindsByChain` (the answers) |
| 11.7 | iOS: the App Attest chain is validated by the standard library from the credential certificate (CA flags, path length), and the nonce is read from that certificate: a credential certificate issued by another attested credential key is refused | `devattest.TestIOSChainExtendedBelowAttestedKey` |
| 11.4, 11.7.1 | `signer_refused` on a header older than the app's `min_header_seq`: still answered `signer_refused` (decided before the rollback check), but the header is not written, so the refusal's log entry cannot store a rolled-back header forward; with a current header the entry is written as before | `vault.TestSignerRefusedRolledBackHeader`, `vault.TestSignerRefusedAtUnlock` |
| 13.6 | Fuzzed: the chain verifier with certificates replaced, inserted and appended at every position (whatever is accepted has the extension on the leaf only, the leaf's key bound, CAs above the attestation certificate); `BindSigner`; the previous-release channel file reader | `devattest.FuzzAndroidChain`, `devattest.FuzzBindSigner`, `releasecfg.FuzzPreviousFeatures` |

## Waits of the collect loop and the shared connections (§12.2, §12.2.1; 0.27.2)

VAULT-MESSAGING 0.27.2 wrote down, as built, phase 1 of
VAULT-RELAY-SCALING (this repository's #66). Package paths:
`enclave/egress` (the pool), `enclave/supervisor`, `parent`, `vault`.
The pool's tests shorten the times they wait for (the drain time, the
stall time, the ping) where the spec's values would make a test take
minutes; where a row says "the value itself", the number in the spec is
a constant in the code that no test asserts.

| § | Requirement | Test(s) |
|---|---|---|
| 12.2 | Vaults on one host MUST NOT poll in step: each long-poll asks for a random whole number of seconds from 20 to 25 | `vault.TestPollWaitSpread` (every value from 20 to 25 occurs, none outside; a collector with its own wait does not vary it). That the release's collector is built with the spread (`vault/relay.go`, `ClientRelay.Collector`) is not asserted by a test |
| 12.2 | The first poll after an unlock is sent after a random 0 to 1 s | **not covered by a test** (`vault.Manager.Run`, `firstPollSpread`; tests set `PollWait` and poll at once) |
| 12.2 | After a failed poll the next is sent after a random 0.5 to 1.5 s | `vault.TestRetryWait` (0 and 1 refusals: 0.5 to 1.5 s, at least 100 different waits in 200) |
| 12.2 | While the relay refuses the poll, the wait doubles from 1 s to 15 s, each spread by half either way (at most about 22 s) | `vault.TestRetryWait` (2, 4, 6 and 1,000 refusals in a row) |
| 12.2 | Only `mailbox_unknown` and `timestamp_stale` count as a refusal; a poll that succeeds, or fails for any other reason, starts the wait again at 1 s | **not covered by a test** (the counting in `vault.Manager.Run`; `TestRetryWait` tests the wait for a given count only) |
| 12.2.1 | Fill first: a request takes a stream on the first connection that has one free, not the newest or the emptiest | `egress.TestFillFirst` |
| 12.2.1 | Another connection is opened only when every stream of every connection is in use; one connection carries every vault until its streams are in use (128 at the relay's load balancer) | `egress.TestGrowthAtStreamLimit` (900 held long-polls at 128 streams on exactly 8 connections, none waiting; quick requests beside them open none), `egress.TestSharedHTTP2` |
| 12.2.1 | Connections are opened one at a time | `egress.TestDialFails` (one dial for 200 requests waiting together; never two dials at once), `egress.TestSharedHTTP2` |
| 12.2.1 | The enclave MUST NOT let the host or the relay choose the number of connections: at most 16 per host | `egress.TestMaxConns` (a bound of 3: no further connection, the rest wait), `egress.TestMassReconnect` (the default bound: 900 long-polls on 8, none refused). The value itself (`egress.DefaultMaxConns` = 16) is not asserted |
| 12.2.1 | No further connection while a connection of that host announces fewer than 32 concurrent streams | `egress.TestMinStreams` (a host announcing 8 gets one connection for 30 requests, with the default of 32), `egress.TestOneStream` |
| 12.2.1 | …or has not announced a limit yet: a new connection carries one request until its limit is known, fewer than 32 after one second | `egress.TestLateSettings` (a limit of 1 announced after the wait: one connection, fewer than 32 requests on it), `egress.TestLateSettingsBelowAssumed` (the waiting requests are woken), `egress.TestStreamLimitIsRead` (the limit is read at 1, 31, 32, 100, 128 and 250; two requests on a new connection do not wait) |
| 12.2.1 | Connections are opened at no more than 2 a second after a burst of 32 (twice the bound), failed dials included | `egress.TestDialRate` (a host that closes every connection: twice the bound, then 2 a second), `egress.TestDialFails` (failed dials draw on the rate), `egress.TestMassReconnect` (three losses of every connection in a row recover within the rate) |
| 12.2.1 | At a bound a request waits for a stream until its own deadline and then fails; waits and refusals are counted | `egress.TestMaxConns` (the waiting requests, the request whose deadline ends, `RefusedMaxConns`, `WaitMax`), `egress.TestMinStreams` (`RefusedMinStreams`), `egress.TestTick` (a waiting request looks again every second) |
| 12.2.1 | …the oldest first | **not covered by a test** (the pool's queue of waiting requests; no test asserts the order) |
| 12.2.1 | …75 s for a relay request, 15 s for a push request | **the values are not covered by a test** (`enclave/supervisor/prochost.go`, `vproc.http` and `vproc.push`); that a request whose time ends is answered an error is `supervisor.TestVaultEgressLimit` |
| 12.2.1 | A dial that fails fails the request that started it and every request that was waiting when it started; later ones dial again | `egress.TestDialFails` |
| 12.2.1 | A connection the host is closing (GOAWAY) does not count toward the bound while its requests end; at most as many again; requests on it still end | `egress.TestDrainingDoesNotCount` |
| 12.2.1 | It is closed after 30 s; only 16 (the bound) are let off the count in any 5 minutes, further ones count while they close | `egress.TestDrainingIsBounded` (with a drain time of 500 ms: twice the bound once, the bound from then on, each closed after the drain time). The values themselves (30 s, 5 minutes) are not asserted |
| 12.2.1 | A connection is pinged after 15 s without a frame and closed if the ping is not answered within 10 s | `egress.TestSilentConnections` (asserts the configured 15 s and 10 s, then runs with 300 ms: the silent connections are closed, their requests fail, the pool serves again) |
| 12.2.1 | A connection that holds requests and has answered none for 90 s is closed whatever else it does | `egress.TestStalledConnections` (with a stall time of 1 s; requests beside the stalled connections are answered). The value itself (90 s) is not asserted |
| 12.2.1 | One re-send of a request the host did not process: the connection stopped taking requests before it was sent, the GOAWAY names it, or the stream was refused; only when its body can be sent again; any other failure goes back to the vault process | `egress.TestUnprocessedIsResent` (all three cases, twice refused is an error, a body that cannot be sent again is not re-sent), `egress.TestReconnect` (requests on a lost connection fail) |
| 12.2.1 | Per vault: at most 8 relay and push requests in flight, further ones wait within their own deadline; one vault process cannot take the shared streams from the others | `supervisor.TestVaultEgressLimit` (relay requests: 8 in flight of 20, the rest answered as the first end, one whose time ends is refused and not counted as the relay's failure, another vault is not held up). Push requests take the same places (`vproc.push`) but no test sends one at the limit |
| 12.2.1 | Counts, for the whole instance only: connections (open, opened), the announced stream limit, requests in flight and waiting, the longest wait, requests without an answer, requests that waited at a bound; nothing in it names a vault, a mailbox or an address | `supervisor.TestRelayStats` (the reply is exactly the nine named counts; a failed request is counted, one its vault process gave up is not), `egress.TestMaxConns`, `egress.TestGrowthAtStreamLimit` (the pool's own counts) |
| 12.2.1 | The parent may ask for them; the answer is a snapshot at most one second old, and asking changes nothing | `supervisor.TestRelayStats` (asked again at once: the same answer; a second later: the new count), `egress.TestMaxConns` (reading the counts twice changes nothing) |
| 12.2.1 | The parent publishes them as metrics (VAULT-RELEASES §8.7): by instance only, counters as their increase, a name the parent does not know never reaches the record | `parent.TestMetrics` |
| 12.2.1 | A front end that announces exactly 100 streams is trusted only once it has answered a request | `egress.TestStreamLimitIsRead` (100 announced: read as 100 after an answer, and the first requests do not wait). That such a connection carries 1, then fewer than 32, requests until its first answer is not asserted for a host whose first requests are all held |
| 12.2.1 | The relay's front end MUST NOT be changed to one that announces exactly 100 | not in CI: a requirement on the relay's deployment (VAULT-RELAY-SCALING §10.4), not on this repository |
| 12.2.1 | The rules hold for each HTTP/2 host of the allowlist separately; KMS connections (HTTP/1.1) are not shared this way | **not covered by a test of its own** (one pool per host by construction, `egress.New`; every pool test uses one host, and none runs an HTTP/1.1 host beside an HTTP/2 one) |

## A connected but silent parent (§12.3 "Parent unreachable"; VAULT-HOST-PROTOCOL §3.4, §4.3, §13 point 1; spec text pending)

Owner decision of 2026-10-12 (H3 of vettid.org #236), for staging
release S11. VAULT-MESSAGING 0.27.4 §12.3 and VAULT-HOST-PROTOCOL 0.1.2
§4.3 still describe the rule as it was built before (120 s without a
connection) and announce this one; the rows below are the rule as built
here, to be matched against the spec text when it is written
(docs/V3-NOTES.md, "Enclave ↔ parent", lists the edits). Package paths:
`enclave/supervisor`, `internal/hostproto`. The supervisor's tests run
the check that `maintain` makes every 10 s (`checkParent`) on a clock of
their own, against a stand-in for the vault processes, or against
`procHost` with processes that stand for vault processes (they answer
the lock as one does: a store write through the link, then the answer);
no test runs it with a real vault process and a real parent that goes
silent.

| § | Requirement | Test(s) |
|---|---|---|
| 12.3 | Every vault is locked once 120 s have passed without a `Ping` from the parent, whether the control connection is open or not; not before | `supervisor.TestSilentParentLocks` (connected and silent: nothing at 120 s, locked at the first check after it, 130 s), `supervisor.TestLostConnectionLocks` (no connection: locked within 120 s of the loss) |
| 12.3 | A `Ping` is counted when the enclave reads it, whatever it answers; with pings arriving nothing is locked | `supervisor.TestPingsKeepVaults` (every 20 s for a day, then every 110 s for an hour; the stand-in's instance has not started, so each ping is answered `error` and counts) |
| 12.3 | A new connection does not start the count again: only a `Ping` does | `supervisor.TestReconnectWithoutPings` (a connection every 30 s, no ping: locked 120 s after the last ping), `supervisor.TestReconnectWithPings` |
| 12.3 | The time counts only while a vault runs: a vault unlocked before the parent's first `Ping` (after the enclave's start, a new session, or a lock of every vault) has the whole 120 s | `supervisor.TestBeforeTheFirstPing` (five minutes without a parent, an unlock before the first ping; a parent that never pings: locked 120 s after the unlock), `supervisor.TestSilentParentLocks` (a vault unlocked after every vault was locked) |
| 12.3 | Once the parent is found unreachable no call is made to it until its next `Ping`, whatever connection there is; a connection it has is closed; a hello changes nothing | `supervisor.TestSilentParentThatReconnects` (60 vault processes, a parent that takes every new connection and answers no store request: every final flush fails at once, a call on the new connection fails until a ping, and is sent after it), `supervisor.TestSilentParentLocks` (the connection has ended) |
| 12.3 | Every vault has locked or been killed within 10 s of that check, however many run | `supervisor.TestSilentParentThatReconnects` (60 in well under 10 s), `supervisor.TestLockAllWithinKills` (20 processes, half of which never answer the lock, with a limit of 500 ms: all gone at the limit). The value itself (10 s) is asserted only as the bound of the first |
| 12.3 | A failed final flush loses nothing stored and is not a split brain | by construction (`link.call` fails before anything is sent; `vault.persist` returns `ErrSplitBrain` for a conflict only); `vault.TestSplitBrainZeroizes` is the conflict. **No test locks a real vault with a failing store** |
| 12.3 | A parent found unreachable stays so until its `Ping`, also while no vault runs; a vault that turns up under it is locked by the next check | `supervisor.TestSilentParentLocks` (checks with no vault running, then a new connection: a call still fails; a vault is locked 10 s later, not 120 s; after a ping a vault has 120 s) |
| VAULT-HOST-PROTOCOL 7.3 | The vaults ended while the parent was unreachable are told to it (`Stopped`: `locked`, `split_brain`, `error` for a killed one) when its next `Ping` is read, once, and not before | `supervisor.TestStoppedVaultsAreTold`, `supervisor.TestSilentParentThatReconnects` (60, after the ping), `supervisor.TestLockAllWithinKills` (which were killed). **Not covered:** that the parent then drops the vault and releases its lease (`Parent.notify`; `parent.TestStoppedLogLevels` covers the log level only) |
| VAULT-HOST-PROTOCOL 7.3 | The `Ping` is counted at once; the reports are queued before the parent is reachable again (no call before them), and a full queue does not delay the count | `supervisor.TestPingOrder` |
| VAULT-HOST-PROTOCOL 7.3 | A report is told only when written to the link's connection; one that could not be is kept, the parent stays unreachable, and the next connection's `Ping` tells it; a report whose vault runs again is dropped | `supervisor.TestPingOnDyingConnection` (the connection ended before the ping, and under it), `supervisor.TestReportOfAVaultThatRunsAgain`, `hostproto.TestEndedConnectionTakesNothing` (an ended connection takes no frame though its queue has room; a failed write is not flushed) |
| VAULT-HOST-PROTOCOL 7.3, 11.1 | A `Stopped` for a vault whose enroll or unlock is under way does not release the lease that request took | `parent.TestStoppedDuringUnlockKeepsLease` |
| 11.1 | After a failed renewal the next is tried soon (5 s), and at the usual interval again after one that succeeds | `parent.TestRenewalRetriesSoon` (with 50 ms against an interval of 1 s). The value itself is not asserted |
| 11.1, 12.3 | A lease renewal that gets no answer is given up (10 s, and not past the moment the first lease is lost); the lease is lost before it ends and the enclave told, for every vault, with one call to the table in a pass | `parent.TestLeaseLostWhenTheTableHangs` (40 vaults, a table that never answers, shortened times: every vault told after the margin and before its lease ends, fewer calls than vaults, the pings going on). The values themselves (10 s, 5 s, 15 s) are not asserted. **Not covered:** hundreds of vaults whose locks are slow (`LeaseLost` goes one vault at a time) |
| 12.3 | A warning at half the time, once for each time the count started, naming no vault | `supervisor.TestWarnsBeforeTheLock` (also: no other record is sent) |
| VAULT-HOST-PROTOCOL 3.4 | Time in which the enclave's own reader waits at 128 requests in flight is not counted as the parent's silence, up to 120 s of it; a `Ping` that waited in the socket is read when the reader goes on | `supervisor.TestReaderAtLimitIsNotSilence`, `hostproto.TestReaderAtLimit` (nothing is read while the reader waits), `hostproto.TestReaderAtLimitClosed` |
| VAULT-HOST-PROTOCOL 3.4 | A frame to the parent that is not written within 60 s ends the connection; senders that waited are released | `hostproto.TestWriteTimeout` (with 300 ms), `hostproto.TestWriteTimeoutSlowReader` (a slow reader is not cut off: the time is per frame), `supervisor.TestParentStopsReading` (asserts the 60 s of the control connection, then runs with 500 ms) |
| VAULT-HOST-PROTOCOL 3.4, 7.4 | A log record never waits for the parent: one that does not fit the outgoing queue is dropped and counted, and the count is logged | `supervisor.TestLoggingNeverWaits` (a connection without a write timeout to a parent that does not read: once it holds its 257 frames, 1,001 records return at once and are counted; the count is kept while its own record is dropped or there is no connection, and told to the next parent) |
| VAULT-HOST-PROTOCOL 3.4, 7.1–7.3 | A descriptor, a lifecycle event and a stopped vault are not dropped while the connection lives: they wait for the queue, at most until the write time ends the connection | `supervisor.TestParentStopsReading` (a lifecycle event waits, then returns when the connection ends); `Stopped` and `Descriptor` go the same way (`link.notify`) and have no test of their own |
| 12.3 | A registry write that hangs does not stop the parent's pings: it is given up after 10 s; the parent warns when its heartbeat is late | `parent.TestPingsGoOnWhenTheRegistryHangs` (with 150 ms: a ping at every tick past a table that never answers, each still followed by its write). The value itself (10 s) is not asserted |
| VAULT-HOST-PROTOCOL 3.4 | A connection that takes no write deadline is used all the same and says so once | `hostproto.TestWriteTimeoutRefused` |
| 12.3 | The parent sends `Ping` every 20 s (the S10 parent too) | **not covered by a test of the interval**: `parent.Config.Heartbeat` defaults to 20 s, and neither it nor `cmd/vault-parent -heartbeat` refuses a larger value; `parent.TestRegistryAndStore` runs the heartbeat at 100 ms |

## Responses are never silence; `message.list` pages; volatile reads (§8.1, §8.2, §10.1, §10.5.2, §15 item 38; 0.32.0)

The rules of 0.32.0 that apply to every message ("0.32.0", not
"0.32.0, release A"), for staging release 13. The attachments of
release A (§10.5.1, `message.attachment.*`) are not built here.

| § | Requirement | Test(s) |
|---|---|---|
| 8.1, 10.1 | A response that cannot be sealed within §5.5's bound (padded inner plaintext > 245,760 bytes, checked with the widest `seq` so that a retransmission fits too) is replaced by the error `response_too_large` (no body), cached and sent instead, never silence; on every response path: cached answers, volatile answers (sent, not cached), and a cached answer of an older release resent on a retransmission | `vault.TestResponseTooLarge`, `vault.TestResponseTooLargeAtMaxSeq`, `vault.TestResendCachedTooLarge` |
| 8.2, 10.5.2 | `message.list` and `message.get` are volatile: never cached, never in vault state, a retransmission executed again; an agent's answer (a LEASH grant) is volatile too | `messaging.TestListGetVolatile`, `vault.TestVolatileHeldAndAgents`, `e2e.TestMessageListPages` |
| 8.2 | No answer to a volatile request is cached, errors included (a refusal, the held-approvals limit, `denied`, `approval_timeout`), so no retransmission is answered from a cache. A volatile request referred for an app's approval is held: a retransmission while it waits is a duplicate, and once answered its id is forgotten. `message.list` and `message.get` have no desktop step-up, so in practice only an agent's LEASH referral holds them; the desktop path is exercised with a test type | `vault.TestVolatileErrorsNotCached` (refused, then held under the same id: one answer, after the approval; denied; timed out; the limit), `vault.TestVolatileHeldAndAgents` (`test.bigv`: a desktop's step-up and an agent's referral) |
| 10.5.2 | `message.list{before?}`: newest first from the position `before` (arrival order, exclusive) or the newest, at most `limit` and at most 131,072 bytes of `body`, at least one message when one is older; oldest first; `next_before` = its oldest message's id, only when older messages remain; a cursor not held (unknown, deleted, another conversation's) is `not_found` | `messaging.TestListPagesByBytes`, `messaging.TestListAtLeastOne`, `messaging.TestListCursor`, `e2e.TestMessageListPages` |
| 8.1, 15 item 38 | The other lists against §5.5: `item.list` pages by bytes (0.21.0); `audit.list` fits (about 216 KB at most); `feed.list` (guide items) and `connection.list` (stored profiles) can exceed it and are answered `response_too_large` until the specification pages them | `vault.TestResponseTooLarge` (the rule); no paging test, by design |

## Message attachments (§1.2, §3.3, §5.5, §7.1–§7.3, §8.2, §8.6, §10.1, §10.2, §10.5, §10.5.1, §10.9, §10.11, §12.5, §16; 0.32.0, release A)

The attachments of release A, for staging release 14, with
VAULT-HOST-PROTOCOL 0.1.9 (the two key rows, P15) and RELAY-PROTOCOL
0.9.2–0.9.4 (the blob API, `owner_device`, the per-sender share, the
checks before the body, `POST /v1/blobs`). e2e tests run two vaults and
their apps against the real relay (vettid-relay cc3ce89); a vault's
windows run on an injected clock (`vault.Options.AttachClock`) while
messages keep the real time.

| § | Requirement | Test(s) |
|---|---|---|
| 5.5, 16 | The blob: `ver 0x01 \|\| nonce \|\| XChaCha20-Poly1305(key, nonce, "vettid/vms/2/blob" \|\| 0x00 \|\| ver, framed)`, framed = `uint32be(len) \|\| content \|\| zeros` to Padmé(4 + len); refused: an unknown `ver` (before decryption), a framed length other than Padmé(4 + len), `len` beyond it, non-zero padding; `sha256` checked in constant time before decryption, `size` against `len` after. `blob.json` reproduces §16's libsodium values byte for byte, and its blobs that MUST fail fail with the right error | `vectors.TestBlobVectors` (also Padmé against its definition for every length below 2^16, and the reference numbers 8,257,532 / 8,257,577 / 34,857), `vectors.TestVectorsUpToDate` (`-tags vmsvectors`: regenerated through `envelope.SealBlobWithKey` with the nonce scripted), `envelope.TestBlobRoundTrip`, `attwire.FuzzUnframe` |
| 10.5.1, 16 | The at-rest object: the blob's framing under `k_att`, AAD `"vettid/vms/2/att" \|\| 0x00 \|\| vault_id \|\| 0x00 \|\| att_id \|\| 0x00 \|\| part \|\| 0x00 \|\| ver` with the upper-case ULID; keys `vaults/<id>/att/<lowercase att_id>` and `.t`. `attachment.json` (parts `c` and `t`) reproduces §16's part `c` | `vectors.TestAttachmentVectors`, `attwire.TestObjectRoundTrip` (another part, vault or attachment does not open it) |
| 10.5.1 | Sniffing: JPEG, PNG, WebP by their first bytes only; nothing else is a photo | `attwire.TestSniff`, `e2e.TestAttachmentMaliciousPeer` (a GIF blob is refused, type) |
| 10.5.1 | The device send and peer views are parsed strictly: `size` 1 to `attachment_max_bytes`, `width`/`height` 1 to 8,192, a thumbnail of 1 to 32,768 decoded bytes that sniffs as a photo, `blob` and `expires_at` together, the blob's `size` equal to the view's | `attwire.TestParseDeviceSend`, `attwire.TestParsePeerView`, `attwire.FuzzParsePeerView` |
| 1.2, 7.1 | Every standing token of the vault's app carries `owner_device` (owner decision of 2026-10-15: only the app sends attachments); no other token does (a desktop's, an agent's, a connection's standing, reconnect, request tokens); a vault from before release A re-mints its app's standing token once at its first unlock under it | `vault.TestDeviceTokensOwnerDevice`, `vault.TestVaultSealedByS9` (an S9-shaped vault without the marker) |
| 7.2 | A connection's `relay.token.refresh` while the latest standing token issued to it has 3 days or more left (a quota refresh, whatever token the request came under): a fresh token at most once per 24 hours, the old ones denylisted; otherwise `too_soon {allowed_after}`; near the latest token's end, a refresh at most once an hour | `vault.TestTokenRefreshAfterQuota`. **Not covered:** the vault's own retry after a token quota (`attAskToken`): no test relay answers a token quota with `quota: token` |
| 10.5, 10.5.1 | A photo from the phone goes to its vault (stored, then sent as a fresh blob), to the connection's vault (stored), and to each phone on demand; the caption travels with it; `message.send` answers `{message_id, sent_at, att_id}`; progress as `sync.event{message.attachment}`; device views carry the sniffed `mime` once stored and never a blob id or key; `message.get` has no `thumb`, `part: "thumb"` returns it; `vault.status` counts the store | `e2e.TestAttachmentPhotoEndToEnd`, `vault.TestStatusAttachments` (bytes counted as for `attachment_storage`; not to agents) |
| 5.5, 10.5.1 | Every blob is deleted by its recipient once fetched, good or bad, and a blob nobody will fetch is deleted (a refused send, an unasked upload, an orphan older than 24 hours once the collect loop drained the mailbox) | `e2e.TestAttachmentPhotoEndToEnd`, `e2e.TestAttachmentMaliciousPeer`, `e2e.TestAttachmentQuotas` (refused sends), `e2e.TestAttachmentCrashBetweenFlushes` (the orphan purge) |
| 10.5.1 | Receiving: a blob whose sha256, size, framing or key is wrong is refused and deleted; after `attachment_reoffers` + 1 failed fetches the attachment is failed (bad); views over the limits are dropped and audited (`drop.attachment_malformed`); a thumbnail or a kind that is not a photo is refused (type), with the message stored | `e2e.TestAttachmentMaliciousPeer` |
| 10.5.1 | Missing: one attachment of a connection asked for at a time, at most once per `missing_backoff` (10 minutes doubling to 24 hours, the attachment's own), in turn after `missing_turn` | `e2e.TestAttachmentMissingTurns`, `e2e.TestAttachmentMaliciousPeer` (the backoff between rounds). **Not covered:** the room check against the relay's `max_bytes - used_bytes` with a full mailbox |
| 10.5.1 | Delivery to the peer: fresh uploads on `missing` at most `attachment_reoffers` times, within `peer_reuploads` (over it, kept and served when the rolling budget allows), then `withdrawn{limit}` and failed (missing); a missing for a message_id never sent is ignored; for a deleted one, `withdrawn{deleted}` | `e2e.TestAttachmentEndlessMissing`, `e2e.TestAttachmentDeletion` |
| 10.5.1 | A recipient locked past the blob's TTL still gets the photo: the sender fails it (unconfirmed, audited, feed) after `attachment_window`, goes back to sending on the recipient's `missing` within `missing_window`, and uploads a fresh blob | `e2e.TestAttachmentLockedRecipientReoffer` |
| 5.3, 10.5.1 | A peer without release A answers `message.attachment.deliver` with `unsupported_type`: failed (unsupported), audited, with the feed item | `vault.TestAttachmentUnsupportedPeer` |
| 10.5.1 | Owner decision of 2026-10-15: a received attachment's declared size holds room only while its fetch is in progress; one waiting for an upload holds none; an upload is checked against `attachment_storage` and `peer_storage` when it arrives and before its fetch starts, and refused (full) if it does not fit | `e2e.TestAttachmentReservations` (four connections declaring 8 MiB that never upload do not block the owner's photos; an upload that no longer fits is refused) |
| 10.5.1 | A damaged object is read again only with the backoff and, after 3 reads, the attachment fails (bad, audited); every error path of the runner schedules a retry; no transfer of one attachment starts within a second of its last | `e2e.TestAttachmentCorruptObject` (reads counted) |
| 10.5.1 | An outgoing attachment owed a fresh upload fails (unconfirmed) when the peer's mailbox refused for good or past `missing_window`, never left owed | `vault.TestOwedAttachmentEnds` |
| 10.5.1, 12.4 | Zeroize wipes every `k_att`, blob key and held thumbnail; a dropped blob reference's key is wiped; each job wipes its copies (the jobs by construction) | `vault.TestZeroizeWipesAttachmentKeys` |
| 7.3, 10.5.1 | `peer_attachments` refuses with reason `rate` (`drop.attachment_rate`; the sender sees `refused:rate`); `peer_storage` and `attachment_storage` refuse with no reason (`full`: the sender sees `refused`, the recipient's member the feed item and `failed (full)`); the sender's own store answers `limit attachment_storage {max, size}` and deletes the blob | `e2e.TestAttachmentQuotas` (with `vault.Options.AttachLimits` lowered) |
| 10.5.1 | Write order: an entry in the same flush as its message; objects only after it, marked written with their versions in a later flush; a crash between an object's write and its flush, or between the content's flush and the blob's deletion, loses and duplicates nothing | `e2e.TestAttachmentCrashBetweenFlushes` (`thumb`, `prepared`) |
| 10.5.1 | Desktops neither send nor fetch (`forbidden`), get no `thumb` or `name`; the app's probe `message.attachment.get{}` is `bad_request`; `message.attachment.discard` deletes only the device's own upload | `e2e.TestAttachmentDesktop`, `messaging.TestAttachmentGetShape` |
| 10.5.1, 10.11 | Agents: `message.send` with an attachment is `forbidden` whatever the grants; a message with an attachment is its caption alone, one without a caption does not exist (list, paging, get, read, `before`) | `vault.TestAppOnlyFormsForbidden`, `messaging.TestAgentsDoNotSeeAttachments` |
| 3.6.3, 10.5.1 | Held: receiving and storing go on; the owner's `message.send` (its blob deleted), `message.attachment.get` and `.discard` are `owner_check_required`, after the shape check | `e2e.TestAttachmentHeldVault` |
| 10.5.1 | A removed connection's attachments in progress fail (removed); stored ones stay | `e2e.TestAttachmentConnectionRemoved` |
| 8.2 | `message.attachment.get` is volatile (both parts) | `messaging.TestListGetVolatile` |
| 10.5.1 | An owner fetch starts within 30 s (else `busy`) and is answered within 120 s of the request (`relay_error` after) | by construction (`OwnerFetchStart`, `attFetchBound`); **no test of the 120 s bound** |
| 10.5.1, 12.5 | `message.delete` erases both objects and then the entry; vault deletion waits (75 s) for the runner's store writes in flight, which a lock does not cancel (each bounded at 60 s), writes nothing once locked, and erases every object the index names (written ones at their recorded versions) before the state; every convergence path (an unlock, a recovery request) reports `deleted` | `e2e.TestAttachmentDeletion`, `vault.TestDeletionErasesAttachments`, `vault.TestDeletionWaitsForWrites`, `vault.TestDeletionWaitsForLateWrite` (a store that returns on cancellation while the write lands later), `vault.TestConvergenceReportsDeleted` |
| VAULT-HOST-PROTOCOL P15 | After its own conditional update marked the row deleted (whether or not the `vault_deleted` notice was written), the parent deletes every object under `vaults/<id>/att/`, retrying until the prefix is empty; nothing when the update was refused; it re-reads the row before each pass and stops if the vault is no longer deleted (a row that is gone does not stop it); the row records `att_sweep_pending` with the deletion, removed when done, and a parent's start resumes the sweeps left pending (the scan retried with a backoff); an enrollment of the same vault id clears the record | `parent.TestAttachmentSweepAfterDeleted`, `parent.TestAWSBackend` (LocalStack: the pending record, the row read, its removal). **Not covered:** `AWS.ListObjects` against S3 or LocalStack |
| 10.5.1 | Transfers and memory: at most 2 per vault and 2 waiting; the instance admits one only while available memory less `MemoryReserve` is at least 64 MiB × (in flight + 1), at most 4 until measured, nothing when memory reads 0; by priority (an owner's fetch first, honoured for one transfer of a process at a time; reuploads last), then first come; a process's admissions end with it, are reclaimed after 5 minutes, and an end that arrives before its request refuses it; the relay proxy carries blob bodies (downloads, uploads over 1 MiB) only within admitted transfers, one body per transfer at a time, on plain clean paths (no escapes, nothing `path.Clean` changes), and its client follows no redirect. An instance with many unlocked vaults and every transfer queued never reaches the memory-pressure threshold, and every transfer completes | `supervisor.TestTransferAdmissionKeepsReserve` (60 idle vaults, 120 transfers whose use grows to its peak after admission, against a memory model), `supervisor.TestTransferAdmissionOrder`, `supervisor.TestTransferThroughChannel`, `supervisor.TestTransferAdmissionUntrusted`, `supervisor.TestBlobBodiesNeedAdmission` (escaped and uncleaned blob paths), `supervisor.TestEgressClientNoRedirects`. **Not covered:** the budget measured on a release (the peak of one 8 MiB transfer through both processes); it is the constant 64 MiB |
| VAULT-HOST-PROTOCOL 9 | The relay proxy and the store channel carry a blob of `max_blob_bytes` (8 MiB) both ways and the largest attachment object (8,257,577 bytes), under the vault's own prefix only | `supervisor.TestAttachmentSizesThroughChannel` |

## Recovery rebuilt and the phone-held unlock secret (§11.14; VAULT-HOST-PROTOCOL 0.1.10 §8.1, P16–P18; VAULT-RELEASES 0.1.28; 0.33.0, release R)

Tests marked (tc) need `-tags vettid_testcost` (the recovery wrap at 8 MiB instead of 1 GiB; no release build can carry the tag).

| § | Requirement | Test(s) |
|---|---|---|
| 11.14.1, 16 | unlock_key, dek_wrap, dek_wrap_next, secret_check, the phone's secret; the §16 excerpts byte for byte, and the real Argon2id (64 MiB) in unlock.json | `recovery.TestStandInUnlock`, `vectors.TestReleaseRVectors` |
| 11.14.3, 16 | secrets encoding, K, wrap, opener, the wrong-pair tag; §16 excerpts byte for byte; the real 1 GiB Argon2id output in recovery.json (`VMS_HEAVY_VECTORS=1`), confirmed with libsodium | `recovery.TestStandInRecoveryWrap`, `recovery.TestStandInWrongTag`, `vectors.TestReleaseRVectors` |
| 11.14.6, 11.14.8, 16 | the open's and the request's signing strings (a cancel's last line empty) | `recovery.TestStandInSigningStrings` |
| VHP 8.1, 16 | counter object names keyed with counter_key | `recovery.TestStandInCounterNames` |
| 11.14.6 | W(k): 0, 1, 2, 4, 8, 16, 30, 30, 30; earliest next 1 … 121 units | `recovery.TestWaitSchedule`, `counter.TestScheduleOfWaits` |
| 11.14.7 | NFC before any use; 12 characters, not one repeated, not common, not the PIN, 10^10 guesses; the arming rule (1, 2, 5); the shared verdict file | `recovery.TestNormalizeNFC`, `recovery.TestPasswordVerdicts`, `recovery.TestArmingRules`, `credential.TestPasswordNFC`, `credential.TestCreateReleaseR` |
| 11.14.1 | an unlock without a 32-byte secret is bad_request before the PIN; a wrong secret is device_secret and not a PIN failure | `vault.TestUnlockNeedsThePhoneSecret` |
| 11.14.1 | state format 0x02 with the clear dek_version in the AAD; a 0x01 state and a version 1 header are refused | `vault.TestStateBlobBinding`, `vault.TestReleaseRRefusesEarlierFormats` |
| 11.14.1 | the PIN check of a running vault compares unlock keys; the header holds no DEK and no unlock key | `vault.TestHeaderContents`, `credential.TestOwnerCheck` |
| 11.14.2 | three writes; the run ended after step 1 (old pair drops `next`, new pair completes), after step 2 (only the new pair; step 3 at the unlock), a step 1 that fails or is "written" but not kept (retry, nothing changed), an older header after a change opens nothing newer | `vault.TestPINChangeCompletes`, `vault.TestPINChangeEndsAfterStep1`, `vault.TestPINChangeEndsAfterStep2`, `vault.TestStep1Dropped`, `vault.TestOldHeaderOpensNothingNewer` (tc) |
| 11.14.3 | arming only with a backup copy, a password meeting rules 1, 2, 5, an open generation; busy and an unreachable counter leave needs_check; the wrap opens only with the pair | `vault.TestArming`, `vault.TestArmingRefusals` (tc) |
| 11.14.3, 11.14.9 | PIN, password, reset: a new generation computed before the old is closed; counter_unavailable and busy change nothing; renew keeps the generation with a new opener | `vault.TestChangeRefusals`, `vault.TestPINChangeCompletes` (tc), `credential.TestPINChangeAndRenew`, `credential.TestPasswordChangeReleaseR` |
| 11.14.3 | backup off closes the generation (counter_unavailable when not confirmed); re-armed with unchanged secrets only without used attempts | `vault.TestBackupOffClosesTheGeneration` (tc) |
| 11.14.4, VHP 8.1, P17 | G2 one spent per attempt among many callers; G4 close is final; G8 failures count as used, unavailable only when nothing was used; a delete marker never yields a test; a stored write answered with an error; no Spend retried | `counter.TestManyEnclavesOneAttempt`, `counter.TestCloseIsFinal`, `counter.TestFailuresFallOnTheSafeSide`, `counter.TestDeleteMarkerNeverYieldsATest`, `counter.TestStoredWriteAnsweredWithAnError` |
| 11.14.5, 11.14.6 step 4b | the quiet period by the counter's clock; newest presence; presence written between spend and confirm uses the attempt untested; held status and spend answers; a success ends its wait without giving the attempt back; not_before | `counter.TestQuietPeriodAndPresence`, `counter.TestHeldAnswers`, `counter.TestSuccessEndsItsWait`, `counter.TestNotBefore` |
| 11.14.5 | presence at the owner check, retried every minute for an hour | `vault.TestPresence` (tc) |
| VHP 8.1, P16 | virtual-hosted name, x-amz-expected-bucket-owner signed, no redirects, keys only under recovery/v1/, pagination to the end | `s3counter.TestCounterOverHTTP`, `s3counter.TestRedirectNotFollowed` |
| 11.14.3, VHP 6.6 | one heavy-derivation permit, floor plus need, unknown memory refuses; heavy_kdf_free; a process may use one counter prefix | `supervisor.TestHeavyPermitAdmission`, `supervisor.TestRelayStats`, `supervisor.TestCounterPrefixPinned` |
| 11.14.6 | the open: counted before tested; wrong, wrong_again (not counted), the wait, success; the DEK replaced for the phone's secret, the phone's app key, the old app's secret refused | `vault.TestRecoveryOpenSchedule` (tc) |
| 11.14.6 | busy, counter_unavailable and quiet use nothing; stored_mismatch at step 2 uses nothing; not_armed | `vault.TestRecoveryOpenRefusals`, `vault.TestRecoveryOpenStoredMismatchAndNotArmed` (tc) |
| 11.11.3 | a registered phone is recorded in the recovery record only, never as an unlock key | `vault.TestRecoveryHeaderOps` |
| 11.14.8 | the member API's signature: pinned key, the message's members, 5 minutes, request_id not seen | `enclave.TestRecoverySignature` |
| 11.14.10 | the transfer's hs.init carries the secret; step 1 with the new phone in `next`; device.unlinked held and sent at the new phone's first unlock at that DEK version; the answer `{"unlink":"after_new_unlock"}` | `vault.TestTransfer`, `credential.TestTransfer` |
| 3.4 | one successor per key: a second successor suspends the connection; connection.rotation.resolve (holder only) | `vault.TestRotationConflict` |
| 11.10.8, 11.14.14 | the release constants; production wait unit ≥ 1 day, quiet ≥ 72 h, the channel's own bucket; a test on the production image; check-tcb refuses the test tag and a recovery test clock in release binaries | `releasecfg.TestRecoveryConstants`, `releasecfg.TestProductionImageRecoveryRules`, `make check-tcb` |
| 11.14.6 (0.34.0) | `attempt_used` in every result, ok or not: true for wrong, a spent attempt's retry and ok; false for wrong_again, wait from the first look, counter_unavailable, and a repeat through the `next` wrap; a result without it is malformed | `altchan.TestRecoveryOpenResultAttemptUsed`, `vault.TestAttemptUsedLostSpend`, `vault.TestAttemptUsedFailedConfirm`, `vault.TestAttemptUsedStoredDataAfterTheSpend`, `vault.TestAttemptUsedVaultMissingAfterTheSpend`, `vault.TestAttemptUsedRetryAfterStep1`, `s3counter.TestPutCreateIsNeverRetried`, `vault.TestRecoveryOpenSchedule`, `vault.TestRecoveryOpenRefusals`, `vault.TestRecoveryOpenResumesAfterStep1`, `vault.TestRecoveryOpenPresenceBetweenStatusAndSpend` (tc; `Counted` is `attempt_used`), e2e `TestRecoveryR` |
| 11.2, 11.10.9 (0.34.0) | the descriptor names the image's capabilities after not_after, bound by the attestation (a list with a name removed fails it), on every ETK; absent is a release before R; a malformed list refuses the descriptor | `enclave.TestDescriptorCapabilities`, `altchan.TestDescriptorCapabilities`, `altchan.TestValidCapabilities`, `altchan.TestMarshalDescriptorValidatesCapabilities` |
| 11.10.9 (0.34.0; owner decision 2026-10-16) | `recovery_offered` is listed exactly when the measured release constant offers recovery, in the descriptor and a transfer's bundle; it reaches the configuration and the vault options | `altchan.TestReleaseCapabilities`, `enclave.TestDescriptorCapabilities`, `enclave.TestRecoveryOfferedReachesCapabilities`, `vault.TestInviteBundleCapabilities` |
| 11.14.6 (0.34.0; owner decision 2026-10-16) | a lost ok: the recovered phone's own unlock before its first handshake carries the bundle and a token, repeatably, with no counter call; the old phone's does not; none after the pairing; the recovered invite outlives its expiry, is renewed by that unlock and replaced by a later recovery | e2e `TestRecoveryRLostOK`, `vault.TestRecoveredInviteUntilPairing` |
| 6.4, 6.7.1, 11.10.9 (0.34.0) | a transfer's bundle (kind app) carries the capabilities, bound by the QR's hash; no other kind carries them; absent is a release before R | `vault.TestInviteBundleCapabilities`, `invite.TestBundleCapabilities` |

## The staging time scale (§10.2, §11.10.8, §11.10.9, §11.14.14; VAULT-RELEASES 0.1.32 §5.2; STAGING-TIME-SCALE 0.1.0; 0.43.0)

| § | Requirement | Test |
|---|---|---|
| 11.10.8, 11.14.14 | `time_scale` in the channel file: production exactly 1 (missing, a placeholder or any other value refused by the release gate), staging 1 or 24; staging's quiet period exactly 259,200 / `time_scale`, production's at least 259,200; the committed files say 1 and 24 (10,800 s) | `releasecfg.TestTimeScaleRules`, `releasecfg.TestCommittedTimeScale`, `cmd/releasecfg.TestCheckCommand` |
| 11.10.8, 11.14.14 | the accessor returns the file's value only in the staging channel, 1 otherwise (a production Config holding 24 included); a production image's file says 1 and its scale is 1 whatever the file says; the enclave returns 1 again in a production image | `releasecfg.TestTimeScaleAccessorIgnoresFileOutsideStaging`, `releasecfg.TestProductionImageRecoveryRules` (`make channels`, prod tag), `enclave.TestReleaseConfigTimeScale` |
| STS 3, 5.5 | each scaled wait at 24 and at 1: owner check interval (S1; settings in real units, the shorter-interval move), recovery code delay and validity (S5, S6, also after a wait), counter notice (S8), pending unlink (S11), provisional window (S13, enclave and header); rounded up to a whole second | `vault.TestScale`, `vault.TestTimeScaleOwnerCheck`, `vault.TestTimeScaleRecoveryRequest`, `vault.TestTimeScaleRecoveryValidityAfterWait` (tc), `vault.TestTimeScaleCounterNotice`, `vault.TestTimeScalePendingUnlink`, `vault.TestTimeScaleEnrollWindow`, `enclave.TestTimeScaleDescriptorAndEnrollWindow` (also per channel tag, `make channels`: 1 in a production build) |
| STS 5.5 | a timer started before the vault runs a scaled release keeps its time (owner-check deadline, recovery not_before/expires, a held notice without `until`, a header without `enroll_until`) | `vault.TestTimeScaleOwnerCheckTransition`, `vault.TestTimeScaleRecoveryRequest`, `vault.TestTimeScalePendingUnlink`, `vault.TestTimeScaleEnrollWindow` |
| STS 2.2, 3 rule 4 | nothing in the not-scaled list changes: the constants keep their values, the wait unit is used as given, the owner-check bounds are unchanged | `vault.TestTimeScaleLeavesTheRestAlone` |
| 10.2, 11.2, 11.10.9 | the descriptor carries `time_scale` after `capabilities`, bound by the attestation; a transfer bundle carries it (kind app only, bound by the QR's hash); `vault.status` to the app and desktops (not agents); absent is 0, malformed refused | `altchan.TestDescriptorTimeScale`, `invite.TestBundleTimeScale`, `enclave.TestTimeScaleDescriptorAndEnrollWindow`, `vault.TestTimeScaleReported` |
| STS 5.1 | the dev stack's `-time-scale` reaches the dev enclave and the vault processes (1 to 86,400) | `cmd/devstack.TestParseFlags`, `enclavetest.TestDevVaultTimeScaleArgs` |
