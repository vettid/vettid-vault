package vault

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/peerwire"
)

// State is the DEK-encrypted vault state (§3.3). It is serialized as JSON
// and encrypted under the DEK on every flush. It is secret in its entirety.
type State struct {
	V        int    `json:"v"`
	VaultID  string `json:"vault_id"`
	UserGUID string `json:"user_guid"`
	StateSeq uint64 `json:"state_seq"`
	// MessagingRelease is §6.3.1's marker (0.87.1, "No upgrade: release 29
	// starts clean"): written as 29 from a vault's first flush; a state
	// without it, or with a smaller value, is not started (R29-U1).
	MessagingRelease int `json:"messaging_release,omitempty"`
	// CleanEnd (card GC #6875): the state was written by a lock's last
	// write, after its last drain, so every deposit's Tried is stored. A
	// state loaded without it (a crash, a kill, a release before) may have
	// lost a Tried, so init marks every waiting session-mode deposit Tried:
	// none of them is then stamped again (a peer could run it twice).
	CleanEnd bool `json:"clean_end,omitempty"`
	// loadedClean (not stored): this state was loaded with CleanEnd, so its
	// Tried flags were trusted; until a write since the load succeeds, the
	// store still says clean, and nothing is deposited (review M1, #218).
	loadedClean bool
	// OutboxTried (0.88.7 §8.3): the outbox's entries carry Tried. A state
	// written before (release 29) did not record it: at its first load every
	// sealed session-mode entry not done is taken as one that may have
	// reached the relay (init).
	OutboxTried bool `json:"outbox_tried,omitempty"`

	Relay        RelayState        `json:"relay"`
	IdentitySeed []byte            `json:"ik_seed"`
	KEMSeed      []byte            `json:"kem_seed"`
	RetiredKEMs  []RetiredKEM      `json:"retired_kems,omitempty"`
	Rotations    []json.RawMessage `json:"rotations,omitempty"` // own identity.rotate chain (§3.4)
	// RotatedAt is when the vault last rotated its ik (S5's resend, 0.86.0).
	RotatedAt time.Time `json:"rotated_at,omitzero"`
	WakeSeed  []byte    `json:"wake_seed"`
	// RotationOwed is the owed mark (§11.14.10 "The owed mark"): a rotation
	// of the vault's keys still to be made. Recovery is the recovery_id of
	// a completed recovery (§11.14.6 step 6), written in its step-2 state
	// write. Transfer is the transfer_id of a transfer, written in the
	// approval's step-2 state write. Retried when the recovered phone has
	// paired, when the relay settles the transfer's notice to the old phone,
	// and at each later unlock; any rotation clears both.
	RotationOwed *RotationOwed `json:"rotation_owed,omitempty"`

	Devices     map[string]*Peer `json:"devices"`
	Connections map[string]*Peer `json:"connections"`

	Issued     []IssuedToken          `json:"issued"`
	DeniedSubs []string               `json:"denied_subs,omitempty"` // relay keys we revoked (§7.4); refused for re-pairing (§6.7)
	Invites    map[string]*Invite     `json:"invites"`
	Awaiting   map[string]*AwaitingHS `json:"awaiting"` // our hs.resp sent, awaiting hs.fin
	Outgoing   map[string]*OutgoingHS `json:"outgoing"` // our hs.init sent, awaiting hs.resp
	// Requests are connection requests, pairings and transfers whose
	// handshake is complete and which await approval (§6.4, §6.7,
	// 0.10.3), by pending_id (incoming) or connection_id (outgoing).
	Requests map[string]*Request `json:"requests,omitempty"`

	SeenMsgIDs map[string]time.Time `json:"seen_msg_ids"` // relay msg_id dedupe (16 d)
	SeenInner  map[string]time.Time `json:"seen_inner"`   // principal|inner id (16 d)
	// SeenInit are the transcript hashes th1 of the reconnect hs.init the
	// vault answered (§6.6 "Replay", 0.72.0), hex, kept 16 days + 5 minutes.
	SeenInit  map[string]time.Time      `json:"seen_init,omitempty"`
	Responses map[string]CachedResponse `json:"responses"` // principal|inner id (24 h)
	Outbox    []*OutboxEntry            `json:"outbox"`
	Audit     []AuditEntry              `json:"audit"`

	Settings Settings                   `json:"settings"`
	Features map[string]json.RawMessage `json:"features"`

	// Blocks are the owner's block list (§7.4, §10.4), by block id.
	Blocks map[string]*Block `json:"blocks,omitempty"`
	// AccessRequests are desktops' and agents' pending access-session
	// requests (§6.8), by request id.
	AccessRequests map[string]*AccessRequest `json:"access_requests,omitempty"`
	// Held are requests held for an app's approval (§6.8), by approval id.
	Held map[string]*HeldRequest `json:"held,omitempty"`
	// Transfer is the direct transfer to a new phone in progress (§6.7.1),
	// at most one.
	Transfer *Transfer `json:"transfer,omitempty"`
	// Deleting marks a deletion in progress (§12.5): the vault never runs
	// again.
	Deleting *Deletion `json:"deleting,omitempty"`

	// Release state (§11.10.4): the release the vault is sealed to, a
	// pending move, and the release last announced to the owner's devices
	// (sync.event vault.release, §10.1).
	SealedRelease    string       `json:"sealed_release"`
	ReleaseMove      *ReleaseMove `json:"release_move,omitempty"`
	AnnouncedRelease string       `json:"announced_release,omitempty"`

	// Account is the member's account snapshot from the member API
	// (0.15.0, §11.13): display only.
	Account *AccountState `json:"account,omitempty"`
	// NameRequest is the latest account.name.set request and NameSeq its
	// counter (0.18.0, §10.8; from 1).
	NameRequest *NameRequest `json:"name_request,omitempty"`
	NameSeq     uint64       `json:"name_seq,omitempty"`

	// OwnerCheck is the daily owner check's record (§3.6.1); nil in a
	// vault from before 0.13.0 until its first start.
	OwnerCheck *OwnerCheck `json:"owner_check,omitempty"`

	// Push is the app's push registration (0.24.0, §14.1), at most one;
	// PushRegs are when registrations reached the gateway (the rolling
	// 24 h window of push_registrations). PushPending is the latest
	// registration the gateway answered with a pending registration and a
	// challenge to the token (PUSH-GATEWAY 0.5.0), at most one, waiting
	// for push.confirm; the registration in Push stays in force meanwhile.
	Push        *PushRegistration `json:"push,omitempty"`
	PushPending *PushPending      `json:"push_pending,omitempty"`
	PushRegs    []time.Time       `json:"push_regs,omitempty"`

	// DeviceTokensMarked: every owner device's standing token carries
	// owner_device (§7.1; 0.32.0, release A). A vault from before release
	// A re-mints them at its first unlock under it (§7.2).
	DeviceTokensMarked bool `json:"device_tokens_marked,omitempty"`

	// Attach is the attachment index and its bookkeeping (§3.3, §10.5.1;
	// 0.32.0, release A); nil until the first attachment.
	Attach *AttachState `json:"attach,omitempty"`

	// Release R (§11.14.11): the counter's attempts the vault has recorded
	// in the audit log ("<generation>/<n>" → "success" | "not_success"),
	// the used count audited per generation, the generation of the last
	// completed recovery, and when the 24-hour counter notice was raised.
	RecoveryAttempts map[string]string `json:"recovery_attempts,omitempty"`
	RecoveryUsed     map[string]int    `json:"recovery_used,omitempty"`
	// RecoveredGeneration is from before RecoveredAttempt: no longer read
	// (without the attempt it cannot say "since"; its attempts are urgent).
	RecoveredGeneration uint64 `json:"recovered_generation,omitempty"`
	// RecoveredAttempt is the last completed recovery's attempt
	// (generation, n): attempts of that generation up to n are the
	// member's and not urgent; every other attempt is (§11.14.11, "since").
	// A state from before this field has none, so all are urgent.
	RecoveredAttempt      []uint64  `json:"recovered_attempt,omitempty"`
	RecoveryCounterNotice time.Time `json:"recovery_counter_notice,omitempty"`
	// PendingUnlink is a transfer's held notice to the old app (§11.14.10).
	PendingUnlink *PendingUnlink `json:"pending_unlink,omitempty"`
	// HeldKeyRotation is the credential key's rotation statement made at a
	// transfer's approval and held until the new phone's first unlock from
	// storage (§11.14.10 "The credential key, at the approval").
	HeldKeyRotation *HeldKeyRotation `json:"held_key_rotation,omitempty"`
	// RecoveredSigner is the vault's signer binding before a completed
	// recovery removed the old app, until the recovered phone pairs and
	// the binding moves (§11.7.1, §11.14.6): digest and class.
	RecoveredSigner []string `json:"recovered_signer,omitempty"`
	// KeptSigner is the last recorded Android signer (digest, class)
	// while the vault's app has none (an iOS app): the vault's signer
	// binding across it, so that a later move to an Android app of another
	// signer is a change (§11.7.1 "Across an iOS app", decided
	// 2026-10-11; IOS-PLAN VA4). Set when the binding moves from a signer
	// to an app without one, cleared when it moves to an app with one.
	// A state written before VA4 has none: a vault moved to an iOS app
	// before VA4 lost its binding at that move (no iOS app has been
	// released, so none is known).
	KeptSigner []string `json:"kept_signer,omitempty"`
	// PendingSucceed is a completed recovery's attempt (generation, n)
	// whose success the counter has not confirmed; PresentPending a
	// presence (after a recovery or a transfer) not yet recorded. Both are
	// sent again at every unlock and owner check (§11.14.6).
	PendingSucceed []uint64 `json:"pending_succeed,omitempty"`
	PresentPending bool     `json:"present_pending,omitempty"`
}

// ReleaseMove is a recorded, not yet confirmed move to another release
// (§11.10.4 step 6).
type ReleaseMove struct {
	To             string `json:"to"`
	ToRelease      uint64 `json:"to_release"`
	From           string `json:"from"`
	ManifestSerial uint64 `json:"manifest_serial"`
	ApprovedBy     string `json:"approved_by"`
}

// RelayState is the vault's own relay identity (§3.2).
type RelayState struct {
	URL     string `json:"url"`
	Seed    []byte `json:"seed"`
	Mailbox string `json:"mailbox"`
}

// RotationOwed holds the owed rotation marks (see State.RotationOwed).
// DEKVersion and At belong to the transfer's mark: the DEK version its
// step 2 wrote (the rotation waits for an unlock from the stored objects
// under it or a later one, "after the new phone's first unlock") and the
// approval's time (from 7 days after it the rotation no longer waits for
// the old phone's notice).
type RotationOwed struct {
	Recovery   string    `json:"recovery,omitempty"`
	Transfer   string    `json:"transfer,omitempty"`
	DEKVersion uint64    `json:"dek_version,omitempty"`
	At         time.Time `json:"at,omitzero"`
}

// RetiredKEM is a retired static KEM key, kept 400 days for reconnects.
type RetiredKEM struct {
	Seed      []byte    `json:"seed"`
	RetiredAt time.Time `json:"retired_at"`
}

// Principal kinds.
const (
	KindApp        = "app"
	KindDesktop    = "desktop"
	KindAgent      = "agent"
	KindConnection = "connection"
)

// Peer states.
const (
	PeerPending = "pending"
	PeerActive  = "active"
	PeerStale   = "stale"
)

// Peer is the record of one owner device or one connection (§3.3).
type Peer struct {
	ID        string            `json:"id"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name,omitempty"`
	State     string            `json:"state"`
	IK        []byte            `json:"ik"`
	KEM       []byte            `json:"kem"`
	Relay     PeerRelay         `json:"relay"`
	Chain     []json.RawMessage `json:"chain,omitempty"` // the peer's rotation chain
	Profile   json.RawMessage   `json:"profile,omitempty"`
	Suite     uint8             `json:"suite"` // pinned suite (§13.4)
	CreatedAt time.Time         `json:"created_at"`

	Sessions    handshake.KeyringState `json:"sessions"`
	LastEpochID []byte                 `json:"last_epoch_id,omitempty"`
	// OwnChainAtEpoch is len(State.Rotations) when the last epoch was made,
	// so a reconnect sends only the rotations since then (§6.6).
	OwnChainAtEpoch int `json:"own_chain_at_epoch"`

	Standing  HeldToken `json:"standing"`  // token the peer issued to us
	Reconnect HeldToken `json:"reconnect"` // connections only
	// QuotaMailbox is the tokenTag of a standing token under which a
	// quota_exceeded without `quota` (a relay before 0.9.2) was read as the
	// mailbox's (§8.6): under that token every later one is read so too.
	QuotaMailbox string `json:"quota_mailbox,omitempty"`
	// QuotaReqs are the request ids of the quota refreshes (§7.2) still
	// open, asked under the standing token QuotaReqTok names (tokenTag):
	// an answer to any of them is taken, also after a restart (the
	// issuer grants the first and answers the later ones too_soon). At
	// most quotaReqsMax; forgotten once another standing token is held.
	QuotaReqs   []string `json:"quota_reqs,omitempty"`
	QuotaReqTok string   `json:"quota_req_tok,omitempty"`
	// Carried are the tokens a reconnect hs.init of the peer's carried, for
	// each epoch the vault activated as responder and has not yet adopted
	// them in (VAULT-MESSAGING 0.88.2 §6.3.1 "A handshake's tokens are
	// adopted at confirmation", R29-T1): adopted when the confirmed epoch
	// reaches that epoch, discarded if it is destroyed or demoted first,
	// when one is answered token_revoked, or at the wait's bound.
	Carried []CarriedTokens `json:"carried,omitempty"`

	// Attestation is an app's device-attestation binding at pairing
	// (§6.7, §11.7); the sealed header's copy is authoritative afterwards.
	Attestation json.RawMessage `json:"attestation,omitempty"`
	// Recovering marks an app registered by recovery that has not yet
	// authenticated with the credential password (§11.11.5).
	Recovering bool `json:"recovering,omitempty"`
	// APIKey is a transfer's new app's app key from its hs.init (0.15.0,
	// §6.2): the vault's app key once the transfer completes.
	APIKey []byte `json:"api_key,omitempty"`

	// LastActiveAt is when the principal's last message was processed
	// (§10.3, §10.4 listings), to the minute.
	LastActiveAt time.Time `json:"last_active_at,omitempty"`
	// Owner metadata of a connection (connection.update, §10.4), versioned
	// as one object (§10.1).
	Meta *PeerMeta `json:"meta,omitempty"`
	// Access is a desktop's or agent's access session (§6.8).
	Access *AccessSession `json:"access,omitempty"`
	// AccessRequestedAt is when the vault last accepted a
	// device.session.request from this desktop or agent (§6.8, 0.40.0);
	// the next is accepted AccessRequestEvery after it.
	AccessRequestedAt time.Time `json:"access_requested_at,omitempty"`
	// PairGrants are an agent's initial LEASH grants, from the pairing
	// approval until the pairing completes (§6.7, §10.11).
	PairGrants json.RawMessage `json:"pair_grants,omitempty"`
	// Asks is a connection's §10.4.1 state (0.23.0): mute, pause,
	// cooldowns, the ask-rate window and the held neutral answers.
	Asks *AskState `json:"asks,omitempty"`
	// Conflict is a connection's two successors of one identity key
	// (release R, §3.4): the connection is suspended until the holder
	// resolves it.
	Conflict *RotationConflict `json:"rotation_conflict,omitempty"`
	// Rejected holds the successors the holder dropped at a resolution.
	Rejected []RejectedSuccessor `json:"rejected_successors,omitempty"`

	// PeerKind is what the inviter declared in the invitation bundle
	// ("service", 0.69.0, §6.4): read at connection.invite.accept, copied
	// into the connection at activation and never changed afterwards. Only
	// a connection that is a service keeps an epoch history (§6.6, 0.72.0).
	PeerKind string `json:"peer_kind,omitempty"`
	// History is the epochs a service connection activated whose successor
	// took over less than 35 days ago (§6.6 "Epoch history", 0.72.0), the
	// current one last. Person connections keep none.
	History []EpochRecord `json:"epoch_history,omitempty"`
	// Watch is the epoch line a restored service's reconnect replaced
	// (§6.6 "Fork detection", 0.72.0): authenticated evidence of it means
	// two copies of the peer exist.
	Watch *ForkWatch `json:"fork_watch,omitempty"`
	// Fork is set when the connection was suspended on that evidence
	// (§6.6): it sends nothing and accepts nothing until a new invitation
	// replaces it.
	Fork *ForkSuspension `json:"fork_suspension,omitempty"`

	// Heard: a device or agent has sent the vault a message (R29-D4 judges
	// only such a device); UpdateNoticed: device.update_needed was shown
	// for it (once per device until it advertises hs_confirm).
	Heard         bool `json:"heard,omitempty"`
	UpdateNoticed bool `json:"update_noticed,omitempty"`

	// PeerFeatures are the capability names the peer advertised (0.86.0,
	// §10.8, §5.3), sorted; a name is only ever added. Nil: none seen yet.
	PeerFeatures []string `json:"peer_features,omitempty"`

	// Epochs are what §3.4.1 and §6.3.1 (0.86.0) need to know about each
	// epoch with the peer, in activation (or establishment) order: who
	// signed it, who began it, where it was established, and whether rule
	// E destroyed or an ik link demoted it. Pruned when nothing needs it.
	Epochs []EpochMeta `json:"epochs,omitempty"`
	// Pending is the vault's own rekey or reconnect epoch awaiting the
	// peer's confirmation (§6.3.1 "Initiator").
	Pending *PendingEpoch `json:"pending_epoch,omitempty"`
	// Confirmed is the confirmed epoch (§6.3.1 "Responder"): the newest,
	// in activation order, under which the peer sent a message other than
	// hs.fin, or that the vault activated itself at confirmation. It never
	// moves back. Set at the peer's first epoch.
	Confirmed []byte `json:"confirmed_epoch,omitempty"`
	// Abandoned are the ids of the vault's own pending epochs it abandoned
	// (for any reason): a reconnect naming one is accepted until a newer
	// epoch is confirmed, unless R29-K9 ended it (§6.3.1).
	Abandoned [][]byte `json:"abandoned_epochs,omitempty"`
	// Seen are the valid identity links of the peer that passed rule C but
	// were not followed (one in an unfinished handshake's rotations, or in
	// an identity.rotate then refused; a rekey's only once it passed
	// rekeyPrecheck), at most one per old key, only from the current ik,
	// an ancestor or a key a seen link reaches, and at most MaxSeen
	// (§3.4.1 rule C, 0.86.0): a later different successor of that key is
	// a second successor.
	Seen []json.RawMessage `json:"seen_links,omitempty"`
	// ConfirmAt is when the vault last queued hs.confirm to the peer
	// (§6.3.1 "Responder": again ConfirmResend after it while the epoch
	// is unconfirmed).
	ConfirmAt time.Time `json:"confirm_at,omitzero"`
	// RevokedHeld are the standing tokens for the peer a relay answered
	// token_revoked for (0.88.2 §8.6), by jti, kept until their exp: never
	// used again, and refused if offered again.
	RevokedHeld []RevokedToken `json:"revoked_held,omitempty"`
	// RC counts the failed tries of the vault's reconnects to the peer
	// naming one epoch (§3.4.1 "The reconnect bound").
	RC *ReconnectCount `json:"reconnect_tries,omitempty"`
	// IDResend counts S5's identity.rotate resends to the peer for the
	// vault's latest rotation (0.86.0).
	IDResend *IDResend `json:"id_resend,omitempty"`
}

// RevokedToken is a revoked standing token's jti and exp.
type RevokedToken struct {
	JTI string    `json:"jti"`
	Exp time.Time `json:"exp"`
}

// ReconnectCount is Peer.RC: the epoch the reconnects named, and how many
// tries failed.
type ReconnectCount struct {
	Epoch []byte `json:"epoch"`
	Tries int    `json:"tries"`
}

// IDResend is S5's resend bookkeeping: for which rotation (the length of
// the vault's chain), how many, and when the last went.
type IDResend struct {
	Rotation int       `json:"rotation"`
	N        int       `json:"n"`
	At       time.Time `json:"at,omitzero"`
}

// EpochMeta is one epoch with a peer (0.86.0, §3.4.1 "Terms": the epoch
// signer and the position of the message that established it).
type EpochMeta struct {
	ID []byte `json:"id"`
	// Signer is the peer-side ik that signed its handshake.
	Signer []byte `json:"signer,omitempty"`
	// Mine: the vault began it (it was the handshake's initiator).
	Mine bool `json:"mine,omitempty"`
	// EstAt and EstMsg are the position (deposited_at, msg_id) of the
	// message that established it.
	EstAt  time.Time `json:"est_at,omitzero"`
	EstMsg string    `json:"est_msg,omitempty"`
	// Pending: the vault's own pending epoch, not yet confirmed.
	// Abandoned: a pending epoch the vault abandoned; nothing under it
	// confirms any more, and it never becomes the confirmed epoch.
	Pending   bool `json:"pending,omitempty"`
	Abandoned bool `json:"abandoned,omitempty"`
	// Superseded is when it stopped being current (zero while current or
	// pending).
	Superseded time.Time `json:"superseded,omitzero"`
	// Destroyed by rule E (§6.3.1) with the accepted hs.init's inner ts:
	// an authenticated message under it with a later ts is fork evidence,
	// one with an earlier ts is refused (superseded_epoch).
	Destroyed bool      `json:"destroyed,omitempty"`
	DestroyTS time.Time `json:"destroy_ts,omitzero"`
	// Demoted by an ik link at the position (DemotedAt, DemotedMsg)
	// (§3.4.1 "Epochs after an ik link"): messages under it deposited
	// after that are refused (ancestor_ik).
	Demoted    bool      `json:"demoted,omitempty"`
	DemotedAt  time.Time `json:"demoted_at,omitzero"`
	DemotedMsg string    `json:"demoted_msg,omitempty"`
	// OwnChain is the own rotation count whose ik signed its handshake: a
	// reconnect naming it carries the vault's links from there.
	OwnChain int `json:"own_chain,omitempty"`
	// Ended: an epoch the vault began and abandoned while pending, ended
	// at P's identity.rotate (§3.4.1 R29-K9): an authenticated message
	// under it is fork evidence, and a reconnect naming it is refused.
	Ended bool `json:"ended,omitempty"`
	// GotFromPeer is §6.3.1's received flag (owner decision S13 a): a
	// message from P other than hs.fin (hs.confirm, hs.init and session
	// messages included) opened under this epoch and passed acceptFrom
	// steps 1-4.
	GotFromPeer bool `json:"got_from_peer,omitempty"`
}

// PendingEpoch is an initiator's pending epoch (§6.3.1).
type PendingEpoch struct {
	ID      []byte            `json:"id"`
	Purpose handshake.Purpose `json:"purpose"`
	// FinAt is when the vault sent (queued) hs.fin; B runs from it.
	FinAt time.Time `json:"fin_at"`
	// RespTS is the inner ts of the hs.resp the vault processed: a rekey
	// hs.init from the peer under the current epoch that is not later
	// crosses it and is dropped.
	RespTS time.Time `json:"resp_ts"`
	// Issued are the tokens the hs.init minted, recorded at confirmation;
	// OwnChain is the own rotation count whose ik signed the handshake.
	Issued   []IssuedToken `json:"issued,omitempty"`
	OwnChain int           `json:"own_chain"`
	// Carried are the tokens the peer's hs.resp carried (0.88.2 §6.3.1,
	// R29-T1): adopted in the write that confirms this epoch, never before.
	Carried *CarriedTokens `json:"carried,omitempty"`
}

// CarriedTokens are the standing and reconnect tokens one handshake carried
// for the vault, held apart from the tokens it uses until they are adopted
// (0.88.2 §6.3.1, R29-T1). Epoch is the handshake's epoch (the responder's
// record; empty on an initiator's pending epoch, which is its own); Since is
// when the responder activated it (the wait's 32-day cap runs from it).
type CarriedTokens struct {
	Epoch     []byte    `json:"epoch,omitempty"`
	Standing  HeldToken `json:"standing"`
	Reconnect HeldToken `json:"reconnect"`
	Since     time.Time `json:"since,omitzero"`
	// Discarded: never to be adopted (its epoch destroyed or demoted, a
	// token of it answered token_revoked, or the wait's bound passed); kept
	// while its epoch is current so that "hs.confirm again" stops for it.
	Discarded bool `json:"discarded,omitempty"`
}

// EpochRecord is one epoch of a service connection's history (§6.6, 0.72.0).
type EpochRecord struct {
	ID        []byte    `json:"id"`
	Activated time.Time `json:"activated"`
	// Superseded is when the epoch stopped being current; zero for the
	// current epoch, which is always accepted. The 35-day window runs from
	// it.
	Superseded time.Time `json:"superseded,omitempty"`
	// OwnChain is the own rotation-chain count whose key signed the
	// epoch's handshake (not the count at activation): the responder's
	// `rotations` for a reconnect naming this epoch run from it.
	OwnChain int `json:"own_chain"`
}

// ForkWatch is the line a restored service's accepted reconnect replaced.
type ForkWatch struct {
	// Replaced are the ids of the epochs after the one the reconnect named.
	Replaced [][]byte `json:"replaced"`
	// TS is the inner ts of the accepted reconnect hs.init: only evidence
	// with a later ts counts (the same sender's clock).
	TS time.Time `json:"ts"`
	// Until ends the watch with the records of the replaced line (the
	// 35-day window from the accepted reconnect).
	Until time.Time `json:"until"`
}

// ForkSuspension marks a connection suspended on fork evidence (§6.6).
type ForkSuspension struct {
	At time.Time `json:"at"`
}

// suspended reports whether p sends nothing and accepts nothing: two
// successors of one identity key (§3.4) or fork evidence (§6.6, 0.72.0).
func (p *Peer) suspended() bool {
	return p.Kind == KindConnection && (p.Conflict != nil || p.Fork != nil)
}

// replaceable reports whether a new invitation may replace the connection:
// a stale one (§7.4), or one suspended on fork evidence, whose only way out
// is a new invitation (§6.6, 0.72.0).
func (p *Peer) replaceable() bool { return p.State == PeerStale || p.Fork != nil }

// isService reports whether p is a connection the inviter declared a
// service (§6.4, 0.69.0).
func (p *Peer) isService() bool { return p.Kind == KindConnection && p.PeerKind == "service" }

// RejectedSuccessor is a successor of OldIK the holder dropped at
// connection.rotation.resolve (§3.4): a later copy of it is refused, not a
// new conflict.
type RejectedSuccessor struct {
	OldIK []byte `json:"old_ik"`
	NewIK []byte `json:"new_ik"`
}

// RotationConflict holds both rotation statements with the same old_ik.
type RotationConflict struct {
	OldIK      []byte            `json:"old_ik"`
	Statements []json.RawMessage `json:"statements"`
	At         time.Time         `json:"at"`
}

// PeerMeta is the owner's own metadata about a connection: never sent to
// the peer.
type PeerMeta struct {
	Version  uint64   `json:"version"`
	Alias    string   `json:"alias,omitempty"`
	Note     string   `json:"note,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	Favorite bool     `json:"favorite,omitempty"`
	Archived bool     `json:"archived,omitempty"`
}

// Block is one block-list entry (§7.4, §10.4): the peer's identity key
// and relay key, refused in any later handshake.
type Block struct {
	ID           string    `json:"id"`
	IK           []byte    `json:"ik"`
	RelayPK      []byte    `json:"relay_pk,omitempty"`
	Name         string    `json:"name,omitempty"`
	Note         string    `json:"note,omitempty"`
	ConnectionID string    `json:"connection_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// AccessSession is an app-approved window in which a desktop or agent may
// act (§6.8). It is not the E2E session of §6.1.
type AccessSession struct {
	ID        string    `json:"id"`
	Expires   time.Time `json:"expires"`
	GrantedBy string    `json:"granted_by"`
}

// AccessRequest is a desktop's or agent's pending request for an access
// session (§6.8).
type AccessRequest struct {
	ID       string    `json:"id"`
	DeviceID string    `json:"device_id"`
	Seconds  uint64    `json:"seconds"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
}

// HeldRequest is a desktop's or agent's request held until an app approves
// or denies it (§6.8). Inner is the request's inner plaintext JSON.
type HeldRequest struct {
	ID       string    `json:"id"`
	DeviceID string    `json:"device_id"`
	Key      string    `json:"key"` // principal|inner id (§8.2)
	Inner    []byte    `json:"inner"`
	Created  time.Time `json:"created"`
	Expires  time.Time `json:"expires"`
}

// PeerRelay is a peer's relay address.
type PeerRelay struct {
	URL     string `json:"url"`
	Mailbox string `json:"mailbox"`
	PK      []byte `json:"pk"`
}

// HeldToken is a deposit token another principal issued to the vault.
type HeldToken struct {
	Token string    `json:"token,omitempty"`
	Exp   time.Time `json:"exp,omitempty"`
}

// Token kinds (§7.1), as vms/peerwire defines them.
const (
	TokStanding  = peerwire.TokenStanding
	TokReconnect = peerwire.TokenReconnect
	TokOpen      = peerwire.TokenOpen
	// TokRequest covers only the rest of a handshake that awaits
	// approval and connection.approved (§7.1, 0.10.3).
	TokRequest = peerwire.TokenRequest
)

// IssuedToken is one entry of the issued-token registry (§7, §3.3).
type IssuedToken struct {
	JTI    string    `json:"jti"`
	Kind   string    `json:"kind"`
	Sub    string    `json:"sub"` // base64 relay key, "*" for open tokens
	PeerID string    `json:"peer_id,omitempty"`
	Exp    time.Time `json:"exp"`
	Denied bool      `json:"denied,omitempty"`
	// Handshake: minted in a handshake's hs.init or hs.resp (recorded at
	// activation). A refresh after quota_exceeded spares the newest such
	// standing token, which the peer may not yet have adopted (0.88.2 §7.2,
	// §6.3.1 "Revocation by the issuer").
	Handshake bool `json:"handshake,omitempty"`
	// Prompt: re-minted at a reconnect's confirmation, the prompt to adopt
	// (§6.3.1); the quota refresh spares the newest one too.
	Prompt bool `json:"prompt,omitempty"`
}

// Invite is an outstanding connection invitation or device pairing (§6.4,
// §6.7). Kind is "connection", "app", "desktop" or "agent".
type Invite struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Remote    bool      `json:"remote"`
	Exp       time.Time `json:"exp"`
	OpenJTI   string    `json:"open_jti"`
	ClaimID   string    `json:"claim_id"`
	Used      bool      `json:"used"`
	CreatedBy string    `json:"created_by"`
	// The first app, bound at enrollment (§11.3): its hs.init is accepted
	// without approval if it presents exactly these keys.
	EnrollIK      []byte          `json:"enroll_ik,omitempty"`
	EnrollRelayPK []byte          `json:"enroll_relay_pk,omitempty"`
	EnrollKEM     []byte          `json:"enroll_kem,omitempty"`
	EnrollAttest  json.RawMessage `json:"enroll_attest,omitempty"`
	// An introduction's invitation (§10.15): accepted only from IntroIK;
	// IntroBy is the introducer's connection id.
	IntroIK []byte `json:"intro_ik,omitempty"`
	IntroBy string `json:"intro_by,omitempty"`
	// Transfer marks the pairing of a direct transfer's new app (§6.7.1),
	// the only app pairing a vault accepts after enrollment.
	Transfer bool `json:"transfer,omitempty"`
}

// AwaitingHS is a handshake where the vault sent hs.resp and awaits hs.fin.
// Peer is the record that becomes active (new principals) or the existing
// peer id (rekey, reconnect).
type AwaitingHS struct {
	ID      string                   `json:"id"`
	PeerID  string                   `json:"peer_id"`
	New     *Peer                    `json:"new,omitempty"`
	Purpose handshake.Purpose        `json:"purpose"`
	Created time.Time                `json:"created"`
	Resp    handshake.ResponderState `json:"resp"`
	// Tokens minted for the peer in hs.resp, recorded on activation.
	Issued []IssuedToken `json:"issued,omitempty"`

	// First contact (0.10.3): the invitation or pairing the hs.init used.
	// Direct handshakes (enrollment, recovery) are answered without
	// approval and active at hs.fin; the others become a Request.
	InviteID string    `json:"invite_id,omitempty"`
	Remote   bool      `json:"remote,omitempty"`
	IntroBy  string    `json:"intro_by,omitempty"` // §10.15
	Expires  time.Time `json:"expires,omitempty"`
	Direct   bool      `json:"direct,omitempty"`

	// OwnChain is the own rotation-chain count whose key signed hs.resp
	// (§6.6, 0.72.0); nil in a record written before it.
	OwnChain *int `json:"own_chain,omitempty"`
	// RespOutbox is the outbox entry holding hs.resp, so that a reconnect
	// abandoned before it was deposited sends nothing (§6.6 "Crossing
	// reconnects", 0.72.1).
	RespOutbox string `json:"resp_outbox,omitempty"`
	// Th1 is the transcript hash of the reconnect hs.init this answers: the
	// crossing tie-break between two persons compares it with the th1 of the
	// vault's own open reconnect (§6.6 "Between two persons", 0.74.0); nil
	// in a record written before it.
	Th1 []byte `json:"th1,omitempty"`
	// Reconnect is what an answered reconnect applies once hs.fin
	// verified: nothing changes before sig_I (§6.6 "Replay", 0.72.0).
	Reconnect *PendingReconnect `json:"reconnect,omitempty"`
	// Replaced marks a rekey answer open when a restore was accepted: it
	// was made on an epoch of the line the restore replaced (§6.6).
	Replaced bool `json:"replaced,omitempty"`
	// 0.86.0 (§6.3.1): NamedConfirmed marks an answer whose hs.init named
	// the confirmed epoch while it was not current (rule E applies at its
	// hs.fin); InitTS is the hs.init's inner ts.
	NamedConfirmed bool      `json:"named_confirmed,omitempty"`
	InitTS         time.Time `json:"init_ts,omitzero"`
	// Signer is the peer's ik that sig_I must verify under (the epoch's
	// signer, §3.4.1); Links the links a rekey's hs.init carried (S8),
	// followed at hs.fin.
	Signer []byte            `json:"signer,omitempty"`
	Links  []json.RawMessage `json:"links,omitempty"`
}

// PendingReconnect is a reconnect hs.init's effects, held until hs.fin.
type PendingReconnect struct {
	Standing  HeldToken `json:"standing"`
	Reconnect HeldToken `json:"reconnect"`
	// IK and Rotations are the initiator's identity and every rotation
	// statement its hs.init carried; the links not yet followed are worked
	// out again at hs.fin (§3.4, §6.6).
	IK        []byte            `json:"ik,omitempty"`
	Rotations []json.RawMessage `json:"rotations,omitempty"`
	// Named is the epoch the hs.init's ctx named. Older: it was not the
	// current one (a restore of a service, §6.6 "Accepting ctx"); Fork: it
	// named an epoch of a replaced line (evidence of two copies).
	Named []byte `json:"named,omitempty"`
	Older bool   `json:"older,omitempty"`
	Fork  bool   `json:"fork,omitempty"`
	// ForkRef is the fork suspension's ref ("epoch": §3.4.1 F2, 0.86.0).
	ForkRef string `json:"fork_ref,omitempty"`
	// TS is the hs.init's inner ts.
	TS time.Time `json:"ts"`
}

// OutgoingHS is a handshake the vault initiated, awaiting hs.resp.
type OutgoingHS struct {
	ID      string                   `json:"id"`
	PeerID  string                   `json:"peer_id"`
	New     *Peer                    `json:"new,omitempty"`
	Purpose handshake.Purpose        `json:"purpose"`
	EphKid  []byte                   `json:"eph_kid"`
	Th1     []byte                   `json:"th1"`
	Created time.Time                `json:"created"`
	Init    handshake.InitiatorState `json:"init"`
	Issued  []IssuedToken            `json:"issued,omitempty"`
	// OwnChain is the own rotation-chain count whose key signed hs.init
	// (§6.6, 0.72.0); nil in a record written before it. InitOutbox is the
	// outbox entry holding the hs.init, so that an abandoned reconnect
	// (0.72.1), or one dropped at restore (a connection request too),
	// sends nothing.
	OwnChain   *int   `json:"own_chain,omitempty"`
	InitOutbox string `json:"init_outbox,omitempty"`
	// Replaced marks a rekey open when a restore was accepted: it was made
	// on an epoch of the replaced line (§6.6); it blocks nothing, and its
	// hs.resp is fork evidence when it carries a later ts.
	Replaced bool `json:"replaced,omitempty"`
	// Named is the epoch a reconnect named (its ctx; after a demotion or by
	// strict F1 another than the current one, §3.4.1).
	Named []byte `json:"named,omitempty"`

	// An outgoing connection request in state waiting (§6.4, §10.4):
	// what the accept learned from the bundle, and when it ends.
	Remote  bool      `json:"remote,omitempty"`
	Name    string    `json:"name,omitempty"`
	IntroBy string    `json:"intro_by,omitempty"`
	Expires time.Time `json:"expires,omitempty"`
}

// Request directions.
const (
	ReqIn  = "in"  // the inviting vault's request (pending_id), or a pairing
	ReqOut = "out" // the accepting vault's request (connection_id)
)

// Request is a connection request, pairing or transfer whose handshake
// has completed: the epoch is established but not active until approval
// (§6.3, §6.4, §6.7, 0.10.3).
type Request struct {
	ID  string `json:"id"`
	Dir string `json:"dir"`
	// Peer is the principal's record. Until the peer's connection.approved
	// arrives, Standing holds the request token the peer issued.
	Peer  *Peer                `json:"peer"`
	Epoch handshake.EpochState `json:"epoch"`
	SAS   string               `json:"sas"`
	// Approved: our member approved (connection.approved sent);
	// PeerApproved: the peer's connection.approved arrived.
	Approved     bool `json:"approved,omitempty"`
	PeerApproved bool `json:"peer_approved,omitempty"`
	// PeerRequest keeps the peer's request token once its
	// connection.approved replaced Peer.Standing: connection.declined
	// still travels on it (§6.4, 0.10.5).
	PeerRequest *HeldToken `json:"peer_request,omitempty"`
	InviteID    string     `json:"invite_id,omitempty"` // invite_id or pairing_id
	Remote      bool       `json:"remote,omitempty"`
	Name        string     `json:"name,omitempty"` // outgoing: the bundle's hint.name
	IntroBy     string     `json:"intro_by,omitempty"`
	Created     time.Time  `json:"created"`
	Expires     time.Time  `json:"expires"`
	// OwnChain is the own rotation-chain count whose key signed the
	// handshake (§6.6, 0.72.0); nil in a record written before it.
	OwnChain *int `json:"own_chain,omitempty"`
}

// CachedResponse is a response kept for 24 h so a duplicate request gets
// the same answer without re-execution (§8.2).
type CachedResponse struct {
	Inner   []byte    `json:"inner"`
	Expires time.Time `json:"expires"`
}

// Outbox entry kinds.
const (
	OpDeposit     = "deposit"
	OpRevoke      = "revoke"
	OpDeleteClaim = "delete_claim"
)

// OutboxEntry is a relay side effect made durable before it is performed
// (§8.3 step 5). Deposits carry the sealed envelope; the token is resolved
// at deposit time from the peer's record unless Token is set (open and
// reconnect tokens, best-effort notices to removed peers).
type OutboxEntry struct {
	ID       string `json:"id"`
	Op       string `json:"op"`
	PeerID   string `json:"peer_id,omitempty"`
	RelayURL string `json:"relay_url,omitempty"`
	Mailbox  string `json:"mailbox,omitempty"`
	Token    string `json:"token,omitempty"`
	Payload  []byte `json:"payload,omitempty"`
	// Type is the message's inner type, recorded at queue time (card GC
	// #6875: the member's "not delivered" notice covers the member's own
	// messages, not the vault's upkeep). Empty for an entry queued before.
	Type       string    `json:"type,omitempty"`
	BestEffort bool      `json:"best_effort,omitempty"`
	Kind       string    `json:"kind,omitempty"`  // revoke: "jti" | "sub"
	Value      string    `json:"value,omitempty"` // revoke value, claim id
	Created    time.Time `json:"created"`
	Attempts   int       `json:"attempts"`
	NotBefore  time.Time `json:"not_before,omitempty"`
	// NotAfter ends the retries of a best-effort deposit (0.10.5:
	// connection.declined, device.pair.rejected); zero: no limit.
	NotAfter time.Time `json:"not_after,omitempty"`
	Done     bool      `json:"done,omitempty"` // removed at the next flush
	// AwaitToken: the peer's standing token expired; the deposit waits
	// for the fresh one the reconnect it started brings (§6.6, §8.6).
	AwaitToken bool `json:"await_token,omitempty"`
	// QuotaWait: the relay refused the deposit for its standing token's
	// quota (§8.6 quota_exceeded, `token`). It is not retried unchanged:
	// it waits for a fresh token (asked for, §7.2), and, as AwaitToken,
	// the later deposits to the mailbox under the standing token wait
	// behind it, in order; one that carries its own token (a handshake's)
	// and the refresh itself (QuotaRefresh) go. QuotaTok names the
	// standing token it was refused under (tokenTag): it is never sent
	// again under that one (RELAY-PROTOCOL §7.1), only asks again for a
	// refresh; tried under another one, the wait ends (QuotaWait false),
	// and a refusal there with no `quota` is the mailbox's (§8.6). Kept
	// after the wait, so that reading sticks.
	QuotaWait bool   `json:"quota_wait,omitempty"`
	QuotaTok  string `json:"quota_tok,omitempty"`
	// QuotaRefresh marks the relay.token.refresh a quota wait asked for:
	// the one deposit under the standing token that passes the wait. Its
	// QuotaTok is the token it was asked under: under another one it is
	// not sent (the wait it was for is over), and QuotaReq is its request
	// id, dropped from the pending requests when it ends unsent.
	QuotaRefresh bool   `json:"quota_refresh,omitempty"`
	QuotaReq     string `json:"quota_req,omitempty"`
	// Wake is the deposit's push wake class (0.24.0, §14.2): the app is
	// woken once the relay accepted it; "" for none.
	Wake string `json:"wake,omitempty"`
	// Unlink marks the deposit of a transfer's held notice to the old app
	// (§11.14.10): its transfer_id. The relay's answer settles the notice
	// or leaves it for the next unlock (unlinkOutcome).
	Unlink string `json:"unlink,omitempty"`
	// Confirm marks an hs.confirm (§6.3.1: a new one is queued only when
	// none to the peer is still in the outbox); FinEpoch the epoch an
	// hs.fin establishes (rule E drops one not yet sent for an epoch it
	// destroys); Handshake an hs.* deposit (it is not held while a
	// reconnect's epoch is pending).
	Confirm bool `json:"confirm,omitempty"`
	// CarriedTok: Token is a carried token (an hs.resp, hs.fin or
	// hs.confirm deposited with the token its handshake carried, 0.88.2
	// §6.3.1): token_revoked on it drops the entry and discards that
	// handshake's carried tokens (§8.6).
	CarriedTok bool `json:"carried_tok,omitempty"`
	// Held is the inner plaintext (sealed-mode JSON, no seq) of a message
	// made while the peer's current epoch was demoted by an ik link
	// (§3.4.1: nothing is sent until a new epoch is established); it is
	// sealed under that epoch when it is established (sealHeld), and has
	// no Payload until then.
	Held []byte `json:"held,omitempty"`
	// HeldExp is the held message's exp (zero: none): past it the entry
	// is discarded, not sealed (0.86.2).
	HeldExp time.Time `json:"held_exp,omitzero"`
	// Tried (0.88.7 §8.3): a deposit of this entry may have reached the
	// relay (accepted, or no relay answer: a transport error, or a 5xx
	// without a relay error code), so the peer may hold its inner id: a
	// re-seal keeps its ts (sealHeld).
	Tried bool `json:"tried,omitempty"`
	// Unconfirmed (card GC #6875, the late window, lead a #7901): the member
	// was told this message may not have been delivered (deposited with a ts
	// older than RestampAfter, as it is), once; it still goes.
	Unconfirmed bool `json:"unconfirmed,omitempty"`
	// InnerID (0.88.7) is the inner id of the message a durable deposit
	// carries, for the not-delivered audit's ref (§8.3, §10.9); "" for a
	// handshake message or an entry written before.
	InnerID string `json:"inner_id,omitempty"`
	// Ephemeral (0.88.7): the message is of an ephemeral type (§8.5); at a
	// key change the entry ends silently.
	Ephemeral bool   `json:"ephemeral,omitempty"`
	FinEpoch  []byte `json:"fin_epoch,omitempty"`
	Handshake bool   `json:"handshake,omitempty"`
}

// AuditEntry records a dropped or refused message (§6.3, §6.6, §7.3).
// It never contains plaintext, keys or tokens.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	PeerID string    `json:"peer_id,omitempty"`
	// Ref (0.88.7) is the message's inner id for drop.undelivered_* and
	// drop.stale_or_future (§10.9); "" otherwise.
	Ref string `json:"ref,omitempty"`
}

// Settings are the owner's settings (§10.8), versioned as one object.
type Settings struct {
	Version             uint64            `json:"version,omitempty"`
	AutoApproveInPerson bool              `json:"auto_approve_in_person"`
	CredentialUnlockTTL uint64            `json:"credential_unlock_ttl,omitempty"` // seconds; 0 = default
	FeedRetentionDays   uint64            `json:"feed_retention_days,omitempty"`
	App                 map[string]string `json:"app,omitempty"`
	NoBackup            bool              `json:"no_backup,omitempty"` // credential.backup off (§3.5.6)
	// The member's own location log (§10.16): off by default.
	LocationHistory        bool   `json:"location_history,omitempty"`
	LocationHistoryDays    uint64 `json:"location_history_days,omitempty"`     // 0 = default
	LocationHistorySeconds uint64 `json:"location_history_interval,omitempty"` // seconds; 0 = default
	// The daily owner check (§3.6.2, §3.6.7): the interval (0 = 24 h) and
	// the hold switch (off only through a successful check).
	OwnerCheckSeconds uint64     `json:"owner_check_interval,omitempty"`
	HoldOff           bool       `json:"hold_off,omitempty"`
	HoldOffUntil      *time.Time `json:"hold_off_until,omitempty"`
	// The idle lock (§3.6.8, 0.29.0, release L): seconds past the
	// owner-check deadline; 0 = the default, 7 days.
	IdleLockSeconds uint64 `json:"idle_lock_after,omitempty"`
}
