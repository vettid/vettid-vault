package vault

import (
	"encoding/json"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// State is the DEK-encrypted vault state (§3.3). It is serialized as JSON
// and encrypted under the DEK on every flush. It is secret in its entirety.
type State struct {
	V        int    `json:"v"`
	VaultID  string `json:"vault_id"`
	UserGUID string `json:"user_guid"`
	StateSeq uint64 `json:"state_seq"`

	Relay        RelayState        `json:"relay"`
	IdentitySeed []byte            `json:"ik_seed"`
	KEMSeed      []byte            `json:"kem_seed"`
	RetiredKEMs  []RetiredKEM      `json:"retired_kems,omitempty"`
	Rotations    []json.RawMessage `json:"rotations,omitempty"` // own identity.rotate chain (§3.4)
	WakeSeed     []byte            `json:"wake_seed"`

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

	SeenMsgIDs map[string]time.Time      `json:"seen_msg_ids"` // relay msg_id dedupe (16 d)
	SeenInner  map[string]time.Time      `json:"seen_inner"`   // principal|inner id (16 d)
	Responses  map[string]CachedResponse `json:"responses"`    // principal|inner id (24 h)
	Outbox     []*OutboxEntry            `json:"outbox"`
	Audit      []AuditEntry              `json:"audit"`

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

	// OwnerCheck is the daily owner check's record (§3.6.1); nil in a
	// vault from before 0.13.0 until its first start.
	OwnerCheck *OwnerCheck `json:"owner_check,omitempty"`
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
	// PairGrants are an agent's initial LEASH grants, from the pairing
	// approval until the pairing completes (§6.7, §10.11).
	PairGrants json.RawMessage `json:"pair_grants,omitempty"`
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

// Token kinds (§7.1).
const (
	TokStanding  = "standing"
	TokReconnect = "reconnect"
	TokOpen      = "open"
	// TokRequest covers only the rest of a handshake that awaits
	// approval and connection.approved (§7.1, 0.10.3).
	TokRequest = "request"
)

// IssuedToken is one entry of the issued-token registry (§7, §3.3).
type IssuedToken struct {
	JTI    string    `json:"jti"`
	Kind   string    `json:"kind"`
	Sub    string    `json:"sub"` // base64 relay key, "*" for open tokens
	PeerID string    `json:"peer_id,omitempty"`
	Exp    time.Time `json:"exp"`
	Denied bool      `json:"denied,omitempty"`
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
	ID         string    `json:"id"`
	Op         string    `json:"op"`
	PeerID     string    `json:"peer_id,omitempty"`
	RelayURL   string    `json:"relay_url,omitempty"`
	Mailbox    string    `json:"mailbox,omitempty"`
	Token      string    `json:"token,omitempty"`
	Payload    []byte    `json:"payload,omitempty"`
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
}

// AuditEntry records a dropped or refused message (§6.3, §6.6, §7.3).
// It never contains plaintext, keys or tokens.
type AuditEntry struct {
	At     time.Time `json:"at"`
	Event  string    `json:"event"`
	PeerID string    `json:"peer_id,omitempty"`
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
}
