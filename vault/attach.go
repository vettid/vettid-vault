package vault

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Message attachments (VAULT-MESSAGING 0.32.0 §10.5.1, release A). The
// messaging feature keeps the messages; this file keeps the attachment
// index (vault state, §3.3), its limits and views, and the decisions on
// what arrives from devices and peers. attach_run.go moves the blobs and
// writes the objects in the background.
//
// Write order (§10.5.1): an entry is created in the same flush as its
// message and the request's or event's inner-id record, with both
// objects not written and the thumbnail held in it; an object is written
// only once a flushed entry names it, and marked written (with its store
// version) in a later flush; an entry is removed only after its objects
// are deleted. At unlock the runner finishes what a lock or crash
// interrupted, from the flags.

// Attachment states (§10.5.1 "The views").
const (
	AttPreparing = "preparing"
	AttSending   = "sending"
	AttDelivered = "delivered"
	AttFetching  = "fetching"
	AttStored    = "stored"
	AttFailed    = "failed"
)

// Failure reasons (§10.5.1).
const (
	ReasonBad         = "bad"
	ReasonType        = "type"
	ReasonUnsupported = "unsupported"
	ReasonRefused     = "refused"
	ReasonMissing     = "missing"
	ReasonUnconfirmed = "unconfirmed"
	ReasonRemoved     = "removed"
	ReasonFull        = "full"
	ReasonRate        = "rate"
	ReasonExpired     = "expired"
	ReasonWithdrawn   = "withdrawn"
)

// Statuses of message.attachment.status.
const (
	StatusStored    = "stored"
	StatusMissing   = "missing"
	StatusRefused   = "refused"
	StatusWithdrawn = "withdrawn"
)

// Message types of attachments.
const (
	TypeAttDeliver = "message.attachment.deliver"
	TypeAttStatus  = "message.attachment.status"
	TypeAttGet     = "message.attachment.get"
	TypeAttDiscard = "message.attachment.discard"
)

// AttachState is the attachment index and its bookkeeping, in vault state.
type AttachState struct {
	Entries map[string]*AttEntry `json:"entries"`
	// Accepted are the attachments accepted from each connection within
	// the rolling 24 hours (peer_attachments, §7.3).
	Accepted map[string][]AttStamp `json:"accepted,omitempty"`
	// Reuploads are the fresh uploads made for each connection on its
	// missing within the rolling 24 hours (peer_reuploads).
	Reuploads map[string][]AttStamp `json:"reuploads,omitempty"`
	// Turns is each connection's receiving turn (missing_turn).
	Turns map[string]*AttTurn `json:"turns,omitempty"`
	// Refreshed is when each connection was last granted a fresh
	// standing token after quota_exceeded (§7.2).
	Refreshed map[string]time.Time `json:"refreshed,omitempty"`
	// Renewed is when each connection last got a refresh near its token's
	// end: at most one an hour (§7.2, owner decision of 2026-10-15).
	Renewed map[string]time.Time `json:"renewed,omitempty"`
	// Gone are outgoing attachments the member deleted, until their
	// missing_window ends: a missing for one is answered withdrawn
	// (deleted), not ignored (§10.5.1 "Delivery to the peer").
	Gone []AttGone `json:"gone,omitempty"`
	// PurgedAt is when the orphan purge last ran.
	PurgedAt time.Time `json:"purged_at,omitempty"`
	// FullFed is when each connection's last refusal for a full store made
	// a feed item: at most one a day per connection (coalesced).
	FullFed map[string]time.Time `json:"full_fed,omitempty"`
}

// AttStamp is one counted attachment or upload.
type AttStamp struct {
	At    time.Time `json:"at"`
	Bytes int64     `json:"bytes"`
	Att   string    `json:"att,omitempty"`
}

// AttTurn is the attachment a connection is asked for now.
type AttTurn struct {
	Att   string    `json:"att"`
	Since time.Time `json:"since"`
}

// AttGone is a deleted outgoing attachment.
type AttGone struct {
	Conn  string    `json:"conn"`
	Msg   string    `json:"msg"`
	Until time.Time `json:"until"`
}

// AttBlob is a claim-check reference to a blob in the vault's own mailbox
// (a device's upload, or a peer's).
type AttBlob struct {
	ID      string    `json:"id"`
	Key     []byte    `json:"key"`
	SHA256  []byte    `json:"sha256"`
	Size    int       `json:"size"`
	Expires time.Time `json:"expires,omitempty"`
}

// AttEntry is one attachment of the index (§10.5.1 "The index").
type AttEntry struct {
	ID       string `json:"id"`
	Conn     string `json:"conn"`
	Msg      string `json:"msg"`
	Dir      string `json:"dir"` // "in" or "out"
	Kind     string `json:"kind"`
	Mime     string `json:"mime,omitempty"` // sniffed, once the content is stored
	Size     int    `json:"size"`
	ThumbLen int    `json:"thumb_len"`
	Width    int    `json:"w"`
	Height   int    `json:"h"`
	Name     string `json:"name,omitempty"`
	HasName  bool   `json:"has_name,omitempty"`
	Key      []byte `json:"k"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`

	// The objects: written flags and their store versions.
	CW   bool          `json:"cw,omitempty"`
	CVer store.Version `json:"cv,omitempty"`
	TW   bool          `json:"tw,omitempty"`
	TVer store.Version `json:"tv,omitempty"`
	// Thumb is held until its object is written.
	Thumb []byte `json:"thumb,omitempty"`
	// Erasing: being deleted (message.delete); removed once its objects
	// are gone.
	Erasing bool `json:"erasing,omitempty"`

	// SentAt: out, the message's sent_at; in, its arrival in this vault
	// (the windows, never the peer's sent_at).
	SentAt time.Time `json:"sent_at"`
	// Blob is the upload to fetch from the own mailbox: the device's
	// (out, preparing) or the peer's (in, fetching).
	Blob *AttBlob `json:"blob,omitempty"`
	// Uploader is the device that sent the message (out).
	Uploader string `json:"uploader,omitempty"`
	// Caption is the message's text until the first deliver is queued
	// (out); HasCaption tells "" from none.
	Caption    string `json:"caption,omitempty"`
	HasCaption bool   `json:"has_caption,omitempty"`
	// DeliverID is the inner id of the latest message.attachment.deliver
	// (out), matched to an unsupported_type answer; DeliverAt when the
	// first was queued.
	DeliverID string    `json:"deliver_id,omitempty"`
	DeliverAt time.Time `json:"deliver_at,omitempty"`
	// Reoffers counts uploads after the first (out); Owed is an upload a
	// missing asked for, not made yet.
	Reoffers int  `json:"reoffers,omitempty"`
	Owed     bool `json:"owed,omitempty"`
	// TokenAsked: a fresh standing token was asked for after a token
	// quota (out), with the token's expiry at the time.
	TokenAsked time.Time `json:"token_asked,omitempty"`
	TokenExp   time.Time `json:"token_exp,omitempty"`
	TokenTried bool      `json:"token_tried,omitempty"`
	// LatePending: the window ended while the vault was locked; one
	// delivery attempt follows the unlock before it fails (§10.5.1).
	LatePending bool `json:"late,omitempty"`
	// Fetches counts fetches that failed their checks (in); Asked: the
	// vault asked for an upload with missing since the last one arrived;
	// AskedAt and Backoff the missing_backoff.
	Fetches int           `json:"fetches,omitempty"`
	Asked   bool          `json:"asked,omitempty"`
	AskedAt time.Time     `json:"asked_at,omitempty"`
	Backoff time.Duration `json:"backoff,omitempty"`
	// NotBefore and Attempts schedule the retry of a transient failure.
	NotBefore time.Time `json:"not_before,omitempty"`
	Attempts  int       `json:"attempts,omitempty"`
	// Stopped: the peer's mailbox refused for good (token_revoked,
	// mailbox_unknown): no more uploads; the window decides.
	Stopped bool `json:"stopped,omitempty"`
	// Corrupt counts reads of its objects that did not open (a damaged
	// object); at attCorruptMax the attachment fails (bad).
	Corrupt int `json:"corrupt,omitempty"`
}

// attCorruptMax is how many times an object that does not open is read
// again (with the retry's backoff) before its attachment fails.
const attCorruptMax = 3

// GoneMax bounds the list of deleted outgoing attachments kept for
// withdrawn{deleted} (as many as the index holds).
const GoneMax = attwire.CountMax

// dropBlob deletes the entry's blob of the own mailbox (best effort) and
// wipes its key.
func (m *Manager) dropBlob(e *AttEntry) {
	if e.Blob == nil {
		return
	}
	m.attDropBlob(e.Blob.ID)
	suite.Wipe(e.Blob.Key)
	e.Blob = nil
}

// wipeEntry wipes an entry's secrets: k_att, a blob key, a held thumbnail.
func (e *AttEntry) wipe() {
	suite.Wipe(e.Key)
	suite.Wipe(e.Thumb)
	if e.Blob != nil {
		suite.Wipe(e.Blob.Key)
	}
}

func (st *State) attach() *AttachState {
	if st.Attach == nil {
		st.Attach = &AttachState{}
	}
	a := st.Attach
	if a.Entries == nil {
		a.Entries = map[string]*AttEntry{}
	}
	if a.Accepted == nil {
		a.Accepted = map[string][]AttStamp{}
	}
	if a.Reuploads == nil {
		a.Reuploads = map[string][]AttStamp{}
	}
	if a.Turns == nil {
		a.Turns = map[string]*AttTurn{}
	}
	if a.Refreshed == nil {
		a.Refreshed = map[string]time.Time{}
	}
	if a.FullFed == nil {
		a.FullFed = map[string]time.Time{}
	}
	if a.Renewed == nil {
		a.Renewed = map[string]time.Time{}
	}
	return a
}

// contentBytes is what an entry's content counts against the store: its
// size once stored; its declared size while the own sending prepares it,
// or while a received one's fetch is in progress (inFlight); nothing while
// a received one waits for an upload (owner decision of 2026-10-15: a
// waiting attachment holds no room), or once it failed without content.
func (e *AttEntry) contentBytes(inFlight bool) int64 {
	if e.CW || e.State == AttPreparing || e.State == AttFetching && inFlight {
		return int64(e.Size)
	}
	return 0
}

// attInFlight reports whether a transfer of the entry is in progress.
func (m *Manager) attInFlight(e *AttEntry) bool { return m.att != nil && m.att.running[e.ID] }

// attUsage is the store's use: count and bytes, and one connection's
// received bytes (peer_storage) if conn is set.
func (m *Manager) attUsage(conn string) (count int, bytes, peer int64) {
	if m.st.Attach == nil {
		return 0, 0, 0
	}
	for _, e := range m.st.Attach.Entries {
		count++
		b := e.contentBytes(m.attInFlight(e)) + int64(e.ThumbLen)
		bytes += b
		if conn != "" && e.Conn == conn && e.Dir == DirIn {
			peer += b
		}
	}
	return
}

// DirIn and DirOut are an attachment's directions.
const (
	DirIn  = "in"
	DirOut = "out"
)

// attMaxContent is attachment_max_bytes for the vault's relay; 0 when the
// relay advertises no blobs (attachments are then not offered, §1.2).
func (m *Manager) attMaxContent() int {
	l := m.limits
	if l.MaxBlobBytes == nil || l.BlobTTLSeconds == nil || *l.MaxBlobBytes <= 0 {
		return 0
	}
	return envelope.MaxBlobContent(int(*l.MaxBlobBytes))
}

func (m *Manager) attMaxBlob() int {
	if m.limits.MaxBlobBytes == nil {
		return 0
	}
	return int(*m.limits.MaxBlobBytes)
}

// AttView is an attachment's device view (§10.5.1).
type AttView struct {
	AttID         string
	Kind          string
	Mime          string
	Size          int
	Width, Height int
	Name          string
	HasName       bool
	State, Reason string
	Thumb         []byte
}

func (e *AttEntry) view() AttView {
	v := AttView{AttID: e.ID, Kind: e.Kind, Size: e.Size, Width: e.Width, Height: e.Height, Name: e.Name, HasName: e.HasName,
		State: e.State, Reason: e.Reason}
	if e.CW {
		v.Mime = e.Mime // the type the vault sniffed, once stored
	}
	return v
}

// JSON renders the device view; withThumb adds thumb when it is known,
// desktop leaves out thumb and name (§10.5.1 "Desktops").
func (v AttView) JSON(withThumb, desktop bool) []byte {
	b := strictjson.NewBuilder().String("att_id", v.AttID).String("kind", v.Kind)
	if v.Mime != "" {
		b.String("mime", v.Mime)
	}
	b.Uint("size", uint64(v.Size)).Uint("width", uint64(v.Width)).Uint("height", uint64(v.Height))
	if v.HasName && !desktop {
		b.String("name", v.Name)
	}
	b.String("state", v.State)
	if v.Reason != "" {
		b.String("reason", v.Reason)
	}
	if withThumb && !desktop && len(v.Thumb) > 0 {
		b.Base64("thumb", v.Thumb)
	}
	return b.Bytes()
}

// AttachmentHost is what the messaging feature asks of the runtime for
// attachments (managerHost implements it). Every method runs with the
// vault's lock held, inside the handler of the message.
type AttachmentHost interface {
	// AttachMaxContent is attachment_max_bytes, 0 without relay blobs.
	AttachMaxContent() int
	// AttachSend checks a device's attachment and creates its entry
	// (sending steps 3-4); it returns the att_id.
	AttachSend(s *Session, conn, msgID string, sentAt time.Time, caption string, hasCaption bool, d *attwire.DeviceSend) (string, error)
	// AttachRefusedSend deletes the blob a refused message.send names.
	AttachRefusedSend(s *Session, blobID string)
	// AttachReceive decides on a new message's attachment from a peer
	// (receiving step 1): an entry (att_id) or a refusal (reason, a view
	// to store with the message).
	AttachReceive(s *Session, msgID string, v *attwire.PeerView) (attID string, refused *AttView)
	// AttachRedeliver handles a known message_id's deliver (step 4).
	AttachRedeliver(s *Session, msgID string, v *attwire.PeerView)
	// AttachStatus handles message.attachment.status from a peer.
	AttachStatus(s *Session, body []byte) error
	// AttachGet answers message.attachment.get (ErrDeferred: answered
	// later, for content).
	AttachGet(s *Session, conn, msgID, attID, part string) (json.RawMessage, error)
	// AttachDiscard handles message.attachment.discard.
	AttachDiscard(s *Session, blobID string)
	// AttachErase erases a deleted message's attachment.
	AttachErase(s *Session, attID string)
	// AttachView returns an attachment's device view.
	AttachView(attID string) (AttView, bool)
}

// ErrDeferred from a handler: the request is answered later (a volatile
// answer, §10.5.1 "Fetching"), not now.
var ErrDeferred = errors.New("vault: answered later")

// Attachments returns the session's AttachmentHost (nil without one).
func (s *Session) Attachments() AttachmentHost {
	if h, ok := s.host.(AttachmentHost); ok {
		return h
	}
	return nil
}

func (h managerHost) AttachMaxContent() int { return h.m.attMaxContent() }

func (h managerHost) AttachView(attID string) (AttView, bool) {
	if h.m.st.Attach == nil {
		return AttView{}, false
	}
	e := h.m.st.Attach.Entries[attID]
	if e == nil {
		return AttView{}, false
	}
	v := e.view()
	v.Thumb = e.Thumb
	return v, true
}

// attNotify sends sync.event{message.attachment} for an entry's state
// change to every owner device (§10.5.1). Messages go out at the real
// time, whatever clock the windows run on.
func (m *Manager) attNotify(e *AttEntry, _ time.Time) {
	now := m.now()
	b := strictjson.NewBuilder().String("kind", "message.attachment").String("connection_id", e.Conn).
		String("message_id", e.Msg).String("state", e.State)
	if e.Reason != "" {
		b.String("reason", e.Reason)
	}
	m.notifyDevices("sync.event", b.Bytes(), "", now)
}

// attSet changes an entry's state and tells the owner's devices.
func (m *Manager) attSet(e *AttEntry, state, reason string, now time.Time) {
	if e.State == state && e.Reason == reason {
		return
	}
	e.State, e.Reason = state, reason
	if state == AttFailed || state == AttStored || state == AttDelivered {
		e.Owed = false
		if state != AttFailed || !e.CW {
			e.NotBefore = time.Time{}
		}
	}
	m.dirty = true
	m.attNotify(e, now)
	m.attWake()
}

// attFail fails an entry: audited message.attachment_failed (ref
// message_id, §10.5.1 "History and search"), and for an outgoing one that the member must know
// about (unsupported, refused, missing, unconfirmed) the feed item.
func (m *Manager) attFail(e *AttEntry, reason string, now time.Time) {
	if e.State == AttFailed && e.Reason == reason {
		return
	}
	m.attSet(e, AttFailed, reason, now)
	rt := m.now()
	m.record(Activity{Kind: "message.attachment_failed", ConnectionID: e.Conn, Ref: e.Msg, Direction: e.Dir, Audit: true}, rt)
	if e.Dir == DirOut {
		switch reasonBase(reason) {
		case ReasonUnsupported, ReasonRefused, ReasonMissing, ReasonUnconfirmed:
			m.record(Activity{Kind: "message.attachment_failed", ConnectionID: e.Conn, Ref: e.Msg, Direction: e.Dir, Feed: true}, rt)
		}
	}
	m.dropBlob(e)
}

func reasonBase(r string) string {
	for i := 0; i < len(r); i++ {
		if r[i] == ':' {
			return r[:i]
		}
	}
	return r
}

// newAttEntry creates an entry with a fresh k_att and att_id.
func (m *Manager) newAttEntry(now time.Time) (*AttEntry, error) {
	k, err := suite.RandomBytes(suite.KeySize)
	if err != nil {
		return nil, err
	}
	return &AttEntry{ID: m.newID(now), Key: k}, nil
}

// AttachSend: sending steps 3 and 4 (§10.5.1). The shape and the
// connection were checked by the feature.
func (h managerHost) AttachSend(s *Session, conn, msgID string, sentAt time.Time, caption string, hasCaption bool, d *attwire.DeviceSend) (string, error) {
	m := h.m
	now := s.now
	lim := m.attLim()
	count, used, _ := m.attUsage("")
	add := int64(d.Blob.Size) + int64(len(d.Thumb))
	if used+add > lim.Storage {
		if !m.attBlobNamed(d.Blob.ID) {
			m.attDropBlob(d.Blob.ID)
		}
		return "", LimitSizeError("attachment_storage", int(lim.Storage), int(used+add))
	}
	if count >= lim.Count {
		if !m.attBlobNamed(d.Blob.ID) {
			m.attDropBlob(d.Blob.ID)
		}
		return "", LimitError("attachments", lim.Count)
	}
	if m.attBlobNamed(d.Blob.ID) {
		return "", errBadRequest // a blob already named by another attachment
	}
	e, err := m.newAttEntry(now)
	if err != nil {
		return "", NewError("internal", "")
	}
	e.Conn, e.Msg, e.Dir, e.Kind = conn, msgID, DirOut, d.Kind
	e.Size, e.ThumbLen, e.Width, e.Height = d.Blob.Size, len(d.Thumb), d.Width, d.Height
	e.Name, e.HasName = d.Blob.Name, d.Blob.HasName
	e.State, e.SentAt = AttPreparing, sentAt
	e.Thumb = append([]byte(nil), d.Thumb...)
	e.Blob = &AttBlob{ID: d.Blob.ID, Key: append([]byte(nil), d.Blob.Key...), SHA256: append([]byte(nil), d.Blob.SHA256[:]...), Size: d.Blob.Size}
	e.Uploader = s.from.ID
	e.Caption, e.HasCaption = caption, hasCaption
	m.st.attach().Entries[e.ID] = e
	m.dirty = true
	m.attWake()
	return e.ID, nil
}

// attBlobNamed reports whether an entry names a blob of the own mailbox.
func (m *Manager) attBlobNamed(id string) bool {
	if m.st.Attach == nil {
		return false
	}
	for _, e := range m.st.Attach.Entries {
		if e.Blob != nil && e.Blob.ID == id {
			return true
		}
	}
	return false
}

func (h managerHost) AttachRefusedSend(_ *Session, blobID string) {
	if envelope.ValidULID(blobID) && !h.m.attBlobNamed(blobID) {
		h.m.attDropBlob(blobID)
	}
}

// attRefusedSendBody deletes the blob that a message.send refused before
// its handler names (§10.5.1: every refusal of a message.send that names
// a blob deletes the blob, best effort).
func (m *Manager) attRefusedSendBody(body []byte) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return
	}
	a, err := o.Object("attachment")
	if err != nil {
		return
	}
	b, err := a.Object("blob")
	if err != nil {
		return
	}
	if id, err := b.String("id"); err == nil && envelope.ValidULID(id) && !m.attBlobNamed(id) {
		m.attDropBlob(id)
	}
}

// pruneStamps drops stamps older than the rolling window and returns the
// count and bytes left.
func pruneStamps(s []AttStamp, now time.Time) ([]AttStamp, int, int64) {
	kept := s[:0]
	var n int
	var b int64
	for _, x := range s {
		if now.Sub(x.At) < attwire.RollingWindow {
			kept = append(kept, x)
			n++
			b += x.Bytes
		}
	}
	return kept, n, b
}

// AttachReceive: receiving step 1 for a new message_id.
func (h managerHost) AttachReceive(s *Session, msgID string, v *attwire.PeerView) (string, *AttView) {
	m := h.m
	now := m.attNow()
	conn := s.from.ID
	a := m.st.attach()
	lim := m.attLim()
	refuse := func(reason string) (string, *AttView) {
		rv := &AttView{Kind: v.Kind, Size: v.Size, Width: v.Width, Height: v.Height, State: AttFailed, Reason: reason}
		if v.Blob != nil && !m.attBlobNamed(v.Blob.ID) {
			m.attDropBlob(v.Blob.ID)
		}
		body := strictjson.NewBuilder().String("message_id", msgID).String("status", StatusRefused)
		switch reason {
		case ReasonRate, ReasonType:
			body.String("reason", reason)
		} // full: no reason, so the sender learns only that it failed
		m.attSendStatus(conn, body, now)
		rt := s.now
		switch reason {
		case ReasonRate:
			m.record(Activity{Kind: "drop.attachment_rate", ConnectionID: conn, Ref: msgID, Audit: true}, rt)
		default:
			m.record(Activity{Kind: "message.attachment_refused", ConnectionID: conn, Ref: msgID, Direction: DirIn, Audit: true}, rt)
		}
		if reason == ReasonFull {
			// The member learns that the store is full; refusals of one
			// connection within a day make one feed item.
			if t, ok := a.FullFed[conn]; !ok || now.Sub(t) >= 24*time.Hour {
				a.FullFed[conn] = now
				m.record(Activity{Kind: "message.attachment_refused", ConnectionID: conn, Ref: msgID, Direction: DirIn, Feed: true}, rt)
			}
		}
		return "", rv
	}
	if v.Kind != attwire.KindPhoto || v.ThumbBad {
		return refuse(ReasonType)
	}
	add := int64(v.Size) + int64(len(v.Thumb))
	var n int
	var b int64
	a.Accepted[conn], n, b = pruneStamps(a.Accepted[conn], now)
	if n >= lim.PeerAccept || b+add > lim.PeerAcceptBytes {
		return refuse(ReasonRate)
	}
	// The store limits: the thumbnail, and the content only when its blob
	// arrives (now, if one is named; else when it is uploaded on missing).
	need := int64(len(v.Thumb))
	if v.Blob != nil {
		need = add
	}
	count, used, peer := m.attUsage(conn)
	if peer+need > lim.PeerStorage || used+need > lim.Storage || count >= lim.Count {
		return refuse(ReasonFull)
	}
	if v.Blob != nil && m.attBlobNamed(v.Blob.ID) {
		return refuse(ReasonType) // a blob another attachment names: never fetched twice
	}
	e, err := m.newAttEntry(now)
	if err != nil {
		return refuse(ReasonFull)
	}
	e.Conn, e.Msg, e.Dir, e.Kind = conn, msgID, DirIn, v.Kind
	e.Size, e.ThumbLen, e.Width, e.Height = v.Size, len(v.Thumb), v.Width, v.Height
	e.State, e.SentAt = AttFetching, now.UTC()
	e.Thumb = append([]byte(nil), v.Thumb...)
	if v.Blob != nil {
		e.Blob = &AttBlob{ID: v.Blob.ID, Key: append([]byte(nil), v.Blob.Key...), SHA256: append([]byte(nil), v.Blob.SHA256[:]...),
			Size: v.Blob.Size, Expires: v.Expires}
		e.Name, e.HasName = v.Blob.Name, v.Blob.HasName
	}
	a.Accepted[conn] = append(a.Accepted[conn], AttStamp{At: now, Bytes: add, Att: e.ID})
	a.Entries[e.ID] = e
	m.dirty = true
	m.attWake()
	return e.ID, nil
}

// attFits reports whether a received entry's content fits the store limits
// (attachment_storage, peer_storage) as they are now, its own reservation
// left out.
func (m *Manager) attFits(e *AttEntry) bool {
	lim := m.attLim()
	_, used, peer := m.attUsage(e.Conn)
	if own := e.contentBytes(m.attInFlight(e)); own > 0 {
		used, peer = used-own, peer-own
	}
	return used+int64(e.Size) <= lim.Storage && peer+int64(e.Size) <= lim.PeerStorage
}

// attRefuseFull refuses a received attachment whose upload does not fit:
// failed (full), refused to the sender without a reason, audited, and the
// member's feed item (one a day per connection).
func (m *Manager) attRefuseFull(e *AttEntry, now time.Time) {
	m.attFail(e, ReasonFull, now)
	m.attSendStatus(e.Conn, strictjson.NewBuilder().String("message_id", e.Msg).String("status", StatusRefused), now)
	rt := m.now()
	m.record(Activity{Kind: "message.attachment_refused", ConnectionID: e.Conn, Ref: e.Msg, Direction: DirIn, Audit: true}, rt)
	a := m.st.attach()
	if t, ok := a.FullFed[e.Conn]; !ok || m.attNow().Sub(t) >= 24*time.Hour {
		a.FullFed[e.Conn] = m.attNow()
		m.record(Activity{Kind: "message.attachment_refused", ConnectionID: e.Conn, Ref: e.Msg, Direction: DirIn, Feed: true}, rt)
	}
}

// attUncount takes an entry out of its connection's peer_attachments.
func (m *Manager) attUncount(e *AttEntry) {
	a := m.st.attach()
	kept := a.Accepted[e.Conn][:0]
	for _, x := range a.Accepted[e.Conn] {
		if x.Att != e.ID {
			kept = append(kept, x)
		}
	}
	a.Accepted[e.Conn] = kept
}

// attByMsg finds the entry of a connection's message in a direction.
func (m *Manager) attByMsg(conn, msgID, dir string) *AttEntry {
	if m.st.Attach == nil {
		return nil
	}
	for _, e := range m.st.Attach.Entries {
		if e.Conn == conn && e.Msg == msgID && e.Dir == dir {
			return e
		}
	}
	return nil
}

// AttachRedeliver: receiving step 4, a known message_id. A fresh upload
// this vault asked for replaces the blob reference; anything else is
// ignored, and a named blob it will not fetch is deleted.
func (h managerHost) AttachRedeliver(s *Session, msgID string, v *attwire.PeerView) {
	m := h.m
	e := m.attByMsg(s.from.ID, msgID, DirIn)
	if e == nil || e.Erasing || e.State != AttFetching {
		if v.Blob != nil && (e == nil || e.Blob == nil || e.Blob.ID != v.Blob.ID) && !m.attBlobNamed(v.Blob.ID) {
			m.attDropBlob(v.Blob.ID)
		}
		return
	}
	if v.Blob == nil {
		// The sender's answer without a blob (the mailbox had no room for
		// it): asked again after the backoff (§10.5.1).
		return
	}
	if !e.Asked || e.Blob != nil && e.Blob.ID == v.Blob.ID || v.Blob.Size != e.Size || m.attBlobNamed(v.Blob.ID) {
		if !(e.Blob != nil && e.Blob.ID == v.Blob.ID) && !m.attBlobNamed(v.Blob.ID) {
			m.attDropBlob(v.Blob.ID)
		}
		return
	}
	if !m.attFits(e) {
		// The upload arrived: checked against the store limits now.
		m.attDropBlob(v.Blob.ID)
		m.attRefuseFull(e, s.now)
		return
	}
	if e.Blob != nil {
		suite.Wipe(e.Blob.Key)
	}
	e.Blob = &AttBlob{ID: v.Blob.ID, Key: append([]byte(nil), v.Blob.Key...), SHA256: append([]byte(nil), v.Blob.SHA256[:]...),
		Size: v.Blob.Size, Expires: v.Expires}
	if v.Blob.HasName && !e.HasName {
		e.Name, e.HasName = v.Blob.Name, true
	}
	e.Asked, e.Backoff, e.NotBefore, e.Attempts = false, 0, time.Time{}, 0 // the backoff restarts once an upload arrived
	m.dirty = true
	m.attWake()
}

// attSendStatus queues message.attachment.status to a connection (at the
// real time).
func (m *Manager) attSendStatus(conn string, body *strictjson.Builder, _ time.Time) {
	now := m.now()
	p := m.st.Connections[conn]
	if p == nil || p.State != PeerActive {
		return
	}
	m.sendTo(p, TypeAttStatus, body.String("at", envelope.FormatTS(now)).Bytes(), now)
}

// AttachStatus handles message.attachment.status (§10.5.1): stored,
// missing and refused from the recipient to the sender, withdrawn from
// the sender to the recipient. Malformed ones are dropped and audited.
func (h managerHost) AttachStatus(s *Session, body []byte) error {
	m := h.m
	now := m.attNow()
	conn := s.from.ID
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return m.attMalformed(conn, now)
	}
	msgID, err1 := o.String("message_id")
	st, err2 := o.String("status")
	at, err3 := o.String("at")
	reason, hasReason, err4 := o.OptString("reason")
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || !envelope.ValidULID(msgID) || hasReason && (reason == "" || len(reason) > 32) {
		return m.attMalformed(conn, now)
	}
	if _, err := envelope.ParseTS(at); err != nil {
		return m.attMalformed(conn, now)
	}
	switch st {
	case StatusStored, StatusMissing, StatusRefused:
		e := m.attByMsg(conn, msgID, DirOut)
		if st == StatusMissing {
			m.attMissing(conn, msgID, e, now)
			return nil
		}
		if e == nil || e.Erasing {
			return nil
		}
		if st == StatusStored {
			if e.State == AttSending || e.State == AttFailed && e.Reason == ReasonUnconfirmed {
				e.LatePending = false
				m.attSet(e, AttDelivered, "", now)
			}
			return nil
		}
		if e.State == AttSending || e.State == AttFailed && e.Reason == ReasonUnconfirmed {
			r := ReasonRefused
			if reason == ReasonRate || reason == ReasonType {
				r += ":" + reason
			}
			m.attFail(e, r, now)
		}
	case StatusWithdrawn:
		e := m.attByMsg(conn, msgID, DirIn)
		if e == nil || e.Erasing || e.State != AttFetching {
			return nil
		}
		switch reason {
		case "deleted", "limit", "expired":
			m.attFail(e, ReasonWithdrawn+":"+reason, now)
		default:
			m.attFail(e, ReasonWithdrawn, now)
		}
	default:
		return m.attMalformed(conn, now)
	}
	return nil
}

func (m *Manager) attMalformed(conn string, _ time.Time) error {
	m.record(Activity{Kind: "drop.attachment_malformed", ConnectionID: conn, Audit: true}, m.now())
	return nil
}

// attMissing is the sender's side of a missing (§10.5.1 "Delivery to the
// peer"): a fresh upload, or withdrawn with a reason; never silence for
// an attachment it sent.
func (m *Manager) attMissing(conn, msgID string, e *AttEntry, now time.Time) {
	withdraw := func(reason string) {
		m.attSendStatus(conn, strictjson.NewBuilder().String("message_id", msgID).String("status", StatusWithdrawn).String("reason", reason), now)
	}
	if e == nil || e.Erasing {
		// Deleted: withdrawn{deleted} until missing_window, unless it was
		// delivered or refused before (then ignored, as for one never sent).
		for _, g := range m.st.attach().Gone {
			if g.Conn == conn && g.Msg == msgID {
				withdraw("deleted")
				return
			}
		}
		return
	}
	switch {
	case e.State == AttDelivered, e.State == AttFailed && reasonBase(e.Reason) == ReasonRefused:
		return // the recipient has its answer
	case e.State == AttFailed && e.Reason == ReasonMissing:
		withdraw("limit")
		return
	case e.State != AttSending && !(e.State == AttFailed && e.Reason == ReasonUnconfirmed):
		return // never sent (preparing, bad, unsupported, removed)
	}
	if !e.CW {
		withdraw("deleted") // the attachment is gone
		return
	}
	if now.Sub(e.SentAt) > attwire.MissingWindow {
		withdraw("expired")
		return
	}
	if e.Reoffers >= m.attLim().Reoffers {
		withdraw("limit")
		m.attFail(e, ReasonMissing, now)
		return
	}
	if e.State == AttFailed {
		m.attSet(e, AttSending, "", now)
	}
	if !e.Owed {
		e.Owed = true
		e.NotBefore, e.Attempts, e.Stopped = time.Time{}, 0, false
		m.dirty = true
		m.attWake()
	}
}

// attUnsupported matches an unsupported_type answer to the deliver it
// answers (§5.3, §10.5.1): the attachment fails (unsupported). It
// reports whether the answer was one.
func (m *Manager) attUnsupported(p *Peer, in *envelope.Inner, now time.Time) bool {
	if m.st.Attach == nil || in.Status != envelope.StatusError || in.Error == nil || in.Error.Code != "unsupported_type" {
		return false
	}
	for _, e := range m.st.Attach.Entries {
		if e.Dir == DirOut && e.Conn == p.ID && e.DeliverID == in.Re && !e.Erasing &&
			(e.State == AttSending || e.State == AttFailed && e.Reason == ReasonUnconfirmed) && now.Sub(e.DeliverAt) < 14*24*time.Hour {
			m.attFail(e, ReasonUnsupported, now)
			return true
		}
	}
	return false
}

// AttachGet: message.attachment.get (§10.5.1 "Fetching"). The shape was
// checked by the feature (before the hold).
func (h managerHost) AttachGet(s *Session, conn, msgID, attID, part string) (json.RawMessage, error) {
	m := h.m
	if attID == "" || m.st.Attach == nil {
		return nil, errNotFound
	}
	e := m.st.Attach.Entries[attID]
	if e == nil || e.Erasing || e.Conn != conn || e.Msg != msgID {
		return nil, errNotFound
	}
	if part == attwire.PartThumb {
		t, err := m.attThumb(s, e)
		if err != nil {
			return nil, err
		}
		defer suite.Wipe(t)
		return strictjson.NewBuilder().Base64("thumb", t).Bytes(), nil
	}
	if !e.CW {
		return nil, NewError("unavailable", "") // not stored in this vault (§10.5.1)
	}
	if m.att == nil || m.att.fetchesOf(s.from.ID) >= attwire.DeviceFetches {
		return nil, LimitError("attachment_fetches", attwire.DeviceFetches)
	}
	m.att.queueFetch(&attFetch{device: s.from.ID, req: envelope.Inner{ID: s.inner.ID, Type: s.inner.Type}, att: e.ID, at: m.now()})
	return nil, ErrDeferred
}

// attThumb returns a thumbnail: held in the entry until its object is
// written, then read from the store.
func (m *Manager) attThumb(s *Session, e *AttEntry) ([]byte, error) {
	if !e.TW {
		if len(e.Thumb) == 0 {
			return nil, NewError("unavailable", "")
		}
		return append([]byte(nil), e.Thumb...), nil
	}
	obj, _, err := m.opt.Store.Get(s.Context(), attwire.ThumbKey(m.st.VaultID, e.ID))
	if err != nil {
		return nil, NewError("unavailable", "")
	}
	t, err := attwire.OpenObject(e.Key, m.st.VaultID, e.ID, attwire.PartThumb, obj)
	if err != nil {
		return nil, NewError("unavailable", "")
	}
	return t, nil
}

// AttachDiscard: the app's Cancel (§10.5.1). Answered {} in every case;
// the runner deletes the blob only when the relay's list says this
// device uploaded it and nothing names it.
func (h managerHost) AttachDiscard(s *Session, blobID string) {
	m := h.m
	p := m.st.Devices[s.from.ID]
	if p == nil || !envelope.ValidULID(blobID) || m.attBlobNamed(blobID) || m.att == nil {
		return
	}
	m.att.queueDiscard(blobID, p.Relay.PK)
}

// AttachErase: message.delete of a message with an attachment marks the
// entry erasing in its flush; the runner deletes the objects (and a blob
// of the own mailbox it held), then removes the entry (§10.5.1
// "Deletion"). k_att goes with the entry.
func (h managerHost) AttachErase(_ *Session, attID string) {
	m := h.m
	if m.st.Attach == nil {
		return
	}
	e := m.st.Attach.Entries[attID]
	if e == nil || e.Erasing {
		return
	}
	e.Erasing = true
	e.Owed = false
	m.dropBlob(e)
	if e.Dir == DirOut && e.State != AttDelivered && !(e.State == AttFailed && e.Reason != ReasonUnconfirmed) {
		a := m.st.attach()
		a.Gone = append(a.Gone, AttGone{Conn: e.Conn, Msg: e.Msg, Until: e.SentAt.Add(attwire.MissingWindow)})
		if n := len(a.Gone); n > GoneMax {
			a.Gone = append([]AttGone(nil), a.Gone[n-GoneMax:]...)
		}
	}
	m.dirty = true
	m.attWake()
}

// attConnectionRemoved: a connection removed or blocked (§10.5.1
// "Connections"): its transfers end, blobs of its in the own mailbox are
// deleted, and entries in progress fail (removed); stored ones stay.
func (m *Manager) attConnectionRemoved(conn string, now time.Time) {
	if m.st.Attach == nil {
		return
	}
	a := m.st.Attach
	for _, e := range a.Entries {
		if e.Conn != conn || e.Erasing {
			continue
		}
		if e.State == AttPreparing || e.State == AttSending || e.State == AttFetching {
			m.attFail(e, ReasonRemoved, now)
		}
		e.Owed = false
	}
	delete(a.Accepted, conn)
	delete(a.Reuploads, conn)
	delete(a.Turns, conn)
	delete(a.Refreshed, conn)
	delete(a.FullFed, conn)
	delete(a.Renewed, conn)
	m.dirty = true
}

// attStatusJSON is vault.status's attachments member (§10.2).
func (m *Manager) attStatusJSON() []byte {
	count, bytes, _ := m.attUsage("")
	lim := m.attLim()
	return strictjson.NewBuilder().Uint("count", uint64(count)).Uint("bytes", uint64(bytes)).
		Uint("max_count", uint64(lim.Count)).Uint("max_bytes", uint64(lim.Storage)).Bytes()
}

// attHousekeeping applies the windows (§10.5.1) before each batch and in
// the runner: unconfirmed after attachment_window, expired after
// missing_window, the Gone list's end. It does no I/O.
func (m *Manager) attHousekeeping(now time.Time) {
	a := m.st.Attach
	if a == nil {
		return
	}
	for _, e := range sortedEntries(a) {
		if e.Erasing {
			continue
		}
		switch {
		case e.Dir == DirOut && e.State == AttSending && e.Owed && (e.Stopped || now.Sub(e.SentAt) > attwire.MissingWindow):
			// A fresh upload owed to a peer whose mailbox refused for good,
			// or past missing_window: it can never be made.
			e.Owed = false
			m.attFail(e, ReasonUnconfirmed, now)
		case e.Dir == DirOut && e.State == AttSending && now.Sub(e.SentAt) >= attwire.Window && !e.Owed &&
			(!e.LatePending || m.attPeerReady(e.Conn) == nil):
			m.attFail(e, ReasonUnconfirmed, now)
		case e.Dir == DirIn && e.State == AttFetching && now.Sub(e.SentAt) >= attwire.MissingWindow:
			m.attFail(e, ReasonExpired, now)
		}
	}
	kept := a.Gone[:0]
	for _, g := range a.Gone {
		if now.Before(g.Until) {
			kept = append(kept, g)
		}
	}
	a.Gone = kept
	for c, s := range a.Reuploads {
		if a.Reuploads[c], _, _ = pruneStamps(s, now); len(a.Reuploads[c]) == 0 {
			delete(a.Reuploads, c)
		}
	}
	for c, s := range a.Accepted {
		if a.Accepted[c], _, _ = pruneStamps(s, now); len(a.Accepted[c]) == 0 {
			delete(a.Accepted, c)
		}
	}
	for c, t := range a.Refreshed {
		if now.Sub(t) > 24*time.Hour {
			delete(a.Refreshed, c)
		}
	}
	for c, t := range a.Renewed {
		if now.Sub(t) > time.Hour {
			delete(a.Renewed, c)
		}
	}
	for c, t := range a.FullFed {
		if now.Sub(t) > 24*time.Hour {
			delete(a.FullFed, c)
		}
	}
}

// attLateAtUnlock marks outgoing attachments whose window ended while the
// vault was locked: one delivery attempt follows before they fail.
func (m *Manager) attLateAtUnlock(now time.Time) {
	if m.st.Attach == nil {
		return
	}
	for _, e := range m.st.Attach.Entries {
		if e.Dir == DirOut && e.State == AttSending && !e.Erasing && now.Sub(e.SentAt) >= attwire.Window {
			e.LatePending = true
			e.NotBefore, e.Stopped = time.Time{}, false
			m.dirty = true
		}
	}
}

// sortedEntries returns the entries oldest first (by att_id, a ULID).
func sortedEntries(a *AttachState) []*AttEntry {
	out := make([]*AttEntry, 0, len(a.Entries))
	for _, e := range a.Entries {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// attObjects lists the store keys of every attachment object the index
// names (§12.5 step 3): a written one with its recorded version, one not
// marked written with "" (read, then deleted, a missing one counting as
// deleted: an earlier attempt may have left it). No key material.
func (m *Manager) attObjects() []storedObject {
	if m.st == nil || m.st.Attach == nil {
		return nil
	}
	var out []storedObject
	for _, e := range sortedEntries(m.st.Attach) {
		c, t := storedObject{Key: attwire.ContentKey(m.st.VaultID, e.ID)}, storedObject{Key: attwire.ThumbKey(m.st.VaultID, e.ID)}
		if e.CW {
			c.Ver = e.CVer
		}
		if e.TW {
			t.Ver = e.TVer
		}
		out = append(out, c, t)
	}
	return out
}

// storedObject is a store key with the version to delete it at.
type storedObject struct {
	Key string
	Ver store.Version
}

// MailboxBlobs lists the blobs in the vault's own relay mailbox (tests and
// tools; RELAY-PROTOCOL 0.9.2 §6.8).
func (m *Manager) MailboxBlobs(ctx context.Context) (BlobList, error) {
	m.mu.Lock()
	if m.locked || m.relay == nil {
		m.mu.Unlock()
		return BlobList{}, ErrLocked
	}
	r := m.relay
	m.mu.Unlock()
	return r.ListBlobs(ctx)
}

// AttachEntries returns a copy of the attachment index without keys or
// thumbnails (tests and tools).
func (m *Manager) AttachEntries() []AttEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.st == nil || m.st.Attach == nil {
		return nil
	}
	var out []AttEntry
	for _, e := range sortedEntries(m.st.Attach) {
		c := *e
		c.Key, c.Thumb, c.Caption = nil, nil, ""
		if e.Blob != nil {
			b := *e.Blob
			b.Key = nil
			c.Blob = &b
		}
		out = append(out, c)
	}
	return out
}

// AttachLimits are the release constants that bound attachments
// (§10.5.1); Options.AttachLimits lowers them in tests.
type AttachLimits struct {
	Storage           int64 // attachment_storage
	Count             int   // attachments
	PeerStorage       int64 // peer_storage
	PeerAccept        int   // peer_attachments, count
	PeerAcceptBytes   int64 // peer_attachments, bytes
	PeerReuploads     int   // peer_reuploads, count
	PeerReuploadBytes int64 // peer_reuploads, bytes
	Reoffers          int   // attachment_reoffers
}

// DefaultAttachLimits are release A's.
var DefaultAttachLimits = AttachLimits{Storage: attwire.StorageMax, Count: attwire.CountMax, PeerStorage: attwire.PeerStorageMax,
	PeerAccept: attwire.PeerAcceptMax, PeerAcceptBytes: attwire.PeerAcceptBytes, PeerReuploads: attwire.PeerReuploadMax,
	PeerReuploadBytes: attwire.PeerReuploadByte, Reoffers: attwire.Reoffers}

func (m *Manager) attLim() AttachLimits {
	if l := m.opt.AttachLimits; l != nil {
		return *l
	}
	return DefaultAttachLimits
}

// attNow is the clock of the attachment windows (Options.AttachClock in
// tests, which move it while the relay keeps real time).
func (m *Manager) attNow() time.Time {
	if c := m.opt.AttachClock; c != nil {
		return c()
	}
	return m.now()
}

// SendRaw queues a durable message of any type and body to a connection
// and delivers it (tests and tools: what a faulty or malicious peer
// vault could send).
func (m *Manager) SendRaw(ctx context.Context, conn, typ string, body []byte) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.locked {
		return "", ErrLocked
	}
	p := m.st.Connections[conn]
	if p == nil || p.State != PeerActive {
		return "", ErrNoSession
	}
	id := m.sendTo(p, typ, body, m.now())
	if id == "" {
		return "", ErrNoSession
	}
	m.drainOutbox(ctx)
	return id, m.flushIfDirty(ctx)
}

// PutBlobTo uploads data as is to a connection's mailbox under the
// standing token it issued the vault (tests and tools, as SendRaw).
func (m *Manager) PutBlobTo(ctx context.Context, conn string, data []byte) (string, time.Time, error) {
	m.mu.Lock()
	if m.locked {
		m.mu.Unlock()
		return "", time.Time{}, ErrLocked
	}
	p := m.st.Connections[conn]
	if p == nil {
		m.mu.Unlock()
		return "", time.Time{}, ErrNoSession
	}
	url, mb, tok, r := p.Relay.URL, p.Relay.Mailbox, p.Standing.Token, m.relay
	m.mu.Unlock()
	return r.PutBlob(ctx, url, mb, tok, data)
}
