package trustmodel

import "slices"

// Messages, party state, stored vs in-memory state.

type Kind int

const (
	KSession   Kind = iota // any other session-mode message (the probe)
	KUpdate                // relay.address.update
	KTokIssued             // relay.token.issued
	KIdRot                 // identity.rotate
	KInit                  // hs.init (rekey, reconnect)
	KResp                  // hs.resp
	KFin                   // hs.fin
	KConfirm               // hs.confirm (0.86.0 draft, §6.3.1)
)

var kindName = [...]string{"session", "relay.address.update", "relay.token.issued", "identity.rotate", "hs.init", "hs.resp", "hs.fin", "hs.confirm"}

type IKLink struct{ Old, New, KEM Key }
type RLink struct{ Old, New Key }

// Msg is an abstract message. Fields are used by kind.
type Msg struct {
	Kind  Kind
	Inner int   // inner id, deduped by the receiver (§8.3)
	Epoch int   // session mode: the epoch it is sealed under; 0: sealed to a kem
	Probe int   // KSession: a probe number
	Ts    int64 // inner ts, set when the message is made

	RelayPK Key // KUpdate
	RLinks  []RLink
	Toks    []Token // KUpdate, KTokIssued, KInit (reconnect), KResp (reconnect)

	Rot []IKLink // KIdRot: rotations then rotation (last); KInit/KResp: rotations

	HS        int  // handshake id (th1 / eph)
	Reconnect bool // purpose
	Ctx       int  // epoch named
	FromIK    Key
	FromKEM   Key
	FromRelay Key
	NewEpoch  int // KResp/KFin: the epoch the handshake makes
	Sig       Key // KResp: sig_R's key; KFin: sig_I's key
}

// Pos is where a message sits in Q's mailboxes (§3.4.1 "Cut-off").
type Pos struct {
	Box   Key
	ID    int
	DepAt int64
}

// after reports whether m was deposited after the position x.
func (x Pos) after(m Pos) bool {
	if m.Box == x.Box {
		return m.ID >= x.ID // "before" only if its msg_id is smaller
	}
	return m.DepAt > x.DepAt
}

type Epoch struct {
	ID         int
	Signer     Key // the peer-side ik that signed its handshake
	Own        Key // my ik that signed it (S8: links from it)
	Est        Pos // position of the message that established it here
	Demoted    bool
	DemotedAt  Pos
	Superseded int64
	EstAt      int64
	Pending    bool // §6.3.1: an initiator's epoch awaiting confirmation
	Abandoned  bool // §6.3.1: a pending epoch abandoned (nothing under it confirms)
}

// PendEp is an initiator's pending epoch (§6.3.1).
type PendEp struct {
	ID        int
	Signer    Key
	Own       Key
	FinAt     int64
	RespTs    int64
	Reconnect bool
}

type Earlier struct {
	Key   Key
	Cut   Pos
	Until int64
}

type HS struct {
	ID        int
	Reconnect bool
	Ctx       int
	PeerIK    Key // the peer's ik it is pinned to
	OwnIK     Key
	Relay     Key // initiator: the relay key the hs.init announced
	Toks      []Token
	Links     []IKLink // responder: the hs.init's links, applied at hs.fin
	Started   int64
	FinSent   bool
	NewEpoch  int
	Fork      bool
	RespFrom  Key     // responder: my ik that signed the epoch ctx names (S8)
	RespToks  []Token // responder: the tokens my hs.resp carries
	RespInner int     // responder: the hs.resp's inner id (the same bytes each time)
}

const (
	stActive = iota
	stSuspended
	stStale
	stConflicted // a device or its vault: rule C between a vault and its own device
)

type PeerRec struct {
	ID       PID
	Device   bool // the peer is a device or agent of mine, or my vault (no suspension)
	Status   int
	Ref      string
	CandA    IKLink // identity conflict candidates (followed, other)
	CandB    IKLink
	RelayFrk bool
	Warned   bool // rule C between a vault and its own device: the member was told

	Pend      *PendEp // §6.3.1: my pending epoch (I initiated)
	ConfID    int     // §6.3.1: my confirmed epoch's id (I responded), until the peer confirms
	ConfKeep  int     // the confirmed epoch whose receive keys are kept until ConfUntil
	ConfUntil int64
	Reconfirm bool // a message under the confirmed epoch in this batch: queue hs.confirm

	IK, KEM Key
	Chain   []IKLink // followed identity links
	Dropped []IKLink // dropped at connection.rotation.resolve

	Relay   Key
	RChain  []RLink // followed relay links
	Earlier []Earlier

	Epochs []Epoch
	Cur    int // current epoch id; 0: none (demoted)

	Toks   []Token // tokens P issued to me, for depositing to P
	Issued []Token // tokens I issued to P

	KeyFor    Key // S1: my relay key P has acknowledged (newest token from P for it)
	LastFin   int // inner id of my last hs.fin to P (S2 re-deposit)
	LastFinHS int
	LastFinRC bool
	WantRC    bool  // start a reconnect after this flush
	Own       *HS   // my open handshake with P
	Ans       []HS  // my answers awaiting hs.fin
	Answered  []int // th1 of reconnects I answered (replay)

	Deferred  []deferral
	LastSend  int64 // last update resend (b)
	ResendEnd bool
	RevokedAt int64 // S9: first token_revoked for an earlier key's token
	S9Audited bool
	RestartIK Key   // H5: restarted reconnect spent once per change of the current ik
	Stamp     int64 // when this record last changed status (stale bookkeeping)
}

type deferral struct {
	MsgID  int
	First  int64
	Reason string
}

type Entry struct {
	ID       int
	To       PID
	M        Msg
	Target   Key   // KUpdate: the relay key it announces (held until current)
	Box      Key   // explicit mailbox (an hs.resp to a reconnect's from.relay)
	Tok      Token // explicit token (that hs.init's standing token; a reconnect token)
	With     Key   // explicit sending key (0: my key for the peer)
	Done     bool  // answered 201; removed at the next write
	Tried    bool  // deposited at least once (its bytes are fixed)
	Resend   bool  // an update resent by (b)
	Indef    bool  // last attempt had no definite answer
	Ended    bool  // ended by a definite refusal
	Revoke   []int // KDeny pseudo-entry: jtis to revoke at mailbox Box with key With
	Denylist bool
}

type Pending struct {
	Key     Key
	Refused bool
	Path    int
	Fresh   bool // a recovery already took the fresh key once (O5 b)
}

type OldKey struct {
	Key      Key
	GraceEnd int64
	Since    int64 // second write
}

type State struct {
	Relay   Key
	Pend    *Pending
	Old     []OldKey
	Owed    bool
	IK, KEM Key
	Chain   []IKLink // own rotation chain
	RLinks  []RLink  // own signed relay links (kept even if the key is discarded)
	LastRot int64

	Peers []PeerRec
	Out   []Entry
	Seen  map[int]bool
	First map[int]int64 // msg_id -> first seen, for defer bounds
}

func (s *State) peer(id PID) *PeerRec {
	for i := range s.Peers {
		if s.Peers[i].ID == id {
			return &s.Peers[i]
		}
	}
	return nil
}

func cloneHS(h *HS) *HS {
	if h == nil {
		return nil
	}
	c := *h
	c.Toks = slices.Clone(h.Toks)
	c.Links = slices.Clone(h.Links)
	c.RespToks = slices.Clone(h.RespToks)
	return &c
}

func (s *State) clone() State {
	c := *s
	if s.Pend != nil {
		p := *s.Pend
		c.Pend = &p
	}
	c.Old = slices.Clone(s.Old)
	c.Chain = slices.Clone(s.Chain)
	c.RLinks = slices.Clone(s.RLinks)
	c.Peers = make([]PeerRec, len(s.Peers))
	for i, p := range s.Peers {
		q := p
		q.Chain = slices.Clone(p.Chain)
		q.Dropped = slices.Clone(p.Dropped)
		q.RChain = slices.Clone(p.RChain)
		q.Earlier = slices.Clone(p.Earlier)
		q.Epochs = slices.Clone(p.Epochs)
		q.Toks = slices.Clone(p.Toks)
		q.Issued = slices.Clone(p.Issued)
		q.Own = cloneHS(p.Own)
		if p.Pend != nil {
			pe := *p.Pend
			q.Pend = &pe
		}
		q.Ans = make([]HS, len(p.Ans))
		for j := range p.Ans {
			q.Ans[j] = *cloneHS(&p.Ans[j])
		}
		q.Answered = slices.Clone(p.Answered)
		q.Deferred = slices.Clone(p.Deferred)
		c.Peers[i] = q
	}
	c.Out = make([]Entry, len(s.Out))
	for i, e := range s.Out {
		f := e
		f.M = cloneMsg(e.M)
		f.Revoke = slices.Clone(e.Revoke)
		c.Out[i] = f
	}
	c.Seen = make(map[int]bool, len(s.Seen))
	for k, v := range s.Seen {
		c.Seen[k] = v
	}
	c.First = make(map[int]int64, len(s.First))
	for k, v := range s.First {
		c.First[k] = v
	}
	return c
}

func cloneMsg(m Msg) Msg {
	m.RLinks = slices.Clone(m.RLinks)
	m.Toks = slices.Clone(m.Toks)
	m.Rot = slices.Clone(m.Rot)
	return m
}

// ikState is the §3.4.1 `ik` state of k, given the links a message carries.
type ikSt int

const (
	ikCurrent ikSt = iota
	ikReached
	ikAncestor
	ikRejected
	ikUnknown
)

var ikName = [...]string{"current", "reached", "ancestor", "rejected", "unknown"}

func (r *PeerRec) followed(l IKLink) bool {
	return slices.Contains(r.Chain, l)
}
func (r *PeerRec) isAncestor(k Key) bool {
	for _, l := range r.Chain {
		if l.Old == k {
			return true
		}
	}
	return false
}
func (r *PeerRec) isRejected(k Key) bool {
	for _, l := range r.Dropped {
		if l.New == k {
			return true
		}
	}
	return false
}

// resolve applies §3.4's chain resolution to links: it returns the links
// to append (not yet followed) or ok=false if the chain is rejected.
func (r *PeerRec) resolve(links []IKLink) (app []IKLink, ok bool) {
	i := 0
	for i < len(links) && r.followed(links[i]) {
		i++
	}
	if i > 0 && links[i-1].New != r.IK {
		return nil, false // returns to an earlier key
	}
	at := r.IK
	for _, l := range links[i:] {
		if l.Old != at || l.Old == l.New {
			return nil, false
		}
		at = l.New
	}
	return links[i:], true
}

// state of ik k for a message carrying links; app: the links that reach k.
func (r *PeerRec) ikState(k Key, links []IKLink) (ikSt, []IKLink) {
	if k == r.IK {
		return ikCurrent, nil
	}
	if r.isRejected(k) {
		return ikRejected, nil
	}
	if r.isAncestor(k) {
		return ikAncestor, nil
	}
	if app, ok := r.resolve(links); ok {
		for i, l := range app {
			if r.isRejected(l.New) {
				return ikRejected, nil // reached only through a dropped statement
			}
			if l.New == k {
				return ikReached, app[:i+1]
			}
		}
	}
	return ikUnknown, nil
}

// relay-key state of a sender, at position pos.
type rkSt int

const (
	rkCurrent rkSt = iota
	rkBefore
	rkAfter
	rkForeign
)

func (r *PeerRec) relayState(sender Key, pos Pos) rkSt {
	if sender == r.Relay {
		return rkCurrent
	}
	for _, e := range r.Earlier {
		if e.Key == sender {
			if e.Cut.after(pos) {
				return rkAfter
			}
			return rkBefore
		}
	}
	return rkForeign
}

func (r *PeerRec) keeps(k Key) bool {
	if k == r.Relay {
		return true
	}
	for _, e := range r.Earlier {
		if e.Key == k {
			return true
		}
	}
	return false
}

func (r *PeerRec) epoch(id int) *Epoch {
	for i := range r.Epochs {
		if r.Epochs[i].ID == id {
			return &r.Epochs[i]
		}
	}
	return nil
}

// lastEpoch: the newest epoch not demoted.
func (r *PeerRec) lastEpoch() *Epoch {
	for i := len(r.Epochs) - 1; i >= 0; i-- {
		if e := r.Epochs[i]; !e.Demoted && !e.Pending && !e.Abandoned {
			return &r.Epochs[i]
		}
	}
	return nil
}
