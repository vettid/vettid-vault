package trustmodel

import "sort"

// Abstract keys, tokens and the relay (RELAY-PROTOCOL §5, §6.1-6.7, §6.10).

type Key int // any key: relay, ik or kem; unique in a world
type PID int // a party

const (
	minute = int64(60)
	hour   = 60 * minute
	day    = 24 * hour

	visTimeout    = minute    // visibility_timeout_seconds
	graceLen      = 7 * day   // rotation grace (RELAY §6.7)
	msgTTL        = 14 * day  // message_ttl_seconds
	standingLife  = 30 * day  // §7.1
	reconnectLife = 365 * day // §6.6
	freshWindow   = 90        // RELAY §4.1
	hsLife        = 7 * day   // model: an initiator's open handshake expires (spec silent)
	ansLife       = 8 * day   // model: a responder's answer outlives it (spec silent)
	reconnectFail = 7 * day   // §6.6: a reconnect not completed within 7 days fails
	staleAfter    = 30 * day  // S1
	maxCollect    = 32        // §12.2
)

type Token struct {
	JTI       int
	Iss, Sub  Key // iss: the issuing mailbox (its key), sub: the sender's relay key
	Reconnect bool
	Iat, Exp  int64
}

func (t Token) valid(now int64) bool { return t.JTI != 0 && t.Iat <= now && now < t.Exp }

// RMsg is a message as the relay stores it.
type RMsg struct {
	ID         int // msg_id: per-mailbox arrival order (global counter)
	Box        Key // the mailbox (its owner key)
	DepAt      int64
	Sender     Key // the key that signed the deposit (asserted by the relay)
	JTI        int
	Reconnect  bool // deposited under a reconnect token
	P          *Msg
	leaseUntil int64
	Actor      PID // ground truth: who deposited (never read by the parties)
	Seq        int // ground truth arrival order
}

type mailbox struct {
	key      Key
	msgs     []*RMsg
	denyJTI  map[int]bool
	denySub  map[Key]bool
	deleteAt int64 // end of its rotation grace; 0: none
	succ     Key
	tnb      int64 // tokens-not-before (from a tombstone)
}

type relayErr string

const (
	okRes          relayErr = ""
	mailboxUnknown relayErr = "mailbox_unknown"
	tokenInvalid   relayErr = "token_invalid"
	tokenExpired   relayErr = "token_expired"
	tokenRevoked   relayErr = "token_revoked"
	sigInvalid     relayErr = "signature_invalid"
	quotaExceeded  relayErr = "quota_exceeded"
	rateLimited    relayErr = "429"
	badRequest     relayErr = "400" // a definite refusal of a rotate or registration
)

func (e relayErr) definite() bool { return e != okRes && e != rateLimited }

type Relay struct {
	w     *World
	boxes map[Key]*mailbox
	tomb  map[Key]int64
	used  map[int]int // reconnect-token deposits by jti
	next  int
}

func newRelay(w *World) *Relay {
	return &Relay{w: w, boxes: map[Key]*mailbox{}, tomb: map[Key]int64{}, used: map[int]int{}}
}

func (r *Relay) register(k Key) relayErr {
	if r.w.inject429() || r.w.holdRotate {
		return rateLimited
	}
	if r.w.injectRefuse() {
		return badRequest
	}
	if _, ok := r.boxes[k]; !ok {
		r.boxes[k] = &mailbox{key: k, denyJTI: map[int]bool{}, denySub: map[Key]bool{}, tnb: r.tomb[k]}
	}
	return okRes
}

// rotate: signed by old, creates the successor (RELAY §6.7, "Repeating a rotation").
func (r *Relay) rotate(old, nw Key) relayErr {
	if r.w.inject429() || r.w.holdRotate {
		return rateLimited
	}
	if r.w.injectRefuse() {
		return badRequest
	}
	b := r.boxes[old]
	if b == nil {
		return mailboxUnknown
	}
	if _, ok := r.boxes[nw]; !ok {
		r.boxes[nw] = &mailbox{key: nw, denyJTI: map[int]bool{}, denySub: map[Key]bool{}, tnb: r.tomb[nw]}
	}
	if b.deleteAt == 0 {
		b.deleteAt = r.w.Now + graceLen
	}
	b.succ = nw
	return okRes
}

func (r *Relay) live(k Key) bool { return r.boxes[k] != nil }

func (r *Relay) remove(k Key, at int64) {
	if r.boxes[k] == nil {
		return
	}
	delete(r.boxes, k)
	r.tomb[k] = at + freshWindow
	for ok, b := range r.boxes { // predecessors in grace go with it (§6.10)
		if b.succ == k && b.deleteAt != 0 {
			r.remove(ok, at)
		}
	}
}

func (r *Relay) deposit(actor PID, sender Key, tok Token, box Key, m *Msg) (int, relayErr) {
	b := r.boxes[box]
	if b == nil {
		return 0, mailboxUnknown
	}
	if tok.JTI == 0 || tok.Iss != box || r.w.issuer[tok.JTI] != box {
		return 0, tokenInvalid
	}
	if !tok.valid(r.w.Now) {
		return 0, tokenExpired
	}
	if b.denyJTI[tok.JTI] || b.denySub[tok.Sub] || tok.Iat < b.tnb {
		return 0, tokenRevoked
	}
	if sender != tok.Sub {
		return 0, sigInvalid
	}
	if tok.Reconnect && r.used[tok.JTI] >= 4 {
		return 0, quotaExceeded
	}
	if r.w.inject429() {
		return 0, rateLimited
	}
	if tok.Reconnect {
		r.used[tok.JTI]++
	}
	r.next++
	r.w.seq++
	b.msgs = append(b.msgs, &RMsg{ID: r.next, Box: box, DepAt: r.w.Now, Sender: sender, JTI: tok.JTI,
		Reconnect: tok.Reconnect, P: m, Actor: actor, Seq: r.w.seq})
	return r.next, okRes
}

// collect returns up to max oldest unleased messages and leases them.
func (r *Relay) collect(box Key, max int) ([]*RMsg, relayErr) {
	b := r.boxes[box]
	if b == nil {
		return nil, mailboxUnknown
	}
	var out []*RMsg
	for _, m := range b.msgs {
		if len(out) == max {
			break
		}
		if m.leaseUntil > r.w.Now {
			continue
		}
		m.leaseUntil = r.w.Now + visTimeout
		out = append(out, m)
	}
	return out, okRes
}

func (r *Relay) ack(box Key, id int) {
	if b := r.boxes[box]; b != nil {
		for i, m := range b.msgs {
			if m.ID == id {
				b.msgs = append(b.msgs[:i:i], b.msgs[i+1:]...)
				return
			}
		}
	}
}

func (r *Relay) deny(box Key, jtis []int) {
	if b := r.boxes[box]; b != nil {
		for _, j := range jtis {
			b.denyJTI[j] = true
		}
	}
}

// advance ends graces and expires messages.
func (r *Relay) advance() {
	keys := make([]Key, 0, len(r.boxes))
	for k := range r.boxes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	for _, k := range keys {
		b := r.boxes[k]
		if b == nil {
			continue
		}
		if b.deleteAt != 0 && r.w.Now >= b.deleteAt {
			for _, m := range b.msgs {
				if m.P.Kind == KFin || m.P.Kind == KResp || m.P.Kind == KConfirm {
					r.w.ttlFin[[2]PID{m.Actor, r.w.owner(k)}] = "deleted-with-old-mailbox"
					if m.P.Kind == KFin {
						r.w.noteFinLost(m.Actor, r.w.owner(k))
					}
				}
				if m.P.Kind == KSession && r.w.probeFate[m.P.Probe] == "" {
					r.w.probeFate[m.P.Probe] = "deleted with the old mailbox"
				}
			}
			delete(r.boxes, k)
			r.tomb[k] = b.deleteAt + freshWindow
			continue
		}
		kept := b.msgs[:0]
		for _, m := range b.msgs {
			if r.w.Now < m.DepAt+msgTTL {
				kept = append(kept, m)
			} else {
				if m.P.Kind == KFin || m.P.Kind == KResp || m.P.Kind == KConfirm {
					r.w.ttlFin[[2]PID{m.Actor, r.w.owner(k)}] = "expired-at-relay-TTL"
					if m.P.Kind == KFin {
						r.w.noteFinLost(m.Actor, r.w.owner(k))
					}
				}
				if m.P.Kind == KSession && r.w.probeFate[m.P.Probe] == "" {
					r.w.probeFate[m.P.Probe] = "expired (relay TTL)"
				}
			}
		}
		b.msgs = kept
	}
}

func (r *Relay) pending() int {
	n := 0
	for _, b := range r.boxes {
		n += len(b.msgs)
	}
	return n
}

// swapPos: a misbehaving relay swaps the asserted positions (msg_id,
// deposited_at) of two messages in a mailbox; delivery order is unchanged.
func (r *Relay) swapPos(box Key, a, b *RMsg) {
	a.ID, b.ID = b.ID, a.ID
	a.DepAt, b.DepAt = b.DepAt, a.DepAt
}
