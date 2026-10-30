package vote

import (
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// What a record's states are called (§10.19.3).
const (
	StateChecking = "checking"
	StateUpcoming = "upcoming"
	StateOpen     = "open"
	StateClosed   = "closed"
	StateRejected = "rejected"
)

// Why a proposal is `checking` (§10.19.3).
const (
	ReasonServiceList = "service_list"
	ReasonTrustRoot   = "trust_root"
	ReasonSite        = "site"
	ReasonRestore     = "restore"
)

// Why a proposal is `rejected`: the reason of §10.19.4.
const (
	RejectMalformed = "malformed"
	RejectService   = "service"
	RejectSignature = "signature"
	RejectRecord    = "record"
	RejectAnchor    = "anchor"
)

// The result check (§10.19.3, §10.19.6). "" until it is due.
const (
	CheckPending     = "pending"
	CheckVerified    = "verified"
	CheckUnconfirmed = "unconfirmed"
	CheckFailed      = "failed"
	CheckGaveUp      = "gave_up"
)

// The ballot (§10.19.3). Set by casting (PR 3); the bookkeeping of the
// records below already depends on it.
const (
	BallotSending  = "sending"
	BallotWaiting  = "waiting"
	BallotRecorded = "recorded"
	BallotRefused  = "refused"
	BallotConflict = "conflict"
	BallotDisputed = "disputed"
)

// The site comparison states (§10.19.4 "Comparing with the public site").
const (
	SiteMatches     = "matches"
	SiteMismatch    = "mismatch"
	SiteNotListed   = "not_listed"
	SiteUnreachable = "unreachable"
	SiteUnpublished = "unpublished"
)

// Timings (§10.19.4, §10.19.6, §10.19.7).
const (
	CheckDelay     = 2 * time.Hour
	NotListedAfter = 10 * time.Minute
	AnchorAhead    = 5 * time.Minute
	ProblemFeedGap = 24 * time.Hour
	recheckEvery   = time.Hour
)

type proof struct {
	Index    uint64   `json:"index"`
	TreeSize uint64   `json:"tree_size"`
	Path     [][]byte `json:"path"`
}

// extRec is an extension held (§10.19.4 "On vote.extended").
type extRec struct {
	N      int64           `json:"n"`
	Doc    []byte          `json:"doc"`
	Sig    []byte          `json:"sig"`
	Bundle json.RawMessage `json:"bundle"`
	Closes int64           `json:"closes_at"`
}

// ballot is the member's ballot and what came back (PR 3 fills it).
type ballot struct {
	State      string   `json:"state"`
	Code       string   `json:"code,omitempty"`
	ChoiceID   string   `json:"choice_id,omitempty"`
	BallotSig  []byte   `json:"ballot_sig,omitempty"`
	MsgMS      int64    `json:"msg_ms,omitempty"`
	ReceiptSig []byte   `json:"receipt_sig,omitempty"`
	Refusals   [][]byte `json:"refusals,omitempty"` // signed refusals, verbatim, the last 8
}

func (b *ballot) final() bool {
	switch b.State {
	case BallotRecorded, BallotRefused, BallotConflict, BallotDisputed:
		return true
	}
	return false
}

// record is one proposal kept (§10.19.2).
type record struct {
	Conn      string `json:"connection_id"`
	ID        string `json:"proposal_id"`
	ServiceIK []byte `json:"ik"` // the connection's ik when the proposal was kept

	Proposal    []byte          `json:"proposal"`
	ProposalSig []byte          `json:"proposal_sig"`
	Bundle      json.RawMessage `json:"bundle,omitempty"`
	Hash        []byte          `json:"proposal_hash"`
	Secret      []byte          `json:"record_secret"`
	Tag         []byte          `json:"record_tag"`
	Proof       *proof          `json:"record_proof"`
	ReceivedMS  int64           `json:"received_ms"`
	KeptMS      int64           `json:"kept_ms"`
	ChangedMS   int64           `json:"changed_ms"`

	// From the proposal document; Closes moves with the extensions.
	Opens     int64  `json:"opens_at"`
	Closes    int64  `json:"closes_at"`
	OrigClose int64  `json:"orig_closes_at"`
	Title     string `json:"title,omitempty"`

	Exts  []*extRec `json:"extensions,omitempty"`
	Aside *extRec   `json:"aside,omitempty"`

	// The voting key: the seed until the vote is final, then only vk.
	VKSeed []byte `json:"vk_seed,omitempty"`
	VK     []byte `json:"vk"`

	Reason       string `json:"reason,omitempty"`        // checking
	RejectReason string `json:"reject_reason,omitempty"` // rejected
	OpenFeed     bool   `json:"open_feed,omitempty"`     // vote.open made

	// A different proposal under the same id (one copy, as evidence).
	Conflict *evidence `json:"conflict,omitempty"`

	// vote.closed: the results hash and when it arrived.
	ResultsHash []byte `json:"results_hash,omitempty"`
	ClosedMS    int64  `json:"closed_ms,omitempty"`

	Check       string `json:"check,omitempty"`
	CheckReason string `json:"check_reason,omitempty"`

	Ballot         *ballot `json:"ballot,omitempty"`
	RefusalProblem bool    `json:"refusal_problem,omitempty"` // a refusal raised a vote.problem

	Site      string    `json:"site,omitempty"`
	SiteCopy  *evidence `json:"site_copy,omitempty"` // the site's copy of a mismatch
	SiteSince int64     `json:"site_since_ms,omitempty"`
	// SiteAlert is the last site finding the member was told of (audit and
	// feed), so that a finding is raised once.
	SiteAlert string `json:"site_alert,omitempty"`
}

// evidence is a proposal's bytes, signature and bundle kept as proof.
type evidence struct {
	Proposal []byte          `json:"proposal"`
	Sig      []byte          `json:"sig,omitempty"`
	Bundle   json.RawMessage `json:"bundle,omitempty"`
	AtMS     int64           `json:"at_ms"`
}

// compact is what is kept of an evicted record (§10.19.2): what cannot be
// fetched again.
type compact struct {
	Conn       string   `json:"connection_id"`
	ID         string   `json:"proposal_id"`
	Hash       []byte   `json:"proposal_hash"`
	Tag        []byte   `json:"record_tag"`
	ServiceIK  []byte   `json:"ik"`
	VK         []byte   `json:"vk,omitempty"`
	ChoiceID   string   `json:"choice_id,omitempty"`
	BallotSig  []byte   `json:"ballot_sig,omitempty"`
	MsgMS      int64    `json:"msg_ms,omitempty"`
	ReceiptSig []byte   `json:"receipt_sig,omitempty"`
	Refusals   [][]byte `json:"refusals,omitempty"`
	Outcome    string   `json:"outcome"`
	ClosedAt   int64    `json:"closed_at"` // unix s: the close in force
}

type droppedNote struct {
	Count  int   `json:"count"`
	LastMS int64 `json:"last_ms"`
}

type state struct {
	List     *listState              `json:"list,omitempty"`
	Records  map[string]*record      `json:"records"`
	Compact  map[string][]*compact   `json:"compact,omitempty"`
	Dropped  map[string]*droppedNote `json:"dropped,omitempty"`  // votes dropped for the cap, by connection
	Problems map[string]bool         `json:"problems,omitempty"` // the problem cap was hit, by connection
	FeedAt   map[string]int64        `json:"feed_at,omitempty"`  // the last cap vote.problem feed item, by connection (ms)
}

func (st *state) init() {
	if st.Records == nil {
		st.Records = map[string]*record{}
	}
	if st.Compact == nil {
		st.Compact = map[string][]*compact{}
	}
	if st.Dropped == nil {
		st.Dropped = map[string]*droppedNote{}
	}
	if st.Problems == nil {
		st.Problems = map[string]bool{}
	}
	if st.FeedAt == nil {
		st.FeedAt = map[string]int64{}
	}
}

func key(conn, id string) string { return conn + "|" + id }

// state is the record's state at now (§10.19.3).
func (r *record) state(now time.Time) string {
	switch {
	case r.RejectReason != "":
		return StateRejected
	case r.Reason != "":
		return StateChecking
	case now.Unix() >= r.Closes:
		return StateClosed
	case now.Unix() < r.Opens:
		return StateUpcoming
	}
	return StateOpen
}

func (r *record) closed(now time.Time) bool { return now.Unix() >= r.Closes }

// dueAt is when the results check is due (§10.19.6): at the close, if
// vote.closed came before it; right at vote.closed, if after; else two
// hours after the close in force.
func (r *record) dueAt() time.Time {
	closes := time.Unix(r.Closes, 0)
	if r.ClosedMS > 0 {
		at := time.UnixMilli(r.ClosedMS)
		if at.Before(closes) {
			return closes
		}
		return at
	}
	return closes.Add(CheckDelay)
}

// checkPending reports a check that is due and not yet settled.
func (r *record) checkPending(now time.Time) bool {
	if r.RejectReason != "" || r.Reason != "" {
		return false
	}
	return r.Check == CheckPending || r.Check == "" && !now.Before(r.dueAt()) && r.closed(now)
}

// problem reports whether the record is in the problem set (§10.19.2).
func (r *record) problem() bool {
	if r.RejectReason != "" || r.Check == CheckFailed || r.RefusalProblem {
		return true
	}
	if b := r.Ballot; b != nil && (b.State == BallotConflict || b.State == BallotDisputed) {
		return true
	}
	return r.Site == SiteMismatch || r.Site == SiteUnpublished
}

// evictable reports whether the record may be evicted for room (§10.19.2):
// not a problem, closed, and either its check is final and clean, or it
// closed without a ballot and its check is not due. In-progress records
// (checking, upcoming, open, a pending check, a ballot not final) never.
func (r *record) evictable(now time.Time) bool {
	if r.problem() || r.Reason != "" || !r.closed(now) || r.checkPending(now) {
		return false
	}
	clean := r.Check == CheckVerified || r.Check == CheckUnconfirmed || r.Check == CheckGaveUp
	if r.Ballot == nil {
		return clean || r.Check == ""
	}
	return r.Ballot.final() && clean
}

// toCompact is what an evicted record leaves behind.
func (r *record) toCompact() *compact {
	c := &compact{Conn: r.Conn, ID: r.ID, Hash: r.Hash, Tag: r.Tag, ServiceIK: r.ServiceIK, ClosedAt: r.Closes, Outcome: "closed"}
	if r.Check != "" {
		c.Outcome = r.Check
	}
	if b := r.Ballot; b != nil {
		c.VK, c.ChoiceID, c.BallotSig, c.MsgMS, c.ReceiptSig, c.Refusals = r.VK, b.ChoiceID, b.BallotSig, b.MsgMS, b.ReceiptSig, b.Refusals
	}
	return c
}

// limitHit says which bound refused a proposal.
type limitHit struct {
	max      int
	problems bool
}

func (f *Feature) forConn(conn string) []*record {
	var out []*record
	for _, r := range f.st.Records {
		if r.Conn == conn {
			out = append(out, r)
		}
	}
	return out
}

// admit makes room for rec, a new record of its connection: it evicts that
// connection's oldest evictable records to compact ones when a bound is
// reached (§10.19.2), and says which bound refused it if none can go.
func (f *Feature) admit(rec *record, now time.Time) *limitHit {
	conn := rec.Conn
	problems := 0
	for _, r := range f.forConn(conn) {
		if r.problem() {
			problems++
		}
	}
	if problems >= votewire.MaxProblemsPerConnection {
		return &limitHit{max: votewire.MaxProblemsPerConnection, problems: true}
	}
	newProblem := rec.problem()
	newClosed := rec.closed(now)
	for {
		nonProblem, open := 0, 0
		for _, r := range f.forConn(conn) {
			if !r.problem() {
				nonProblem++
				if !r.closed(now) {
					open++
				}
			}
		}
		var hit *limitHit
		switch {
		case len(f.st.Records) >= votewire.MaxProposals:
			hit = &limitHit{max: votewire.MaxProposals}
		case !newProblem && nonProblem >= votewire.MaxPerConnection:
			hit = &limitHit{max: votewire.MaxPerConnection}
		case !newProblem && !newClosed && open >= votewire.MaxOpenPerConnection:
			hit = &limitHit{max: votewire.MaxOpenPerConnection}
		}
		if hit == nil {
			return nil
		}
		v := f.oldestEvictable(conn, now)
		if v == nil {
			return hit
		}
		f.evict(v)
	}
}

func (f *Feature) oldestEvictable(conn string, now time.Time) *record {
	var best *record
	for _, r := range f.forConn(conn) {
		if r.evictable(now) && (best == nil || r.KeptMS < best.KeptMS || r.KeptMS == best.KeptMS && r.ID < best.ID) {
			best = r
		}
	}
	return best
}

// evict replaces a record by its compact record. The proposal and the
// results are public and write-once on the site, and are fetched again.
func (f *Feature) evict(r *record) {
	f.st.Compact[r.Conn] = append(f.st.Compact[r.Conn], r.toCompact())
	delete(f.st.Records, key(r.Conn, r.ID))
}

// prune ages out what is old (§10.19.2): compact records 365 days after
// their close, and at most 512 per connection (oldest first); problem
// records 365 days after their close. It also, at most hourly, checks the
// `checking` proposals again (the pinned roots may be newer than when they
// were kept, a service list may have arrived).
func (f *Feature) prune(s *vault.Session) {
	now := s.Now()
	keep := time.Duration(votewire.CompactRetentionDays) * 24 * time.Hour
	for conn, cs := range f.st.Compact {
		var out []*compact
		for _, c := range cs {
			if now.Sub(time.Unix(c.ClosedAt, 0)) < keep {
				out = append(out, c)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return out[i].ClosedAt < out[j].ClosedAt })
		if len(out) > votewire.MaxCompactPerConnection {
			out = out[len(out)-votewire.MaxCompactPerConnection:]
		}
		if len(out) == 0 {
			delete(f.st.Compact, conn)
		} else {
			f.st.Compact[conn] = out
		}
	}
	for k, r := range f.st.Records {
		if r.problem() && r.closed(now) && now.Sub(time.Unix(r.Closes, 0)) >= keep {
			delete(f.st.Records, k)
		}
	}
	if now.UnixMilli()-f.last >= recheckEvery.Milliseconds() {
		f.last = now.UnixMilli()
		f.recheck(s)
	}
}
