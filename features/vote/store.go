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
	ReasonClock       = "clock" // 0.81.1: max(t_tsa, t_int) > now + 300 s
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

// sendRec is one send of the ballot (vote.cast), kept to tell which earlier
// sends are unanswered and which body a refusal answers.
type sendRec struct {
	ID       string `json:"id"`
	AtMS     int64  `json:"at_ms"`
	Gen      int    `json:"gen"` // the body generation sent (b.Gen at the time)
	Answered bool   `json:"answered,omitempty"`
}

// ballot is the member's ballot and what came back (VAULT-MESSAGING
// §10.19.3, §10.19.5).
type ballot struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"` // waiting: not_open, not_signed_in, closed, bad_ballot
	Code   string `json:"code,omitempty"`   // refused: the signed refusal's code, or connection_ended

	ChoiceID  string `json:"choice_id"`
	VK        []byte `json:"vk,omitempty"` // the voting key the ballot was signed with
	BallotSig []byte `json:"ballot_sig"`
	CastSig   []byte `json:"cast_sig,omitempty"`
	Body      []byte `json:"body,omitempty"` // the exact vote.cast body, re-signed at a credential rotation

	// Gen counts the re-signed bodies sent to the connection after a
	// rotation statement; SentGen is the generation last sent.
	Gen     int       `json:"gen,omitempty"`
	SentGen int       `json:"sent_gen,omitempty"`
	Sends   []sendRec `json:"sends,omitempty"`    // the last 64
	LostOld bool      `json:"lost_old,omitempty"` // an unanswered send fell out of Sends

	FirstSendMS  int64 `json:"first_send_ms,omitempty"`
	LastAnswerMS int64 `json:"last_answer_ms,omitempty"` // a verified answer
	RoundStartMS int64 `json:"round_start_ms,omitempty"`
	Round        int   `json:"round,omitempty"` // sends in the current round of the schedule
	NextSendMS   int64 `json:"next_send_ms,omitempty"`
	NextStatusMS int64 `json:"next_status_ms,omitempty"`

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

// svcBallot is the ballot the service holds for the member's code, which the
// member is asked to confirm (after a restore, §10.19.5), or the other
// ballot of a conflict or a dispute (evidence).
type svcBallot struct {
	VK         []byte `json:"vk"`
	ChoiceID   string `json:"choice_id"`
	BallotSig  []byte `json:"ballot_sig"`
	MsgMS      int64  `json:"msg_ms,omitempty"`
	ReceiptSig []byte `json:"receipt_sig,omitempty"`
}

// results is what the vault keeps of a checked result (§10.19.6).
type results struct {
	Doc    []byte          `json:"doc"`
	Sig    []byte          `json:"sig"`
	Bundle json.RawMessage `json:"bundle,omitempty"`
	Row    *svcBallot      `json:"row,omitempty"` // nil: an empty row
	Proof  *proof          `json:"proof,omitempty"`
	AtMS   int64           `json:"at_ms"`
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
	NoRelay     bool            `json:"no_relay,omitempty"` // the relay's time was unknown
	KeptMS      int64           `json:"kept_ms"`
	ChangedMS   int64           `json:"changed_ms"`

	// From the proposal document; Closes moves with the extensions.
	Opens     int64  `json:"opens_at"`
	Closes    int64  `json:"closes_at"`
	OrigClose int64  `json:"orig_closes_at"`
	Title     string `json:"title,omitempty"`
	// Signer is the service key the proposal was signed with (equal to the
	// connection's ik or an earlier one on its chain).
	Signer []byte `json:"signer,omitempty"`

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

	// Restore: the vault was restored (a recovery, a transfer) and asks the
	// service what it recorded; no cast until it answers (§10.19.5). AskMS
	// is the next ask.
	// ConflictEv: the service showed a ballot the vault never signed (or
	// another than its own) with no ballot of the vault's own to change: a
	// conflict kept as evidence (VAULT-MESSAGING §10.19.5).
	ConflictEv bool  `json:"conflict_ev,omitempty"`
	Restore    bool  `json:"restore,omitempty"`
	AskMS      int64 `json:"ask_ms,omitempty"`
	// ServiceBallot is the ballot a status answer carried that the vault
	// has no receipt for: the member confirms it (vote.confirm).
	ServiceBallot *svcBallot `json:"service_ballot,omitempty"`
	// Other is the other ballot of a conflict or a dispute (evidence).
	Other *svcBallot `json:"other,omitempty"`
	// StatusAnswers are the signed status answers and refusals kept as
	// evidence, verbatim, the last 8.
	StatusAnswers [][]byte `json:"status_answers,omitempty"`
	CheckAskMS    int64    `json:"check_ask_ms,omitempty"` // the last app-asked vote.status (rate limit)
	// EvidenceHash is the digest of the record when vote.evidence last
	// returned it (EvidenceMS the time): vote.release needs the record
	// unchanged since.
	EvidenceHash []byte `json:"evidence_hash,omitempty"`
	EvidenceMS   int64  `json:"evidence_ms,omitempty"`
	ClosingFeed  bool   `json:"closing_feed,omitempty"` // vote.closing made, or none due (kept after its moment)
	// OtherLatest is the latest foreign ballot beside the first (Other).
	OtherLatest  *svcBallot `json:"other_latest,omitempty"`
	CheckDueSent bool       `json:"check_due_sent,omitempty"`
	Results      *results   `json:"results,omitempty"`
	ResultsMatch string     `json:"results_hash_match,omitempty"` // "", "yes" or "no": vote.closed's hash against the results (evidence only)

	// AbsentMS is the vault-clock time of the first `absent` answer after the
	// close in force (a found document clears it); unpublished needs a second
	// at least ten minutes later.
	AbsentMS  int64     `json:"absent_ms,omitempty"`
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

	// A released problem record also holds every signed item that is not on
	// the public site (§10.19.2): the held proposal, its signature and bundle
	// when the site does not match, the site's copy of a mismatch, every
	// status answer, the other ballot of a conflict or dispute, and the
	// reason a proposal was rejected.
	Released      bool            `json:"released,omitempty"`
	Proposal      []byte          `json:"proposal,omitempty"`
	ProposalSig   []byte          `json:"proposal_sig,omitempty"`
	Bundle        json.RawMessage `json:"bundle,omitempty"`
	Site          string          `json:"site,omitempty"`
	SiteCopy      *evidence       `json:"site_copy,omitempty"`
	StatusAnswers [][]byte        `json:"status_answers,omitempty"`
	Other         *svcBallot      `json:"other,omitempty"`
	RejectReason  string          `json:"reject_reason,omitempty"`
}

type droppedNote struct {
	Count  int   `json:"count"`
	LastMS int64 `json:"last_ms"`
	// Shown: vote.list returned it; the next vote.list drops it ("until the
	// member opens it", §10.19.2).
	Shown bool `json:"shown,omitempty"`
}

type state struct {
	List     *listState              `json:"list,omitempty"`
	Records  map[string]*record      `json:"records"`
	Compact  map[string][]*compact   `json:"compact,omitempty"`
	Dropped  map[string]*droppedNote `json:"dropped,omitempty"`  // votes dropped for the cap, by connection
	Problems map[string]bool         `json:"problems,omitempty"` // the problem cap was hit, by connection
	FeedAt   map[string]int64        `json:"feed_at,omitempty"`  // the last cap vote.problem feed item, by connection (ms)
	// OversizeHash is the latest over-cap service list's hash (first 8 bytes,
	// hex) and OversizeAtMS when vote.list_ignored was last audited (at most
	// once a day).
	OversizeHash string `json:"oversize_hash,omitempty"`
	OversizeAtMS int64  `json:"oversize_at_ms,omitempty"`
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
	case r.Reason != "" || r.Restore:
		return StateChecking
	case now.Unix() >= r.Closes:
		return StateClosed
	case now.Unix() < r.Opens:
		return StateUpcoming
	}
	return StateOpen
}

// signers are the service keys to look the record's service up by.
func (r *record) signers() [][]byte { return [][]byte{r.ServiceIK, r.Signer} }

// checkingReason is the reason shown for a `checking` record.
func (r *record) checkingReason() string {
	if r.Reason != "" {
		return r.Reason
	}
	if r.Restore {
		return ReasonRestore
	}
	return ""
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
	if r.RejectReason != "" || r.Reason != "" || r.Restore {
		return false
	}
	return r.Check == CheckPending || r.Check == "" && !now.Before(r.dueAt()) && r.closed(now)
}

// problem reports whether the record is in the problem set (§10.19.2).
func (r *record) problem() bool {
	if r.RejectReason != "" || r.Check == CheckFailed || r.RefusalProblem || r.ConflictEv {
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
	if r.problem() || r.Reason != "" || r.Restore || !r.closed(now) || r.checkPending(now) {
		return false
	}
	clean := r.Check == CheckVerified || r.Check == CheckUnconfirmed || r.Check == CheckGaveUp
	if r.Ballot == nil {
		return clean || r.Check == ""
	}
	return r.Ballot.final() && clean
}

// toCompact is what an evicted record leaves behind.
// release is the compact record of a problem record released by the member
// (§10.19.2): what an eviction keeps, and every signed item that is not on
// the public site.
func (r *record) release() *compact {
	c := r.toCompact()
	c.Released, c.Outcome = true, "released"
	if r.Check != "" {
		c.Outcome = "released:" + r.Check
	}
	if r.RejectReason != "" {
		c.Outcome, c.RejectReason = "released:rejected", r.RejectReason
	}
	c.Site, c.SiteCopy, c.StatusAnswers, c.Other = r.Site, r.SiteCopy, r.StatusAnswers, r.Other
	if r.Closes == 0 {
		c.ClosedAt = r.KeptMS / 1000
	}
	if r.Site != SiteMatches || r.RejectReason != "" {
		c.Proposal, c.ProposalSig, c.Bundle = r.Proposal, r.ProposalSig, r.Bundle
	}
	return c
}

// digest identifies the record's content apart from the fields that the
// act of looking changes.
func (r *record) digest() []byte {
	c := *r
	c.EvidenceHash, c.EvidenceMS, c.ChangedMS, c.CheckAskMS, c.AskMS = nil, 0, 0, 0, 0
	if b := c.Ballot; b != nil {
		// The schedule moves on by itself (an hourly status ask); it is not
		// evidence, and must not force a fresh export.
		cb := *b
		cb.NextSendMS, cb.NextStatusMS, cb.Round, cb.RoundStartMS, cb.LastAnswerMS = 0, 0, 0, 0, 0
		c.Ballot = &cb
	}
	b, _ := json.Marshal(&c)
	return votewire.H(b)
}

func (r *record) toCompact() *compact {
	c := &compact{Conn: r.Conn, ID: r.ID, Hash: r.Hash, Tag: r.Tag, ServiceIK: r.ServiceIK, ClosedAt: r.Closes, Outcome: "closed"}
	if r.Check != "" {
		c.Outcome = r.Check
	}
	if b := r.Ballot; b != nil {
		c.VK, c.ChoiceID, c.BallotSig, c.MsgMS, c.ReceiptSig, c.Refusals = b.VK, b.ChoiceID, b.BallotSig, b.MsgMS, b.ReceiptSig, b.Refusals
		if len(c.VK) == 0 {
			c.VK = r.VK
		}
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
		// 365 days after the close; a record with no close (a malformed
		// document's) from when it was kept.
		base := time.Unix(r.Closes, 0)
		if r.Closes == 0 {
			base = time.UnixMilli(r.KeptMS)
		}
		if r.problem() && now.Sub(base) >= keep && (r.Closes == 0 || r.closed(now)) {
			delete(f.st.Records, k)
		}
	}
	if now.UnixMilli()-f.last >= recheckEvery.Milliseconds() {
		f.last = now.UnixMilli()
		f.recheck(s)
	}
}
