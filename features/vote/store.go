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

// CheckRowsUnavailable is the reason of a check that stays pending (or
// gave up) because the app could not get the member's row (0.83.3).
const CheckRowsUnavailable = "rows_unavailable"

// CheckExtension is the reason of a check that waits for the bundle of an
// extension the results carry, which alone would bring a kept-aside
// receipt into the window (VAULT-MESSAGING 7adc8fe).
const CheckExtension = "extension"

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

	// Held is the cast_sig and body signed under a new credential key whose
	// rotation statement is held (a transfer's approval, §11.14.10): put in
	// force once the statement is sent.
	Held *heldCast `json:"held,omitempty"`

	// Aside is a verified receipt for this ballot whose msg_ms is at or
	// after the close in force but before the original close + 86,400 s
	// (0.88.12, §10.19.5 ok): an extension the vault has not learned yet.
	// It is judged again whenever the close moves and taken (then nil) once
	// msg_ms is before it; one still outside at a final judgement of the
	// results is rejected and kept as evidence. The latest only.
	Aside *keptReceipt `json:"aside,omitempty"`
	// Stopped: already_voted showed an own-vk ballot, the service's final
	// answer to this one: it is not sent again (GC #7991 E).
	Stopped bool `json:"stopped,omitempty"`
}

// shownAside is the receipt of a ballot the service showed (with the
// ballot it is for) kept aside for an extension not learned yet: Answer
// when it came in already_voted.
type shownAside struct {
	Ballot   *svcBallot `json:"ballot"`
	Answer   bool       `json:"answer,omitempty"`
	Rejected bool       `json:"rejected,omitempty"`
}

// keptReceipt is a receipt kept aside (ballot.Aside).
type keptReceipt struct {
	MsgMS      int64  `json:"msg_ms"`
	ReceiptSig []byte `json:"receipt_sig"`
	Rejected   bool   `json:"rejected,omitempty"` // still outside at a final judgement: no receipt, evidence
}

// heldCast is a cast_sig, and its vote.cast body, under the credential key
// Key, kept until Key's rotation statement is sent.
type heldCast struct {
	Key     []byte `json:"key"`
	CastSig []byte `json:"cast_sig"`
	Body    []byte `json:"body"`
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
	// Late: the receipt is for an extension not learned yet and is kept
	// aside (record.AsideShown); it does not count until a verified
	// extension brings it into the window (7adc8fe).
	Late bool `json:"late,omitempty"`
}

// results is what the vault keeps of a checked result (§10.19.6).
type results struct {
	Doc    []byte          `json:"doc"`
	Sig    []byte          `json:"sig"`
	Bundle json.RawMessage `json:"bundle,omitempty"`
	Row    *svcBallot      `json:"row,omitempty"` // nil: an empty row
	Proof  *proof          `json:"proof,omitempty"`
	Others []*otherRow     `json:"other_rows,omitempty"` // second rows under the member's tag (row_duplicate)
	AtMS   int64           `json:"at_ms"`
}

// otherRow is an extra row of the results under the member's tag that
// verified to the signed rows_root at an index other than the main row's.
type otherRow struct {
	Row   *svcBallot `json:"row,omitempty"` // nil: an empty row
	Proof *proof     `json:"proof"`
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
	// RowsProblem: the vote.problem of a rows_unavailable submission was
	// raised (once per record).
	RowsProblem bool `json:"rows_problem,omitempty"`

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
	// ResultsConflict: vote.results_conflict was audited (once per record,
	// 0.88.12).
	ResultsConflict bool `json:"results_conflict,omitempty"`

	// A ballot under the record's own voting key that is not the vault's
	// own (0.88.12, §10.19.3): SelfUnrecorded when the vault held no ballot
	// of its own, SelfConflict when it held a different one. Self is the
	// first such ballot, SelfLatest the latest beside it (evidence);
	// SelfFeed: vote.self_mismatch was made (once per record). TwoReceipts:
	// the service signed receipts for two different ballots under the tag
	// (GC #7991 D), a vote.problem counted toward the cap.
	SelfUnrecorded bool       `json:"self_unrecorded,omitempty"`
	SelfConflict   bool       `json:"self_conflict,omitempty"`
	Self           *svcBallot `json:"self,omitempty"`
	SelfLatest     *svcBallot `json:"self_latest,omitempty"`
	SelfFeed       bool       `json:"self_feed,omitempty"`
	TwoReceipts    bool       `json:"two_receipts,omitempty"`
	// OldVKs are the earlier public voting keys the record held (a reopened
	// vote never cast gets a fresh one): a ballot under any is own-vk.
	OldVKs [][]byte `json:"old_vks,omitempty"`
	// AsideShown is a shown ballot (foreign or own-vk) whose receipt is for
	// an extension not learned yet (GC #7991 C), kept aside like the vault's
	// own receipt (ballot.Aside). AsideProblem: one still outside at a final
	// judgement raised vote.problem (once).
	AsideShown   *shownAside `json:"aside_shown,omitempty"`
	AsideProblem bool        `json:"aside_problem,omitempty"`

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
	// (0.88.12) the own-vk ballots of self_unrecorded or self_conflict (the
	// first and the latest), and a receipt kept aside that was never taken.
	Self       *svcBallot   `json:"self,omitempty"`
	SelfLatest *svcBallot   `json:"self_latest,omitempty"`
	Aside      *keptReceipt `json:"aside,omitempty"`
	AsideShown *shownAside  `json:"aside_shown,omitempty"`
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
	// OversizeHash is the latest over-cap service list's hash (first 8 bytes,
	// hex) and OversizeAtMS when vote.list_ignored was last audited (at most
	// once a day).
	OversizeHash string `json:"oversize_hash,omitempty"`
	// OversizeAudited is the hash last audited; a latest hash that differs
	// is pending until a day has passed since OversizeAtMS.
	OversizeAudited string `json:"oversize_audited,omitempty"`
	OversizeAtMS    int64  `json:"oversize_at_ms,omitempty"`
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

// problem reports whether the record is in the problem set (§10.19.2):
// (0.88.12) self_unrecorded and self_conflict included.
func (r *record) problem() bool {
	return r.capProblem() || r.SelfUnrecorded || r.SelfConflict
}

// capProblem reports whether the record is a problem that counts toward the
// cap of 16 problem records per connection: (0.88.12) a record whose only
// problem is self_unrecorded or self_conflict is not the service's doing
// and does not.
func (r *record) capProblem() bool {
	// A gave_up check never saw results that verify, so it is never clean
	// (0.83.6): a service must not withhold its results and then evict it.
	if r.RejectReason != "" || r.Check == CheckFailed || r.Check == CheckGaveUp || r.RefusalProblem || r.ConflictEv {
		return true
	}
	// A check that waits for a row the app cannot get (0.83.3) is a problem
	// record, not an in-progress one: it is never evicted.
	if r.Check == CheckPending && r.CheckReason == CheckRowsUnavailable {
		return true
	}
	if r.TwoReceipts || r.AsideProblem {
		return true
	}
	if b := r.Ballot; b != nil && (b.State == BallotConflict || b.State == BallotDisputed) {
		return true
	}
	return r.Site == SiteMismatch || r.Site == SiteUnpublished
}

// evictable reports whether the record may be evicted for room (§10.19.2):
// not a problem, closed, and its check final and clean: verified, or
// unconfirmed with a ballot. Not before (the row check is what shows a
// ballot cast under the member's tag by someone else), and never gave_up,
// which is a problem record. In-progress records (checking, upcoming,
// open, a pending check, a ballot not final) never.
func (r *record) evictable(now time.Time) bool {
	if r.problem() || r.Reason != "" || r.Restore || !r.closed(now) || r.checkPending(now) {
		return false
	}
	clean := r.Check == CheckVerified || r.Check == CheckUnconfirmed
	if r.Ballot == nil {
		return r.Check == CheckVerified
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
	c.Self, c.SelfLatest, c.AsideShown = r.Self, r.SelfLatest, r.AsideShown
	if r.Ballot != nil {
		c.Aside = r.Ballot.Aside
	}
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
		if r.capProblem() {
			problems++
		}
	}
	if problems >= votewire.MaxProblemsPerConnection {
		return &limitHit{max: votewire.MaxProblemsPerConnection, problems: true}
	}
	newProblem := rec.problem()
	// A record in `checking` (a check reason, or a restore not yet
	// confirmed) may never verify: it counts toward the 32 and the 128 but
	// not toward the 16 not yet closed (§10.19.2).
	newClosed := rec.closed(now) || rec.Reason != "" || rec.Restore
	for {
		nonProblem, open := 0, 0
		for _, r := range f.forConn(conn) {
			if !r.problem() {
				nonProblem++
				if !r.closed(now) && r.Reason == "" && !r.Restore {
					open++
				}
			}
		}
		// Only closed records are evictable, so evicting cannot lower the
		// count not yet closed: at that cap, refuse before evicting anything.
		if !newProblem && !newClosed && open >= votewire.MaxOpenPerConnection {
			return &limitHit{max: votewire.MaxOpenPerConnection}
		}
		var hit *limitHit
		switch {
		case len(f.st.Records) >= votewire.MaxProposals:
			hit = &limitHit{max: votewire.MaxProposals}
		case !newProblem && nonProblem >= votewire.MaxPerConnection:
			hit = &limitHit{max: votewire.MaxPerConnection}
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
