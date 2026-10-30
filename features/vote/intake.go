package vote

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

func eq(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

func okBody(id string) json.RawMessage {
	return strictjson.NewBuilder().String("proposal_id", id).Bytes()
}

func (f *Feature) audit(s *vault.Session, kind, conn, ref string) {
	s.Record(vault.Activity{Kind: kind, ConnectionID: conn, Ref: ref, Audit: true})
}

// feed makes a feed item (§10.9, §10.19.7). The id of a proposal, never a
// choice.
func (f *Feature) feed(s *vault.Session, kind, conn, ref, priority string) {
	s.Record(vault.Activity{Kind: kind, ConnectionID: conn, Ref: ref, Feed: true, Priority: priority})
}

// event tells the owner's app that a vote changed (§10.19.8 vote.event).
func (f *Feature) event(s *vault.Session, r *record, event string) {
	b := strictjson.NewBuilder().String("proposal_id", r.ID).String("connection_id", r.Conn).String("event", event).
		String("state", r.state(s.Now()))
	s.NotifyAllDevices("vote.event", b.Bytes())
}

// idOf reads a proposal_id from document bytes that failed the document
// check, if they have a valid one (for the audit entry's ref, and a
// rejected record).
func idOf(doc []byte) string {
	o, err := strictjson.ParseObject(doc)
	if err != nil {
		return ""
	}
	id, err := o.String("proposal_id")
	if err != nil || !votewire.ValidProposalID(id) {
		return ""
	}
	return id
}

// isConnKey reports whether ik is the connection's identity key now or an
// earlier one on its rotation chain (§3.4, §6.6).
func isConnKey(s *vault.Session, conn string, ik []byte) bool {
	c, ok := s.Connection(conn)
	if !ok {
		return false
	}
	return eq(c.IK, ik) || s.PriorIdentity(conn, ik)
}

// anchorResult is what §10.19.4 step 6 concludes.
type anchorResult int

const (
	anchorOK anchorResult = iota
	anchorServiceList
	anchorTrustRoot
	anchorRejected
	anchorLate
	anchorClock
	anchorSite // a status answer without a bundle: the site's arrives later
)

// listIndex is the held service list, parsed once when it is kept (the
// parse of a list near its 4 MiB cap takes about a second), with its
// services indexed by identity key. It is memory only and rebuilt when the
// held list changes.
type listIndex struct {
	src  *listState
	list *votewire.ServiceList
	byIK map[string]*votewire.ServiceEntry
}

func (f *Feature) index() *listIndex {
	if f.st.List == nil {
		return nil
	}
	if f.idx != nil && f.idx.src == f.st.List {
		return f.idx
	}
	ix := &listIndex{src: f.st.List}
	if l, err := votewire.ParseServiceList(f.st.List.Doc); err == nil {
		ix.list, ix.byIK = l, l.ByIK()
	}
	f.idx = ix
	return ix
}

// acceptedKeys are the anchor keys the service list names for this
// connection's service and the connection's own key certifies: the entry
// that lists a key of the connection (its current key, or one of keys: the
// ones the proposal was signed with and kept under), and each of its anchor
// keys whose anchor_cert verifies over H(SPKI) under an ik that is a key
// of the connection (not merely the ik the entry names, §10.19.4 step 6).
func (f *Feature) acceptedKeys(s *vault.Session, conn string, keys ...[]byte) [][]byte {
	ix := f.index()
	if ix == nil || ix.list == nil {
		return nil
	}
	cands := keys
	if c, ok := s.Connection(conn); ok {
		cands = append(append([][]byte{}, keys...), c.IK)
	}
	var out [][]byte
	seen := map[*votewire.ServiceEntry]bool{}
	for _, k := range cands {
		e := ix.byIK[string(k)]
		if e == nil || seen[e] || !isConnKey(s, conn, k) {
			continue
		}
		seen[e] = true
		for _, a := range e.AnchorKeys {
			if isConnKey(s, conn, a.IK) && votewire.VerifyAnchorCert(a.IK, a.Key, a.AnchorCert) == nil {
				out = append(out, a.Key)
			}
		}
	}
	return out
}

// anchor is §10.19.4 step 6 for one document and its bundle: no verified
// list, or none naming an accepted key of this service, or a bundle whose
// key is not among them, is service_list; a document the bundle
// contradicts, a stamp after notAfter (zero: no limit) or t_int - t_tsa
// outside -60..600 s is rejected; anything the roots do not verify or this
// release does not recognise is trust_root; a stamp more than 300 s ahead
// of this vault's clock is clock (0.81.1).
func (f *Feature) anchor(s *vault.Session, conn string, signers [][]byte, doc []byte, bundle json.RawMessage, notAfter time.Time) anchorResult {
	if f.st.List == nil {
		return anchorServiceList
	}
	keys := f.acceptedKeys(s, conn, signers...)
	if len(keys) == 0 {
		return anchorServiceList
	}
	if len(bundle) == 0 {
		return anchorSite // a status answer without a bundle waits for the site's
	}
	_, err := votewire.VerifyBundle(doc, bundle, keys, f.opt.Roots, notAfter, s.Now())
	switch {
	case err == nil:
		return anchorOK
	case errors.Is(err, votewire.ErrAnchorKey):
		return anchorServiceList
	case errors.Is(err, votewire.ErrAnchor):
		return anchorRejected
	case errors.Is(err, votewire.ErrAnchorLate):
		return anchorLate
	case errors.Is(err, votewire.ErrBundleClock):
		return anchorClock
	}
	return anchorTrustRoot
}

// reject records a refusal of the request itself: the audit entry, and,
// for a proposal with a valid id that is not yet held, the rejected record
// that is kept as evidence and listed (§10.19.3), with a vote.problem
// feed item.
func (f *Feature) reject(s *vault.Session, conn, id, reason string, msg *votewire.ProposalMsg, p *votewire.Proposal) error {
	ref := conn + ":" + reason
	if id != "" {
		ref = id + ":" + reason
	}
	f.audit(s, "vote.proposal_rejected", conn, ref)
	if id == "" || f.st.Records[key(conn, id)] != nil {
		return errBad
	}
	now := s.Now()
	r := &record{Conn: conn, ID: id, ServiceIK: append([]byte{}, s.From().IK...), Proposal: msg.Proposal, ProposalSig: msg.ProposalSig,
		Bundle: msg.Bundle, Hash: votewire.H(msg.Proposal), Secret: msg.RecordSecret, RejectReason: reason,
		ReceivedMS: s.RelayTime().UnixMilli(), NoRelay: !s.RelayTimeKnown(), KeptMS: now.UnixMilli(), ChangedMS: now.UnixMilli()}
	if tag, err := votewire.RecordTag(id, msg.RecordSecret); err == nil {
		r.Tag = tag
	}
	if msg.RecordProof != nil {
		r.Proof = &proof{Index: msg.RecordProof.Index, TreeSize: msg.RecordProof.TreeSize, Path: msg.RecordProof.Path}
	}
	if p != nil {
		r.Opens, r.Closes, r.OrigClose, r.Title = p.OpensAt, p.ClosesAt, p.ClosesAt, p.Title
	}
	if hit := f.admit(r, now); hit != nil {
		return f.limit(s, conn, hit)
	}
	f.st.Records[key(conn, id)] = r
	f.feed(s, "vote.problem", conn, id, "high")
	f.event(s, r, "problem")
	return errBad
}

func (f *Feature) limit(s *vault.Session, conn string, hit *limitHit) error {
	now := s.Now()
	f.audit(s, "drop.vote_limit", conn, conn)
	d := f.st.Dropped[conn]
	if d == nil {
		d = &droppedNote{}
		f.st.Dropped[conn] = d
	}
	if hit.problems {
		f.st.Problems[conn] = true
	} else {
		d.Count++
		d.LastMS = now.UnixMilli()
	}
	// At most one feed item per connection per 24 hours.
	if last, ok := f.st.FeedAt[conn]; !ok || now.Sub(time.UnixMilli(last)) >= ProblemFeedGap {
		f.st.FeedAt[conn] = now.UnixMilli()
		f.feed(s, "vote.problem", conn, conn, "high")
	}
	return &vault.HandlerError{Code: "limit", Body: strictjson.NewBuilder().String("limit", "votes").Uint("max", uint64(hit.max)).Bytes()}
}

func sameProof(a *proof, b *votewire.RecordProof) bool {
	if a == nil || b == nil || a.Index != b.Index || a.TreeSize != b.TreeSize || len(a.Path) != len(b.Path) {
		return false
	}
	for i := range a.Path {
		if !eq(a.Path[i], b.Path[i]) {
			return false
		}
	}
	return true
}

// onProposal is §10.19.4 "On vote.proposal", steps 1 to 8.
func (f *Feature) onProposal(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	conn := s.From().ID
	// 1. Shape.
	msg, err := votewire.ParseProposalMsg(in.Body)
	if err != nil {
		f.audit(s, "drop.vote_malformed", conn, conn)
		return nil, errBad
	}
	return f.intake(s, conn, msg)
}

// intake is steps 2 to 8, for the members of a vote.proposal, or of a
// vote.status answer for a proposal the vault was never sent (whose bundle
// may be absent: `checking` (site)).
func (f *Feature) intake(s *vault.Session, conn string, msg *votewire.ProposalMsg) (json.RawMessage, error) {
	now := s.Now()
	// 2. The document.
	p, err := votewire.ParseProposal(msg.Proposal)
	if err != nil {
		return nil, f.reject(s, conn, idOf(msg.Proposal), RejectMalformed, msg, nil)
	}
	id := p.ProposalID
	// 3. The service.
	if !isConnKey(s, conn, p.Service) {
		return nil, f.reject(s, conn, id, RejectService, msg, p)
	}
	if votewire.VerifyProposal(p.Service, msg.Proposal, msg.ProposalSig) != nil {
		return nil, f.reject(s, conn, id, RejectSignature, msg, p)
	}
	// 4. The tag.
	tag, err := votewire.RecordTag(id, msg.RecordSecret)
	if err != nil || msg.RecordProof.Verify(p, tag) != nil {
		return nil, f.reject(s, conn, id, RejectRecord, msg, p)
	}
	// 5. Duplicates.
	notAfter := time.Time{}
	if s.RelayTimeKnown() {
		notAfter = s.RelayTime().Add(AnchorAhead)
	}
	if old := f.st.Records[key(conn, id)]; old != nil {
		if eq(old.Proposal, msg.Proposal) && eq(old.ProposalSig, msg.ProposalSig) && eq(old.Secret, msg.RecordSecret) && sameProof(old.Proof, msg.RecordProof) {
			// A re-send (step 5): nothing changes, whatever bundle it carries.
			// A `checking` record recovers only through recheck (unlock, a
			// service list, new roots, hourly), never by the service's say-so.
			if old.RejectReason != "" {
				return nil, errBad // the same refusal again
			}
			return okBody(id), nil
		}
		if old.Conflict == nil {
			old.Conflict = &evidence{Proposal: msg.Proposal, Sig: msg.ProposalSig, Bundle: msg.Bundle, AtMS: now.UnixMilli()}
			old.ChangedMS = now.UnixMilli()
		}
		f.audit(s, "vote.proposal_conflict", conn, id)
		return nil, errBad
	}
	// 6. The anchor.
	var reason, rejected string
	switch f.anchor(s, conn, [][]byte{p.Service, s.From().IK}, msg.Proposal, msg.Bundle, notAfter) {
	case anchorServiceList:
		reason = ReasonServiceList
	case anchorTrustRoot:
		reason = ReasonTrustRoot
	case anchorClock:
		reason = ReasonClock
	case anchorSite:
		reason = ReasonSite
	case anchorRejected, anchorLate:
		rejected = RejectAnchor
	}
	if rejected != "" {
		return nil, f.reject(s, conn, id, rejected, msg, p)
	}
	// 7. The state is the clock's (a proposal already past its close is
	// kept closed, with no feed item); 8. keeping.
	r := &record{Conn: conn, ID: id, ServiceIK: append([]byte{}, s.From().IK...), Proposal: msg.Proposal, ProposalSig: msg.ProposalSig,
		Bundle: msg.Bundle, Hash: votewire.H(msg.Proposal), Secret: msg.RecordSecret, Tag: tag,
		Proof:      &proof{Index: msg.RecordProof.Index, TreeSize: msg.RecordProof.TreeSize, Path: msg.RecordProof.Path},
		ReceivedMS: s.RelayTime().UnixMilli(), NoRelay: !s.RelayTimeKnown(), KeptMS: now.UnixMilli(), ChangedMS: now.UnixMilli(),
		Opens: p.OpensAt, Closes: p.ClosesAt, OrigClose: p.ClosesAt, Title: p.Title, Reason: reason, Signer: p.Service}
	if hit := f.admit(r, now); hit != nil {
		return nil, f.limit(s, conn, hit)
	}
	seed, err := suite.RandomBytes(ed25519.SeedSize)
	if err != nil {
		return nil, vault.NewError("internal", "")
	}
	r.VKSeed = seed
	r.VK = append([]byte{}, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)...)
	f.st.Records[key(conn, id)] = r
	f.opened(s, r)
	f.event(s, r, "proposal")
	return okBody(id), nil
}

// opened makes the vote.open feed item when a record is upcoming or open
// and the member has not been told (§10.19.7): at keeping, or when a
// `checking` proposal becomes verified. A closed record gets none.
func (f *Feature) opened(s *vault.Session, r *record) {
	st := r.state(s.Now())
	if r.OpenFeed || (st != StateUpcoming && st != StateOpen) {
		return
	}
	r.OpenFeed = true
	f.feed(s, "vote.open", r.Conn, r.ID, "")
}

// onClosed is §10.19.4 "On vote.closed": unsigned, so it closes nothing; it
// only brings the results check forward.
func (f *Feature) onClosed(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	conn := s.From().ID
	m, err := votewire.ParseClosedMsg(in.Body)
	if err != nil {
		f.audit(s, "drop.vote_malformed", conn, conn)
		return nil, errBad
	}
	r := f.st.Records[key(conn, m.ProposalID)]
	if r == nil {
		return nil, errNotFound
	}
	if r.ResultsHash == nil {
		r.ResultsHash = m.ResultsHash
		r.ClosedMS = s.Now().UnixMilli()
		r.ChangedMS = r.ClosedMS
		f.event(s, r, "closed")
	}
	return okBody(r.ID), nil
}

// onExtended is §10.19.4 "On vote.extended".
func (f *Feature) onExtended(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	conn := s.From().ID
	m, err := votewire.ParseExtendedMsg(in.Body)
	if err != nil {
		f.audit(s, "drop.vote_malformed", conn, conn)
		return nil, errBad
	}
	r := f.st.Records[key(conn, m.ProposalID)]
	if r == nil || r.RejectReason != "" {
		return nil, errNotFound
	}
	fail := func(reason string) (json.RawMessage, error) {
		f.audit(s, "vote.extension_rejected", conn, r.ID+":"+reason)
		return nil, errBad
	}
	ext, err := votewire.ParseExtension(m.Extension)
	if err != nil || ext.ProposalID != r.ID {
		return fail("malformed")
	}
	// The proposal's own key signs every document of it.
	p, err := votewire.ParseProposal(r.Proposal)
	if err != nil {
		return fail("malformed")
	}
	if votewire.VerifyExtension(p.Service, r.Hash, m.Extension, m.ExtensionSig) != nil {
		return fail("signature")
	}
	// n: the next one, a repeat, or a later one kept aside until its
	// predecessors arrive.
	next := int64(len(r.Exts)) + 1
	rec := &extRec{N: ext.N, Doc: m.Extension, Sig: m.ExtensionSig, Bundle: m.Bundle, Closes: ext.ClosesAt}
	switch {
	case ext.N <= int64(len(r.Exts)):
		if eq(r.Exts[ext.N-1].Doc, m.Extension) {
			return okBody(r.ID), nil
		}
		return fail("order")
	case ext.N > next:
		if r.Aside != nil && !eq(r.Aside.Doc, m.Extension) {
			return fail("order")
		}
		r.Aside = rec
		return okBody(r.ID), nil
	}
	if reason := f.applyExtension(s, r, rec); reason != "" {
		return fail(reason)
	}
	// A later one that waited can follow now.
	if a := r.Aside; a != nil && a.N == int64(len(r.Exts))+1 {
		r.Aside = nil
		if reason := f.applyExtension(s, r, a); reason != "" {
			f.audit(s, "vote.extension_rejected", conn, r.ID+":"+reason)
		}
	}
	return okBody(r.ID), nil
}

// applyExtension checks the order, the total and the anchor of the next
// extension and, if they hold, moves the close (§10.19.4). It returns the
// reason of a refusal, or "".
func (f *Feature) applyExtension(s *vault.Session, r *record, e *extRec) string {
	ext, err := votewire.ParseExtension(e.Doc)
	p, perr := votewire.ParseProposal(r.Proposal)
	if err != nil || perr != nil {
		return "malformed"
	}
	// Order (0.81.1): a close above the one in force, an outage longer than
	// 3,600 s that starts inside the voting window, and a new close within
	// the outage rounded up to the hour. Then the total.
	if e.Closes <= r.Closes || !ext.OrderOK(p.OpensAt, r.Closes) {
		return "order"
	}
	if e.Closes-r.OrigClose > votewire.MaxExtension {
		return "total"
	}
	// Anchored before the close it extends (the one in force), on the
	// truncated genTime.
	switch f.anchor(s, r.Conn, r.signers(), e.Doc, e.Bundle, time.Unix(r.Closes-1, 0)) {
	case anchorOK:
	case anchorLate:
		return "late"
	default:
		return "anchor"
	}
	r.Exts = append(r.Exts, e)
	r.Closes = e.Closes
	r.AbsentMS = 0 // the 404s counted were for the old close
	if r.Ballot == nil && len(r.VKSeed) == 0 {
		// A vote that was never cast and has reopened needs a voting key again.
		if seed, err := suite.RandomBytes(ed25519.SeedSize); err == nil {
			r.VKSeed = seed
			r.VK = append([]byte{}, ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)...)
		}
	}
	if b := r.Ballot; b != nil && !b.final() { // a verified extension restarts sending
		b.Round, b.NextSendMS = 0, 0
	}
	r.ChangedMS = s.Now().UnixMilli()
	f.audit(s, "vote.extended", r.Conn, r.ID+":"+strconv.FormatInt(e.N, 10))
	f.event(s, r, "extended")
	return ""
}
