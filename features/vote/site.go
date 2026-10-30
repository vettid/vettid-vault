package vote

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// listState is the latest verified service list (§10.19.4 "The service
// list") and when it was last seen confirmed.
type listState struct {
	Doc         []byte `json:"doc"`
	Sig         []byte `json:"sig"`
	Version     int64  `json:"version"`
	ConfirmedMS int64  `json:"confirmed_ms"`
}

// Results of SyncServices (the `services` member of vote.site.sync's
// answer, §10.19.8).
const (
	ListKept      = "kept"
	ListConfirmed = "confirmed"
	ListIgnored   = "ignored"
	ListRejected  = "rejected"
)

// SyncServices handles the service list the app fetched from
// votes.vettid.org (`services.json` and its `.sig`): the signature under
// the site key pinned in the release, the strict document, and the chain
// to the list held. The same version again only refreshes the time it was
// last confirmed. A newer list, or a confirmation, makes the vault check
// its `checking` proposals again.
func (f *Feature) SyncServices(s *vault.Session, doc, sig []byte) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncServices(s, doc, sig)
}

func (f *Feature) syncServices(s *vault.Session, doc, sig []byte) string {
	now := s.Now()
	if len(f.opt.SiteKey) == 0 || votewire.VerifyServiceList(f.opt.SiteKey, doc, sig) != nil {
		f.audit(s, "vote.list_rejected", "", "")
		return ListRejected
	}
	l, err := votewire.ParseServiceList(doc)
	if err != nil {
		f.audit(s, "vote.list_rejected", "", "")
		return ListRejected
	}
	held := f.st.List
	if held == nil {
		if !allZero(l.Previous) {
			f.audit(s, "vote.list_rejected", "", "")
			return ListIgnored
		}
	} else {
		hl, err := votewire.ParseServiceList(held.Doc)
		if err != nil {
			// Cannot happen for a list this vault verified; a list that
			// replaces an unreadable one is not trusted blindly.
			f.audit(s, "vote.list_rejected", "", "")
			return ListIgnored
		}
		switch {
		case l.Version == held.Version && eq(doc, held.Doc):
			held.ConfirmedMS = now.UnixMilli()
			f.recheck(s)
			return ListConfirmed
		case l.Version < held.Version:
			return ListIgnored // an older copy (a cache); nothing to say
		case !hl.Extends(held.Doc, l):
			f.audit(s, "vote.list_rejected", "", "")
			return ListIgnored
		}
	}
	f.st.List = &listState{Doc: append([]byte{}, doc...), Sig: append([]byte{}, sig...), Version: l.Version, ConfirmedMS: now.UnixMilli()}
	f.recheck(s)
	return ListKept
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}

// recheck looks again at the `checking` proposals whose reason is the
// service list or the roots: information ends the state, never a lack of
// it (§10.19.4): one whose key is still not named stays `checking`.
func (f *Feature) recheck(s *vault.Session) {
	now := s.Now()
	for _, r := range f.st.Records {
		if r.RejectReason != "" || (r.Reason != ReasonServiceList && r.Reason != ReasonTrustRoot) {
			continue
		}
		switch f.anchor(s, r.Conn, r.Proposal, r.Bundle, time.UnixMilli(r.ReceivedMS).Add(AnchorAhead)) {
		case anchorOK:
			r.Reason = ""
			r.ChangedMS = now.UnixMilli()
			f.opened(s, r)
			f.event(s, r, "proposal")
		case anchorRejected, anchorLate:
			r.RejectReason, r.Reason = RejectAnchor, ""
			r.ChangedMS = now.UnixMilli()
			f.audit(s, "vote.proposal_rejected", r.Conn, r.ID+":"+RejectAnchor)
			f.feed(s, "vote.problem", r.Conn, r.ID, "high")
			f.event(s, r, "problem")
		case anchorServiceList:
			r.Reason = ReasonServiceList
		case anchorTrustRoot:
			r.Reason = ReasonTrustRoot
		}
	}
}

// SiteDoc is what the app found at p/<proposal_id>/proposal.json on
// votes.vettid.org (VOTES-SITE §3): the document, not the index.
type SiteDoc struct {
	Answered bool            // the site answered at all
	Found    bool            // a document exists (false: a 404)
	Proposal []byte          // its exact bytes
	Sig      []byte          // proposal.json.sig
	Bundle   json.RawMessage // proposal.json.sigstore.json
}

// ErrNoSuchVote is returned for a proposal the vault does not hold.
var ErrNoSuchVote = errors.New("vote: no such proposal")

// SiteDocument records the comparison with the public site (§10.19.4
// "Comparing with the public site"; BALLOT-PROTOCOL §9.2, a split view):
//
//   - matches: the document's bytes equal the held bytes;
//   - mismatch: it exists with other bytes. Kept as evidence, audited
//     `vote.proposal_conflict` (`<id>:mismatch`), a vote.problem feed item;
//     it blocks a cast, and changes no ballot;
//   - not_listed: an answering site has no document. More than ten minutes
//     after the proposal arrived it is audited (`<id>:not_listed`) and
//     made a vote.problem feed item; the member can still vote;
//   - unpublished: no document after the close in force: a positive
//     problem (`<id>:unpublished`);
//   - unreachable: no answer; blocks nothing.
//
// Each finding is raised once.
func (f *Feature) SiteDocument(s *vault.Session, conn, id string, d SiteDoc) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.st.Records[key(conn, id)]
	if r == nil {
		return ErrNoSuchVote
	}
	now := s.Now()
	var next, alert string
	switch {
	case !d.Answered:
		next = SiteUnreachable
	case d.Found && eq(d.Proposal, r.Proposal):
		next = SiteMatches
	case d.Found:
		next, alert = SiteMismatch, "mismatch"
	case r.closed(now):
		next, alert = SiteUnpublished, "unpublished"
	default:
		next = SiteNotListed
		if now.Sub(time.UnixMilli(r.ReceivedMS)) > NotListedAfter {
			alert = "not_listed"
		}
	}
	if next != r.Site {
		r.Site, r.SiteSince, r.ChangedMS = next, now.UnixMilli(), now.UnixMilli()
	}
	if next == SiteMismatch && r.SiteCopy == nil {
		r.SiteCopy = &evidence{Proposal: d.Proposal, Sig: d.Sig, Bundle: d.Bundle, AtMS: now.UnixMilli()}
	}
	if alert != "" && r.SiteAlert != alert {
		r.SiteAlert = alert
		f.audit(s, "vote.proposal_conflict", conn, id+":"+alert)
		f.feed(s, "vote.problem", conn, id, "high")
		f.event(s, r, "problem")
	}
	return nil
}
