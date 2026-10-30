package vote

import (
	"encoding/hex"
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
	// The size first (BALLOT-PROTOCOL 0.12.5): a list over the cap, or one
	// the vault cannot take, changes nothing; the vault keeps the last list
	// it verified and goes on with the services that list names.
	if len(doc) > votewire.MaxServiceList {
		// VAULT-MESSAGING 0.81.2: ignored, not an error. The latest hash is
		// kept; one audit entry (`vote.list_ignored`, ref size:<first 8 bytes
		// of SHA-256, hex>) when it changes, at most once a day, and no feed
		// item. The held list stays. The bytes are unverified, so nothing of
		// them (a version) is read.
		h := hex.EncodeToString(votewire.H(doc)[:8])
		if h != f.st.OversizeHash {
			f.st.OversizeHash = h
			if f.st.OversizeAtMS == 0 || now.Sub(time.UnixMilli(f.st.OversizeAtMS)) >= 24*time.Hour {
				f.st.OversizeAtMS = now.UnixMilli()
				f.audit(s, "vote.list_ignored", "", "size:"+h)
			}
		}
		return ListIgnored
	}
	if len(f.opt.SiteKey) == 0 || votewire.VerifyServiceList(f.opt.SiteKey, doc, sig) != nil {
		f.audit(s, "vote.list_rejected", "", "")
		return ListRejected
	}
	held := f.st.List
	if held != nil && eq(doc, held.Doc) {
		// The same bytes again (the signature was just verified): it only
		// refreshes the time the list was last confirmed.
		held.ConfirmedMS = now.UnixMilli()
		f.recheck(s)
		return ListConfirmed
	}
	l, err := votewire.ParseServiceList(doc)
	if err != nil {
		f.audit(s, "vote.list_rejected", "", "")
		return ListRejected
	}
	if held == nil {
		// 0.81.1: a vault with no list takes any that verifies and parses,
		// whatever its version or previous; chaining begins after it.
	} else {
		var hl *votewire.ServiceList
		if ix := f.index(); ix != nil {
			hl = ix.list
		}
		if hl == nil {
			// Cannot happen for a list this vault verified; a list that
			// replaces an unreadable one is not trusted blindly.
			f.audit(s, "vote.list_rejected", "", "")
			return ListIgnored
		}
		switch {
		case l.Version < held.Version:
			return ListIgnored // an older copy (a cache); nothing to say
		case !hl.Extends(held.Doc, l):
			f.audit(s, "vote.list_rejected", "", "")
			return ListIgnored
		}
	}
	f.st.List = &listState{Doc: append([]byte{}, doc...), Sig: append([]byte{}, sig...), Version: l.Version, ConfirmedMS: now.UnixMilli()}
	f.idx = &listIndex{src: f.st.List, list: l, byIK: l.ByIK()} // parsed once, here
	f.recheck(s)
	return ListKept
}

// SyncCatchUp handles the service-list versions the app hands over in one
// vote.site.sync, oldest first (0.81.1 "Catch-up"): each is applied in
// turn as SyncServices does, and the first that is not kept or confirmed
// stops the rest, which are answered "ignored". It returns one result per
// list.
func (f *Feature) SyncCatchUp(s *vault.Session, lists []ServiceListDoc) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.syncCatchUp(s, lists)
}

func (f *Feature) syncCatchUp(s *vault.Session, lists []ServiceListDoc) []string {
	out := make([]string, len(lists))
	stopped := false
	for i, l := range lists {
		if stopped {
			out[i] = ListIgnored
			continue
		}
		out[i] = f.syncServices(s, l.Doc, l.Sig)
		stopped = out[i] != ListKept && out[i] != ListConfirmed
	}
	return out
}

// ServiceListDoc is a service list's bytes with its signature.
type ServiceListDoc struct{ Doc, Sig []byte }

// recheck looks again at the `checking` proposals whose reason is the
// service list, the roots or the clock: information ends the state, never a
// lack of it (§10.19.4): one whose anchor key is still not named stays
// `checking` (`service_list`).
func (f *Feature) recheck(s *vault.Session) {
	for _, r := range f.st.Records {
		f.recheckOne(s, r)
	}
}

func (f *Feature) recheckOne(s *vault.Session, r *record) {
	now := s.Now()
	if r.RejectReason != "" || (r.Reason != ReasonServiceList && r.Reason != ReasonTrustRoot && r.Reason != ReasonClock) {
		return
	}
	var notAfter time.Time
	if !r.NoRelay {
		notAfter = time.UnixMilli(r.ReceivedMS).Add(AnchorAhead)
	}
	switch f.anchor(s, r.Conn, r.signers(), r.Proposal, r.Bundle, notAfter) {
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
	case anchorClock:
		r.Reason = ReasonClock
	}
}

// Unlocked implements vault.UnlockObserver: at unlock the `checking`
// proposals are looked at again (0.81.1): the roots of this release may be
// newer than when they were kept, and a `clock` reason goes when the
// vault's clock has caught up.
func (f *Feature) Unlocked(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = s.Now().UnixMilli()
	f.recheck(s)
}

// The answers for the site's p/<proposal_id>/proposal.json (VOTES-SITE §3),
// as the app reports them (0.81.2): the app gives no time; the vault's own
// clock times every answer.
const (
	StatusFound       = "found"       // the document exists
	StatusAbsent      = "absent"      // the site answered 404
	StatusUnreachable = "unreachable" // no answer
)

// SiteDoc is the app's report on one proposal's document: its status and,
// when found, the exact bytes, `.sig` and bundle.
type SiteDoc struct {
	Status   string
	Proposal []byte          // its exact bytes (found)
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
//   - unpublished: no document after the close in force, **twice**: a
//     second `absent` at least ten minutes after the first, both after the
//     close and both timed on the vault's clock; a found document in
//     between clears the first. One 404 is only not_listed. A positive
//     problem (`<id>:unpublished`);
//   - unreachable: no answer; blocks nothing and counts for nothing.
//
// Each finding is raised once.
func (f *Feature) SiteDocument(s *vault.Session, conn, id string, d SiteDoc) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.siteDocument(s, conn, id, d)
}

func (f *Feature) siteDocument(s *vault.Session, conn, id string, d SiteDoc) error {
	r := f.st.Records[key(conn, id)]
	if r == nil {
		return ErrNoSuchVote
	}
	// Once found, a mismatch and an unpublished proposal are permanent: the
	// site is write-once and takes uploads only before the close, so a later
	// answer changes neither.
	if r.Site == SiteMismatch || r.Site == SiteUnpublished {
		return nil
	}
	now := s.Now()
	status := d.Status
	// A document that is not a valid proposal of this id signed under the
	// service's key is not a split view, it is garbage: no answer.
	if status == StatusFound && !eq(d.Proposal, r.Proposal) && !f.siteDocValid(r, d) {
		status = StatusUnreachable
	}
	// A proposal kept from a status answer without a bundle waits for the
	// site's (checking, site). The site's bundle is taken only if it verifies
	// for the held bytes; anything else (another proposal's, garbage) leaves
	// the record as it is, never rejected and never under another reason.
	if status == StatusFound && r.Reason == ReasonSite && eq(d.Proposal, r.Proposal) && len(d.Bundle) > 0 {
		var notAfter time.Time
		if !r.NoRelay {
			notAfter = time.UnixMilli(r.ReceivedMS).Add(AnchorAhead)
		}
		if f.anchor(s, r.Conn, r.signers(), r.Proposal, d.Bundle, notAfter) == anchorOK {
			r.Bundle, r.Reason = d.Bundle, ""
			r.ChangedMS = now.UnixMilli()
			f.opened(s, r)
			f.event(s, r, "proposal")
		}
	}
	var next, alert string
	switch status {
	case StatusFound:
		r.AbsentMS = 0 // a found document in between clears the first 404
		if eq(d.Proposal, r.Proposal) {
			next = SiteMatches
		} else {
			next, alert = SiteMismatch, "mismatch"
		}
	case StatusAbsent:
		next = SiteNotListed
		if now.Sub(time.UnixMilli(r.ReceivedMS)) > NotListedAfter {
			alert = "not_listed"
		}
		if r.closed(now) {
			switch {
			case r.AbsentMS == 0:
				r.AbsentMS = now.UnixMilli()
			case now.Sub(time.UnixMilli(r.AbsentMS)) >= NotListedAfter:
				next, alert = SiteUnpublished, "unpublished"
			}
		}
	default: // unreachable, or anything the vault does not know
		next = SiteUnreachable
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

// siteDocValid reports whether the site's document is a valid proposal
// with the held proposal's id, signed under the service's key.
func (f *Feature) siteDocValid(r *record, d SiteDoc) bool {
	held, err := votewire.ParseProposal(r.Proposal)
	if err != nil {
		return false
	}
	p, err := votewire.ParseProposal(d.Proposal)
	return err == nil && p.ProposalID == r.ID && votewire.VerifyProposal(held.Service, d.Proposal, d.Sig) == nil
}
