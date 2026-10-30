package votewire

import (
	"encoding/hex"
	"encoding/json"
	"unicode/utf8"
)

// The documents of BALLOT-PROTOCOL §8.5. Each is JCS (RFC 8785) and is
// parsed only from its exact canonical bytes, with every member present and
// no other. Binary members are []byte, which encoding/json writes as
// standard base64 with padding.

// Choice is one of a proposal's choices.
type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// Quorum is a proposal's quorum rule.
type Quorum struct {
	Text       string `json:"text"`
	MinBallots int64  `json:"min_ballots"`
}

// Proposal is the proposal document (§8.5).
type Proposal struct {
	V              int64    `json:"v"`
	ProposalID     string   `json:"proposal_id"`
	Service        []byte   `json:"service"`
	Title          string   `json:"title"`
	Text           string   `json:"text"`
	Choices        []Choice `json:"choices"`
	Quorum         Quorum   `json:"quorum"`
	Binding        bool     `json:"binding"`
	RemovedMayVote bool     `json:"removed_may_vote"`
	RecordAt       int64    `json:"record_at"`
	OpensAt        int64    `json:"opens_at"`
	ClosesAt       int64    `json:"closes_at"`
	Eligible       int64    `json:"eligible"`
	RecordRoot     []byte   `json:"record_root"`
	OutageRule     string   `json:"outage_rule"`
}

// Outage is the outage an extension is for.
type Outage struct {
	From   int64  `json:"from"`
	To     int64  `json:"to"`
	Source string `json:"source"`
}

// Extension is an extension document (§8.5).
type Extension struct {
	V          int64  `json:"v"`
	ProposalID string `json:"proposal_id"`
	N          int64  `json:"n"`
	ClosesAt   int64  `json:"closes_at"`
	Outage     Outage `json:"outage"`
}

// Signed is a document's bytes with its detached signature.
type Signed struct {
	Doc []byte `json:"doc"`
	Sig []byte `json:"sig"`
}

// Counts are the results' counts.
type Counts struct {
	Eligible  int64 `json:"eligible"`
	Ballots   int64 `json:"ballots"`
	Removed   int64 `json:"removed"`
	Unhandled int64 `json:"unhandled"`
}

// Results is the results document (§8.5).
type Results struct {
	V          int64            `json:"v"`
	ProposalID string           `json:"proposal_id"`
	Proposal   Signed           `json:"proposal"`
	Extensions []Signed         `json:"extensions"`
	RowsHash   []byte           `json:"rows_hash"`
	RowsRoot   []byte           `json:"rows_root"`
	Tally      map[string]int64 `json:"tally"`
	Counts     Counts           `json:"counts"`
}

// AnchorKey is one anchor key of a service list entry: an ECDSA P-256
// public key (SPKI DER) with the service's certificate over H(key).
type AnchorKey struct {
	Key        []byte `json:"key"`
	AnchorCert []byte `json:"anchor_cert"`
	IK         []byte `json:"ik"`
}

// ServiceEntry is one service of the service list.
type ServiceEntry struct {
	ServiceID  string      `json:"service_id"`
	Name       string      `json:"name"`
	IKs        [][]byte    `json:"iks"`
	AnchorKeys []AnchorKey `json:"anchor_keys"`
}

// ServiceList is the document votes.vettid.org publishes and signs
// (services.json, §8.5).
type ServiceList struct {
	V        int64          `json:"v"`
	Version  int64          `json:"version"`
	Previous []byte         `json:"previous"`
	Services []ServiceEntry `json:"services"`
}

// schema is the exact member names of a document's objects: a key maps to
// nested names for an object, a one-element []any{schema} for an array of
// objects, "map" for an object of integers, or nil for a leaf (whose type
// the decode checks).
type schema map[string]any

var (
	signedSchema   = schema{"doc": nil, "sig": nil}
	proposalSchema = schema{
		"v": nil, "proposal_id": nil, "service": nil, "title": nil, "text": nil,
		"choices": []any{schema{"id": nil, "label": nil}},
		"quorum":  schema{"text": nil, "min_ballots": nil},
		"binding": nil, "removed_may_vote": nil, "record_at": nil, "opens_at": nil,
		"closes_at": nil, "eligible": nil, "record_root": nil, "outage_rule": nil,
	}
	extensionSchema = schema{
		"v": nil, "proposal_id": nil, "n": nil, "closes_at": nil,
		"outage": schema{"from": nil, "to": nil, "source": nil},
	}
	resultsSchema = schema{
		"v": nil, "proposal_id": nil, "proposal": signedSchema,
		"extensions": []any{signedSchema}, "rows_hash": nil, "rows_root": nil,
		"tally":  "map",
		"counts": schema{"eligible": nil, "ballots": nil, "removed": nil, "unhandled": nil},
	}
	serviceListSchema = schema{
		"v": nil, "version": nil, "previous": nil,
		"services": []any{schema{
			"service_id": nil, "name": nil, "iks": nil,
			"anchor_keys": []any{schema{"key": nil, "anchor_cert": nil, "ik": nil}},
		}},
	}
)

// checkSchema refuses an object whose members are not exactly the schema's,
// or are null where a value belongs.
func checkSchema(m map[string]any, s schema) error {
	for k, sub := range s {
		v, ok := m[k]
		if !ok || v == nil {
			return ErrDocument
		}
		switch t := sub.(type) {
		case schema:
			o, ok := v.(map[string]any)
			if !ok || checkSchema(o, t) != nil {
				return ErrDocument
			}
		case []any:
			a, ok := v.([]any)
			if !ok {
				return ErrDocument
			}
			for _, e := range a {
				o, ok := e.(map[string]any)
				if !ok || checkSchema(o, t[0].(schema)) != nil {
					return ErrDocument
				}
			}
		case string: // "map": an object of integers
			o, ok := v.(map[string]any)
			if !ok {
				return ErrDocument
			}
			for _, e := range o {
				if _, ok := e.(int64); !ok {
					return ErrDocument
				}
			}
		}
	}
	for k := range m {
		if _, ok := s[k]; !ok {
			return ErrDocument
		}
	}
	return nil
}

// parseDoc checks data's canonical form and schema, then decodes it.
func parseDoc(data []byte, s schema, out any) error {
	m, err := checkCanonical(data)
	if err != nil {
		return err
	}
	if err := checkSchema(m, s); err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return ErrDocument
	}
	// encoding/json accepts some forms a re-encode changes (base64 with
	// stray characters or without padding); the round trip refuses them.
	again, err := encodeCanonical(out)
	if err != nil || !eq(again, data) {
		return ErrDocument
	}
	return nil
}

// ParseProposal parses a proposal's exact bytes and checks the bounds of
// VAULT-MESSAGING §10.19.4 step 2 (the same on the service's side from
// BALLOT-PROTOCOL 0.12.0).
func ParseProposal(data []byte) (*Proposal, error) {
	if len(data) > MaxProposal {
		return nil, ErrDocument
	}
	var p Proposal
	if err := parseDoc(data, proposalSchema, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate checks a proposal's fields: v is 1, proposal_id a canonical
// ULID, title 1 to 200 bytes, text at most 16,384, 3 to 17 choices with
// unique ids matching [a-z0-9-]{1,32} and `abstain` among them, each label
// 1 to 200 bytes, quorum.text at most 1,024 bytes and min_ballots at least
// 0, outage_rule at most 1,024 bytes, opens_at < closes_at with a window of
// at most 604,800 s, eligible at least 1, and every string valid UTF-8.
func (p *Proposal) Validate() error {
	switch {
	case p.V != 1,
		!ValidProposalID(p.ProposalID),
		len(p.Service) != KeyLen,
		len(p.Title) < 1 || len(p.Title) > MaxTitle,
		len(p.Text) > MaxText,
		len(p.Choices) < MinChoices || len(p.Choices) > MaxChoices,
		p.Quorum.MinBallots < 0 || len(p.Quorum.Text) > MaxQuorumText,
		len(p.OutageRule) > MaxOutageRule,
		p.OpensAt >= p.ClosesAt || p.ClosesAt-p.OpensAt > MaxWindow,
		p.Eligible < 1,
		len(p.RecordRoot) != HashLen:
		return ErrDocument
	}
	seen, abstain := map[string]bool{}, false
	for _, c := range p.Choices {
		if !ValidChoiceID(c.ID) || seen[c.ID] || len(c.Label) < 1 || len(c.Label) > MaxLabel {
			return ErrDocument
		}
		seen[c.ID] = true
		abstain = abstain || c.ID == AbstainID
	}
	if !abstain {
		return ErrDocument
	}
	strs := []string{p.Title, p.Text, p.Quorum.Text, p.OutageRule}
	for _, c := range p.Choices {
		strs = append(strs, c.Label)
	}
	for _, s := range strs {
		if !utf8.ValidString(s) {
			return ErrDocument
		}
	}
	return nil
}

// HasChoice reports whether id is one of the proposal's choices.
func (p *Proposal) HasChoice(id string) bool {
	for _, c := range p.Choices {
		if c.ID == id {
			return true
		}
	}
	return false
}

// ParseExtension parses an extension's exact bytes: v is 1, proposal_id a
// canonical ULID, n at least 1, outage.from < outage.to.
func ParseExtension(data []byte) (*Extension, error) {
	if len(data) > MaxExtensionDoc {
		return nil, ErrDocument
	}
	var e Extension
	if err := parseDoc(data, extensionSchema, &e); err != nil {
		return nil, err
	}
	if e.V != 1 || !ValidProposalID(e.ProposalID) || e.N < 1 || e.Outage.From >= e.Outage.To {
		return nil, ErrDocument
	}
	return &e, nil
}

// ParseResults parses the results document's exact bytes.
func ParseResults(data []byte) (*Results, error) {
	if len(data) > MaxResultsDoc {
		return nil, ErrDocument
	}
	var r Results
	if err := parseDoc(data, resultsSchema, &r); err != nil {
		return nil, err
	}
	if r.V != 1 || !ValidProposalID(r.ProposalID) || len(r.RowsHash) != HashLen || len(r.RowsRoot) != HashLen ||
		len(r.Proposal.Sig) != SigLen || r.Tally == nil || r.Extensions == nil || len(r.Extensions) > MaxExtensions || len(r.Tally) > MaxChoices ||
		r.Counts.Eligible < 1 || r.Counts.Ballots < 0 || r.Counts.Removed < 0 || r.Counts.Unhandled < 0 {
		return nil, ErrDocument
	}
	for _, e := range r.Extensions {
		if len(e.Sig) != SigLen {
			return nil, ErrDocument
		}
	}
	for _, n := range r.Tally {
		if n < 0 {
			return nil, ErrDocument
		}
	}
	return &r, nil
}

// CheckProposal checks the results against the proposal they are for
// (§10.19.6 step 2): the same proposal_id, `tally` naming exactly the
// proposal's choices and `counts.eligible` equal to the proposal's.
func (r *Results) CheckProposal(p *Proposal) error {
	if r.ProposalID != p.ProposalID || r.Counts.Eligible != p.Eligible || len(r.Tally) != len(p.Choices) {
		return ErrDocument
	}
	for _, c := range p.Choices {
		if _, ok := r.Tally[c.ID]; !ok {
			return ErrDocument
		}
	}
	return nil
}

// ParseServiceList parses services.json's exact bytes: v is 1, version at
// least 1, previous 32 bytes, each service_id the lower-case hex of
// H(first ik)[0:16], each ik 32 bytes, each anchor key's cert 64 bytes and
// ik 32 bytes.
func ParseServiceList(data []byte) (*ServiceList, error) {
	var l ServiceList
	if err := parseDoc(data, serviceListSchema, &l); err != nil {
		return nil, err
	}
	if l.V != 1 || l.Version < 1 || len(l.Previous) != HashLen || l.Services == nil {
		return nil, ErrDocument
	}
	ids, iks := map[string]bool{}, map[string]bool{}
	for _, s := range l.Services {
		if ids[s.ServiceID] {
			return nil, ErrDocument
		}
		ids[s.ServiceID] = true
		for _, k := range s.IKs {
			if iks[string(k)] {
				return nil, ErrDocument
			}
			iks[string(k)] = true
		}
		if len(s.IKs) == 0 || s.AnchorKeys == nil || s.ServiceID != hex.EncodeToString(H(s.IKs[0])[:16]) || !utf8.ValidString(s.Name) {
			return nil, ErrDocument
		}
		for _, ik := range s.IKs {
			if len(ik) != KeyLen {
				return nil, ErrDocument
			}
		}
		for _, a := range s.AnchorKeys {
			if len(a.Key) == 0 || len(a.AnchorCert) != SigLen || len(a.IK) != KeyLen || !s.hasIK(a.IK) {
				return nil, ErrDocument
			}
		}
	}
	return &l, nil
}

// Entry returns the entry that lists ik among its iks, or nil.
func (l *ServiceList) Entry(ik []byte) *ServiceEntry {
	for i := range l.Services {
		for _, k := range l.Services[i].IKs {
			if eq(k, ik) {
				return &l.Services[i]
			}
		}
	}
	return nil
}

func (s *ServiceEntry) hasIK(ik []byte) bool {
	for _, k := range s.IKs {
		if eq(k, ik) {
			return true
		}
	}
	return false
}

// Extends reports whether next is a valid next version of l, whose exact
// bytes are data (BALLOT-PROTOCOL §3.3; vettid/votes site/services.go
// Extends): a higher version, previous equal to the hash of l's bytes, and
// every service of l still present under the same service_id with all its
// identity keys and anchor keys (matched by key).
func (l *ServiceList) Extends(data []byte, next *ServiceList) bool {
	if next.Version <= l.Version || !eq(next.Previous, H(data)) {
		return false
	}
	for _, ps := range l.Services {
		var ns *ServiceEntry
		for i := range next.Services {
			if next.Services[i].ServiceID == ps.ServiceID {
				ns = &next.Services[i]
			}
		}
		if ns == nil {
			return false
		}
		for _, k := range ps.IKs {
			if !ns.hasIK(k) {
				return false
			}
		}
		for _, a := range ps.AnchorKeys {
			found := false
			for _, b := range ns.AnchorKeys {
				found = found || eq(a.Key, b.Key)
			}
			if !found {
				return false
			}
		}
	}
	return true
}
