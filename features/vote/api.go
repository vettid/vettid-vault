package vote

import (
	"encoding/base64"
	"encoding/json"
	"sort"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// The app's API (VAULT-MESSAGING 0.81.2 §10.19.8). Every request is the
// owner app's only (a desktop or an agent is forbidden by the runtime), and
// every request about one proposal names connection_id and proposal_id: a
// missing or malformed connection_id is bad_request, a pair the vault does
// not hold is not_found.

// Credential is the credential feature, for vote.release: the holder only,
// the UTK a request presents spent first, the PIN sealed to it (§3.5.4), as
// for audit.export.
type Credential interface {
	HolderGate(s *vault.Session, in *envelope.Inner) error
	SpendPIN(s *vault.Session, in *envelope.Inner, utkID string, sealed []byte) ([]byte, error)
}

var apps = []string{vault.KindApp}

// appTypes are the app's requests.
func appTypes() []vault.TypeSpec {
	var out []vault.TypeSpec
	for _, t := range []string{"vote.list", "vote.get", "vote.cast", "vote.check", "vote.confirm", "vote.release",
		"vote.site.sync", "vote.results.submit", "vote.evidence"} {
		out = append(out, vault.TypeSpec{Type: t, Request: true, From: apps})
	}
	return out
}

func (f *Feature) handleApp(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	switch in.Type {
	case "vote.list":
		return f.apiList(s, in.Body)
	case "vote.get":
		return f.apiGet(s, in.Body)
	case "vote.cast":
		return f.apiCast(s, in.Body)
	case "vote.check":
		return f.apiCheck(s, in.Body)
	case "vote.confirm":
		return f.apiConfirm(s, in.Body)
	case "vote.release":
		return f.apiRelease(s, in)
	case "vote.evidence":
		return f.apiEvidence(s, in.Body)
	case "vote.results.submit":
		return f.apiResults(s, in.Body)
	case "vote.site.sync":
		return f.apiSync(s, in)
	}
	return nil, vault.NewError("unsupported_type", "")
}

// pair reads connection_id and proposal_id.
func pair(o strictjson.Object) (conn, id string, err error) {
	conn, err = o.String("connection_id")
	if err != nil || conn == "" || len(conn) > 64 {
		return "", "", errBad
	}
	id, err = o.String("proposal_id")
	if err != nil || !votewire.ValidProposalID(id) {
		return "", "", errBad
	}
	return conn, id, nil
}

func ts(sec int64) string { return envelope.FormatTS(time.Unix(sec, 0)) }

// castBlock is the code vote.cast would answer, apart from the unlock
// window ("" when none): the checks of §10.19.5 in their order.
func (f *Feature) castBlock(s *vault.Session, r *record, pinned []byte) string {
	now := s.Now()
	switch r.state(now) {
	case StateChecking:
		return "checking"
	case StateUpcoming:
		return "not_open"
	case StateClosed, StateRejected:
		return "closed"
	}
	if !now.Before(time.Unix(r.Closes, 0).Add(-CastMargin)) {
		return "closing"
	}
	if r.Ballot != nil {
		return "already_voted"
	}
	if r.Site == SiteMismatch {
		return "site_mismatch"
	}
	if c, ok := s.Connection(r.Conn); !ok || c.State != vault.PeerActive {
		return "connection_unavailable"
	}
	if len(pinned) == 0 {
		return "not_signed_in"
	}
	return ""
}

func ballotJSON(b *ballot) []byte {
	o := strictjson.NewBuilder().String("state", b.State)
	if b.Code != "" {
		o.String("code", b.Code)
	}
	if b.Reason != "" {
		o.String("reason", b.Reason)
	}
	return o.Bytes()
}

// summary is a vote's summary (§10.19.8). pinned is the credential key the
// connection pinned (nil: never signed in).
func (f *Feature) summary(s *vault.Session, r *record, pinned []byte) *strictjson.Builder {
	now := s.Now()
	st := r.state(now)
	b := strictjson.NewBuilder().String("proposal_id", r.ID).String("connection_id", r.Conn).String("title", r.Title).String("state", st)
	if why := r.checkingReason(); st == StateChecking && why != "" {
		b.String("reason", why)
	} else if st == StateRejected {
		b.String("reason", r.RejectReason)
	}
	if r.Closes != 0 {
		b.String("opens_at", ts(r.Opens)).String("closes_at", ts(r.Closes))
	}
	if r.Ballot != nil {
		b.Raw("ballot", ballotJSON(r.Ballot))
	}
	if r.Check != "" || r.checkPending(now) {
		state := r.Check
		if state == "" {
			state = CheckPending
		}
		c := strictjson.NewBuilder().String("state", state)
		if r.CheckReason != "" {
			c.String("reason", r.CheckReason)
		}
		if state == CheckPending {
			c.String("due_at", envelope.FormatTS(r.dueAt()))
		}
		b.Raw("check", c.Bytes())
	}
	if r.conflictEvidence() {
		b.Bool("conflict_evidence", true) // the service showed another ballot under the member's code
	}
	if r.ServiceBallot != nil {
		b.Bool("confirm_pending", true) // vote.confirm is waiting for the member
	}
	block := f.castBlock(s, r, pinned)
	b.Bool("can_cast", block == "")
	if block != "" {
		b.String("cannot_cast", block)
	}
	if r.Site != "" {
		b.String("site", r.Site)
	}
	return b
}

// pins reads what member authentication pinned, before this feature's lock
// is taken (each has its own, and they are never held across each other).
func (f *Feature) pins() func(conn string) []byte {
	cache := map[string][]byte{}
	return func(conn string) []byte {
		if f.dep.Auth == nil {
			return nil
		}
		if k, ok := cache[conn]; ok {
			return k
		}
		cache[conn] = f.dep.Auth.SignedInKey(conn)
		return cache[conn]
	}
}

// order ranks a record for vote.list: open, upcoming, checking and rejected
// first (by closes_at), then closed by closes_at descending.
func listOrder(rs []*record, now time.Time) {
	grp := func(r *record) int {
		if r.state(now) == StateClosed {
			return 1
		}
		return 0
	}
	sort.SliceStable(rs, func(i, j int) bool {
		gi, gj := grp(rs[i]), grp(rs[j])
		if gi != gj {
			return gi < gj
		}
		if rs[i].Closes != rs[j].Closes {
			if gi == 0 {
				return rs[i].Closes < rs[j].Closes
			}
			return rs[i].Closes > rs[j].Closes
		}
		if rs[i].Conn != rs[j].Conn {
			return rs[i].Conn < rs[j].Conn
		}
		return rs[i].ID < rs[j].ID
	})
}

func (f *Feature) apiList(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	filter, present, err := o.OptString("state")
	if err != nil || present && filter != "open" && filter != "closed" && filter != "all" {
		return nil, errBad
	}
	if !present {
		filter = "all"
	}
	after, _, err := o.OptString("after")
	if err != nil || len(after) > 256 {
		return nil, errBad
	}
	limit := uint64(50)
	if v, ok, err := o.OptUint("limit", 1, 100); err != nil {
		return nil, errBad
	} else if ok {
		limit = v
	}
	var ack []string
	if raw, ok, err := o.OptArray("ack_dropped"); err != nil || len(raw) > 128 {
		return nil, errBad
	} else if ok {
		for _, x := range raw {
			c, err := strictjson.AsString(x)
			if err != nil || len(c) > 256 {
				return nil, errBad
			}
			ack = append(ack, c)
		}
	}
	pin := f.pins()
	f.mu.Lock()
	seen := map[string]bool{}
	for _, r := range f.st.Records {
		seen[r.Conn] = true
	}
	f.mu.Unlock()
	for c := range seen {
		pin(c)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// 0.81.3: a dropped notice goes only when the app acknowledges it (after
	// showing it); an unknown connection is ignored.
	for _, c := range ack {
		delete(f.st.Dropped, c)
	}
	now := s.Now()
	var rs []*record
	for _, r := range f.st.Records {
		closed := r.state(now) == StateClosed
		if filter == "open" && closed || filter == "closed" && !closed {
			continue
		}
		rs = append(rs, r)
	}
	listOrder(rs, now)
	start := 0
	if after != "" {
		start = len(rs)
		for i, r := range rs {
			if cursor(r) == after {
				start = i + 1
			}
		}
	}
	var page []*record
	next := ""
	for i := start; i < len(rs); i++ {
		if uint64(len(page)) == limit {
			next = cursor(page[len(page)-1])
			break
		}
		page = append(page, rs[i])
	}
	arr := []byte{'['}
	for i, r := range page {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, f.summary(s, r, pin(r.Conn)).Bytes()...)
	}
	out := strictjson.NewBuilder().Raw("votes", append(arr, ']'))
	if next != "" {
		out.String("next", next)
	}
	out.Raw("dropped", f.droppedJSON()).Raw("problems", f.problemsJSON()).Raw("reconnect", f.reconnectJSON(s))
	if l := f.st.List; l != nil {
		out.Uint("list_version", uint64(l.Version)).Base64("list_sha256", votewire.H(l.Doc))
	}
	return out.Bytes(), nil
}

func cursor(r *record) string { return base64.RawURLEncoding.EncodeToString([]byte(key(r.Conn, r.ID))) }

// droppedJSON is the notice of proposals the vault dropped for its caps
// (§10.19.2): it returns until the app acknowledges it with ack_dropped
// (0.81.3).
func (f *Feature) droppedJSON() []byte {
	conns := make([]string, 0, len(f.st.Dropped))
	for c := range f.st.Dropped {
		conns = append(conns, c)
	}
	sort.Strings(conns)
	arr := []byte{'['}
	for i, c := range conns {
		d := f.st.Dropped[c]
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("connection_id", c).Uint("count", uint64(d.Count)).
			String("last_at", envelope.FormatTS(time.UnixMilli(d.LastMS))).Bytes()...)
	}
	return append(arr, ']')
}

// problemsJSON is the notice that a connection is at its cap of problem
// records (§10.19.2): until a record is released.
func (f *Feature) problemsJSON() []byte {
	count := map[string]int{}
	for _, r := range f.st.Records {
		if r.problem() {
			count[r.Conn]++
		}
	}
	conns := make([]string, 0, len(f.st.Problems))
	for c, on := range f.st.Problems {
		if on {
			conns = append(conns, c)
		}
	}
	sort.Strings(conns)
	arr := []byte{'['}
	for i, c := range conns {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, strictjson.NewBuilder().String("connection_id", c).Uint("count", uint64(count[c])).Bytes()...)
	}
	return append(arr, ']')
}

// reconnectJSON lists the person connections whose pinned ik is an ik of a
// listed service: a service connected to before the invitation said so. It
// changes nothing about them, and lists nothing before a list is held.
func (f *Feature) reconnectJSON(s *vault.Session) []byte {
	ix := f.index()
	arr := []byte{'['}
	if ix != nil && ix.list != nil {
		n := 0
		for _, c := range s.Connections() {
			if c.Kind != vault.KindConnection || c.IsService() || c.State != vault.PeerActive {
				continue
			}
			if e := ix.byIK[string(c.IK)]; e != nil {
				if n > 0 {
					arr = append(arr, ',')
				}
				n++
				arr = append(arr, strictjson.NewBuilder().String("connection_id", c.ID).String("service_id", e.ServiceID).String("name", e.Name).Bytes()...)
			}
		}
	}
	return append(arr, ']')
}

func (f *Feature) apiGet(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, id, err := pair(o)
	if err != nil {
		return nil, err
	}
	pin := f.pins()
	pinned := pin(conn)
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(conn, id)
	if r == nil {
		return nil, errNotFound
	}
	b := f.summary(s, r, pinned)
	p, err := votewire.ParseProposal(r.Proposal)
	if err == nil {
		b.String("text", p.Text)
		ch := []byte{'['}
		for i, c := range p.Choices {
			if i > 0 {
				ch = append(ch, ',')
			}
			ch = append(ch, strictjson.NewBuilder().String("id", c.ID).String("label", c.Label).Bytes()...)
		}
		b.Raw("choices", append(ch, ']'))
		b.Raw("quorum", strictjson.NewBuilder().String("text", p.Quorum.Text).Uint("min_ballots", uint64(p.Quorum.MinBallots)).Bytes())
		b.Bool("binding", p.Binding)
	}
	b.Base64("record_tag", r.Tag)
	// choice_id: only here, and only after the member cast.
	if r.Ballot != nil && r.Ballot.ChoiceID != "" {
		b.String("choice_id", r.Ballot.ChoiceID)
	}
	b.Uint("extensions", uint64(len(r.Exts)))
	if sb := r.ServiceBallot; sb != nil {
		// While a vote.confirm is pending: the ballot the service holds
		// under the record's own voting key ("Is this your vote?").
		b.Raw("service_ballot", strictjson.NewBuilder().String("choice_id", sb.ChoiceID).Uint("msg_ms", uint64(sb.MsgMS)).Bytes())
	}
	// tally and counts come only from verified results.
	if r.Results != nil && (r.Check == CheckVerified || r.Check == CheckUnconfirmed) {
		if res, err := votewire.ParseResults(r.Results.Doc); err == nil {
			t := strictjson.NewBuilder()
			names := make([]string, 0, len(res.Tally))
			for k := range res.Tally {
				names = append(names, k)
			}
			sort.Strings(names)
			for _, k := range names {
				t.Uint(k, uint64(res.Tally[k]))
			}
			b.Raw("tally", t.Bytes())
			b.Raw("counts", strictjson.NewBuilder().Uint("eligible", uint64(res.Counts.Eligible)).Uint("ballots", uint64(res.Counts.Ballots)).
				Uint("removed", uint64(res.Counts.Removed)).Uint("unhandled", uint64(res.Counts.Unhandled)).Bytes())
		}
	}
	b.String("ik_fingerprint", suite.FormatIKFingerprint(r.ServiceIK))
	return b.Bytes(), nil
}

func (f *Feature) apiCast(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, id, err := pair(o)
	if err != nil {
		return nil, err
	}
	choice, err := o.String("choice_id")
	if err != nil || !votewire.ValidChoiceID(choice) {
		return nil, errBad
	}
	res, err := f.Cast(s, conn, id, choice)
	if err != nil {
		return nil, err
	}
	return res.Body(), nil
}

func (f *Feature) apiCheck(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, id, err := pair(o)
	if err != nil {
		return nil, err
	}
	if err := f.Check(s, conn, id); err != nil {
		return nil, err
	}
	return json.RawMessage(`{}`), nil
}

func (f *Feature) apiConfirm(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, id, err := pair(o)
	if err != nil {
		return nil, err
	}
	mine, err := o.Bool("mine")
	if err != nil {
		return nil, errBad
	}
	st, err := f.Confirm(s, conn, id, mine)
	if err != nil {
		return nil, err
	}
	return strictjson.NewBuilder().Raw("ballot", strictjson.NewBuilder().String("state", st).Bytes()).Bytes(), nil
}

func (f *Feature) apiResults(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	conn, id, err := pair(o)
	if err != nil {
		return nil, err
	}
	var in ResultsSubmit
	if in.Results, err = o.Base64("results", -1); err != nil || len(in.Results) == 0 || len(in.Results) > votewire.MaxBody {
		return nil, errBad
	}
	if in.Sig, err = o.Base64("results_sig", votewire.SigLen); err != nil {
		return nil, errBad
	}
	raw, ok := o["bundle"]
	if !ok || len(raw) > votewire.MaxBundle {
		return nil, errBad
	}
	if _, err := strictjson.AsObject(raw); err != nil {
		return nil, errBad
	}
	in.Bundle = append(json.RawMessage{}, raw...)
	// row: {ballot: {vk, choice_id, ballot_sig} | null}
	ro, err := o.Object("row")
	if err != nil {
		return nil, errBad
	}
	br, ok := ro["ballot"]
	if !ok || len(ro) != 1 {
		return nil, errBad
	}
	if string(br) != "null" {
		bo, err := strictjson.AsObject(br)
		if err != nil {
			return nil, errBad
		}
		rb := &votewire.RowBallot{}
		if rb.VK, err = bo.Base64("vk", votewire.KeyLen); err != nil {
			return nil, errBad
		}
		if rb.ChoiceID, err = bo.String("choice_id"); err != nil || !votewire.ValidChoiceID(rb.ChoiceID) {
			return nil, errBad
		}
		if rb.BallotSig, err = bo.Base64("ballot_sig", votewire.SigLen); err != nil {
			return nil, errBad
		}
		in.Row = rb
	}
	praw, ok := o["row_proof"]
	if !ok {
		return nil, errBad
	}
	if in.Proof, err = votewire.ParseRecordProof(praw); err != nil {
		return nil, errBad
	}
	out, err := f.SubmitResults(s, conn, id, in)
	if err != nil {
		return nil, err
	}
	c := strictjson.NewBuilder().String("state", out.State)
	if out.Reason != "" {
		c.String("reason", out.Reason)
	}
	if out.ConflictEvidence {
		c.Bool("conflict_evidence", true)
	}
	return strictjson.NewBuilder().String("proposal_id", id).Raw("check", c.Bytes()).Bytes(), nil
}
