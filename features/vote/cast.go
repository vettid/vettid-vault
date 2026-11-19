package vote

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/credwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// Timers between a vault and a service are not scaled (VAULT-MESSAGING
// §10.19.2, STAGING-TIME-SCALE T4): the service and the relay count real time.
const (
	CastMargin    = 120 * time.Second // casting stops this long before the close in force
	StatusEvery   = time.Hour
	NoAnswerAfter = 24 * time.Hour
	FinalAfter    = 24 * time.Hour // a signed answer without a ballot is final this long after the close
	CheckGiveUp   = 7 * 24 * time.Hour
	CheckAskEvery = 10 * time.Minute
	pendTTL       = 25 * time.Hour // an unanswered request is forgotten (the Manager's featureReqTTL)
)

// The schedule of sending again (chosen): 1, 5 and 30 minutes after the
// first send of a round, then hourly.
var sendOffsets = []time.Duration{time.Minute, 5 * time.Minute, 30 * time.Minute}

// pendRef is a request this feature sent and awaits an answer to.
type pendRef struct {
	conn, id string        // the record
	kind     string        // "cast" or "status"
	site     *SiteProposal // a status request for a proposal not held: the site's documents (its bytes the answer must equal)
	restore  bool          // the record was waiting for the answer to a restore when the request was sent
	atMS     int64
}

// errs with the codes and bodies of §10.19.5.
func codeErr(code string, body []byte) error {
	return &vault.HandlerError{Code: code, Body: body}
}

func tsBody(name string, unix int64) []byte {
	return strictjson.NewBuilder().String(name, envelope.FormatTS(time.Unix(unix, 0))).Bytes()
}

// CastResult is the answer to vote.cast: {proposal_id, ballot: {state}}.
type CastResult struct {
	ProposalID string
	State      string
}

// Body is the response body.
func (c CastResult) Body() json.RawMessage {
	return strictjson.NewBuilder().String("proposal_id", c.ProposalID).
		Raw("ballot", strictjson.NewBuilder().String("state", c.State).Bytes()).Bytes()
}

func (f *Feature) get(conn, id string) *record { return f.st.Records[key(conn, id)] }

// ballotLeaf is the leaf of the stored ballot.
func (r *record) ballotLeaf() ([]byte, error) {
	b := r.Ballot
	return (&votewire.Ballot{RecordTag: r.Tag, VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}).Leaf()
}

// Cast is vote.cast (§10.19.5): the checks in their order, then the ballot
// signed, stored (the batch's flush comes before anything is sent), and
// sent after any rotation statement still owed to the connection. The
// caller (the app's request) has the credential's unlock window open or is
// refused credential_locked.
func (f *Feature) Cast(s *vault.Session, conn, id, choice string) (CastResult, error) {
	// What member authentication knows is read before this feature's lock is
	// taken (each has its own, and they are never held across each other).
	var pinned, owed []byte
	if f.dep.Auth != nil {
		pinned, owed = f.dep.Auth.SignedInKey(conn), f.dep.Auth.RotatedBody(conn)
	}
	res, err := f.cast(s, conn, id, choice, pinned, owed)
	return res, err
}

// cast is Cast under the lock.
func (f *Feature) cast(s *vault.Session, conn, id, choice string, pinned, owed []byte) (CastResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	r := f.get(conn, id)
	if r == nil || r.RejectReason != "" {
		return CastResult{}, errNotFound
	}
	if r.NotEligible {
		return CastResult{}, vault.NewError("not_eligible", "")
	}
	switch r.state(now) {
	case StateChecking:
		return CastResult{}, codeErr("checking", nil)
	case StateUpcoming:
		return CastResult{}, codeErr("not_open", tsBody("opens_at", r.Opens))
	case StateClosed:
		return CastResult{}, codeErr("closed", tsBody("closes_at", r.Closes))
	}
	if !now.Before(time.Unix(r.Closes, 0).Add(-CastMargin)) {
		return CastResult{}, codeErr("closing", tsBody("closes_at", r.Closes))
	}
	p, err := votewire.ParseProposal(r.Proposal)
	if err != nil || !p.HasChoice(choice) {
		return CastResult{}, errBad
	}
	if b := r.Ballot; b != nil {
		if b.ChoiceID == choice {
			return CastResult{ProposalID: id, State: b.State}, nil // a repeat
		}
		return CastResult{}, codeErr("already_voted", strictjson.NewBuilder().Raw("ballot", strictjson.NewBuilder().String("state", b.State).Bytes()).Bytes())
	}
	if r.Site == SiteMismatch {
		return CastResult{}, codeErr("site_mismatch", nil)
	}
	if c, ok := s.Connection(conn); !ok || c.State != vault.PeerActive {
		return CastResult{}, codeErr("connection_unavailable", nil)
	}
	if len(pinned) == 0 {
		return CastResult{}, codeErr("not_signed_in", strictjson.NewBuilder().String("connection_id", conn).Bytes())
	}
	if r.ServiceBallot != nil { // a vote.confirm is pending: no second ballot under the same key
		return CastResult{}, codeErr("checking", nil)
	}
	if r.Restore { // not reachable while state() says checking; kept as the spec's own row
		return CastResult{}, codeErr("checking", nil)
	}
	if f.dep.Keys == nil {
		return CastResult{}, codeErr("credential_locked", nil)
	}
	credKey, ok := f.dep.Keys.UseKey(now, s.Settings().UnlockTTL())
	if !ok {
		return CastResult{}, codeErr("credential_locked", nil)
	}
	// 1. The ballot, signed by the voting key, and cast_sig by the credential
	// key.
	if len(r.VKSeed) != ed25519.SeedSize {
		return CastResult{}, vault.NewError("internal", "")
	}
	vk := ed25519.NewKeyFromSeed(r.VKSeed)
	bal, err := votewire.SignBallot(vk, r.Hash, r.Tag, choice)
	suite.Wipe(vk)
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	leaf, err := bal.Leaf()
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	castSig, err := votewire.SignCast(credKey, r.Hash, leaf)
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	body, err := votewire.MarshalCast(id, bal, castSig)
	if err != nil {
		return CastResult{}, vault.NewError("internal", "")
	}
	// 2. Stored; the flush precedes the sending. A rotation statement still
	// owed to the connection goes first in the same outbox.
	r.Ballot = &ballot{State: BallotSending, ChoiceID: choice, VK: bal.VK, BallotSig: bal.BallotSig, CastSig: castSig, Body: body}
	r.ChangedMS = now.UnixMilli()
	f.audit(s, "vote.cast", conn, id) // never the choice
	if r.SelfUnrecorded {
		r.SelfUnrecorded = false // the record holds a ballot of its own now (GC #8012)
	}
	if r.Self != nil && (!r.Self.is(r.Ballot) || r.SelfLatest != nil && !r.SelfLatest.is(r.Ballot)) {
		// A self_unrecorded record can cast (0.88.12): its own ballot then
		// meets the one shown under its vk as self_conflict.
		f.setSelfConflict(s, r)
	}
	if credPub := credKey.Public().(ed25519.PublicKey); s.KeyRotationHeld() && !eq(pinned, credPub) {
		// A transfer's credential key statement is still held (§11.14.10):
		// the connection does not follow the key yet. The ballot waits
		// aside and is sent after the statement (CredentialKeyRotationsSent).
		r.Ballot.Held = &heldCast{Key: append([]byte(nil), credPub...), CastSig: castSig, Body: body}
		r.Ballot.CastSig, r.Ballot.Body = nil, nil
		f.event(s, r, "ballot")
		return CastResult{ProposalID: id, State: r.Ballot.State}, nil
	}
	if len(owed) > 0 {
		_ = s.SendToConnection(conn, "connection.authenticate.rotated", owed)
	}
	f.sendBallot(s, r)
	f.event(s, r, "ballot")
	return CastResult{ProposalID: id, State: r.Ballot.State}, nil
}

// sendOwedChain queues the chain member authentication gives the
// connection (read before the lock into f.owed) before a ballot, once per
// tick or answer. It is queued whether or not it went out when the
// statement was made, so a deposit the peer never processed is made good;
// a peer that already followed it ignores the repeat, which ends at the
// key it pins.
func (f *Feature) sendOwedChain(s *vault.Session, conn string) {
	if body := f.owed[conn]; len(body) > 0 {
		_ = s.SendToConnection(conn, "connection.authenticate.rotated", body)
		delete(f.owed, conn)
	}
}

// sendBallot sends the stored body as a new request with a new inner id.
func (f *Feature) sendBallot(s *vault.Session, r *record) {
	b := r.Ballot
	if b.Stopped {
		return // already_voted with an own-vk ballot was the service's final answer (0.88.12)
	}
	now := s.Now()
	id, err := s.SendRequest(r.Conn, "vote.cast", b.Body)
	if err != nil {
		// No session now: tried again at the next tick.
		b.NextSendMS = now.Add(time.Minute).UnixMilli()
		return
	}
	f.pend[id] = pendRef{conn: r.Conn, id: r.ID, kind: "cast", atMS: now.UnixMilli()}
	b.Sends = append(b.Sends, sendRec{ID: id, AtMS: now.UnixMilli(), Gen: b.Gen})
	if len(b.Sends) > 64 {
		if !b.Sends[0].Answered {
			b.LostOld = true
		}
		b.Sends = b.Sends[len(b.Sends)-64:]
	}
	b.SentGen = b.Gen
	if b.FirstSendMS == 0 {
		b.FirstSendMS = now.UnixMilli()
	}
	if b.Round == 0 {
		b.RoundStartMS = now.UnixMilli()
	}
	switch {
	case b.Reason == "not_signed_in":
		b.NextSendMS = now.Add(time.Hour).UnixMilli() // hourly
	case b.Round < len(sendOffsets):
		b.NextSendMS = time.UnixMilli(b.RoundStartMS).Add(sendOffsets[b.Round]).UnixMilli()
	default:
		b.NextSendMS = now.Add(time.Hour).UnixMilli()
	}
	if b.NextSendMS <= now.UnixMilli() {
		b.NextSendMS = now.Add(time.Minute).UnixMilli()
	}
	b.Round++
}

// askStatus sends vote.status for a record.
// SiteProposal is a proposal as the votes site publishes it: the bytes,
// proposal_sig and the anchor bundle (vote.site.sync's document).
type SiteProposal struct {
	Proposal, Sig []byte
	Bundle        json.RawMessage
}

func (f *Feature) askStatus(s *vault.Session, conn, id string, site *SiteProposal) bool {
	restore := false
	if r := f.get(conn, id); r != nil {
		restore = r.Restore
	}
	body, err := votewire.MarshalStatusRequest(id)
	if err != nil {
		return false
	}
	reqID, err := s.SendRequest(conn, "vote.status", body)
	if err != nil {
		return false
	}
	f.pend[reqID] = pendRef{conn: conn, id: id, kind: "status", site: site, restore: restore, atMS: s.Now().UnixMilli()}
	return true
}

// setFinal ends the ballot in a final state: the seed of vk is erased (the
// public half stays, for comparing with the service's ballot after a
// restore), and the app is told.
func (f *Feature) setFinal(s *vault.Session, r *record, state, code string) {
	b := r.Ballot
	b.State, b.Code, b.Reason = state, code, ""
	suite.Wipe(r.VKSeed)
	r.VKSeed = nil
	r.ChangedMS = s.Now().UnixMilli()
	f.event(s, r, "ballot")
}

func (f *Feature) setWaiting(s *vault.Session, r *record, reason string) {
	b := r.Ballot
	b.State, b.Reason = BallotWaiting, reason
	if reason == "not_signed_in" {
		b.NextSendMS = s.Now().Add(time.Hour).UnixMilli() // hourly, and at once after the next signed response
	}
	r.ChangedMS = s.Now().UnixMilli()
	f.event(s, r, "ballot")
}

// Response implements vault.ResponseObserver: the answers to vote.cast and
// vote.status. Only a verified answer counts (§10.19.5).
func (f *Feature) Response(s *vault.Session, in *envelope.Inner) bool {
	// An answer to a cast may send the ballot again (bad_ballot): the chain
	// member authentication gives the connection is read before the lock
	// and queued first (sendOwedChain).
	f.mu.Lock()
	ref, ok := f.pend[in.Re]
	f.mu.Unlock()
	owed := map[string][]byte{}
	if ok && ref.kind == "cast" && f.dep.Auth != nil {
		if body := f.dep.Auth.RotatedBody(ref.conn); len(body) > 0 {
			owed[ref.conn] = body
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owed = owed
	defer func() { f.owed = nil }()
	ref, ok = f.pend[in.Re]
	if !ok {
		return true // after a restart: dropped, as an answer matching no request
	}
	delete(f.pend, in.Re)
	// The answer being handled: a problem raised from it pins it among the
	// kept answers (pinCurrent), never evicted by those that follow.
	f.cur = &curAnswer{body: in.Body}
	if in.Status == envelope.StatusError && in.Error != nil {
		f.cur.code = in.Error.Code
	}
	defer func() { f.cur = nil }()
	switch ref.kind {
	case "cast":
		if r := f.get(ref.conn, ref.id); r != nil && r.Ballot != nil {
			f.castAnswer(s, r, in)
		}
	case "status":
		f.statusAnswer(s, ref, in)
	}
	return true
}

// ownConnections are H of the vault's own identity keys, current or earlier.
func ownConnections(s *vault.Session) [][]byte {
	var out [][]byte
	for _, k := range s.OwnIdentityKeys() {
		out = append(out, votewire.H(k))
	}
	return out
}

// marksAnswered records that the send answered by reqID got a verified
// answer.
func (b *ballot) marksAnswered(reqID string, now time.Time) (gen int) {
	for i := range b.Sends {
		if b.Sends[i].ID == reqID {
			b.Sends[i].Answered = true
			gen = b.Sends[i].Gen
		}
	}
	b.LastAnswerMS = now.UnixMilli()
	return gen
}

// sendGen is the body generation of the send with that request id (0 for
// one the ballot does not list).
func (b *ballot) sendGen(reqID string) int {
	for _, x := range b.Sends {
		if x.ID == reqID {
			return x.Gen
		}
	}
	return 0
}

// castRequest identifies the request a cast refusal answered: the
// request_hash its signature covers, H(ballot_leaf), and the generation of
// the body sent. A re-signed body (§3.5.5) keeps its leaf, so the
// generation is what tells the final refusal of the body in force from one
// of an older send: both are kept, each with its own msg_ms.
func castRequest(leaf []byte, gen int) []byte {
	out := append([]byte{}, votewire.H(leaf)...)
	return binary.BigEndian.AppendUint64(out, uint64(gen))
}

// unansweredBefore reports whether a send other than reqID has no verified
// answer.
func (b *ballot) unansweredBefore(reqID string) bool {
	if b.LostOld {
		return true
	}
	for _, x := range b.Sends {
		if x.ID != reqID && !x.Answered {
			return true
		}
	}
	return false
}

// keep adds a signed answer (a status answer or a refusal, with the error
// code it came with) to a list of kept answers. An answer whose signed
// content is the same as a held one's, code included, is not kept again
// (answerKey: every v2 answer carries a fresh time and signature, and the
// unsigned members prove nothing), so what the member exported does not
// change. At most votewire.MaxRefusalsKept entries are kept apart from the
// pinned ones (pinAnswer), which are never evicted. Over that, the oldest
// unpinned one that is not evidence goes, else the oldest unpinned one; one
// that is not evidence never pushes out one that is. It reports whether the
// list changed.
func (r *record) keep(list keptAnswers, code string, request, body []byte) (keptAnswers, bool) {
	k := answerKey(code, request, body)
	for _, x := range list {
		if answerKey(x.Code, x.Request, x.Body) == k {
			return list, false
		}
	}
	list = append(list, keptAnswer{Code: code, Request: append([]byte(nil), request...), Body: append([]byte{}, body...)})
	n := 0
	for _, x := range list {
		if !x.Pinned {
			n++
		}
	}
	if n <= votewire.MaxRefusalsKept {
		return list, true
	}
	drop, oldest := -1, -1
	for i, x := range list {
		if x.Pinned {
			continue
		}
		if oldest < 0 {
			oldest = i
		}
		if !r.evidenceAnswer(x.Body) {
			drop = i
			break
		}
	}
	if drop < 0 {
		drop = oldest // all evidence: the oldest unpinned goes
	}
	if drop == len(list)-1 {
		return list[:len(list)-1], false // the new one is not evidence and all else is
	}
	return append(list[:drop:drop], list[drop+1:]...), true
}

// maxPinned bounds the pinned answers per list.
const maxPinned = votewire.MaxRefusalsKept

// pinAnswer marks the kept answer with that code, request hash and signed
// content as one that raised the record's problem: it is never evicted.
func (r *record) pinAnswer(code string, request, body []byte) {
	k := answerKey(code, request, body)
	pin := func(list keptAnswers) {
		n := 0
		for _, x := range list {
			if x.Pinned {
				n++
			}
		}
		for i := range list {
			// At most maxPinned per list (the first proofs): a service that
			// signs ever more evidence cannot grow the record without bound.
			if !list[i].Pinned && n < maxPinned && answerKey(list[i].Code, list[i].Request, list[i].Body) == k {
				n++
				list[i].Pinned = true
			}
		}
	}
	pin(r.StatusAnswers)
	if r.Ballot != nil {
		pin(r.Ballot.Refusals)
	}
}

// answerKey identifies a kept answer by what its signature covers
// (BALLOT-PROTOCOL 0.15.0 §4.2) and its code, from decoded values (so that
// another JSON spelling of the same value is the same answer): for a status
// answer, the proposal, the connection, the tag (from proposal_id and
// record_secret) and the ballot; for a refusal, the code, proposal_hash, the
// connection, the tag, the request hash it answered and an already_voted
// ballot (signed by its own key). The time, the signature over it, a receipt
// and every other member are left out. An answer stored before 0.15.0 (or
// one that does not parse) is its bytes.
func answerKey(code string, request, body []byte) string {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "bytes|" + string(body)
	}
	b64 := func(obj strictjson.Object, name string) string {
		v, err := obj.Base64(name, -1)
		if err != nil {
			return "?" + string(obj[name])
		}
		return hex.EncodeToString(v)
	}
	str := func(obj strictjson.Object, name string) string {
		v, err := obj.String(name)
		if err != nil {
			return "?" + string(obj[name])
		}
		return strconv.Quote(v)
	}
	ballot := func() string {
		raw, ok := o["ballot"]
		if !ok || string(raw) == "null" {
			return "-"
		}
		bo, err := strictjson.ParseObject(raw)
		if err != nil {
			return "?" + string(raw)
		}
		return b64(bo, "vk") + "|" + str(bo, "choice_id") + "|" + b64(bo, "ballot_sig")
	}
	if _, ok := o["refusal_sig"]; ok {
		if _, v2 := o["proposal_hash"]; !v2 {
			return "bytes|" + string(body)
		}
		return "refusal|" + strconv.Quote(code) + "|" + hex.EncodeToString(request) + "|" + b64(o, "proposal_hash") + "|" +
			b64(o, "connection") + "|" + b64(o, "record_tag") + "|" + ballot()
	}
	if _, v2 := o["status_msg_ms"]; !v2 {
		return "bytes|" + string(body)
	}
	p, err := o.Base64("proposal", -1)
	if err != nil {
		return "bytes|" + string(body)
	}
	return "status|" + strconv.Quote(code) + "|" + hex.EncodeToString(votewire.H(p)) + "|" + b64(o, "connection") + "|" +
		str(o, "proposal_id") + "|" + b64(o, "record_secret") + "|" + ballot()
}

// pinCurrent pins the answer being handled among r's kept answers: it is
// called where a problem is raised from that answer.
func (f *Feature) pinCurrent(r *record) {
	if f.cur != nil {
		r.pinAnswer(f.cur.code, f.cur.request, f.cur.body)
	}
}

// evidenceAnswer reports whether a kept answer may be evidence: everything
// but a status answer for the held proposal carrying no ballot or the
// vault's own (its receipt is the vault's already) and a refusal under the
// zero hash (BALLOT-PROTOCOL 0.15.0 §8.3), the answers an honest service
// repeats. An answer stored before 0.15.0 counts as evidence.
func (r *record) evidenceAnswer(body []byte) bool {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return true
	}
	if raw, ok := o["refusal_sig"]; ok {
		if string(raw) == "null" {
			return false
		}
		h, err := o.Base64("proposal_hash", votewire.HashLen)
		return err != nil || !eq(h, votewire.NoProposal())
	}
	if _, v2 := o["status_msg_ms"]; !v2 {
		return true
	}
	p, err := o.Base64("proposal", -1)
	if err != nil || !eq(p, r.Proposal) {
		return true
	}
	raw, ok := o["ballot"]
	if !ok || string(raw) == "null" {
		return false
	}
	bo, err := strictjson.ParseObject(raw)
	if err != nil {
		return true
	}
	vk, _ := bo.Base64("vk", -1)
	sig, _ := bo.Base64("ballot_sig", -1)
	choice, _ := bo.String("choice_id")
	b := r.Ballot
	return b == nil || !eq(vk, b.VK) || choice != b.ChoiceID || !eq(sig, b.BallotSig)
}

// receipt records a verified receipt for the stored ballot: it always wins
// over a refusal, whenever it arrives.
func (f *Feature) receipt(s *vault.Session, r *record, msgMS int64, sig []byte) {
	b := r.Ballot
	b.MsgMS, b.ReceiptSig = msgMS, append([]byte{}, sig...)
	f.setFinal(s, r, BallotRecorded, "")
	f.audit(s, "vote.recorded", r.Conn, r.ID)
	f.twoReceipts(s, r)
}

// msgInWindow reports a receipt's msg_ms inside the window: not before
// opens_at and before the verified close (review fix 1: an extension
// adopted from results.json alone never moves it).
func (r *record) msgInWindow(msgMS int64) bool {
	return msgMS >= r.Opens*1000 && msgMS < r.verifiedClose()*1000
}

// verifiedClose is the close moved only by extensions whose bundle the
// vault verified (vote.extended, a site entry): the close of the last held
// extension of the verified prefix. One adopted from results.json carries
// no bundle until one verifies (verifyHeld).
func (r *record) verifiedClose() int64 {
	c := r.OrigClose
	for _, e := range r.Exts {
		if !e.Verified {
			break
		}
		c = e.Closes
	}
	if c == 0 {
		c = r.Closes
	}
	return c
}

// msgAside reports a msg_ms that only an extension the vault has not
// verified yet can bring into the window (0.88.12, §10.19.5 ok): at or
// after the verified close and before the original close + 86,400 s.
func (r *record) msgAside(msgMS int64) bool {
	return msgMS >= r.Opens*1000 && msgMS >= r.verifiedClose()*1000 && msgMS < (r.OrigClose+votewire.MaxExtension)*1000
}

// ownReceipt takes a verified receipt for the vault's own ballot: inside
// the window it is the receipt; one msgAside is kept aside (the latest),
// the ballot keeping its state and sending, and judged again when the
// verified close moves (rejudgeAside). The same receipt again changes
// nothing (review fix 2). It reports false for a receipt that is neither,
// which is no receipt.
func (f *Feature) ownReceipt(s *vault.Session, r *record, msgMS int64, sig []byte) bool {
	if r.msgInWindow(msgMS) {
		f.receipt(s, r, msgMS, sig)
		return true
	}
	if !r.msgAside(msgMS) {
		return false
	}
	b := r.Ballot
	if a := b.Aside; a != nil && a.MsgMS == msgMS && eq(a.ReceiptSig, sig) {
		return true // held already
	}
	b.Aside = &keptReceipt{MsgMS: msgMS, ReceiptSig: append([]byte{}, sig...)}
	r.ChangedMS = s.Now().UnixMilli()
	f.asideAfterFinal(s, r)
	return true
}

// shownBallots are the ballots the service showed that the record keeps.
func (r *record) shownBallots() []*svcBallot {
	var out []*svcBallot
	for _, x := range []*svcBallot{r.Self, r.SelfLatest, r.Other, r.OtherLatest, r.ServiceBallot} {
		if x != nil {
			out = append(out, x)
		}
	}
	return out
}

// holds reports whether the record already keeps exactly sb (the ballot and
// its receipt) as a shown ballot.
func (r *record) holds(sb *svcBallot) bool {
	for _, x := range r.shownBallots() {
		if sameSvc(x, sb) && x.MsgMS == sb.MsgMS && eq(x.ReceiptSig, sb.ReceiptSig) {
			return true
		}
	}
	return false
}

// keepShownAside: a ballot the service showed (foreign or under an own vk)
// whose receipt's msg_ms is msgAside (VAULT-MESSAGING 7adc8fe) is judged
// at once (conflict evidence or self_*), and only its receipt is kept
// aside (Late), for the two-receipts rule and the row, until a verified
// extension brings it into the window. (Review fix 5, the coordinator's
// ruling) After a restore, an own-vk ballot with no ballot of the vault's
// own is held as the restore prompt (ServiceBallot, no cast) with no self
// flag, and offered once its receipt counts.
func (f *Feature) keepShownAside(s *vault.Session, r *record, sb *svcBallot, answer, restore bool) {
	if r.holds(sb) {
		return // the same ballot and receipt again (review fix 2)
	}
	sb.Late = true
	r.ChangedMS = s.Now().UnixMilli()
	f.shown(s, r, sb, answer, restore)
	f.asideAfterFinal(s, r)
}

// keepShownRejected judges a ballot the service showed whose receipt time
// no extension can reach (before the open, or past the latest possible
// close): the ballot as any shown ballot, its receipt rejected at once, as
// a kept-aside one is at a final judgement (it never holds the check).
func (f *Feature) keepShownRejected(s *vault.Session, r *record, sb *svcBallot, answer, restore bool) {
	if r.holds(sb) {
		return
	}
	sb.Late, sb.LateRejected = true, true
	r.ChangedMS = s.Now().UnixMilli()
	f.shown(s, r, sb, answer, restore)
	// One vote.problem for the answer: none again if the ballot raised a
	// service-side problem (capProblem; an own-vk self_conflict is not one).
	f.asideRejected(s, r, r.capProblem())
}

// asideAfterFinal: once the results were judged finally, what is kept
// aside at or after the close in force (adopted extensions included) can
// no longer come into the window: it is no receipt now. One below it, for
// an extension adopted but not verified yet, stays aside until that
// extension's bundle is verified (recheck of a07d2fe).
func (f *Feature) asideAfterFinal(s *vault.Session, r *record) {
	switch r.Check {
	case CheckVerified, CheckUnconfirmed, CheckFailed:
		f.rejectAsideFrom(s, r, r.Closes*1000)
	}
}

// rejudgeAside judges every receipt kept aside again after the verified
// close moved (vote.extended, a site entry; never one adopted from
// results.json, GC #7991 C), whatever the ballot's state (review fix 3):
// once its msg_ms is inside the window, the vault's own receipt is taken as
// any receipt is (it wins over a final closed or late refusal; a ballot in
// conflict or disputed keeps its state and holds it), and a shown ballot's
// receipt counts (two receipts; a held restore prompt is offered).
func (f *Feature) rejudgeAside(s *vault.Session, r *record) {
	if b := r.Ballot; b != nil && b.Aside != nil && !b.Aside.Rejected && r.msgInWindow(b.Aside.MsgMS) {
		a := b.Aside
		b.Aside = nil
		r.ChangedMS = s.Now().UnixMilli()
		switch b.State {
		case BallotRecorded:
		case BallotConflict, BallotDisputed:
			if len(b.ReceiptSig) == 0 {
				b.MsgMS, b.ReceiptSig = a.MsgMS, a.ReceiptSig // evidence, not a state change
			}
		default:
			f.receipt(s, r, a.MsgMS, a.ReceiptSig)
			f.rejudgeResults(s, r)
		}
	}
	changed := false
	for _, x := range r.shownBallots() {
		if x.Late && !x.LateRejected && r.msgInWindow(x.MsgMS) {
			x.Late, changed = false, true // its receipt now counts
		}
	}
	if changed {
		r.ChangedMS = s.Now().UnixMilli()
		if r.ServiceBallot != nil && !r.ServiceBallot.Late {
			f.event(s, r, "ballot") // the restore prompt is offered now
		}
		f.twoReceipts(s, r)
		f.rejudgeResults(s, r) // a receipt that now counts may change a final check
	}
}

// rejudgeResults: a receipt taken after the results were judged finally
// (GC #8012) changes what the vault holds, so the stored row is judged
// again: a failure is `failed` with its reason and one vote.problem (the
// check was not failed before); an unconfirmed check that now verifies is
// verified.
func (f *Feature) rejudgeResults(s *vault.Session, r *record) {
	rs := r.Results
	if rs == nil || (r.Check != CheckVerified && r.Check != CheckUnconfirmed) {
		return
	}
	var row *votewire.RowBallot
	if rs.Row != nil {
		row = &votewire.RowBallot{VK: rs.Row.VK, ChoiceID: rs.Row.ChoiceID, BallotSig: rs.Row.BallotSig}
	}
	switch st, why := verdict(r, row); {
	case st == CheckFailed:
		// Two receipts raised their vote.problem when both were held
		// (GC #8014): no second one.
		quiet := r.TwoReceipts && why == "row_mismatch" && !r.conflictEvidence()
		f.failCheckFeed(s, r, why, !quiet)
	case st == CheckVerified && r.Check == CheckUnconfirmed:
		r.Check, r.ChangedMS = CheckVerified, s.Now().UnixMilli()
		f.audit(s, "vote.check_ok", r.Conn, r.ID)
		f.feed(s, "vote.result", r.Conn, r.ID, "")
		f.event(s, r, "check")
	}
}

// asidePending reports the earliest msg_ms kept aside that is really still
// outside the window and not yet judged finally (0 when none).
func (r *record) asidePending() int64 {
	var at int64
	if b := r.Ballot; b != nil && b.Aside != nil && !b.Aside.Rejected && !r.msgInWindow(b.Aside.MsgMS) {
		at = b.Aside.MsgMS
	}
	for _, x := range r.shownBallots() {
		if x.Late && !x.LateRejected && !r.msgInWindow(x.MsgMS) && (at == 0 || x.MsgMS < at) {
			at = x.MsgMS
		}
	}
	return at
}

// rejectAsideFrom: a receipt kept aside whose msg_ms is at or after from
// (0: all of them), still outside the window at a final judgement of the
// results, is no receipt: audited vote.receipt_rejected then and kept as
// evidence, and (GC #7991 F) the service signed for a cast outside its own
// window, so the member is told (vote.problem, once). The row check is
// unchanged by it. One inside the window by now is judged first, never
// rejected (review fix 3). A restore prompt held for a late receipt becomes
// self_unrecorded (review fix 5).
func (f *Feature) rejectAsideFrom(s *vault.Session, r *record, from int64) {
	f.rejudgeAside(s, r)
	hit := false
	if b := r.Ballot; b != nil && b.Aside != nil && !b.Aside.Rejected && b.Aside.MsgMS >= from {
		b.Aside.Rejected, hit = true, true
	}
	for _, x := range r.shownBallots() {
		if x.Late && !x.LateRejected && x.MsgMS >= from {
			x.LateRejected, hit = true, true
		}
	}
	if !hit {
		return
	}
	f.asideRejected(s, r, false)
}

// asideRejected follows a receipt rejected for its time: audited, the
// problem raised once, and a restore's own-vk ballot judged as one.
func (f *Feature) asideRejected(s *vault.Session, r *record, raised bool) {
	r.ChangedMS = s.Now().UnixMilli()
	f.audit(s, "vote.receipt_rejected", r.Conn, r.ID)
	if !r.AsideProblem {
		r.AsideProblem = true
		if !raised {
			f.pinCurrent(r)
			f.feed(s, "vote.problem", r.Conn, r.ID, "high")
		}
		f.event(s, r, "problem")
	}
	if sb := r.ServiceBallot; sb != nil && sb.Late && sb.LateRejected && r.Ballot == nil {
		r.ServiceBallot = nil
		f.self(s, r, nil, sb, false)
	}
}

// castAnswer handles the answer to a vote.cast (§10.19.5 "The answer").
func (f *Feature) castAnswer(s *vault.Session, r *record, in *envelope.Inner) {
	b := r.Ballot
	now := s.Now()
	final := b.State == BallotRecorded || b.State == BallotConflict || b.State == BallotDisputed || b.State == BallotRefused
	if final && in.Status == envelope.StatusError {
		// A late refusal after the ballot is final tells nothing new, unless
		// it is signed under another non-zero hash: a refusal signed for
		// another version under this id is evidence whatever the times
		// (BALLOT-PROTOCOL 0.15.0 §8.3).
		f.lateRefusal(s, r, in)
		return
	}
	if b.State != BallotRefused && final {
		return // a receipt still wins over a final refusal
	}
	leaf, err := r.ballotLeaf()
	if err != nil {
		return
	}
	request := castRequest(leaf, b.sendGen(in.Re))
	if f.cur != nil {
		f.cur.request = request
	}
	if in.Status != envelope.StatusError {
		a, err := votewire.ParseCastAnswer(in.Body)
		if err != nil || a.Verify(r.Signer, r.ID, r.Hash, leaf) != nil || !r.msgInWindow(int64(a.MsgMS)) && !r.msgAside(int64(a.MsgMS)) {
			f.audit(s, "vote.receipt_rejected", r.Conn, r.ID)
			return
		}
		b.marksAnswered(in.Re, now)
		f.ownReceipt(s, r, int64(a.MsgMS), a.ReceiptSig)
		return
	}
	if in.Error == nil {
		return
	}
	code := in.Error.Code
	rf, err := votewire.ParseRefusal(in.Body)
	// (BALLOT-PROTOCOL 0.15.0) A refusal timed at no deposit of this request
	// the relay told the vault of (a mismatch, or the deposit's answer lost)
	// is discarded as no answer: sending the cast again is idempotent.
	if err != nil || !timed(s, in.Re, rf.MsgMS) ||
		rf.Verify(r.Signer, r.ID, "vote.cast", code, votewire.H(leaf), ownConnections(s), r.Tag) != nil {
		return // unsigned or failing: no answer
	}
	if !castRefusalCode(code) {
		return // a code the vault does not know is no answer
	}
	if !eq(rf.ProposalHash, r.Hash) {
		// (0.15.0) Signed under another hash than the held proposal's: the
		// zero hash (the service holds no proposal published under this id,
		// e.g. after a restore of its table) is kept and shown, not
		// evidence; another hash is a refusal signed for another version
		// under this id: evidence. The ballot goes on as it was either way.
		f.refusalOtherHash(s, r, code, request, in.Body, rf)
		return
	}
	gen := b.marksAnswered(in.Re, now)
	if code != "already_voted" {
		b.Refusals, _ = r.keep(b.Refusals, code, request, in.Body)
	}
	switch code {
	case "not_open":
		f.setWaiting(s, r, "not_open")
	case "not_signed_in":
		f.setWaiting(s, r, "not_signed_in")
	case "closed", "late":
		if b.unansweredBefore(in.Re) {
			// An earlier send may have arrived in time: ask what the service holds.
			f.setWaiting(s, r, "closed")
			b.NextStatusMS = now.UnixMilli()
			return
		}
		f.refuse(s, r, code, false)
	case "not_active", "not_eligible":
		f.refuse(s, r, code, true)
	case "bad_ballot":
		// A copy kept aside under a transfer's held key (b.Held) is never
		// the answer: no connection follows that key before the statement
		// goes out, since no sign-in is signed with it meanwhile (member
		// authentication refuses them, §11.14.10).
		if gen < b.Gen {
			// A send made before the re-signed body: the body already
			// re-signed is the answer, sent once if it was not yet.
			f.setWaiting(s, r, "bad_ballot")
			if b.SentGen < b.Gen && now.Before(time.Unix(r.Closes, 0)) {
				f.sendOwedChain(s, r.Conn)
				f.sendBallot(s, r)
			}
			return
		}
		f.refuse(s, r, code, true)
	case "already_voted":
		eb, err := rf.VerifyExisting(r.Signer, r.Hash, r.Tag)
		if err != nil {
			return
		}
		if eq(eb.VK, b.VK) && eb.ChoiceID == b.ChoiceID && eq(eb.BallotSig, b.BallotSig) {
			// Exactly this vault's ballot: it is the receipt (or one kept
			// aside, 0.88.12); one outside both is rejected as for an ok
			// answer (review fix 6c).
			if !f.ownReceipt(s, r, int64(rf.BallotMsgMS), rf.ReceiptSig) {
				f.audit(s, "vote.receipt_rejected", r.Conn, r.ID)
			}
			return
		}
		sb := &svcBallot{VK: eb.VK, ChoiceID: eb.ChoiceID, BallotSig: eb.BallotSig, MsgMS: int64(rf.BallotMsgMS), ReceiptSig: rf.ReceiptSig}
		switch {
		case r.msgInWindow(sb.MsgMS):
			f.shown(s, r, sb, true, false)
		case r.msgAside(sb.MsgMS):
			f.keepShownAside(s, r, sb, true, false) // GC #7991 C
		default:
			// (0.90.19) A receipt time no extension can reach: the ballot is
			// judged now, its receipt rejected at once.
			f.keepShownRejected(s, r, sb, true, false)
		}
	}
}

// refuse ends the ballot in `refused` with the signed refusal as evidence.
func (f *Feature) refuse(s *vault.Session, r *record, code string, problem bool) {
	f.setFinal(s, r, BallotRefused, code)
	f.audit(s, "vote.refused", r.Conn, r.ID+":"+code)
	if problem {
		r.RefusalProblem = true
		f.pinCurrent(r)
		f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	}
}

// statusAnswer handles the answer to a vote.status (§10.19.5).
func (f *Feature) statusAnswer(s *vault.Session, ref pendRef, in *envelope.Inner) {
	now := s.Now()
	r := f.get(ref.conn, ref.id)
	if in.Status == envelope.StatusError {
		f.statusRefusal(s, r, ref, in)
		return
	}
	a, err := votewire.ParseStatusAnswer(in.Body)
	if err != nil || a.ProposalID != ref.id || !timed(s, in.Re, a.StatusMsgMS) {
		return // (0.15.0) timed at no deposit of this request: no answer
	}
	if r == nil {
		// A proposal the vault was not sent (the site's index has it): the
		// answer is checked as a vote.proposal would be, and its bytes must
		// equal the site's.
		if ref.site != nil && !eq(a.Proposal, ref.site.Proposal) {
			return
		}
		f.intakeStatus(s, ref, a, in.Body)
		return
	}
	if a.VerifySig(r.Signer, ownConnections(s)) != nil {
		return
	}
	if !eq(a.Proposal, r.Proposal) {
		// (0.15.0) A status signed over another proposal under this id, its
		// proposal signed by the service: two signed proposals under one id,
		// evidence. Anything else is no answer.
		if eq(votewire.H(a.Proposal), r.Hash) || votewire.VerifyProposal(r.Signer, a.Proposal, a.ProposalSig) != nil {
			return
		}
		if p, err := votewire.ParseProposal(a.Proposal); err != nil || p.ProposalID != r.ID {
			return
		}
		r.StatusAnswers, _ = r.keep(r.StatusAnswers, "", nil, in.Body)
		f.problem(s, r)
		return
	}
	tag, err := a.Tag()
	if err != nil || !eq(tag, r.Tag) {
		return
	}
	b := r.Ballot
	same := a.Ballot != nil && b != nil && eq(a.Ballot.VK, b.VK) && a.Ballot.ChoiceID == b.ChoiceID && eq(a.Ballot.BallotSig, b.BallotSig)
	if same && !r.msgInWindow(int64(a.MsgMS)) && !r.msgAside(int64(a.MsgMS)) {
		return // the vault's own ballot with a receipt outside the window: no answer, as for vote.cast
	}
	// The same answer again (the hourly ask after the close) is not kept
	// twice and changes nothing the member exported (review fix 2).
	var added bool
	if r.StatusAnswers, added = r.keep(r.StatusAnswers, "", nil, in.Body); added {
		r.ChangedMS = now.UnixMilli()
	}
	if r.Restore {
		r.Restore = false // the service answered: a cast is possible again
		r.ChangedMS = now.UnixMilli()
	}
	if b != nil {
		b.LastAnswerMS = now.UnixMilli()
	}
	if a.Ballot == nil {
		// (BALLOT-PROTOCOL 0.15.0 §8.3) A signed "no ballot" is never
		// evidence by itself, a receipt held or not: the service need not
		// handle a connection's messages in relay order. Receipt against
		// results (§10.19.6) stays the check. The answer is kept and shown.
		switch {
		case b != nil && b.State == BallotWaiting && b.Reason == "closed" && now.After(time.Unix(r.Closes, 0).Add(FinalAfter)):
			f.refuse(s, r, "closed", false) // final only after closes_at + 24 h
		}
		f.event(s, r, "ballot")
		return
	}
	sb := &svcBallot{VK: a.Ballot.VK, ChoiceID: a.Ballot.ChoiceID, BallotSig: a.Ballot.BallotSig, MsgMS: int64(a.MsgMS), ReceiptSig: a.ReceiptSig}
	switch {
	case same:
		// The vault's own ballot (a refused connection_ended one included):
		// the receipt, a lost answer recovered (or kept aside, 0.88.12).
		if b.State != BallotRecorded && b.State != BallotConflict && b.State != BallotDisputed && r.msgInWindow(sb.MsgMS) {
			f.receipt(s, r, sb.MsgMS, sb.ReceiptSig)
		} else {
			if b.State != BallotRecorded && b.State != BallotConflict && b.State != BallotDisputed {
				f.ownReceipt(s, r, sb.MsgMS, sb.ReceiptSig) // kept aside (0.88.12)
			}
			f.event(s, r, "ballot")
		}
	case r.msgAside(sb.MsgMS):
		// For an extension not learned yet (GC #7991 C, 7adc8fe): judged
		// now, its receipt kept aside.
		f.keepShownAside(s, r, sb, false, ref.restore)
	case !r.msgInWindow(sb.MsgMS):
		// (0.90.19) A receipt time no extension can reach (before the open,
		// or past the latest close): the ballot is judged now, as conflict
		// evidence or an own-vk ballot (VAULT-MESSAGING 0.81.3, 0.88.12),
		// and its receipt is rejected at once.
		f.keepShownRejected(s, r, sb, false, ref.restore)
	default:
		f.shown(s, r, sb, false, ref.restore)
	}
}

// shown judges a ballot the service showed that is not the vault's own
// (§10.19.5): answer is an already_voted answer to the vault's cast,
// restore an answer to an ask the restore made.
func (f *Feature) shown(s *vault.Session, r *record, sb *svcBallot, answer, restore bool) {
	b := r.Ballot
	if r.holds(sb) {
		return // judged already (review fix 2)
	}
	switch {
	case b == nil && restore && r.ownVK(sb.VK) && r.ServiceBallot == nil:
		// After a restore the service holds a ballot made with this record's
		// own voting key that the vault lost: the member confirms it
		// (vote.confirm).
		r.ServiceBallot = sb
		r.ChangedMS = s.Now().UnixMilli()
		f.event(s, r, "ballot")
		// A different own-vk ballot shown with a receipt before the prompt
		// makes two receipts in this order too.
		f.twoReceipts(s, r)
	case r.ownVK(sb.VK):
		// A ballot under the record's own vk outside the restore prompt
		// (0.88.12, §10.19.3): self_unrecorded or self_conflict, not
		// conflict evidence; the vault's own ballot keeps its state.
		f.self(s, r, b, sb, answer)
	default:
		// A ballot the vault never signed (another vk), or another one than
		// its own: a conflict, kept as evidence. Without a ballot of the
		// vault's own it prompts nothing and does not change whether it can
		// cast.
		f.foreign(s, r, b, sb, answer)
	}
}

// receiptedSelf are the own-vk ballots shown whose receipt is held (not
// kept aside).
func (r *record) receiptedSelf() []*svcBallot {
	var out []*svcBallot
	for _, x := range []*svcBallot{r.Self, r.SelfLatest} {
		if x != nil && !x.Late {
			out = append(out, x)
		}
	}
	return out
}

// ownVK reports whether vk is the record's voting key, now or an earlier
// one it held (GC #7991 G: a reopened vote never cast gets a fresh one).
func (r *record) ownVK(vk []byte) bool {
	if eq(vk, r.VK) {
		return true
	}
	for _, k := range r.OldVKs {
		if eq(vk, k) {
			return true
		}
	}
	return false
}

// is reports whether sb is exactly the ballot b.
func (sb *svcBallot) is(b *ballot) bool {
	return sb != nil && b != nil && eq(sb.VK, b.VK) && sb.ChoiceID == b.ChoiceID && eq(sb.BallotSig, b.BallotSig)
}

// self records a ballot the service shows under the record's own vk that
// is not the vault's own (0.88.12, §10.19.3 "A ballot under the record's
// own voting key"): only a holder of the vk seed can have made it (this
// vault before a rollback, or someone the seed leaked to), so the vault
// neither takes it as its own nor blames the service. self_unrecorded when
// the vault holds no ballot, self_conflict when it holds another; the
// ballot keeps its state, and with answer (already_voted to the vault's own
// cast, the service's final answer to it) it is not sent again (GC #7991
// E). The first and the latest are kept; the member is told once per
// record (vote.self_mismatch); no vote.conflict, and no vote.problem unless
// the service signed two receipts for the tag (twoReceipts).
func (f *Feature) self(s *vault.Session, r *record, b *ballot, sb *svcBallot, answer bool) {
	if r.Self == nil {
		r.Self = sb
	} else {
		r.SelfLatest = sb
	}
	r.ChangedMS = s.Now().UnixMilli()
	if b == nil && r.ServiceBallot != nil {
		// A restore prompt is pending (review fix 6a): kept as evidence,
		// no flag; judged at the member's answer (Confirm).
		f.twoReceipts(s, r)
		return
	}
	if b == nil {
		if !r.SelfUnrecorded {
			r.SelfUnrecorded = true
			f.audit(s, "vote.self_unrecorded", r.Conn, r.ID)
		}
	} else {
		if answer && !b.final() {
			b.Stopped = true
		}
		f.setSelfConflict(s, r)
	}
	f.selfFeed(s, r)
	f.twoReceipts(s, r)
	f.event(s, r, "problem")
}

// twoReceipts: the service signed receipts for two different ballots under
// the member's tag, its own contradiction (GC #7991 D): the vault's receipt
// for its own ballot beside a different own-vk ballot shown with a
// receipt, or two different own-vk ballots shown. vote.problem (high),
// once; it counts toward the cap of 16, and the check fails (row_mismatch):
// a check judged finally before is judged again here, whichever path made
// the two receipts.
func (f *Feature) twoReceipts(s *vault.Session, r *record) {
	if r.TwoReceipts {
		return
	}
	// Only receipts held count (7adc8fe: as soon as both are, whichever
	// came first); one kept aside (Late) does not yet. A pending restore
	// prompt's ballot is one of them (GC #8014).
	held := r.receiptedSelf()
	if sb := r.ServiceBallot; sb != nil && !sb.Late {
		held = append(held, sb)
	}
	b := r.Ballot
	two := false
	for i, x := range held {
		for _, y := range held[i+1:] {
			if !sameSvc(x, y) {
				two = true
			}
		}
		if b != nil && len(b.ReceiptSig) > 0 && !x.is(b) {
			two = true
		}
	}
	if !two {
		return
	}
	r.TwoReceipts = true
	r.ChangedMS = s.Now().UnixMilli()
	f.pinCurrent(r)
	f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	f.event(s, r, "problem")
	f.rejudgeResults(s, r)
}

// setSelfConflict sets self_conflict, audited once.
func (f *Feature) setSelfConflict(s *vault.Session, r *record) {
	if r.SelfConflict {
		return
	}
	r.SelfConflict = true
	r.ChangedMS = s.Now().UnixMilli()
	f.audit(s, "vote.self_conflict", r.Conn, r.ID)
	f.selfFeed(s, r)
}

// selfFeed makes vote.self_mismatch once per record.
func (f *Feature) selfFeed(s *vault.Session, r *record) {
	if !r.SelfFeed {
		r.SelfFeed = true
		f.feed(s, "vote.self_mismatch", r.Conn, r.ID, "high")
	}
}

// foreign records a ballot the vault did not sign (or another than its
// own): the first is kept as the evidence (the latest beside it), and the
// audit entry and the feed item are made once per record. It is a flag on
// the record (conflict_evidence, 0.81.3), not a ballot state: the member's
// own ballot goes to `conflict` only when it has no receipt (it is not
// final) and the service's already_voted answer to its cast shows the
// foreign ballot (answer true); a recorded ballot stays recorded.
func (f *Feature) foreign(s *vault.Session, r *record, b *ballot, sb *svcBallot, answer bool) {
	seen := r.Other != nil // raised by the first one, whatever came since
	if !seen {
		r.Other = sb
	} else {
		r.OtherLatest = sb
	}
	if answer && b != nil && !b.final() {
		f.setFinal(s, r, BallotConflict, "")
	} else if b == nil || b.State != BallotConflict {
		r.ConflictEv = true
	}
	r.ChangedMS = s.Now().UnixMilli()
	if seen {
		return // raised by the first
	}
	f.audit(s, "vote.conflict", r.Conn, r.ID)
	f.pinCurrent(r)
	f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	f.event(s, r, "problem")
}

// statusRefusal: a signed not_eligible or unknown_proposal is kept as
// evidence and shown (decision 7).
func (f *Feature) statusRefusal(s *vault.Session, r *record, ref pendRef, in *envelope.Inner) {
	if in.Error == nil {
		return
	}
	if r == nil {
		f.notHeldRefusal(s, ref, in)
		return
	}
	code := in.Error.Code
	if code != "not_eligible" && code != "unknown_proposal" {
		return
	}
	rf, err := votewire.ParseRefusal(in.Body)
	if err != nil || !timed(s, in.Re, rf.MsgMS) ||
		rf.Verify(r.Signer, r.ID, "vote.status", code, votewire.H([]byte(r.ID)), ownConnections(s), r.Tag) != nil {
		return
	}
	request := votewire.H([]byte(r.ID))
	if f.cur != nil {
		f.cur.request = request
	}
	r.StatusAnswers, _ = r.keep(r.StatusAnswers, code, request, in.Body)
	r.Restore = false
	r.ChangedMS = s.Now().UnixMilli()
	if rf.NoProposal() {
		// (0.15.0) The zero hash: the service holds no proposal published
		// under this id. Kept and shown, not evidence.
		f.event(s, r, "ballot")
		return
	}
	// Under the held proposal's hash (a signed not_eligible is evidence the
	// member can show, BALLOT-PROTOCOL §10.1), or under another, a refusal
	// signed for another version under this id: evidence either way.
	f.problem(s, r)
}

// problem raises the record's refusal problem once: a vote.problem feed
// item and the record in the problem set.
func (f *Feature) problem(s *vault.Session, r *record) {
	f.pinCurrent(r) // whether or not it is the first: this answer is evidence
	if !r.RefusalProblem {
		r.RefusalProblem = true
		f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	}
	r.ChangedMS = s.Now().UnixMilli()
	f.event(s, r, "problem")
}

// refusalOtherHash handles a verified vote.cast refusal signed under
// another hash than the held proposal's (BALLOT-PROTOCOL 0.15.0 §4.2,
// §8.3). It is kept either way and the ballot's state is unchanged: it
// goes on being sent by its schedule. The zero hash (the service holds no
// proposal published under this id, e.g. in an older state after a restore
// of its table) is shown, not evidence. Another non-zero hash is a refusal
// signed for another version under this id: evidence.
func (f *Feature) refusalOtherHash(s *vault.Session, r *record, code string, request, body []byte, rf *votewire.Refusal) {
	r.Ballot.Refusals, _ = r.keep(r.Ballot.Refusals, code, request, body)
	r.ChangedMS = s.Now().UnixMilli()
	if rf.NoProposal() {
		f.event(s, r, "ballot")
		return
	}
	f.problem(s, r)
}

// castRefusalCode reports whether code is one of vote.cast's refusal
// codes (§10.19.5); any other is no answer.
func castRefusalCode(code string) bool {
	switch code {
	case "not_open", "not_signed_in", "closed", "late", "not_active", "not_eligible", "bad_ballot", "already_voted":
		return true
	}
	return false
}

// lateRefusal keeps a verified vote.cast refusal that arrives after the
// ballot is final only when it is evidence: signed under a non-zero hash
// other than the held proposal's.
func (f *Feature) lateRefusal(s *vault.Session, r *record, in *envelope.Inner) {
	if in.Error == nil {
		return
	}
	leaf, err := r.ballotLeaf()
	if err != nil {
		return
	}
	request := castRequest(leaf, r.Ballot.sendGen(in.Re))
	if f.cur != nil {
		f.cur.request = request
	}
	rf, err := votewire.ParseRefusal(in.Body)
	if err != nil || !castRefusalCode(in.Error.Code) || !timed(s, in.Re, rf.MsgMS) || rf.NoProposal() || eq(rf.ProposalHash, r.Hash) ||
		rf.Verify(r.Signer, r.ID, "vote.cast", in.Error.Code, votewire.H(leaf), ownConnections(s), r.Tag) != nil {
		return
	}
	f.refusalOtherHash(s, r, in.Error.Code, request, in.Body, rf)
}

// timed reports whether ms, the relay's time an answer claims for the
// request it answers (re), is the time of one of the vault's own deposits of
// that request (BALLOT-PROTOCOL 0.15.0 §4.2). A mismatch, or a request whose
// deposit answer was lost, makes the answer no answer, never evidence.
func timed(s *vault.Session, re string, ms uint64) bool {
	for _, t := range s.DepositTimes(re) {
		if t >= 0 && uint64(t) == ms {
			return true
		}
	}
	return false
}

// notHeldRefusal handles a refusal to the vote.status asked for a proposal
// on the votes site that the vault does not hold (VAULT-MESSAGING 0.90.20
// §10.19.4, owner decision 2026-11-18). A signed not_eligible, timed at a
// deposit of the request, under the hash of the site's proposal, which is
// checked as on arrival (steps 2, 3 and 6: the document, the service's
// key and signature, the anchor; not the tag, which a member left off the
// roster does not have), is kept as a record of its own: NotEligible, the
// refusal pinned as evidence, vote.problem once. Anything else keeps
// nothing: the zero hash proves nothing, and the proposal is asked about
// again by the schedule.
func (f *Feature) notHeldRefusal(s *vault.Session, ref pendRef, in *envelope.Inner) {
	site := ref.site
	if site == nil || in.Error.Code != "not_eligible" || f.get(ref.conn, ref.id) != nil {
		return
	}
	rf, err := votewire.ParseRefusal(in.Body)
	if err != nil || !timed(s, in.Re, rf.MsgMS) || !eq(rf.ProposalHash, votewire.H(site.Proposal)) {
		return
	}
	p, err := votewire.ParseProposal(site.Proposal)
	if err != nil || p.ProposalID != ref.id || !isConnKey(s, ref.conn, p.Service) ||
		votewire.VerifyProposal(p.Service, site.Proposal, site.Sig) != nil ||
		rf.Verify(p.Service, ref.id, "vote.status", in.Error.Code, votewire.H([]byte(ref.id)), ownConnections(s), nil) != nil {
		return
	}
	notAfter := time.Time{}
	if s.RelayTimeKnown() {
		notAfter = s.RelayTime().Add(AnchorAhead)
	}
	if f.anchor(s, ref.conn, [][]byte{p.Service, s.From().IK}, site.Proposal, site.Bundle, notAfter) != anchorOK {
		return
	}
	now := s.Now()
	r := &record{Conn: ref.conn, ID: ref.id, ServiceIK: append([]byte{}, s.From().IK...), Proposal: site.Proposal, ProposalSig: site.Sig,
		Bundle: site.Bundle, Hash: votewire.H(site.Proposal), NotEligible: true,
		ReceivedMS: s.RelayTime().UnixMilli(), NoRelay: !s.RelayTimeKnown(), KeptMS: now.UnixMilli(), ChangedMS: now.UnixMilli(),
		Opens: p.OpensAt, Closes: p.ClosesAt, OrigClose: p.ClosesAt, Title: p.Title, Signer: p.Service}
	if !f.admitNotEligible(r) {
		return
	}
	request := votewire.H([]byte(ref.id))
	r.StatusAnswers, _ = r.keep(r.StatusAnswers, in.Error.Code, request, in.Body)
	r.StatusAnswers[0].Pinned = true
	r.RefusalProblem = true
	f.st.Records[key(ref.conn, ref.id)] = r
	f.audit(s, "vote.refused", ref.conn, ref.id+":not_eligible")
	f.feed(s, "vote.problem", ref.conn, ref.id, "high")
	f.event(s, r, "problem")
}

// intakeStatus keeps a proposal from a status answer (§10.19.4 "A proposal
// the vault was never sent"): steps 2 to 6 on the answer's members, a
// missing bundle leaving it `checking` (site) until the site's arrives.
//
// (0.88.12, GC #7991 A) The answer is kept verbatim among the record's
// status answers, and a ballot it carries is judged, not dropped: the
// record's vk is fresh, so it is never under it, and it is always foreign,
// conflict evidence (vote.conflict and vote.problem, once), restore or not.
func (f *Feature) intakeStatus(s *vault.Session, ref pendRef, a *votewire.StatusAnswer, body []byte) {
	conn := ref.conn
	// The answer's signatures first: nothing is kept (not even a rejected
	// record) from an answer that does not verify under the service's key.
	p, err := votewire.ParseProposal(a.Proposal)
	// (0.15.0) status_sig covers the proposal bytes and the tag, not
	// proposal_id: the answer's id must be its proposal's. The tag, derived
	// from the id, fails the signature for a swapped id unless the service
	// signed that inconsistency itself; this check refuses that too.
	if err != nil || p.ProposalID != a.ProposalID || !isConnKey(s, conn, p.Service) || a.VerifySig(p.Service, ownConnections(s)) != nil {
		return
	}
	msg := &votewire.ProposalMsg{Proposal: a.Proposal, ProposalSig: a.ProposalSig, Bundle: a.Bundle, RecordSecret: a.RecordSecret, RecordProof: a.RecordProof}
	_, _ = f.intake(s, conn, msg)
	r := f.get(conn, a.ProposalID)
	if r == nil || r.inert() || r.Ballot != nil || r.ServiceBallot != nil {
		return
	}
	r.StatusAnswers, _ = r.keep(r.StatusAnswers, "", nil, body)
	r.ChangedMS = s.Now().UnixMilli()
	if a.Ballot == nil {
		return
	}
	sb := &svcBallot{VK: a.Ballot.VK, ChoiceID: a.Ballot.ChoiceID, BallotSig: a.Ballot.BallotSig, MsgMS: int64(a.MsgMS), ReceiptSig: a.ReceiptSig}
	switch {
	case r.msgInWindow(sb.MsgMS):
		f.foreign(s, r, nil, sb, false)
	case r.msgAside(sb.MsgMS):
		f.keepShownAside(s, r, sb, false, false) // foreign now, its receipt kept aside
	}
	// A receipt outside both: no answer for the ballot, as for a held
	// record; the answer stays as evidence.
}

// RequestProposal asks the service for a proposal on the site's index that
// the vault does not hold (vote.status, §10.19.4): at most once an hour per
// proposal. The answer must carry exactly siteBytes, the site's proposal.
// It reports whether the request was sent.
func (f *Feature) RequestProposal(s *vault.Session, conn, id string, site SiteProposal) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.requestProposal(s, conn, id, site)
}

func (f *Feature) requestProposal(s *vault.Session, conn, id string, site SiteProposal) bool {
	k := key(conn, id)
	now := s.Now()
	if f.st.Records[k] != nil || f.settled(conn, id) || !votewire.ValidProposalID(id) || len(site.Proposal) == 0 {
		return false
	}
	if at, ok := f.asked[k]; ok && now.Sub(time.UnixMilli(at)) < StatusEvery {
		return false
	}
	if !f.askStatus(s, conn, id, &site) {
		return false
	}
	f.asked[k] = now.UnixMilli()
	return true
}

// Check is vote.check: ask the service what it recorded now, at most once
// per proposal per ten minutes (else `limit` with retry_after).
func (f *Feature) Check(s *vault.Session, conn, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(conn, id)
	if r == nil || r.inert() {
		return errNotFound
	}
	now := s.Now()
	if at := time.UnixMilli(r.CheckAskMS); r.CheckAskMS != 0 && now.Sub(at) < CheckAskEvery {
		left := CheckAskEvery - now.Sub(at)
		return &vault.HandlerError{Code: "limit", Body: strictjson.NewBuilder().String("limit", "vote.check").
			Uint("retry_after", uint64((left+time.Second-1)/time.Second)).Bytes()}
	}
	if !f.askStatus(s, conn, id, nil) {
		return codeErr("connection_unavailable", nil)
	}
	r.CheckAskMS = now.UnixMilli()
	return nil
}

// Confirm is vote.confirm: the member's answer to a ballot the service
// holds that the vault has not (after a restore). "Yes" stores the
// service's ballot and receipt as recorded; "no" sets disputed and keeps
// everything as evidence (BALLOT-PROTOCOL §5).
func (f *Feature) Confirm(s *vault.Session, conn, id string, mine bool) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r := f.get(conn, id)
	if r == nil || r.inert() {
		return "", errNotFound
	}
	sb := r.ServiceBallot
	if sb == nil || sb.Late {
		return "", errBad // (review fix 5) not offered while its receipt is kept aside
	}
	r.ServiceBallot = nil
	r.Ballot = &ballot{ChoiceID: sb.ChoiceID, VK: sb.VK, BallotSig: sb.BallotSig, MsgMS: sb.MsgMS, ReceiptSig: sb.ReceiptSig}
	if mine {
		f.setFinal(s, r, BallotRecorded, "")
		f.audit(s, "vote.recorded", r.Conn, r.ID)
		// An own-vk ballot shown meanwhile is now beside a different
		// ballot of the vault's own (review fix 6a).
		if r.Self != nil && !r.Self.is(r.Ballot) || r.SelfLatest != nil && !r.SelfLatest.is(r.Ballot) {
			f.setSelfConflict(s, r)
		}
		f.twoReceipts(s, r)
	} else {
		f.setFinal(s, r, BallotDisputed, "")
		f.audit(s, "vote.disputed", r.Conn, r.ID)
		f.feed(s, "vote.problem", r.Conn, r.ID, "high")
	}
	return r.Ballot.State, nil
}

// Tick implements vault.TickObserver: the sending schedule, the asks for
// status, the seed of a vote never cast, and the result checks that come
// due. It runs whenever the vault is unlocked, held included.
func (f *Feature) Tick(s *vault.Session) {
	// The chains member authentication still owes a connection with a
	// ballot to send, read before this feature's lock (a connection that
	// was not active when a rotation's statement went out, §10.4): queued
	// before the ballot, as at vote.cast.
	owed := map[string][]byte{}
	if f.dep.Auth != nil {
		for c := range f.pinsFor(func(b *ballot) bool { return b.Body != nil }) {
			if body := f.dep.Auth.RotatedBody(c); len(body) > 0 {
				owed[c] = body
			}
		}
	}
	f.tick(s, owed)
}

// tick is Tick under the lock.
func (f *Feature) tick(s *vault.Session, owed map[string][]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owed = owed
	defer func() { f.owed = nil }()
	now := s.Now()
	for id, p := range f.pend { // as the Manager forgets its own requests
		if now.Sub(time.UnixMilli(p.atMS)) > pendTTL {
			delete(f.pend, id)
		}
	}
	f.auditOversize(s)
	keys := make([]string, 0, len(f.st.Records))
	for k := range f.st.Records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if r := f.st.Records[k]; r != nil && !r.inert() {
			f.tickRecord(s, r, now)
		}
	}
}

// closingAt is when vote.closing is due (§10.19.7): the close in force minus
// the lesser of 24 hours and half the voting window (the proposal's own).
func closingAt(r *record) time.Time {
	lead := 24 * time.Hour
	if half := time.Duration(r.OrigClose-r.Opens) * time.Second / 2; half < lead {
		lead = half
	}
	return time.Unix(r.Closes, 0).Add(-lead)
}

// closingFeed makes the vote.closing item once, if the vote is open and the
// member has not voted. A vault that was locked at the moment makes it at
// the next unlock if more than an hour remains; a held vault makes it
// without a wake. An extension makes no second one.
func (f *Feature) closingFeed(s *vault.Session, r *record, now time.Time) {
	if r.ClosingFeed || r.Ballot != nil || r.state(now) != StateOpen {
		return
	}
	at := closingAt(r)
	if now.Before(at) {
		return
	}
	r.ClosingFeed = true
	if now.Sub(at) > closingLate && time.Unix(r.Closes, 0).Sub(now) <= time.Hour {
		return // missed while locked, and too late to be of use
	}
	f.feed(s, "vote.closing", r.Conn, r.ID, "")
}

// closingLate is how late a tick may be and still count as "at the moment"
// (the vault was unlocked).
const closingLate = 10 * time.Minute

func (f *Feature) tickRecord(s *vault.Session, r *record, now time.Time) {
	closed := r.closed(now)
	f.closingFeed(s, r, now)
	// A vote never cast has no use for its voting key once it closes.
	if r.Ballot == nil && closed && len(r.VKSeed) > 0 {
		suite.Wipe(r.VKSeed)
		r.VKSeed = nil
	}
	f.tickCheck(s, r, now)
	conn, ok := s.Connection(r.Conn)
	active := ok && conn.State == vault.PeerActive
	// After a restore: ask what the service recorded, hourly, until it answers.
	if r.Restore && active && now.UnixMilli() >= r.AskMS {
		if f.askStatus(s, r.Conn, r.ID, nil) {
			r.AskMS = now.Add(StatusEvery).UnixMilli()
		}
	}
	b := r.Ballot
	if b == nil || b.final() || !active {
		return
	}
	if b.Body == nil {
		return
	}
	if !closed {
		if b.State == BallotWaiting && b.Reason == "closed" {
			// An earlier send may have arrived: ask, no more casts.
			f.statusDue(s, r, now)
			return
		}
		if now.UnixMilli() >= b.NextSendMS {
			f.sendOwedChain(s, r.Conn)
			f.sendBallot(s, r)
		}
		// 24 hours without a verified answer: also ask.
		last := b.LastAnswerMS
		if last == 0 {
			last = b.FirstSendMS
		}
		if last != 0 && now.Sub(time.UnixMilli(last)) >= NoAnswerAfter {
			f.statusDue(s, r, now)
		}
		return
	}
	// The close in force has been reached: sending stops, the status is asked.
	f.statusDue(s, r, now)
}

func (f *Feature) statusDue(s *vault.Session, r *record, now time.Time) {
	b := r.Ballot
	if now.UnixMilli() >= b.NextStatusMS {
		if f.askStatus(s, r.Conn, r.ID, nil) {
			b.NextStatusMS = now.Add(StatusEvery).UnixMilli()
		}
	}
}

// ResponseSigned implements connauth.ResponseObserver: a waiting ballot of
// the connection is sent at once after the vault's next signed
// authentication response (§10.19.5 `not_signed_in`).
func (f *Feature) ResponseSigned(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.st.Records {
		if r.Conn == conn && r.Ballot != nil && r.Ballot.State == BallotWaiting && r.Ballot.Reason == "not_signed_in" {
			r.Ballot.NextSendMS = 0
		}
	}
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: records and
// ballots stay as evidence; a ballot still sending or waiting can no longer
// be sent and becomes refused (connection_ended).
func (f *Feature) ConnectionRemoved(s *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.st.Records {
		if r.Conn == conn && r.Ballot != nil && !r.Ballot.final() {
			f.setFinal(s, r, BallotRefused, "connection_ended")
		}
	}
	for id, p := range f.pend {
		if p.conn == conn {
			delete(f.pend, id)
		}
	}
}

// markRestore: after a recovery or a transfer the vault's records may be
// behind the service's. Every proposal without a receipt is `checking`
// (restore) and asked, and nothing is cast until the answer (§10.19.5).
func (f *Feature) markRestore(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.st.Records {
		if r.inert() || (r.Ballot != nil && r.Ballot.State == BallotRecorded) {
			continue
		}
		r.Restore, r.AskMS, r.ChangedMS = true, 0, s.Now().UnixMilli()
		f.event(s, r, "proposal")
	}
}

// TransferCompleted implements vault.TransferObserver (a transfer to a new
// phone, and the release-R recovery).
func (f *Feature) TransferCompleted(s *vault.Session, _, _ string) { f.markRestore(s) }

// RecoveryCompleted implements vault.RecoveryObserver.
func (f *Feature) RecoveryCompleted(s *vault.Session) { f.markRestore(s) }

// CredentialKeyRotated implements credential.KeyRotationObserver: nothing to
// do with the statement (member authentication sends it); the re-signing
// is CredentialKeysOpen, and a transfer's held one CredentialKeysHeld.
func (f *Feature) CredentialKeyRotated(*vault.Session, *credwire.KeyRotation) {}

// CredentialKeyRotationsSent implements credential.KeyRotationFollower: a
// transfer's held statements have gone out (§11.14.10), after every
// observer, so member authentication's chain precedes what this sends.
// What was re-signed under a statement's new key while it was held
// (CredentialKeysHeld) is put in force, as CredentialKeysOpen does for a
// rotation.
func (f *Feature) CredentialKeyRotationsSent(s *vault.Session, rs []*credwire.KeyRotation) {
	pins := f.pinsFor(func(b *ballot) bool { return b.Held != nil })
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, r := range rs {
		for _, k := range f.recordKeys() {
			rec := f.st.Records[k]
			b := rec.Ballot
			if b == nil || b.Held == nil {
				continue
			}
			if b.final() {
				b.Held = nil
				continue
			}
			h := b.Held
			if !eq(h.Key, r.New) {
				continue // a later key's (a second transfer before this statement went out)
			}
			b.Held = nil
			f.adoptCast(s, rec, h.CastSig, h.Body, pins[rec.Conn], r.New, now)
		}
	}
}

// CredentialDeleted implements credential.DeleteObserver: the credential
// was destroyed (credential.reset, §3.5.5). A cast_sig kept aside under a
// transfer's held key belongs to it, whose statement is never sent: it is
// dropped. A ballot that was only kept aside (cast while the statement was
// held) was never sent anywhere and is removed, so the member can cast
// again under the new credential.
func (f *Feature) CredentialDeleted(s *vault.Session) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, k := range f.recordKeys() {
		r := f.st.Records[k]
		b := r.Ballot
		if b == nil || b.Held == nil {
			continue
		}
		b.Held = nil
		if b.Body == nil && !b.final() {
			r.Ballot = nil
			r.ChangedMS = s.Now().UnixMilli()
			f.event(s, r, "ballot")
		}
	}
}

// CredentialKeysOpen implements credential.KeyRotationSigner (VAULT-
// MESSAGING 0.81.1 §3.5.5): while both credential keys are open, the
// cast_sig of every ballot that is not final is signed again under the new
// key, the stored body replaced (the rotation's flush persists it), and the
// new body is sent once, after the rotation statement, to a connection that
// pinned the old key. After the close in force it is only replaced.
// vote.cast and credential.rotate run one at a time in the vault, so no
// cast signed under the old key is flushed after this pass.
func (f *Feature) CredentialKeysOpen(s *vault.Session, _, newKey ed25519.PrivateKey) {
	f.resign(s, newKey, false)
}

// CredentialKeysHeld implements credential.KeyRotationSigner: a transfer's
// approval rotates the credential key but holds the statement until the
// new phone's first unlock from storage (§11.14.10). The cast_sig of every
// ballot that is not final is signed under the new key now, while it is
// open, and kept aside: the body in force, under the key the connection
// pinned, stays in force and is the one sent until the statement goes out
// (CredentialKeyRotated). A body under the new key sent before it would be
// refused bad_ballot by a service that pinned the old key.
func (f *Feature) CredentialKeysHeld(s *vault.Session, _, newKey ed25519.PrivateKey) {
	f.resign(s, newKey, true)
}

// resign signs the cast_sig of every ballot that is not final under newKey;
// held keeps it aside, otherwise it is put in force (adoptCast).
func (f *Feature) resign(s *vault.Session, newKey ed25519.PrivateKey, held bool) {
	newPub := newKey.Public().(ed25519.PublicKey)
	var pins map[string][]byte
	if !held {
		pins = f.pinsFor(func(*ballot) bool { return true })
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := s.Now()
	for _, k := range f.recordKeys() {
		r := f.st.Records[k]
		b := r.Ballot
		if b == nil || b.final() {
			continue
		}
		leaf, err := r.ballotLeaf()
		if err != nil {
			continue
		}
		sig, err := votewire.SignCast(newKey, r.Hash, leaf)
		if err != nil {
			continue
		}
		bal := &votewire.Ballot{RecordTag: r.Tag, VK: b.VK, ChoiceID: b.ChoiceID, BallotSig: b.BallotSig}
		body, err := votewire.MarshalCast(r.ID, bal, sig)
		if err != nil {
			continue
		}
		if held {
			b.Held = &heldCast{Key: append([]byte(nil), newPub...), CastSig: sig, Body: body}
			continue
		}
		b.Held = nil // superseded: this key follows the held one's
		f.adoptCast(s, r, sig, body, pins[r.Conn], newPub, now)
	}
}

// pinsFor reads, before this feature's lock is taken, the key member
// authentication pinned for each connection with a ballot that is not
// final and that want selects.
func (f *Feature) pinsFor(want func(*ballot) bool) map[string][]byte {
	pins := map[string][]byte{}
	f.mu.Lock()
	conns := map[string]bool{}
	for _, r := range f.st.Records {
		if r.Ballot != nil && !r.Ballot.final() && want(r.Ballot) {
			conns[r.Conn] = true
		}
	}
	f.mu.Unlock()
	if f.dep.Auth != nil {
		for c := range conns {
			pins[c] = f.dep.Auth.SignedInKey(c)
		}
	}
	return pins
}

// recordKeys returns the records' keys in order.
func (f *Feature) recordKeys() []string {
	keys := make([]string, 0, len(f.st.Records))
	for k := range f.st.Records {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// adoptCast puts a cast_sig re-signed under newPub, and its body, in force,
// and sends the body once to a connection that pinned another key. It runs
// only right after member authentication has queued the chain to newPub
// for every active connection (a rotation's observers, or the held
// statements' observers before the followers), so the chain precedes the
// body without being queued again here; an inactive connection gets the
// body from the schedule, after the chain (sendOwedChain).
func (f *Feature) adoptCast(s *vault.Session, r *record, sig, body, pin, newPub []byte, now time.Time) {
	b := r.Ballot
	b.CastSig, b.Body = sig, body // the same ballot: vk, choice, ballot_sig and leaf do not change
	if len(pin) == 0 || eq(pin, newPub) {
		return // pinned no key: only replaced
	}
	// Every re-sign for a connection that pinned a key is a new
	// generation, sent or not: a bad_ballot answering an older send is
	// answered by it, whether or not the connection was reachable now.
	b.Gen++
	if !now.Before(time.Unix(r.Closes, 0)) {
		return // after the close in force: only replaced
	}
	c, ok := s.Connection(r.Conn)
	if !ok || c.State != vault.PeerActive {
		return // sent at the next tick, by the schedule
	}
	f.sendBallot(s, r)
}
