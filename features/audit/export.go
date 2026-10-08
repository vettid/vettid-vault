package audit

import (
	"crypto/sha256"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// History export (VAULT-MESSAGING 0.22.0, §10.9; owner decisions of
// 2026-10-08, §15 item 30). The holder's app asks with audit.list's
// filters; a dry run counts the entries that match (newest first, at most
// ExportMax) without a PIN; the export carries the UTK-sealed {pin},
// checked under the §11.8 PIN backoff only (a wrong PIN is not a failed
// owner check), records audit.exported with the summary in ref and
// answers the bound upto_seq. The response never carries the entries: the
// app reads them with audit.list below upto_seq + 1 and writes the file
// itself. The vault writes no file and keeps no copy.

// ExportMax is the export cap (§10.9): the newest ExportMax matching
// entries; more says that more match.
const ExportMax = 10000

// KindExported is the audit kind of a History export (§10.9).
const KindExported = "audit.exported"

// Export formats (§10.9).
var exportFormats = map[string]bool{"csv": true, "json": true}

// Credential is the credential feature: audit.export is the holder's only,
// refused during a clone alarm before the UTK is spent, and carries the
// PIN alone sealed to a UTK (§3.5.4, §3.5.9). It must not call back into
// this feature.
type Credential interface {
	// HolderGate: forbidden unless the sender is the holder's app; the
	// freeze code while a clone alarm is open. It spends nothing.
	HolderGate(s *vault.Session) error
	// SpendPIN runs HolderGate, spends the UTK and opens the sealed
	// {pin}; the caller wipes the PIN.
	SpendPIN(s *vault.Session, in *envelope.Inner, utkID string, sealed []byte) ([]byte, error)
}

// SetCredential connects the credential feature (at construction).
// Without it audit.export is forbidden.
func (f *Feature) SetCredential(c Credential) { f.cred = c }

var (
	errForbidden = vault.NewError("forbidden", "")
	errNotFound  = vault.NewError("not_found", "")
	errInternal  = vault.NewError("internal", "")
)

// exportReq is a parsed audit.export body. shape is the request's
// bad_request, answered after the UTK is spent (§10.9 step 2) when the
// envelope members themselves parse.
type exportReq struct {
	q       *Query
	format  string
	dryRun  bool
	upto    uint64
	hasUpto bool
	utkID   string
	sealed  []byte
	shape   error
}

// parseExport parses an audit.export body. A body whose envelope members
// (dry_run, utk_id, sealed) cannot be read is bad_request at once (there is
// no UTK to spend); any other shape error is kept in shape.
func parseExport(body []byte) (*exportReq, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &exportReq{}
	if o.Has("dry_run") {
		if r.dryRun, err = o.Bool("dry_run"); err != nil {
			return nil, errBad
		}
	}
	if r.dryRun {
		// The preview: no PIN, no UTK, no bound.
		if o.Has("utk_id") || o.Has("sealed") || o.Has("upto_seq") {
			return nil, errBad
		}
	} else {
		if r.utkID, err = o.String("utk_id"); err != nil || r.utkID == "" || len(r.utkID) > 64 {
			return nil, errBad
		}
		s, err := o.String("sealed")
		if err != nil || len(s) > 64*1024 {
			return nil, errBad
		}
		if r.sealed, err = strictjson.DecodeStd(s, -1); err != nil {
			return nil, errBad
		}
	}
	r.shape = r.parseShape(o, body)
	return r, nil
}

// parseShape checks the filters (audit.list's forms, without a cursor or
// limit), format and upto_seq.
func (r *exportReq) parseShape(o strictjson.Object, body []byte) error {
	for _, k := range []string{"before_seq", "after_seq", "limit"} {
		if o.Has(k) {
			return errBad
		}
	}
	q, err := ParseQuery(body, false)
	if err != nil {
		return errBad
	}
	r.q = q
	f, present, err := o.OptString("format")
	if err != nil || present && !exportFormats[f] || !present && !r.dryRun {
		return errBad
	}
	r.format = f
	if !r.dryRun {
		if r.upto, err = o.Uint("upto_seq", 1, strictjson.MaxSafeInteger); err != nil {
			return errBad
		}
		r.hasUpto = true
	}
	return nil
}

// exportCount is what the vault answers for an export's entries.
type exportCount struct {
	count          int
	more           bool
	oldest, newest *Entry
	uptoSeq        uint64
	uptoHash       []byte
	uptoFound      bool
}

// countExport counts the entries that match r's filters, with seq ≤ upto
// (0: the log's newest), newest first, at most max; q is evaluated over
// the whole log, without SearchBudget (§10.9, 0.22.0).
func (f *Feature) countExport(s *vault.Session, q *Query, upto uint64, max int) exportCount {
	f.mu.Lock()
	entries := append([]*Entry(nil), f.st.Entries...)
	head, seq := f.st.Head, f.st.Seq
	f.mu.Unlock()
	c := exportCount{}
	if upto == 0 {
		c.uptoSeq, c.uptoHash, c.uptoFound = seq, head, true
		if len(c.uptoHash) != sha256.Size {
			c.uptoHash = make([]byte, sha256.Size)
		}
	} else {
		c.uptoSeq = upto
	}
	var names *searchNames
	if q.Q != "" {
		names = newSearchNames(s, f.items)
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if e.Seq > c.uptoSeq {
			continue
		}
		if e.Seq == c.uptoSeq && !c.uptoFound {
			c.uptoHash, c.uptoFound = e.Hash, true
		}
		if !q.match(e) || names != nil && !names.match(e, q.Q) {
			continue
		}
		if c.count == max {
			c.more = true
			break
		}
		if c.newest == nil {
			c.newest = e
		}
		c.oldest = e
		c.count++
	}
	return c
}

func (c *exportCount) members(b *strictjson.Builder) {
	b.Uint("count", uint64(c.count)).Bool("more", c.more).Uint("upto_seq", c.uptoSeq).Base64("upto_hash", c.uptoHash)
	if c.count > 0 {
		b.Uint("oldest_seq", c.oldest.Seq).Uint("newest_seq", c.newest.Seq).
			String("oldest_at", envelope.FormatTS(c.oldest.At)).String("newest_at", envelope.FormatTS(c.newest.At))
	}
}

// export handles audit.export (§10.9, 0.22.0). The order is the spec's:
// the clone alarm (before the UTK), the UTK, the request's shape,
// not_found, the PIN backoff, the PIN.
func (f *Feature) export(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	if f.cred == nil {
		return nil, errForbidden
	}
	// Holder only; the clone alarm refuses the preview and the export
	// before anything else, the UTK unspent (§3.5.9).
	if err := f.cred.HolderGate(s); err != nil {
		return nil, err
	}
	r, err := parseExport(in.Body)
	if err != nil {
		return nil, err
	}
	max := f.exportMax
	if max <= 0 {
		max = ExportMax
	}
	if r.dryRun {
		if r.shape != nil {
			return nil, r.shape
		}
		c := f.countExport(s, r.q, 0, max)
		b := strictjson.NewBuilder()
		c.members(b)
		return b.Bytes(), nil
	}
	// Step 1: the UTK, spent whatever happens next; the payload is {pin}.
	pin, err := f.cred.SpendPIN(s, in, r.utkID, r.sealed)
	if err != nil {
		return nil, err
	}
	defer suite.Wipe(pin)
	// Step 2: the request's shape, and upto_seq at most the newest seq.
	if r.shape != nil {
		return nil, r.shape
	}
	f.mu.Lock()
	newest := f.st.Seq
	f.mu.Unlock()
	if r.upto > newest {
		return nil, errBad
	}
	// Step 3: nothing matches (counted against no one).
	c := f.countExport(s, r.q, r.upto, max)
	if c.count == 0 {
		return nil, errNotFound
	}
	if !c.uptoFound {
		return nil, errInternal // retention drops the oldest first: unreachable with count > 0
	}
	// Steps 4–5: the §11.8 PIN backoff, then the PIN. A wrong PIN is
	// bad_pin, counted in the backoff and audited vault.pin_failed by the
	// runtime; it is not a failed owner check (owner decision of
	// 2026-10-08).
	if err := s.VerifyPIN(string(pin)); err != nil {
		return nil, err
	}
	// Step 6, in the same flush: audit.exported, then the answer.
	s.Record(vault.Activity{Kind: KindExported, DeviceID: s.From().ID, Ref: exportSummary(r, &c), Audit: true})
	f.mu.Lock()
	var entrySeq uint64
	if n := len(f.st.Entries); n > 0 && f.st.Entries[n-1].Kind == KindExported {
		entrySeq = f.st.Entries[n-1].Seq
	}
	f.mu.Unlock()
	if entrySeq == 0 {
		return nil, errInternal
	}
	b := strictjson.NewBuilder()
	c.members(b)
	b.Uint("entry_seq", entrySeq)
	return b.Bytes(), nil
}

// exportSummary is audit.exported's ref (§10.9):
// format=<csv|json>;count=<n>;seqs=<oldest>-<newest>;filters=<f>[;since=<t>][;until=<t>],
// <f> "none" or the filters named, in the order connection,kinds,q,dates.
// It names no connection, kind prefix or search text.
func exportSummary(r *exportReq, c *exportCount) string {
	var fs []string
	if r.q.ConnectionID != "" {
		fs = append(fs, "connection")
	}
	if len(r.q.Kinds) > 0 {
		fs = append(fs, "kinds")
	}
	if r.q.Q != "" {
		fs = append(fs, "q")
	}
	if r.q.HasSince || r.q.HasUntil {
		fs = append(fs, "dates")
	}
	filters := "none"
	if len(fs) > 0 {
		filters = strings.Join(fs, ",")
	}
	var sb strings.Builder
	sb.WriteString("format=" + r.format + ";count=" + strconv.Itoa(c.count) + ";seqs=" +
		strconv.FormatUint(c.oldest.Seq, 10) + "-" + strconv.FormatUint(c.newest.Seq, 10) + ";filters=" + filters)
	if r.q.HasSince {
		sb.WriteString(";since=" + envelope.FormatTS(time.UnixMilli(r.q.Since)))
	}
	if r.q.HasUntil {
		sb.WriteString(";until=" + envelope.FormatTS(time.UnixMilli(r.q.Until)))
	}
	return sb.String()
}
