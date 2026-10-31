package vote

import (
	"encoding/json"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// vote.site.sync (VAULT-MESSAGING 0.81.2 §10.19.8): what the app did with the
// public site for the vault. A request over 245,760 bytes travels as one
// §5.5 claim-check blob, {blob: {id, key, sha256, size}}: the runtime
// fetches it, checks sha256 in constant time and then the size, decrypts,
// and the plaintext is handled as the request body under the same limits; a
// blob that fails is bad_request and is deleted.

func (f *Feature) apiSync(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	if !o.Has("blob") {
		return f.syncBody(s, in.Body)
	}
	if len(o) != 1 {
		return nil, errBad
	}
	bo, err := o.Object("blob")
	if err != nil || len(bo) != 4 { // mime and name are absent
		return nil, errBad
	}
	id, err := bo.String("id")
	if err != nil || !envelope.ValidULID(id) {
		return nil, errBad
	}
	key, err := bo.Base64("key", 32)
	if err != nil {
		return nil, errBad
	}
	sum, err := bo.Base64("sha256", 32)
	if err != nil {
		return nil, errBad
	}
	size, err := bo.Uint("size", 1, strictjson.MaxSafeInteger)
	if err != nil {
		return nil, errBad
	}
	// Over the relay's limit, or on a relay without blobs, nothing can be
	// fetched and the held list is kept.
	limit := min(s.BlobLimit(), votewire.MaxSyncBytes)
	if limit <= 0 || size > uint64(limit) {
		return nil, vault.NewError("payload_too_large", "")
	}
	if err := s.DeferBlob(id, key, sum, int(size), func(s *vault.Session, plain []byte) (json.RawMessage, error) {
		return f.syncBody(s, plain)
	}); err != nil {
		return nil, err
	}
	return nil, vault.ErrDeferred
}

// listsOf reads `services`: at most 8 lists, and 1 when one is over 1 MiB.
//
// Shape checks are per item (VAULT-MESSAGING 0.81.5 §10.19.8): a list whose
// `doc` is empty or whose `sig` does not decode to exactly SigLen bytes is
// refused alone, not the call. Versions apply in order, oldest first
// (§10.19.4 "Catch-up"), so a bad version ENDS the catch-up at that point:
// the lists before it are returned to be applied, the bad one is answered
// `rejected` and every later list in the call is answered `ignored` and not
// applied (the app sends it again on the next sync). total is the number of
// lists in the request, so the answer has one result per list.
func listsOf(o strictjson.Object) (lists []ServiceListDoc, total int, err error) {
	arr, present, err := o.OptArray("services")
	if err != nil {
		return nil, 0, errBad
	}
	if !present {
		return nil, 0, nil
	}
	if len(arr) > votewire.MaxSyncLists {
		return nil, 0, errBad
	}
	var out []ServiceListDoc
	bad := false
	for _, raw := range arr {
		lo, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, 0, errBad
		}
		doc, err := lo.Base64("doc", -1)
		if err != nil {
			return nil, 0, errBad
		}
		sg, err := lo.String("sig")
		if err != nil {
			return nil, 0, errBad
		}
		sig, sigErr := strictjson.DecodeStd(sg, -1)
		if sigErr != nil {
			return nil, 0, errBad
		}
		if bad {
			continue // after a bad version: not applied
		}
		if len(doc) == 0 || len(sig) != votewire.SigLen {
			bad = true
			continue
		}
		out = append(out, ServiceListDoc{Doc: doc, Sig: sig})
	}
	for _, l := range out {
		if len(l.Doc) > votewire.BigList && len(arr) > 1 {
			return nil, 0, errBad
		}
	}
	return out, len(arr), nil
}

// syncDocument is an entry's document: found with the proposal, its
// signature and bundle and the extensions, or absent, or unreachable.
type syncDocument struct {
	status string
	doc    SiteDoc
	exts   []*votewire.ExtendedMsg
}

func parseDocument(proposalID string, raw json.RawMessage) (*syncDocument, error) {
	do, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, errBad
	}
	st, err := do.String("status")
	if err != nil {
		return nil, errBad
	}
	d := &syncDocument{status: st}
	switch st {
	case "absent", "unreachable":
		if len(do) != 1 { // the app sends no time: an `at` is bad_request
			return nil, errBad
		}
		d.doc.Status = StatusAbsent
		if st == "unreachable" {
			d.doc.Status = StatusUnreachable
		}
		return d, nil
	case "found":
	default:
		return nil, errBad
	}
	d.doc.Status = StatusFound
	if d.doc.Proposal, err = do.Base64("proposal", -1); err != nil {
		return nil, errBad
	}
	if len(d.doc.Proposal) > votewire.MaxProposal {
		// Per item (0.81.5 §10.19.8): a proposal over the limit is what the
		// app sends for it, `unreachable`. The entry is judged as that.
		d.status = "unreachable"
		d.doc = SiteDoc{Status: StatusUnreachable}
		return d, nil
	}
	// proposal_sig is the base64 of the raw 64 bytes; a missing or failing
	// one is judged by the vault (the site's copy is then no mismatch).
	if sg, ok, _ := do.OptString("proposal_sig"); ok {
		if b, err := strictjson.DecodeStd(sg, -1); err == nil {
			d.doc.Sig = b
		}
	}
	if raw, ok := do["bundle"]; ok && string(raw) != "null" {
		// Per item: a bundle that is not an object or is over the limit is
		// ignored; the entry is processed without it.
		if _, err := strictjson.AsObject(raw); err == nil && len(raw) <= votewire.MaxBundle {
			d.doc.Bundle = append(json.RawMessage{}, raw...)
		}
	}
	arr, _, err := do.OptArray("extensions")
	if err != nil {
		return nil, errBad
	}
	// Per item (0.81.5 §10.19.8): the extensions before the first bad one
	// are kept; it and the rest are dropped (extensions apply in order). More
	// than MaxExtensions keeps the first MaxExtensions.
	if len(arr) > votewire.MaxExtensions {
		arr = arr[:votewire.MaxExtensions]
	}
	for _, e := range arr {
		eo, err := strictjson.AsObject(e)
		if err != nil {
			return nil, errBad
		}
		m := &votewire.ExtendedMsg{ProposalID: proposalID}
		if m.Extension, err = eo.Base64("extension", -1); err != nil {
			return nil, errBad
		}
		if m.ExtensionSig, err = eo.Base64("extension_sig", -1); err != nil {
			return nil, errBad
		}
		braw, ok := eo["bundle"]
		if len(m.Extension) > votewire.MaxExtensionDoc || len(m.ExtensionSig) != votewire.SigLen || !ok || len(braw) > votewire.MaxBundle {
			break
		}
		if _, err := strictjson.AsObject(braw); err != nil {
			break
		}
		m.Bundle = append(json.RawMessage{}, braw...)
		d.exts = append(d.exts, m)
	}
	return d, nil
}

// syncBody is the request body: services, services_confirm and entries.
func (f *Feature) syncBody(s *vault.Session, body []byte) (json.RawMessage, error) {
	if len(body) > votewire.MaxSyncBytes {
		return nil, errBad
	}
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	lists, nLists, err := listsOf(o)
	if err != nil {
		return nil, err
	}
	var confirmVersion uint64
	var confirmSum []byte
	hasConfirm := false
	if raw, ok := o["services_confirm"]; ok {
		co, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		if confirmVersion, err = co.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
			return nil, errBad
		}
		if confirmSum, err = co.Base64("sha256", 32); err != nil {
			return nil, errBad
		}
		hasConfirm = true
	}
	entries, _, err := o.OptArray("entries")
	if err != nil || len(entries) > votewire.MaxSyncEntries {
		return nil, errBad
	}
	type entry struct {
		id        string
		serviceID string
		doc       *syncDocument
	}
	var es []entry
	for _, raw := range entries {
		eo, err := strictjson.AsObject(raw)
		if err != nil {
			return nil, errBad
		}
		e := entry{}
		if e.id, err = eo.String("proposal_id"); err != nil || !votewire.ValidProposalID(e.id) {
			return nil, errBad
		}
		if raw, ok := eo["index"]; ok {
			io, err := strictjson.AsObject(raw)
			if err != nil {
				return nil, errBad
			}
			// Per item: a service_id that is present but not a string drops
			// the index; the entry is processed without it.
			if sid, _, err := io.OptString("service_id"); err == nil {
				e.serviceID = sid
			}
		}
		draw, ok := eo["document"]
		if !ok {
			return nil, errBad
		}
		if e.doc, err = parseDocument(e.id, draw); err != nil {
			return nil, err
		}
		es = append(es, e)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	out := strictjson.NewBuilder()
	if nLists > 0 {
		res := f.syncCatchUp(s, lists)
		// A list refused by shape ended the catch-up (see listsOf): it is
		// `rejected` and the lists after it `ignored`, one result per list.
		for len(res) < nLists {
			r := ListIgnored
			if len(res) == len(lists) && (len(res) == 0 || res[len(res)-1] == ListKept || res[len(res)-1] == ListConfirmed) {
				r = ListRejected
			}
			res = append(res, r)
		}
		arr := []byte{'['}
		for i, r := range res {
			if i > 0 {
				arr = append(arr, ',')
			}
			arr = append(arr, strictjson.MarshalString(r)...)
		}
		out.Raw("services", append(arr, ']'))
	}
	if hasConfirm {
		res := ListIgnored
		if l := f.st.List; l != nil && uint64(l.Version) == confirmVersion && eq(votewire.H(l.Doc), confirmSum) {
			l.ConfirmedMS = s.Now().UnixMilli()
			f.recheck(s)
			res = ListConfirmed
		}
		out.String("services_confirm", res)
	}
	arr := []byte{'['}
	for i, e := range es {
		if i > 0 {
			arr = append(arr, ',')
		}
		result := f.syncEntry(s, e.id, e.serviceID, e.doc)
		eb := strictjson.NewBuilder().String("proposal_id", e.id).String("result", result)
		arr = append(arr, eb.Bytes()...)
	}
	out.Raw("entries", append(arr, ']'))
	return out.Bytes(), nil
}

// syncEntry compares what the app found at the site with what the vault
// holds (§10.19.4): "known" for a proposal it holds (its documents compared,
// its extensions learned), "kept" for one it did not hold and has now asked
// its service for (vote.status), "ignored" for an entry that matches none of
// its service connections or that it asked for within the hour.
func (f *Feature) syncEntry(s *vault.Session, id, serviceID string, d *syncDocument) string {
	held := false
	for _, r := range f.recordsOf(id) {
		held = true
		_ = f.siteDocument(s, r.Conn, id, d.doc)
		if r = f.get(r.Conn, id); r != nil && r.RejectReason == "" {
			for _, m := range d.exts {
				if int64(len(r.Exts)) >= extN(m) {
					continue // held already
				}
				_, _ = f.extend(s, r.Conn, m) // checked as vote.extended is
			}
		}
	}
	if held {
		return "known"
	}
	if d.doc.Status != StatusFound || len(d.doc.Proposal) == 0 {
		return "ignored"
	}
	// Not held: the service connection that lists this service is asked.
	conns := f.serviceConnections(s, serviceID, d.doc.Proposal)
	asked := false
	for _, c := range conns {
		asked = f.requestProposal(s, c, id, d.doc.Proposal) || asked
	}
	if asked {
		return "kept"
	}
	return "ignored"
}

func extN(m *votewire.ExtendedMsg) int64 {
	if e, err := votewire.ParseExtension(m.Extension); err == nil {
		return e.N
	}
	return 1 << 40
}

func (f *Feature) recordsOf(id string) []*record {
	var out []*record
	for _, r := range f.st.Records {
		if r.ID == id {
			out = append(out, r)
		}
	}
	return out
}

// serviceConnections are the active service connections that match an
// index entry: those whose key the held list gives to the entry's service
// (service_id), or, without an index, to the service that signed the
// proposal.
func (f *Feature) serviceConnections(s *vault.Session, serviceID string, proposal []byte) []string {
	ix := f.index()
	if ix == nil || ix.list == nil {
		return nil
	}
	if serviceID == "" {
		if p, err := votewire.ParseProposal(proposal); err == nil {
			if e := ix.byIK[string(p.Service)]; e != nil {
				serviceID = e.ServiceID
			}
		}
	}
	var out []string
	for i := range ix.list.Services {
		e := &ix.list.Services[i]
		if e.ServiceID != serviceID {
			continue
		}
		for _, c := range s.Connections() {
			if !c.IsService() || c.State != vault.PeerActive {
				continue
			}
			for _, k := range e.IKs {
				if isConnKey(s, c.ID, k) {
					out = append(out, c.ID)
					break
				}
			}
		}
	}
	return out
}
