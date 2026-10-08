//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

type exportedEntry struct {
	Seq  uint64 `json:"seq"`
	Kind string `json:"kind"`
	Ref  string `json:"ref"`
	Dev  string `json:"device_id"`
	Prev []byte `json:"prev"`
	Hash []byte `json:"hash"`
}

func decodeEntries(t *testing.T, raw []json.RawMessage) []exportedEntry {
	t.Helper()
	out := make([]exportedEntry, len(raw))
	for i, r := range raw {
		if err := json.Unmarshal(r, &out[i]); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func feedCount(t *testing.T, tv *testVault) int {
	t.Helper()
	var f struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(mustOK(t, tv.request(tv.app, "feed.list", `{}`))["items"], &f.Items); err != nil {
		t.Fatal(err)
	}
	return len(f.Items)
}

// VAULT-MESSAGING 0.22.0 (§10.9 History export) through the real vault and
// relay: the holder's preview counts without a PIN; a wrong PIN is
// bad_pin, audited vault.pin_failed and counted in the §11.8 PIN backoff
// only (no owner-check failure, no owner_check.failed entry, no feed
// item); the right PIN appends exactly one audit.exported with the
// summary and answers the bound; the entries read with audit.list below
// it are the counted ones and chain to upto_hash; not_found comes before
// the backoff, the backoff before the PIN; desktops and agents are
// forbidden.
func TestAuditExport(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	ctx := ctxT(t, 240*time.Second)
	connect(t, a, b, 600)
	if _, err := a.app.CredentialUnlock(ctx, credPW); err != nil {
		t.Fatal(err)
	}

	// Desktops and agents: forbidden at once, never held for an approval.
	desk := pairDesktop(t, a, r.URL)
	agent := pairDevice(t, a, r.URL, vault.KindAgent, 3600)
	for name, d := range map[string]*client.Device{"desktop": desk, "agent": agent} {
		if _, err := d.AuditExportPreview(ctx, client.AuditQuery{}, ""); client.Code(err) != "forbidden" {
			t.Fatalf("%s preview: %v", name, err)
		}
		if rr, err := d.Request(ctx, "audit.export", []byte(`{"format":"json","upto_seq":1,"utk_id":"0011223344556677","sealed":"AAAA"}`)); err != nil || rr.ErrorCode() != "forbidden" {
			t.Fatalf("%s export: %v %v", name, rr, err)
		}
	}

	// The preview: the whole log, then credential entries only.
	all, err := a.app.AuditExportPreview(ctx, client.AuditQuery{}, "")
	if err != nil {
		t.Fatal(err)
	}
	page, err := a.app.AuditSearch(ctx, client.AuditQuery{Limit: 1}, false)
	if err != nil {
		t.Fatal(err)
	}
	if all.Count == 0 || all.More || all.UptoSeq != page.Seq || all.NewestSeq != page.Seq || all.OldestSeq < 1 {
		t.Fatalf("preview %+v, log seq %d", all, page.Seq)
	}
	cq := client.AuditQuery{Kinds: []string{"credential"}}
	pre, err := a.app.AuditExportPreview(ctx, cq, "json")
	if err != nil || pre.Count < 2 || pre.Count >= all.Count {
		t.Fatalf("credential preview %+v %v", pre, err)
	}
	if again, _ := a.app.AuditExportPreview(ctx, client.AuditQuery{}, ""); again.UptoSeq != all.UptoSeq {
		t.Fatal("a preview wrote an audit entry")
	}

	// A wrong PIN, twice: bad_pin, vault.pin_failed, not a failed owner
	// check.
	feedBefore := feedCount(t, a)
	for i := 0; i < 2; i++ {
		if _, err := a.app.AuditExport(ctx, cq, "json", pre.UptoSeq, "999999"); client.Code(err) != "bad_pin" {
			t.Fatalf("wrong PIN: %v", err)
		}
	}
	st, err := a.app.OwnerCheckState(ctx)
	if err != nil || st.Failures != 0 {
		t.Fatalf("a wrong export PIN counted as a failed owner check: %+v %v", st, err)
	}
	if n := feedCount(t, a); n != feedBefore {
		t.Fatalf("feed items %d → %d", feedBefore, n)
	}
	recent, err := a.app.AuditSearchAll(ctx, client.AuditQuery{After: true, AfterSeq: pre.UptoSeq}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	for _, e := range decodeEntries(t, recent) {
		switch {
		case e.Kind == "vault.pin_failed":
			failed++
		case strings.HasPrefix(e.Kind, "owner_check.") || e.Kind == "audit.exported":
			t.Fatalf("entry after a wrong PIN: %+v", e)
		}
	}
	if failed != 2 {
		t.Fatalf("%d vault.pin_failed entries after two wrong PINs", failed)
	}

	// The right PIN (the backoff's earlier failures are reset): exactly
	// one audit.exported, the preview's count, the bound.
	res, err := a.app.AuditExport(ctx, cq, "json", pre.UptoSeq, pin)
	if err != nil {
		t.Fatal(err)
	}
	if res.Count != pre.Count || res.UptoSeq != pre.UptoSeq || !bytes.Equal(res.UptoHash, pre.UptoHash) || res.EntrySeq <= pre.UptoSeq+2 ||
		res.OldestSeq != pre.OldestSeq || res.NewestSeq != pre.NewestSeq {
		t.Fatalf("export %+v, preview %+v", res, pre)
	}
	head, err := a.app.AuditSearchAll(ctx, client.AuditQuery{After: true, AfterSeq: res.EntrySeq - 1}, false, 0)
	if err != nil || len(head) != 1 {
		t.Fatalf("after the export: %d %v", len(head), err)
	}
	ex := decodeEntries(t, head)[0]
	want := "format=json;count=" + itoa(int(res.Count)) + ";seqs=" + itoa(int(res.OldestSeq)) + "-" + itoa(int(res.NewestSeq)) + ";filters=kinds"
	if ex.Kind != "audit.exported" || ex.Ref != want || ex.Dev == "" || ex.Seq != res.EntrySeq {
		t.Fatalf("audit.exported %+v, want ref %q", ex, want)
	}
	// The entries: audit.list below upto_seq + 1, the first count.
	es := decodeEntries(t, mustEntries(t, a.app, cq, res))
	if uint64(len(es)) != res.Count || es[0].Seq != res.NewestSeq || es[len(es)-1].Seq != res.OldestSeq {
		t.Fatalf("%d entries for count %d", len(es), res.Count)
	}
	for _, e := range es {
		if !strings.HasPrefix(e.Kind, "credential.") || e.Seq > res.UptoSeq {
			t.Fatalf("entry outside the export: %+v", e)
		}
	}
	// An unfiltered export is one chain ending at the log head.
	full, err := a.app.AuditExport(ctx, client.AuditQuery{}, "csv", res.EntrySeq, pin)
	if err != nil {
		t.Fatal(err)
	}
	fe := decodeEntries(t, mustEntries(t, a.app, client.AuditQuery{}, full))
	if len(fe) == 0 || fe[0].Seq != res.EntrySeq || !bytes.Equal(fe[0].Hash, full.UptoHash) {
		t.Fatalf("unfiltered export does not end at upto_hash: %+v", full)
	}
	for i := 1; i < len(fe); i++ {
		if fe[i].Seq+1 == fe[i-1].Seq && !bytes.Equal(fe[i-1].Prev, fe[i].Hash) {
			t.Fatalf("entries %d and %d do not chain", fe[i].Seq, fe[i-1].Seq)
		}
	}

	// Nothing matches: not_found (and no PIN tried).
	if _, err := a.app.AuditExport(ctx, client.AuditQuery{Kinds: []string{"nothing"}}, "json", full.EntrySeq, "999999"); client.Code(err) != "not_found" {
		t.Fatalf("no match: %v", err)
	}
	// upto_seq above the newest entry: bad_request.
	if _, err := a.app.AuditExport(ctx, cq, "json", full.EntrySeq+100, pin); client.Code(err) != "bad_request" {
		t.Fatalf("upto_seq above the newest: %v", err)
	}
	// Three wrong PINs start the §11.8 backoff: the right PIN is then
	// refused with backoff and retry_after; not_found still comes first;
	// the owner check's failures stay 0.
	for i := 0; i < 3; i++ {
		if _, err := a.app.AuditExport(ctx, cq, "json", full.EntrySeq, "999999"); client.Code(err) != "bad_pin" {
			t.Fatalf("wrong PIN %d: %v", i, err)
		}
	}
	_, err = a.app.AuditExport(ctx, cq, "json", full.EntrySeq, pin)
	var oe *client.OpError
	if !errors.As(err, &oe) || oe.Code != "backoff" || !strings.Contains(string(oe.Body), `"retry_after"`) {
		t.Fatalf("during the backoff: %v", err)
	}
	if _, err := a.app.AuditExport(ctx, client.AuditQuery{Kinds: []string{"nothing"}}, "json", full.EntrySeq, pin); client.Code(err) != "not_found" {
		t.Fatalf("no match during the backoff: %v", err)
	}
	if st, err := a.app.OwnerCheckState(ctx); err != nil || st.Failures != 0 {
		t.Fatalf("owner-check failures after the backoff: %+v %v", st, err)
	}
	all2, err := a.app.AuditSearchAll(ctx, client.AuditQuery{}, false, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range decodeEntries(t, all2) {
		if strings.HasPrefix(e.Kind, "owner_check.failed") {
			t.Fatalf("owner_check.failed entry: %+v", e)
		}
	}
}

func mustEntries(t *testing.T, d *client.Device, q client.AuditQuery, r *client.AuditExportResult) []json.RawMessage {
	t.Helper()
	es, err := d.AuditExportEntries(ctxT(t, 60*time.Second), q, r)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

// §10.9 (0.22.0), §3.6.3: past the owner check's deadline the app is
// gated: audit.export, the preview included, is owner_check_required.
func TestAuditExportHeld(t *testing.T) {
	r := relaytest.Start(t, nil)
	clk := &ocClock{}
	a := newTestVault(t, r.URL, "a", func(o *vault.Options) { o.OwnerCheckClock = clk.Now })
	ctx := ctxT(t, 120*time.Second)
	if _, err := a.app.AuditExportPreview(ctx, client.AuditQuery{}, ""); err != nil {
		t.Fatal(err)
	}
	clk.add(25 * time.Hour)
	waitEvent(t, a.app, "vault.held", nil)
	if _, err := a.app.AuditExportPreview(ctx, client.AuditQuery{}, ""); client.Code(err) != "owner_check_required" {
		t.Fatalf("preview while held: %v", err)
	}
	if _, err := a.app.AuditExport(ctx, client.AuditQuery{}, "json", 1, pin); client.Code(err) != "owner_check_required" {
		t.Fatalf("export while held: %v", err)
	}
}
