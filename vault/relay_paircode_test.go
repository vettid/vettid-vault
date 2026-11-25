package vault

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/paircode"
)

// fakeRelayRoutes answers the routes the tests below use and records each
// request.
type fakeRelayRoutes struct {
	method string
	path   string
	body   []byte
	answer func(w http.ResponseWriter, r *http.Request)
}

func (f *fakeRelayRoutes) start() (*ClientRelay, func()) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.method, f.path = r.Method, r.URL.Path
		f.body, _ = io.ReadAll(r.Body)
		f.answer(w, r)
	}))
	r := NewClientRelay(srv.URL, ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32)), srv.Client(), nil)
	return r, srv.Close
}

// After the relay module's bump the rotation behaves as before: the
// successor's mailbox id, whether or not the relay reports a tombstone
// (the report is not read yet).
func TestClientRelayRotateAsBefore(t *testing.T) {
	for _, answer := range []string{
		`{"mailbox_id":"bbbbbbbbbbbbbbbbbbbbbbbbbb"}`,
		`{"mailbox_id":"bbbbbbbbbbbbbbbbbbbbbbbbbb","reports_tombstones_at_rotation":true,"tokens_not_before":"2026-11-25T12:00:00Z"}`,
	} {
		f := &fakeRelayRoutes{answer: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, answer)
		}}
		r, done := f.start()
		id, err := r.Rotate(context.Background(), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)))
		done()
		if err != nil || id != "bbbbbbbbbbbbbbbbbbbbbbbbbb" || f.method != "POST" || f.path != "/v1/mailbox/rotate" {
			t.Fatalf("%s: %q %v (%s %s)", answer, id, err, f.method, f.path)
		}
	}
}

// The code claim calls reach the relay's routes with the right bodies.
func TestClientRelayPairCodeCalls(t *testing.T) {
	const r0 = "https://relay.example.org"
	nonce := bytes.Repeat([]byte{1}, 16)
	sid := paircode.SaltID(paircode.SaltR(r0, 493000, nonce))
	f := &fakeRelayRoutes{}
	r, done := f.start()
	defer done()
	ctx := context.Background()

	f.answer = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"salts":[{"salt_id":"`+sid+`","epoch":493000,"nonce":"`+base64.StdEncoding.EncodeToString(nonce)+`"}]}`)
	}
	salts, err := r.PairCodeSalts(ctx)
	if err != nil || len(salts) != 1 || salts[0].SaltID != sid || salts[0].Epoch != 493000 || !bytes.Equal(salts[0].Nonce, nonce) {
		t.Fatalf("salts: %+v %v", salts, err)
	}
	if f.method != "GET" || f.path != "/v1/pair-code/salts" {
		t.Fatalf("%s %s", f.method, f.path)
	}

	const cid = "q4f7m2xk5n3p6r7t2v4w6y7z3a"
	f.answer = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"expires_at":"2026-11-25T12:10:00Z"}`)
	}
	tag, sc := bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 16)
	exp, err := r.PutPairCode(ctx, cid, sid, tag, sc, []byte("blob"))
	if err != nil || !exp.Equal(time.Date(2026, 11, 25, 12, 10, 0, 0, time.UTC)) || f.method != "PUT" || f.path != "/v1/pair-code/"+cid {
		t.Fatalf("put: %v %v (%s %s)", exp, err, f.method, f.path)
	}
	var b map[string]string
	if json.Unmarshal(f.body, &b) != nil || b["salt_id"] != sid || b["tag"] != base64.StdEncoding.EncodeToString(tag) ||
		b["salt"] != base64.StdEncoding.EncodeToString(sc) || b["blob"] != base64.StdEncoding.EncodeToString([]byte("blob")) {
		t.Fatalf("put body %s", f.body)
	}

	f.answer = func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	if err := r.DeletePairCode(ctx, cid); err != nil || f.method != "DELETE" || f.path != "/v1/pair-code/"+cid {
		t.Fatalf("delete: %v (%s %s)", err, f.method, f.path)
	}

	// A code_taken comes back with its code (RelayCode), for the retry.
	f.answer = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"code":"code_taken","message":"x"}`)
	}
	if _, err := r.PutPairCode(ctx, cid, sid, tag, sc, []byte("blob")); RelayCode(err) != "code_taken" {
		t.Fatalf("code_taken: %v", err)
	}
}

// noLimits keeps its meaning with the raw members: none read is empty,
// any read limit is not.
func TestNoLimits(t *testing.T) {
	if !noLimits(Limits{}) {
		t.Fatal("empty")
	}
	if noLimits(Limits{MaxPayloadBytes: 1}) || noLimits(Limits{PairCodes: json.RawMessage(`true`)}) {
		t.Fatal("read limits taken for none")
	}
}

// The relay's true-only flags are kept as true or absent, whatever the
// relay sent: an oversized value is not kept in memory or in the state.
func TestClientRelayNormalLimits(t *testing.T) {
	big := `"` + strings.Repeat("x", 1<<20) + `"`
	for _, c := range []struct {
		pairCodes, tombstones string
		wantCodes, wantTombs  bool
	}{
		{big, big, false, false},
		{`true`, `true`, true, true},
		{` true `, `false`, true, false},
		{`{"true":true}`, `null`, false, false},
		{`1`, `"true"`, false, false},
	} {
		answer := `{"mailbox_id":"aaaaaaaaaaaaaaaaaaaaaaaaaa","limits":{"max_claim_bytes":16384,"pair_codes":` + c.pairCodes +
			`,"reports_tombstones":` + c.tombstones + `}}`
		f := &fakeRelayRoutes{answer: func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, answer)
		}}
		r, done := f.start()
		lim, err := r.Register(context.Background())
		lim2, created, err2 := r.RegisterCreated(context.Background())
		done()
		if err != nil || err2 != nil || !created {
			t.Fatalf("%.40s: %v %v created %v", c.pairCodes, err, err2, created)
		}
		for _, l := range []Limits{lim, lim2} {
			if l.OffersPairCodes() != c.wantCodes || len(l.PairCodes) > 4 || len(l.ReportsTombstones) > 4 {
				t.Fatalf("%.40s: pair_codes %q, reports_tombstones %q", c.pairCodes, l.PairCodes, l.ReportsTombstones)
			}
			if got := string(l.ReportsTombstones) == "true"; got != c.wantTombs {
				t.Fatalf("%.40s: reports_tombstones %q", c.tombstones, l.ReportsTombstones)
			}
			if l.MaxClaimBytes != 16384 {
				t.Fatal("the other limits are not kept")
			}
		}
	}
}
