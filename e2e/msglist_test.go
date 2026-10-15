//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
)

// §10.5.2, §8.2 (0.32.0): a conversation larger than one response is
// listed in pages of at most 131,072 bytes that continue with
// next_before; message.list is volatile (a retransmission is executed
// again, so it sees a deletion since); a deleted cursor is not_found.
// Before 0.32.0 this list could not be sealed and the request timed out.
func TestMessageListPages(t *testing.T) {
	r := relaytest.Start(t, nil)
	a := newTestVault(t, r.URL, "a", nil)
	b := newTestVault(t, r.URL, "b", nil)
	aConn, _ := connect(t, a, b, 3600)
	const n = 20
	var ids []string
	for i := range n {
		ids = append(ids, sendText(t, a, a.app, aConn, strings.Repeat(string(rune('a'+i)), 16*1024)))
	}
	var got []string
	body := `{"connection_id":"` + aConn + `","limit":500}`
	pages := 0
	for {
		l := mustOK(t, a.request(a.app, "message.list", body))
		pages++
		var msgs []json.RawMessage
		_ = json.Unmarshal(l["messages"], &msgs)
		if len(msgs) == 0 || len(msgs) > 7 {
			t.Fatalf("page of %d messages", len(msgs))
		}
		var ps []string
		for _, m := range msgs {
			ps = append(ps, field(t, m, "message_id"))
		}
		got = append(ps, got...)
		nb, err := l.String("next_before")
		if err != nil {
			break
		}
		if nb != ps[0] {
			t.Fatalf("next_before %s, oldest %s", nb, ps[0])
		}
		body = `{"connection_id":"` + aConn + `","limit":500,"before":"` + nb + `"}`
	}
	if strings.Join(got, ",") != strings.Join(ids, ",") || pages != 3 {
		t.Fatalf("%d pages, %d of %d messages", pages, len(got), n)
	}

	// Volatile: the same request id again after a deletion is executed
	// again, not answered from a cache.
	q := json.RawMessage(`{"connection_id":"` + aConn + `","limit":2}`)
	reqID, err := a.app.Send(ctxT(t, 10*time.Second), "message.list", q)
	if err != nil {
		t.Fatal(err)
	}
	r1, err := a.app.AwaitResponse(ctxT(t, 30*time.Second), reqID)
	if err != nil || !r1.OK() || !strings.Contains(string(r1.Body()), ids[n-1]) {
		t.Fatalf("first answer: %v", err)
	}
	mustOK(t, a.request(a.app, "message.delete", `{"connection_id":"`+aConn+`","message_id":"`+ids[n-1]+`"}`))
	if _, err := a.app.SendWithID(ctxT(t, 10*time.Second), reqID, "message.list", q); err != nil {
		t.Fatal(err)
	}
	r2, err := a.app.AwaitResponse(ctxT(t, 30*time.Second), reqID)
	if err != nil || !r2.OK() || strings.Contains(string(r2.Body()), ids[n-1]) || !strings.Contains(string(r2.Body()), ids[n-3]) {
		t.Fatalf("retransmission answered from a cache: %v %s", err, r2.Body())
	}
	// message.get is volatile and returns one message.
	g := mustOK(t, a.request(a.app, "message.get", `{"connection_id":"`+aConn+`","message_id":"`+ids[0]+`"}`))
	if tx, _ := g.String("text"); len(tx) != 16*1024 {
		t.Fatal("message.get")
	}
	// A cursor naming the deleted message is not_found.
	if rr := a.request(a.app, "message.list", `{"connection_id":"`+aConn+`","before":"`+ids[n-1]+`"}`); rr.ErrorCode() != "not_found" {
		t.Fatalf("deleted cursor: %q", rr.ErrorCode())
	}
}
