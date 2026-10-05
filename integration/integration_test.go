//go:build devenclave && integration

package integration

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/parent"
	"github.com/vettid/vettid-vault/vault"
)

const pin1 = "97531086"

var vaultIDRE = regexp.MustCompile(`(?m)^[0-9a-f]{32}$`)

// V3 exit (VAULT-PLAN §4): vaultctl enrolls, unlocks, messages, locks and
// unlocks again through the member API, the queue, the parent and the
// enclave; a second member's vault exchanges messages with it; the vault
// moves from release 3 to release 4 across two instances with leases; and
// when two instances hold the vault, the one whose conditional write loses
// locks it.
func TestV3Exit(t *testing.T) {
	s := newStack(t)
	a := s.start("a", 3)
	// The instance queue carries vettid.org's policy from SSM.
	if p := s.queuePolicyOf(a); !sameJSON(p, s.queuePolicy) {
		t.Fatalf("queue policy: %q", p)
	}

	// --- member 1 (vaultctl): enroll ---
	m1 := filepath.Join(s.dir, "member1.json")
	api := []string{"-api", s.api.URL, "-guid", "member-1", "-pin", pin1}
	s.mustVaultctl(m1, "init", "-role", "app", "-name", "phone", "-relay", relayURL)
	out := s.mustVaultctl(m1, append([]string{"api-enroll"}, api...)...)
	vid := vaultIDRE.FindString(out)
	if vid == "" {
		t.Fatalf("api-enroll: %s", out)
	}
	if r := s.vaultRow(vid); r.State != "unlocked" || r.LeaseInstance != a.id || r.SealedRelease != enclavetest.Spec(3, "").PCR0Hex() {
		t.Fatalf("vault row after enrollment: %+v", r)
	}
	out = s.mustVaultctl(m1, "request", "vault.status", "{}")
	if !strings.Contains(out, `"status": "ok"`) || !strings.Contains(out, vid) {
		t.Fatalf("status: %s", out)
	}

	// --- member 2 (in-process app): enroll, then connect to member 1 ---
	ctx := ctxT(t, 8*time.Minute)
	m2, err := client.New(ctx, client.Config{Role: vault.KindApp, Name: "m2-phone", RelayURL: relayURL, HTTP: s.appHTTP, PollWait: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	api2 := &client.MemberAPI{Base: s.api.URL, Authorize: bearer("member-2")}
	att2 := enclavetest.NewAndroidAttester(0x62, enclavetest.AndroidOptions{})
	trust := s.w.Trust()
	vid2, er, err := m2.EnrollVia(ctx, api2, "member-2", "246801", trust, att2)
	if err != nil || !er.OK {
		t.Fatalf("member 2 enroll: %v %+v", err, er)
	}
	if err := m2.AwaitEnrolled(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m2.CompleteEnrollment(ctx); err != nil {
		t.Fatal(err)
	}
	if err := m2.CredentialCreate(ctx, "member two password"); err != nil {
		t.Fatal(err)
	}
	mustOK(t, req(t, m2, "vault.enroll.confirm", `{}`))
	if vid2 == vid {
		t.Fatal("two members share a vault id")
	}

	inv := firstBody(t, s.mustVaultctl(m1, "request", "connection.invite.create", `{"ttl_seconds":3600}`))
	link, _ := inv["link"].(string)
	acc := mustOK(t, req(t, m2, "connection.invite.accept", `{"link":"`+link+`"}`))
	m2conn, _ := acc.String("connection_id")
	// 0.10.3: the handshake runs first; both members compare the SAS and
	// each approves its own side.
	pending := s.waitCtlEvent(m1, "connection.request.pending", nil)
	sas := str(pending, "sas")
	if len(sas) != 6 {
		t.Fatal("no SAS")
	}
	waitEvent(t, m2, "connection.request.outgoing", func(b json.RawMessage) bool {
		return has("connection_id", m2conn)(b) && has("sas", sas)(b) // the same code on both sides
	})
	s.mustVaultctl(m1, "request", "connection.approve", `{"pending_id":"`+str(pending, "pending_id")+`"}`)
	mustOK(t, req(t, m2, "connection.approve", `{"connection_id":"`+m2conn+`"}`))
	waitEvent(t, m2, "connection.event", has("event", "added"))
	sendText(t, m2, m2conn, "hello from member 2")
	got := s.waitCtlEvent(m1, "message.new", func(b map[string]any) bool { return str(b, "text") == "hello from member 2" })
	if str(got, "direction") != "in" {
		t.Fatalf("message: %v", got)
	}
	a.waitHealth(func(h parent.Health) bool { return h.Vaults == 2 }, "running both vaults")

	// --- lock, a message while locked, unlock again ---
	lock := func() {
		t.Helper()
		out := s.mustVaultctl(m1, append([]string{"api-lock"}, api[:4]...)...)
		if !strings.Contains(out, `"status": "done"`) {
			t.Fatalf("lock: %s", out)
		}
		a.waitHealth(func(h parent.Health) bool { return h.Vaults == 1 }, "with member 1 locked")
		if r := s.vaultRow(vid); r.State != "locked" || r.LeaseInstance != "" {
			t.Fatalf("vault row after lock: %+v", r)
		}
	}
	unlock := func(extra ...string) map[string]any {
		t.Helper()
		out, err := s.vaultctl(m1, append(append([]string{"api-unlock"}, api...), extra...)...)
		if err != nil {
			return map[string]any{"error": out}
		}
		return firstValue(t, out)
	}
	lock()
	stateKey := "vaults/" + vid + "/state"
	oldState := s.getObject(stateKey)
	sendText(t, m2, m2conn, "sent while locked")
	if u := unlock(); u["ok"] != true || u["instance_id"] != a.id {
		t.Fatalf("unlock: %v", u)
	}
	s.waitCtlEvent(m1, "message.new", func(b map[string]any) bool { return str(b, "text") == "sent while locked" })
	if r := s.vaultRow(vid); r.State != "unlocked" || r.LeaseInstance != a.id {
		t.Fatalf("vault row after unlock: %+v", r)
	}

	// --- refusals: a rolled-back state object, a bad device attestation,
	// a replayed unlock ---
	lock()
	newState := s.getObject(stateKey)
	s.putObject(stateKey, oldState) // the host serves an older state (§13.2)
	if u := unlock(); u["ok"] != false || u["code"] != "state_rollback" {
		t.Fatalf("rolled-back state: %v", u)
	}
	s.putObject(stateKey, newState)
	if u := unlock("-attest-seed", "153"); u["ok"] != false || u["code"] != "attestation" {
		t.Fatalf("unlock with another device key: %v", u)
	}
	if u := unlock(); u["ok"] != true {
		t.Fatalf("unlock after the refusals: %v", u)
	}
	// Member 2 locks and unlocks; the host replays that unlock: the
	// enclave's replay set drops it (§11.6) and the vault is not reopened.
	if sl, err := m2.LockVia(ctx, api2); err != nil || sl.Status != "done" {
		t.Fatalf("member 2 lock: %v %+v", err, sl)
	}
	if u, err := m2.UnlockVia(ctx, api2, "member-2", "246801", trust, att2, client.UnlockOptions{}, ""); err != nil || !u.OK {
		t.Fatalf("member 2 unlock: %v %+v", err, u)
	}
	before := s.vaultRow(vid2)
	rid, q, body := s.lastSent("unlock")
	s.requeue(rid, q, body, "member-2")
	slot, err := api2.Poll(ctx, rid)
	if err != nil || slot.Status != "done" || len(slot.Envelope) != 5252 {
		t.Fatalf("replayed unlock: %v %+v", err, slot)
	}
	if after := s.vaultRow(vid2); after != before {
		t.Fatalf("replayed unlock reopened the vault: %+v -> %+v", before, after)
	}
	a.waitHealth(func(h parent.Health) bool { return h.Vaults == 2 }, "running both vaults after the replay")

	// --- release move 3 -> 4 across two instances ---
	s.addRelease(4)
	b := s.start("b", 4)
	out = s.mustVaultctl(m1, append([]string{"api-unlock"}, append(api, "-approve", "4")...)...)
	if u := firstValue(t, out); u["ok"] != true || u["update"] != "moved" || u["instance_id"] != a.id {
		t.Fatalf("approved move: %s", out)
	}
	pcr4 := enclavetest.Spec(4, "").PCR0Hex()
	waitFor(t, "sealed_release = release 4", func() bool { r := s.vaultRow(vid); return r.SealedRelease == pcr4 && r.LeaseInstance == "" })
	a.waitHealth(func(h parent.Health) bool { return h.Vaults == 1 }, "without the moved vault")
	out = s.mustVaultctl(m1, append([]string{"api-unlock"}, api...)...)
	if u := firstValue(t, out); u["ok"] != true || u["release_number"] != float64(4) || u["instance_id"] != b.id {
		t.Fatalf("unlock under release 4: %s", out)
	}
	if r := s.vaultRow(vid); r.LeaseInstance != b.id || r.VaultVersion != pcr4 {
		t.Fatalf("vault row under release 4: %+v", r)
	}
	out = s.mustVaultctl(m1, "request", "vault.status", "{}")
	if !strings.Contains(out, `"status": "ok"`) {
		t.Fatalf("status under release 4: %s", out)
	}

	// --- split brain: a second release-4 instance takes the vault ---
	// The lease is forced to expire, as if b had stalled; the API then
	// routes the unlock to c (least loaded), whose unlock writes a new
	// state version. b may renew its own lease back before the unlock
	// lands; retry until c holds the vault.
	c := s.start("c", 4)
	var cu map[string]any
	waitFor(t, "an unlock routed to c", func() bool {
		_ = expireLease(s, vid)
		out = s.mustVaultctl(m1, append([]string{"api-unlock"}, api...)...)
		cu = firstValue(t, out)
		return cu["instance_id"] == c.id
	})
	if cu["ok"] != true {
		t.Fatalf("unlock at c: %v", cu)
	}
	// b still runs the vault with a stale state version. Its next flush
	// (a message it collects) or its next lease renewal fails, and b locks
	// the vault without overwriting c's state.
	waitFor(t, "b to lock the vault", func() bool {
		_, _ = s.vaultctl(m1, "request", "vault.status", "{}")
		h, err := b.healthNow()
		return err == nil && h.Vaults == 0 && h.SplitBrain+h.LeasesLost > 0
	})
	if r := s.vaultRow(vid); r.LeaseInstance != c.id || r.State != "unlocked" {
		t.Fatalf("vault row after the split brain: %+v", r)
	}
	out = s.mustVaultctl(m1, "request", "vault.status", "{}")
	if !strings.Contains(out, `"status": "ok"`) {
		t.Fatalf("status at c: %s", out)
	}
	sendText(t, m2, m2conn, "after the split brain")
	s.waitCtlEvent(m1, "message.new", func(b map[string]any) bool { return str(b, "text") == "after the split brain" })

	// --- shutdown: queues and registry rows go away; nothing secret was logged ---
	for _, in := range s.instances {
		in.stop()
		if strings.Contains(in.plog.String(), pin1) || strings.Contains(in.elog.String(), pin1) {
			t.Fatalf("instance %s logged the PIN", in.name)
		}
		if strings.Contains(in.plog.String(), `"envelope"`) {
			t.Fatalf("instance %s logged an envelope", in.name)
		}
	}
	waitFor(t, "queues deleted", func() bool { return queueCount(s) == 0 })
}

func bearer(guid string) func(r *http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+guid) }
}

func req(t *testing.T, d *client.Device, typ, body string) *client.Response {
	t.Helper()
	r, err := d.Request(ctxT(t, 60*time.Second), typ, json.RawMessage(body))
	if err != nil {
		t.Fatalf("%s: %v", typ, err)
	}
	return r
}

func mustOK(t *testing.T, r *client.Response) strictjson.Object {
	t.Helper()
	if !r.OK() {
		t.Fatalf("%s: error %s", r.Inner.Type, r.ErrorCode())
	}
	o, err := strictjson.ParseObject(r.Body())
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func has(name, value string) func(json.RawMessage) bool {
	return func(b json.RawMessage) bool {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return false
		}
		v, _ := o.String(name)
		return v == value
	}
}

func waitEvent(t *testing.T, d *client.Device, typ string, pred func(json.RawMessage) bool) {
	t.Helper()
	if _, err := d.WaitEvent(ctxT(t, 60*time.Second), typ, pred); err != nil {
		t.Fatalf("waiting for %s: %v", typ, err)
	}
}

func sendText(t *testing.T, d *client.Device, conn, text string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"connection_id": conn, "text": text})
	mustOK(t, req(t, d, "message.send", string(body)))
}

func str(m map[string]any, k string) string {
	v, _ := m[k].(string)
	return v
}

// firstValue is the first JSON object vaultctl printed.
func firstValue(t *testing.T, out string) map[string]any {
	t.Helper()
	vs := jsonValues(out)
	if len(vs) == 0 {
		t.Fatalf("no JSON in %q", out)
	}
	return vs[0]
}

// firstBody is the body of the response vaultctl request printed.
func firstBody(t *testing.T, out string) map[string]any {
	t.Helper()
	v := firstValue(t, out)
	if v["status"] != "ok" {
		t.Fatalf("request failed: %s", out)
	}
	b, _ := v["body"].(map[string]any)
	return b
}

// waitCtlEvent collects with vaultctl until an event of typ (matching
// pred) arrives, and returns its body.
func (s *stack) waitCtlEvent(state, typ string, pred func(map[string]any) bool) map[string]any {
	s.t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		out := s.mustVaultctl(state, "events", "-wait", "3s")
		for _, ev := range jsonValues(out) {
			if ev["type"] != typ {
				continue
			}
			b, _ := ev["body"].(map[string]any)
			if pred == nil || pred(b) {
				return b
			}
		}
	}
	s.t.Fatalf("no %s event", typ)
	return nil
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(500 * time.Millisecond)
	}
}
