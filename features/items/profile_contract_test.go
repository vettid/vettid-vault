package items_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/vault"
)

// savedProfile is the profile part of the items feature's saved state.
type savedProfile struct {
	Contract map[string]string `json:"contract"`
	Claimed  map[string]string `json:"claimed"`
}

func profileState(t *testing.T, raw []byte) savedProfile {
	t.Helper()
	var st struct {
		Profile savedProfile `json:"profile"`
	}
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	return st.Profile
}

// contractHost has a person connection cA and a service connection cB.
func contractHost() *featuretest.Host {
	h := featuretest.NewHost()
	h.AddConnection("cA")
	h.AddConnection("cB")
	c := h.Conns["cB"]
	c.PeerKind = "service"
	h.Conns["cB"] = c
	return h
}

var contractNow = time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)

func contractSession(h *featuretest.Host) *vault.Session {
	return vault.NewSession(context.Background(), h, vault.PeerInfo{}, contractNow, nil)
}

func newContractSet(optional ...string) *all.Set {
	return all.NewSet(all.Options{CredentialKDF: credential.MinKDF, Optional: optional})
}

// §10.8 (0.90.10): the first update to a service carries the image's
// contract and records it as sent; a person connection is never sent one;
// an unlock under the same image sends nothing.
func TestContractFirstSendAndNoResend(t *testing.T) {
	h := contractHost()
	set := newContractSet("vote")
	s := contractSession(h)
	set.Items.ConnectionAdded(s, "cB")
	set.Items.ConnectionAdded(s, "cA")
	svc, per := toConn(h, "cB"), toConn(h, "cA")
	if len(svc) != 1 || !strings.HasSuffix(string(svc[0].Body), `,"contract":"`+vault.ServiceContract+`"}`) {
		t.Fatalf("service: %v", svc)
	}
	if len(per) == 0 {
		t.Fatal("person: no update")
	}
	for _, x := range per {
		if strings.Contains(string(x.Body), "contract") {
			t.Fatalf("person: %s", x.Body)
		}
	}
	raw, _ := set.Items.Save()
	if got := profileState(t, raw).Contract; len(got) != 1 || got["cB"] != vault.ServiceContract {
		t.Fatalf("sent state: %v", got)
	}
	h.Reset()
	set.Items.Unlocked(s)
	if len(h.Sent) != 0 {
		t.Errorf("unlock under the same image: %v", h.Sent)
	}
}

// Trigger 5: at the first unlock under an image whose contract differs, each
// active service connection gets one update with the next version; once, and
// not again after a reload; a person connection gets nothing.
func TestContractChangedByAnImage(t *testing.T) {
	h := contractHost()
	old := newContractSet("vote")
	s := contractSession(h)
	old.Items.ConnectionAdded(s, "cB")
	raw, _ := old.Items.Save()

	next := newContractSet("vote")
	next.Items.SetContract("1.1")
	if err := next.Items.Load(raw); err != nil {
		t.Fatal(err)
	}
	h.Reset()
	next.Items.Unlocked(s)
	ups := toConn(h, "cB")
	if len(ups) != 1 || !strings.Contains(string(ups[0].Body), `"version":2`) || !strings.HasSuffix(string(ups[0].Body), `,"contract":"1.1"}`) {
		t.Fatalf("after the image: %v", h.Sent)
	}
	if len(toConn(h, "cA")) != 0 {
		t.Error("person sent an update")
	}
	h.Reset()
	next.Items.Unlocked(s)
	raw2, _ := next.Items.Save()
	again := newContractSet("vote")
	again.Items.SetContract("1.1")
	if err := again.Items.Load(raw2); err != nil {
		t.Fatal(err)
	}
	again.Items.Unlocked(s)
	if len(h.Sent) != 0 {
		t.Errorf("second unlock or after reload: %v", h.Sent)
	}
}

// A vault whose state predates `contract` (none recorded as sent): a value
// never sent differs, so the first unlock sends each active service one
// update.
func TestContractNeverSentCountsAsDiffering(t *testing.T) {
	h := contractHost()
	set := newContractSet("vote")
	s := contractSession(h)
	set.Items.ConnectionAdded(s, "cB")
	raw, _ := set.Items.Save()
	var st map[string]json.RawMessage
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	var prof map[string]json.RawMessage
	if err := json.Unmarshal(st["profile"], &prof); err != nil {
		t.Fatal(err)
	}
	delete(prof, "contract")
	st["profile"], _ = json.Marshal(prof)
	old, _ := json.Marshal(st)

	next := newContractSet("vote")
	if err := next.Items.Load(old); err != nil {
		t.Fatal(err)
	}
	h.Reset()
	next.Items.Unlocked(s)
	if ups := toConn(h, "cB"); len(ups) != 1 || !strings.Contains(string(ups[0].Body), `"version":2`) {
		t.Fatalf("first unlock: %v", h.Sent)
	}
}

// The value is recorded only when the update is queued: a service that cannot
// be sent to at the unlock gets it at a later one, once.
func TestContractRecordedOnlyWhenQueued(t *testing.T) {
	h := contractHost()
	old := newContractSet("vote")
	s := contractSession(h)
	old.Items.ConnectionAdded(s, "cB")
	raw, _ := old.Items.Save()
	next := newContractSet("vote")
	next.Items.SetContract("1.1")
	if err := next.Items.Load(raw); err != nil {
		t.Fatal(err)
	}
	h.Reset()
	h.DownConns["cB"] = true
	next.Items.Unlocked(s)
	saved, _ := next.Items.Save()
	if got := profileState(t, saved).Contract["cB"]; got != vault.ServiceContract {
		t.Fatalf("recorded without a send: %q", got)
	}
	delete(h.DownConns, "cB")
	h.Reset()
	next.Items.Unlocked(s)
	if ups := toConn(h, "cB"); len(ups) != 1 || !strings.HasSuffix(string(ups[0].Body), `,"contract":"1.1"}`) {
		t.Fatalf("next unlock: %v", h.Sent)
	}
	h.Reset()
	next.Items.Unlocked(s)
	if len(h.Sent) != 0 {
		t.Errorf("again: %v", h.Sent)
	}
}

// A service connection whose rotation is pending is skipped at the unlock and
// gets the value with its update after the rotation, recorded then.
func TestContractAfterARotation(t *testing.T) {
	h := contractHost()
	old := newContractSet("vote")
	s := contractSession(h)
	old.Items.ConnectionAdded(s, "cB")
	raw, _ := old.Items.Save()
	next := newContractSet("vote")
	next.Items.SetContract("1.1")
	if err := next.Items.Load(raw); err != nil {
		t.Fatal(err)
	}
	c := h.Conns["cB"]
	c.RotationPending = true
	h.Conns["cB"] = c
	h.Reset()
	next.Items.Unlocked(s)
	if len(toConn(h, "cB")) != 0 {
		t.Fatalf("sent while the rotation is pending: %v", h.Sent)
	}
	c.RotationPending = false
	h.Conns["cB"] = c
	next.Items.ConnectionRotated(s, "cB")
	if ups := toConn(h, "cB"); len(ups) != 1 || !strings.HasSuffix(string(ups[0].Body), `,"contract":"1.1"}`) {
		t.Fatalf("after the rotation: %v", h.Sent)
	}
	h.Reset()
	next.Items.Unlocked(s)
	if len(h.Sent) != 0 {
		t.Errorf("unlock after the rotation: %v", h.Sent)
	}
}

// A features change (trigger 4) and a contract change (trigger 5) at the same
// unlock go in one update.
func TestContractAndFeaturesInOneUpdate(t *testing.T) {
	h := contractHost()
	old := newContractSet("presence")
	s := contractSession(h)
	old.Items.ConnectionAdded(s, "cB")
	raw, _ := old.Items.Save()

	next := newContractSet("presence", "vote")
	next.Items.SetContract("1.1")
	if err := next.Items.Load(raw); err != nil {
		t.Fatal(err)
	}
	h.Reset()
	next.Items.Unlocked(s)
	ups := toConn(h, "cB")
	if len(ups) != 1 {
		t.Fatalf("updates: %v", h.Sent)
	}
	b := string(ups[0].Body)
	if !strings.Contains(b, `"version":2`) || !strings.Contains(b, `"features":["hs_confirm","vote"]`) || !strings.HasSuffix(b, `,"contract":"1.1"}`) {
		t.Fatalf("update: %s", b)
	}
}

// Receiving (§10.8): a service's contract of the right form is kept as its
// last claimed; any other type or form counts as absent with the update
// still applied; an applied update without it clears it; an update that is
// ignored or dropped changes nothing; a person's is never kept.
func TestContractReceived(t *testing.T) {
	e := newEnv(t)
	c := e.h.Conns["cB"]
	c.PeerKind = "service"
	e.h.Conns["cB"] = c
	claimed := func() map[string]string {
		raw, err := e.set.Items.Save()
		if err != nil {
			t.Fatal(err)
		}
		return profileState(t, raw).Claimed
	}
	core := func(ik []byte) string {
		return `"first_name":"Svc","last_name":"Co","ik":"` + base64.StdEncoding.EncodeToString(ik) + `","items":[]`
	}
	version := 0
	sendIK := func(id string, ik []byte, contract string) {
		t.Helper()
		version++
		body := `{"version":` + strconv.Itoa(version) + `,` + core(ik)
		if contract != "" {
			body += `,"contract":` + contract
		}
		e.ok(e.call("connection:"+id, "profile.update", body+`}`))
	}
	send := func(id, contract string) { t.Helper(); sendIK(id, e.h.Conns[id].IK, contract) }
	send("cB", `"1.0"`)
	if got := claimed()["cB"]; got != "1.0" {
		t.Fatalf("claimed: %q", got)
	}
	send("cB", `"1.10"`)
	if got := claimed()["cB"]; got != "1.10" {
		t.Fatalf("claimed: %q", got)
	}
	for _, bad := range []string{`1.0`, `"1"`, `"01.0"`, `"1.00"`, `"1.0.0"`, `"12345.0"`, `""`, `null`, `["1.0"]`, `"1.0 "`, `"-1.0"`} {
		send("cB", `"1.0"`)
		send("cB", bad)
		if got, ok := claimed()["cB"]; ok {
			t.Errorf("%s kept as %q", bad, got)
		}
		// It was applied: its version is kept, so the same version again is ignored.
		version--
		send("cB", `"1.0"`)
		if got, ok := claimed()["cB"]; ok {
			t.Errorf("after %s, a repeated version was applied: %q", bad, got)
		}
	}
	send("cB", `"2.3"`)
	version-- // the same version again: ignored, nothing changes
	send("cB", ``)
	if got := claimed()["cB"]; got != "2.3" {
		t.Errorf("an ignored update changed it: %q", got)
	}
	// Applied without contract: cleared.
	send("cB", ``)
	if _, ok := claimed()["cB"]; ok {
		t.Error("not cleared by an update without contract")
	}
	// A dropped update (no core) changes nothing.
	send("cB", `"1.0"`)
	version++
	e.ok(e.call("connection:cB", "profile.update", `{"version":`+strconv.Itoa(version)+`,"items":[]}`))
	if got := claimed()["cB"]; got != "1.0" {
		t.Errorf("a dropped update changed it: %q", got)
	}
	// An update under another ik (dropped) or an earlier ik of the peer's
	// chain (ignored) changes nothing.
	other := make([]byte, 32)
	other[0] = 7
	sendIK("cB", other, `"9.9"`)
	prior := make([]byte, 32)
	prior[0] = 8
	e.h.PriorIKs = map[string][][]byte{"cB": {prior}}
	sendIK("cB", prior, ``)
	if got := claimed()["cB"]; got != "1.0" {
		t.Errorf("another or an earlier ik changed it: %q", got)
	}
	// A person's contract is ignored.
	send("cA", `"1.0"`)
	if _, ok := claimed()["cA"]; ok {
		t.Error("a person's contract kept")
	}
	// The value sent to cB is recorded (a name change sends services one).
	sent := func() map[string]string {
		raw, err := e.set.Items.Save()
		if err != nil {
			t.Fatal(err)
		}
		return profileState(t, raw).Contract
	}
	profileVersion := 0
	setName := func(name string) {
		t.Helper()
		e.ok(e.call("app", "profile.set", `{"version":`+strconv.Itoa(profileVersion)+`,"name":"`+name+`"}`))
		profileVersion++
	}
	setName("Al")
	if got := sent()["cB"]; got != vault.ServiceContract {
		t.Fatalf("sent: %q", got)
	}
	// A connection gone without its removal observed is pruned at the next
	// applied update from another: both what it claimed and what it was sent.
	send("cB", `"1.0"`)
	cB := e.h.Conns["cB"]
	delete(e.h.Conns, "cB")
	send("cA", ``)
	if _, ok := claimed()["cB"]; ok {
		t.Error("claimed not pruned with Peers")
	}
	if _, ok := sent()["cB"]; ok {
		t.Error("sent not pruned with Peers")
	}
	e.h.Conns["cB"] = cB
	send("cB", `"1.0"`)
	setName("Bo")
	if len(claimed()) != 1 || len(sent()) != 1 {
		t.Fatalf("before removal: claimed %v, sent %v", claimed(), sent())
	}
	// Removing the connection forgets both.
	e.set.Items.ConnectionRemoved(vault.NewSession(context.Background(), e.h, vault.PeerInfo{}, e.clk.T, nil), "cB")
	if len(claimed()) != 0 || len(sent()) != 0 {
		t.Errorf("after removal: claimed %v, sent %v", claimed(), sent())
	}
}
