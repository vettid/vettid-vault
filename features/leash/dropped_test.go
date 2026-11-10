package leash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// droppedFor is the refs of the leash.grant.dropped entries recorded for
// device, in order. An entry that is not in the audit log shows as
// "not-audit:<ref>", which no test wants.
func droppedFor(r *rig, device string) []string {
	var out []string
	for _, a := range r.h.Activities {
		if a.Kind == "leash.grant.dropped" && a.DeviceID == device {
			if !a.Audit {
				out = append(out, "not-audit:"+a.Ref)
				continue
			}
			out = append(out, a.Ref)
		}
	}
	return out
}

// pairEdits prepares initial grants for a new agent device, decodes them
// into maps for a test to edit, and returns the device.
func pairEdits(t *testing.T, r *rig, id, raw string) (vault.PeerInfo, []map[string]json.RawMessage) {
	t.Helper()
	r.h.AddDevice(id, vault.KindAgent)
	ag, _ := r.h.Device(id)
	prepared, err := r.f.PrepareAgentGrants(appSession(r, t0), ag.IK, json.RawMessage(raw))
	if err != nil {
		t.Fatalf("prepare %s: %v", raw, err)
	}
	var gs []map[string]json.RawMessage
	if err := json.Unmarshal(prepared, &gs); err != nil {
		t.Fatal(err)
	}
	return ag, gs
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// §10.11 "Initial grants at pairing" (0.88.5): each approved initial grant
// that is malformed or differs from the delegation the member signed for
// it is not installed and is recorded with its reason; the rest of the set
// is installed. The edited grant is the first of two; the second (a plain
// profile.get) is installed in every case.
func TestPairGrantDropped(t *testing.T) {
	const newAgent = "dev-agent-x"
	exp := t0.Add(time.Hour)
	for _, c := range []struct {
		name string
		edit func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage
		want string // the reason; "" for none
	}{
		{"unedited", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage { return g }, ""},
		{"no id", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			delete(g, "id")
			return g
		}, DropDamaged},
		{"a null grant", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage { return nil }, DropDamaged},
		{"no delegation", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			delete(g, "delegation")
			return g
		}, DropDamaged},
		{"no signature", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			delete(g, "delegation_sig")
			return g
		}, DropDamaged},
		{"lost its connections", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			delete(g, "connections")
			return g
		}, DropMismatch},
		{"another connection", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["connections"] = mustJSON(t, []string{r.c2})
			return g
		}, DropMismatch},
		{"lost its expiry", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			delete(g, "expires")
			return g
		}, DropMismatch},
		{"a later expiry", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["expires"] = mustJSON(t, exp.Add(time.Hour))
			return g
		}, DropMismatch},
		{"lost its hourly limit", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			delete(g, "per_hour")
			return g
		}, DropMismatch},
		{"a higher daily limit", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["per_day"] = mustJSON(t, 900)
			return g
		}, DropMismatch},
		{"another approval", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["approval"] = mustJSON(t, Ask)
			return g
		}, DropMismatch},
		{"another scope", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["scope"] = mustJSON(t, "message.get")
			return g
		}, DropMismatch},
		{"another version", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["version"] = mustJSON(t, 2)
			return g
		}, DropMismatch},
		{"another status_ttl", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["status_ttl"] = mustJSON(t, 2*time.Hour)
			return g
		}, DropMismatch},
		{"another id", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			g["id"] = mustJSON(t, "01JB2Z6V9K3M4N5P6Q7R8S9T0V")
			return g
		}, DropMismatch},
		{"a delegation not in canonical form", func(t *testing.T, r *rig, g map[string]json.RawMessage) map[string]json.RawMessage {
			var d []byte
			if err := json.Unmarshal(g["delegation"], &d); err != nil || len(d) < 2 || d[0] != '{' {
				t.Fatalf("delegation: %v", err)
			}
			g["delegation"] = mustJSON(t, append([]byte("{ "), d[1:]...))
			return g
		}, DropMismatch},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			raw := fmt.Sprintf(`[{"scope":"message.send","connections":["%s"],"approval":"auto","per_hour":5,"expires_at":"%s"},{"scope":"profile.get"}]`,
				r.c1, envelope.FormatTS(exp))
			ag, gs := pairEdits(t, r, newAgent, raw)
			if len(gs) != 2 {
				t.Fatalf("prepared %d grants", len(gs))
			}
			gs[0] = c.edit(t, r, gs[0])
			r.f.AgentPaired(appSession(r, t0.Add(time.Minute)), newAgent, ag.IK, mustJSON(t, gs))
			wantN, wantDropped := 2, []string(nil)
			if c.want != "" {
				wantN, wantDropped = 1, []string{c.want}
			}
			if n := r.f.count(newAgent); n != wantN {
				t.Fatalf("%d grants installed, want %d", n, wantN)
			}
			if got := droppedFor(r, newAgent); fmt.Sprint(got) != fmt.Sprint(wantDropped) {
				t.Fatalf("recorded %v, want %v", got, wantDropped)
			}
			if n := issuedFor(r, newAgent); n != wantN {
				t.Fatalf("%d leash.grant.issued, want %d", n, wantN)
			}
			if n, told := lastUpdate(t, r, newAgent); told != 1 || n == 0 {
				t.Fatalf("the pairing: %d updates, grant_seq %d", told, n)
			}
		})
	}
}

// Grants signed for one agent's ik and installed for another's are a
// mismatch: the delegation's sub is not the pairing agent.
func TestPairGrantDroppedOtherAgent(t *testing.T) {
	r := newRig(t)
	_, gs := pairEdits(t, r, "dev-agent-x", `[{"scope":"profile.get"},{"scope":"connection.list"}]`)
	r.h.AddDevice("dev-agent-y", vault.KindAgent)
	other, _ := r.h.Device("dev-agent-y")
	r.f.AgentPaired(appSession(r, t0), "dev-agent-y", other.IK, mustJSON(t, gs))
	if n := r.f.count("dev-agent-y"); n != 0 {
		t.Fatalf("%d grants signed for another agent installed", n)
	}
	if got := droppedFor(r, "dev-agent-y"); fmt.Sprint(got) != "[mismatch mismatch]" {
		t.Fatalf("recorded %v", got)
	}
	// No ik at all (it cannot be confirmed): nothing installed either.
	r.h.AddDevice("dev-agent-z", vault.KindAgent)
	r.f.AgentPaired(appSession(r, t0), "dev-agent-z", nil, mustJSON(t, gs))
	if n := r.f.count("dev-agent-z"); n != 0 {
		t.Fatalf("%d grants installed without the agent's ik", n)
	}
}

// Damage to the set as a whole (an unknown field, trailing data): none of
// it is installed, even the grants that would decode, and one entry is
// recorded for the set.
func TestPairGrantDroppedDamagedSet(t *testing.T) {
	for _, c := range []struct {
		name   string
		damage func(t *testing.T, gs []map[string]json.RawMessage) json.RawMessage
	}{
		{"an unknown field", func(t *testing.T, gs []map[string]json.RawMessage) json.RawMessage {
			gs[1]["per_week"] = json.RawMessage(`3`)
			return mustJSON(t, gs)
		}},
		{"trailing data", func(t *testing.T, gs []map[string]json.RawMessage) json.RawMessage {
			return append(mustJSON(t, gs), []byte(` []`)...)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t)
			ag, gs := pairEdits(t, r, "dev-agent-x", `[{"scope":"profile.get"},{"scope":"connection.list"}]`)
			r.f.AgentPaired(appSession(r, t0), "dev-agent-x", ag.IK, c.damage(t, gs))
			if n := r.f.count("dev-agent-x"); n != 0 {
				t.Fatalf("%d grants installed from a damaged set", n)
			}
			if got := droppedFor(r, "dev-agent-x"); fmt.Sprint(got) != "[damaged]" {
				t.Fatalf("recorded %v, want [damaged]", got)
			}
			if _, told := lastUpdate(t, r, "dev-agent-x"); told != 1 {
				t.Fatalf("the agent was told %d times", told)
			}
		})
	}
}

// expired, cap, and the order of the reasons: the first that applies is
// the one recorded.
func TestPairGrantDroppedExpiryCapAndOrder(t *testing.T) {
	exp := t0.Add(time.Hour)
	raw := fmt.Sprintf(`[{"scope":"profile.get","expires_at":"%s"},{"scope":"connection.list"}]`, envelope.FormatTS(exp))

	t.Run("before its expiry", func(t *testing.T) {
		r := newRig(t)
		ag, gs := pairEdits(t, r, "dev-agent-x", raw)
		r.f.AgentPaired(appSession(r, exp.Add(-time.Second)), "dev-agent-x", ag.IK, mustJSON(t, gs))
		if n, got := r.f.count("dev-agent-x"), droppedFor(r, "dev-agent-x"); n != 2 || got != nil {
			t.Fatalf("%d installed, recorded %v", n, got)
		}
	})
	t.Run("expired", func(t *testing.T) {
		r := newRig(t)
		ag, gs := pairEdits(t, r, "dev-agent-x", raw)
		r.f.AgentPaired(appSession(r, exp), "dev-agent-x", ag.IK, mustJSON(t, gs))
		if n, got := r.f.count("dev-agent-x"), droppedFor(r, "dev-agent-x"); n != 1 || fmt.Sprint(got) != "[expired]" {
			t.Fatalf("%d installed, recorded %v", n, got)
		}
	})
	t.Run("cap", func(t *testing.T) {
		r := newRig(t)
		ag, gs := pairEdits(t, r, "dev-agent-x", raw)
		for i := 0; i < MaxGrants-1; i++ {
			id := fmt.Sprintf("held-%02d", i)
			r.f.d.Grants[id] = &Grant{ID: id, AgentID: "dev-agent-x", Scope: "profile.get"}
		}
		r.f.AgentPaired(appSession(r, t0), "dev-agent-x", ag.IK, mustJSON(t, gs))
		if n, got := r.f.count("dev-agent-x"), droppedFor(r, "dev-agent-x"); n != MaxGrants || fmt.Sprint(got) != "[cap]" {
			t.Fatalf("%d held, recorded %v", n, got)
		}
	})
	// The first grant's id is taken and the grant has expired: expired.
	// The second's id is changed to a taken one: mismatch, not id_taken.
	t.Run("order", func(t *testing.T) {
		r := newRig(t)
		ag, gs := pairEdits(t, r, "dev-agent-x", raw)
		var first, second string
		_ = json.Unmarshal(gs[0]["id"], &first)
		_ = json.Unmarshal(gs[1]["id"], &second)
		r.f.d.Grants[first] = &Grant{ID: first, AgentID: agent, Scope: "profile.get"}
		r.f.d.Grants[second+"x"] = &Grant{ID: second + "x", AgentID: agent, Scope: "profile.get"}
		gs[1]["id"] = mustJSON(t, second+"x")
		r.f.AgentPaired(appSession(r, exp), "dev-agent-x", ag.IK, mustJSON(t, gs))
		if got := droppedFor(r, "dev-agent-x"); fmt.Sprint(got) != "[expired mismatch]" {
			t.Fatalf("recorded %v, want [expired mismatch]", got)
		}
	})
}

// A grant that matches is the one the member signed: what is installed
// carries the same delegation bytes, unchanged.
func TestPairGrantInstalledAsSigned(t *testing.T) {
	r := newRig(t)
	ag, gs := pairEdits(t, r, "dev-agent-x", fmt.Sprintf(`[{"scope":"message.send","connections":["%s"],"approval":"auto"}]`, r.c1))
	var want []byte
	_ = json.Unmarshal(gs[0]["delegation"], &want)
	r.f.AgentPaired(appSession(r, t0), "dev-agent-x", ag.IK, mustJSON(t, gs))
	var id string
	_ = json.Unmarshal(gs[0]["id"], &id)
	g := r.f.d.Grants[id]
	if g == nil || !bytes.Equal(g.Delegation, want) || len(want) == 0 {
		t.Fatal("the installed grant's delegation is not the signed one")
	}
	if got := droppedFor(r, "dev-agent-x"); got != nil {
		t.Fatalf("recorded %v for a grant that matches", got)
	}
}
