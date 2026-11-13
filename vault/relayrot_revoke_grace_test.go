package vault

import (
	"context"
	"strings"
	"testing"
)

// §3.4 (a): an old key revokes only during its grace: not through a
// mailbox whose collects RK14 step 1 ended, nor one whose stop is due.
func TestRelayRotNoRevocationThroughAnEndedOldKey(t *testing.T) {
	for _, c := range []struct {
		name string
		end  func(fx *rotFx)
	}{
		{"stopped", func(fx *rotFx) {
			fx.do(func(m *Manager) { m.st.Relay.Old[0].Collect.Stopped = fx.clk })
		}},
		{"stop due", func(fx *rotFx) {
			fx.do(func(m *Manager) { fx.setClk(m.st.Relay.Old[0].Anchor.Add(OldMailboxStop)) })
		}},
	} {
		fx, old, cur := rotated(t)
		c.end(fx)
		fx.do(func(m *Manager) {
			m.st.Issued = append(m.st.Issued, IssuedToken{JTI: "j-old", Kind: TokStanding, Iss: old})
			for _, kv := range [][2]string{{"jti", "j-old"}, {"sub", "S"}} {
				if err := m.revoke(context.Background(), kv[0], kv[1]); err != nil {
					t.Fatal(err)
				}
			}
		})
		fx.w.mu.Lock()
		got := strings.Join(fx.w.revokes, ",")
		fx.w.mu.Unlock()
		if want := cur + ":sub:S"; got != want {
			t.Fatalf("%s: revokes %s, want %s", c.name, got, want)
		}
	}
}
