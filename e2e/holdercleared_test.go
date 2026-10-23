//go:build devenclave && e2e

package e2e

import (
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/features/audit"
	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/internal/featuretest"
	"github.com/vettid/vettid-vault/internal/relaytest"
	"github.com/vettid/vettid-vault/vault"
)

// ghostHolder is the credential feature of a vault whose stored holder
// names a device the vault does not have: Load, the real load path, puts
// the id in the state it reads, the first time only (a fault, or tampering,
// that a removal, which clears the holder with its device, never makes).
type ghostHolder struct {
	*credential.Feature
	id   string
	done *atomic.Bool
}

func (g *ghostHolder) Load(data json.RawMessage) error {
	if g.done.CompareAndSwap(false, true) {
		var st map[string]json.RawMessage
		if err := json.Unmarshal(data, &st); err != nil {
			return err
		}
		st["holder"], _ = json.Marshal(g.id)
		data, _ = json.Marshal(st)
	}
	return g.Feature.Load(data)
}

// holderClearedEntries returns the credential.holder_cleared entries of the
// audit feature.
func holderClearedEntries(f *audit.Feature) []audit.Entry {
	var out []audit.Entry
	for _, e := range f.Entries() {
		if e.Kind == vault.AuditHolderCleared {
			out = append(out, e)
		}
	}
	return out
}

// VAULT-MESSAGING 0.54.0 (§3.5.9, §10.9; this suite against 0.55.5): the
// load of a vault whose credential holder names no live app, through the
// real runtime and the real features, writes one credential.holder_cleared
// audit entry (device_id = the cleared holder, no ref, no connection, no
// direction) in the flush that clears it: it is still there after a crash
// and a second load, which writes nothing more; it is what the History
// listing (audit.list, also filtered by kind) returns, and no feed item
// records it. The vault is then a vault without a holder: audit.list and
// feed.list are answered credential_required{reason: "no_holder"} until a
// recovery (§3.5.9).
func TestHolderClearedAtLoadAudited(t *testing.T) {
	r := relaytest.Start(t, nil)
	tv := newTestVault(t, r.URL, "a", nil)
	ctx := ctxT(t, 120*time.Second)
	const ghost = "device-removed-0001"

	if h := tv.fs.Credential.Holder(); h != tv.app.DeviceID() {
		t.Fatalf("holder %q, want the enrolled app %q", h, tv.app.DeviceID())
	}
	if n := len(holderClearedEntries(tv.fs.Audit)); n != 0 {
		t.Fatalf("%d holder_cleared entries before the fault", n)
	}
	feedBefore := len(tv.fs.Feed.Items())
	// An entry already in the log, so that the new one's place in the
	// chain is seen.
	seqBefore := uint64(len(tv.fs.Audit.Entries()))

	// A crash (no flush), then a load whose stored holder names a device
	// that does not exist.
	tv.stop()
	tv.manager().Crash()
	var patched atomic.Bool
	m, f, err := tv.unlock(ctx, func(o *vault.Options) {
		for i, ft := range o.Features {
			if c, ok := ft.(*credential.Feature); ok {
				o.Features[i] = &ghostHolder{Feature: c, id: ghost, done: &patched}
			}
		}
	})
	if err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if !patched.Load() {
		t.Fatal("the credential feature was not loaded through the wrapper")
	}
	tv.mu.Lock()
	tv.msg = f
	tv.mu.Unlock()
	tv.start(m)

	check := func(when string) audit.Entry {
		t.Helper()
		es := holderClearedEntries(tv.fs.Audit)
		if len(es) != 1 {
			t.Fatalf("%s: %d credential.holder_cleared entries, want 1: %+v", when, len(es), es)
		}
		e := es[0]
		if e.DeviceID != ghost || e.Ref != "" || e.ConnectionID != "" || e.Direction != "" || e.Seq != seqBefore+1 {
			t.Fatalf("%s: entry %+v, want device_id %q, no ref, connection or direction, seq %d", when, e, ghost, seqBefore+1)
		}
		if h := tv.fs.Credential.Holder(); h != "" {
			t.Fatalf("%s: holder %q kept", when, h)
		}
		return e
	}
	first := check("after the load")
	entriesAfter := len(tv.fs.Audit.Entries())

	// The History listing returns it: the audit feature's own answer, as
	// the runtime hands it to a vault with a holder.
	host := featuretest.NewHost()
	list := func(body string) string {
		t.Helper()
		res := featuretest.Call(tv.fs.Audit, host, time.Now(), "app", "audit.list", body)
		if res.Code != "" {
			t.Fatalf("audit.list %s: %q", body, res.Code)
		}
		return string(res.Body)
	}
	for _, body := range []string{`{}`, `{"kinds":["credential.holder_cleared"]}`} {
		var out struct {
			Entries []struct {
				Seq    uint64  `json:"seq"`
				Kind   string  `json:"kind"`
				Device string  `json:"device_id"`
				Ref    *string `json:"ref"`
				Conn   *string `json:"connection_id"`
			} `json:"entries"`
		}
		if err := json.Unmarshal([]byte(list(body)), &out); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range out.Entries {
			if e.Kind == vault.AuditHolderCleared {
				n++
				if e.Seq != first.Seq || e.Device != ghost || e.Ref != nil || e.Conn != nil {
					t.Fatalf("audit.list %s: %+v", body, e)
				}
			}
		}
		if n != 1 || strings.Contains(body, "kinds") && len(out.Entries) != 1 {
			t.Fatalf("audit.list %s: %d holder_cleared of %d entries", body, n, len(out.Entries))
		}
	}

	// History only: no feed item (the feed is unchanged), and the apps
	// are answered no_holder until a recovery.
	if items := tv.fs.Feed.Items(); len(items) != feedBefore {
		t.Fatalf("feed: %d items, %d before: %+v", len(items), feedBefore, items)
	}
	for _, typ := range []string{"audit.list", "feed.list"} {
		rr := tv.request(tv.app, typ, `{}`)
		if rr.ErrorCode() != "credential_required" || !strings.Contains(string(rr.Body()), `"no_holder"`) {
			t.Fatalf("%s on a vault without a holder: %q %s", typ, rr.ErrorCode(), rr.Body())
		}
	}

	// In the flush that cleared it: a crash and a new load find the entry
	// and the cleared holder, and add nothing.
	tv.restart()
	again := check("after a crash and a second load")
	if again.Seq != first.Seq || string(again.Hash) != string(first.Hash) {
		t.Fatalf("entry changed across the reload: %+v, then %+v", first, again)
	}
	// Nothing but the load's own vault.unlocked is new (the run loop writes
	// it, so it may not be there yet).
	for _, e := range tv.fs.Audit.Entries()[entriesAfter:] {
		if e.Kind != "vault.unlocked" {
			t.Fatalf("entry added by the second load: %s %+v", e.Kind, e)
		}
	}
}
