package vault

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Open asks that arrive only as events (VAULT-MESSAGING 0.70.0 §10.4.2,
// owner decision 2026-10-28, §15 item 44). Apps keep vault content in
// memory only, so what they held is gone after a lock, a hold or a
// restart; pending.list returns the five kinds of ask that had no list
// call. Nothing is stored for it: every ask already lives in the
// DEK-encrypted state (the feature's data, AccessRequests, Held) and is
// listed from there, so it survives a lock, a hold and a restart as long as
// the ask itself does, and the list reads it without extending or ending
// it, writing an audit entry or sending anything to the asker.

// The kinds of pending.list entries (§10.4.2).
const (
	PendingAuthenticate = "authenticate"
	PendingSession      = "session"
	PendingApproval     = "approval"
	PendingAction       = "action"
	PendingLocation     = "location"
)

// Paging of pending.list (§10.4.2).
const (
	PendingDefaultLimit = 50
	PendingMaxLimit     = 100
	// PendingPageBytes bounds the response body.
	PendingPageBytes = 131072
)

// pendingPageBytes is PendingPageBytes; tests lower it.
var pendingPageBytes = PendingPageBytes

// PendingAsk is one open ask: Body is the body of the event it repeats.
type PendingAsk struct {
	Kind string
	ID   string
	Exp  time.Time
	Body []byte
}

// PendingAskSource is implemented by features that hold open asks the
// owner's devices learn of by event (connauth, actions, location). It
// returns the asks still open at now, in no order, and changes nothing.
type PendingAskSource interface {
	OpenAsks(now time.Time) []PendingAsk
}

func (m *Manager) registerPending() {
	m.register(TypeSpec{Type: "pending.list", Request: true, Volatile: true, From: owners}, HandlerFunc(m.hPendingList))
}

// desktopPendingKinds are the kinds a desktop receives and may answer.
var desktopPendingKinds = map[string]bool{PendingAuthenticate: true, PendingAction: true, PendingLocation: true}

// pendingAsks gathers the open asks of kinds the caller may see.
func (m *Manager) pendingAsks(kind string, now time.Time) []PendingAsk {
	var all []PendingAsk
	for _, f := range m.features {
		if src, ok := f.(PendingAskSource); ok {
			all = append(all, src.OpenAsks(now)...)
		}
	}
	if kind == KindApp {
		for _, r := range m.st.AccessRequests {
			p := m.st.Devices[r.DeviceID]
			if p == nil || p.State != PeerActive || !now.Before(r.Expires) {
				continue
			}
			all = append(all, PendingAsk{Kind: PendingSession, ID: r.ID, Exp: r.Expires, Body: sessionPendingBody(r, p)})
		}
		for _, h := range m.st.Held {
			p := m.st.Devices[h.DeviceID]
			if p == nil || p.State != PeerActive || !now.Before(h.Expires) {
				continue
			}
			in, err := envelope.ParseInner(h.Inner, envelope.ModeSealed)
			if err != nil {
				continue
			}
			all = append(all, PendingAsk{Kind: PendingApproval, ID: h.ID, Exp: h.Expires, Body: approvalPendingBody(h, p, in)})
		}
	}
	out := all[:0]
	for _, a := range all {
		if kind == KindApp || desktopPendingKinds[a.Kind] {
			out = append(out, a)
		}
	}
	// Soonest first; the id breaks ties, then the kind (ids are ULIDs).
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if !a.Exp.Equal(b.Exp) {
			return a.Exp.Before(b.Exp)
		}
		if a.ID != b.ID {
			return a.ID < b.ID
		}
		return a.Kind < b.Kind
	})
	return out
}

// pendingCursor is the opaque cursor naming a's position in the order
// (exp, id, kind): the next page resumes at the first entry after it, so
// the entry it names may be decided or expire in between.
func pendingCursor(a PendingAsk) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(a.Exp.UnixNano(), 10) + "\x00" + a.ID + "\x00" + a.Kind))
}

// pendingAfter reports whether a sorts after the position the cursor names.
// ok is false for a cursor that names no position (malformed).
func pendingAfter(cursor string, a PendingAsk) (after, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return false, false
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 3 {
		return false, false
	}
	ns, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return false, false
	}
	exp := time.Unix(0, ns)
	switch {
	case !a.Exp.Equal(exp):
		return a.Exp.After(exp), true
	case a.ID != parts[1]:
		return a.ID > parts[1], true
	default:
		return a.Kind > parts[2], true
	}
}

// hPendingList: `pending.list{after?, limit?}` answers
// `{asks: [{kind, body}], next?}` (§10.4.2). The owner check and the hold
// refuse it like the other lists (it is not on the hold's allow list).
func (m *Manager) hPendingList(_ context.Context, s *Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := obj(in)
	if err != nil {
		return nil, err
	}
	limit, present, err := o.OptUint("limit", 1, PendingMaxLimit)
	if err != nil {
		return nil, errBadRequest
	}
	if !present {
		limit = PendingDefaultLimit
	}
	after, hasAfter, err := o.OptString("after")
	if err != nil {
		return nil, errBadRequest
	}
	asks := m.pendingAsks(s.peer.Kind, s.now)
	start := 0
	if hasAfter {
		// A cursor that names no position starts again from the beginning;
		// one whose entry is gone resumes at the first entry after it.
		if _, ok := pendingAfter(after, PendingAsk{}); ok {
			start = sort.Search(len(asks), func(i int) bool { a, _ := pendingAfter(after, asks[i]); return a })
		}
	}
	const next = `,"next":""`
	size := len(`{"asks":[]}`)
	var arr []byte
	n := 0
	i := start
	for ; i < len(asks) && n < int(limit); i++ {
		item := strictjson.NewBuilder().String("kind", asks[i].Kind).Raw("body", asks[i].Body).Bytes()
		add := len(item)
		if n > 0 {
			add++ // the comma
		}
		if n > 0 && size+add+len(next)+len(pendingCursor(asks[i])) > pendingPageBytes {
			break // at least one entry, and never split or dropped
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, item...)
		size += add
		n++
	}
	b := strictjson.NewBuilder().Raw("asks", append(append([]byte{'['}, arr...), ']'))
	if i < len(asks) && n > 0 {
		b.String("next", pendingCursor(asks[i-1]))
	}
	return b.Bytes(), nil
}
