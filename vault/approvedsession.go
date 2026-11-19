package vault

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
)

// NewApprovedSession is NewSession for a held request an app approved,
// held with note (Approved, HeldNote): how feature tests drive a handler
// as the Manager's runHeld does. It panics outside a test binary, so no
// production code can make a session that claims an approval: only
// runHeld does that.
func NewApprovedSession(ctx context.Context, h Host, from PeerInfo, now time.Time, in *envelope.Inner, note json.RawMessage) *Session {
	if !testing.Testing() {
		panic("vault: NewApprovedSession outside a test")
	}
	return &Session{host: h, from: from, ctx: ctx, now: now, inner: in, approved: true, heldNote: append(json.RawMessage(nil), note...)}
}
