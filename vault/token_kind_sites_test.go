package vault

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/handshake"
)

// Every place the vault takes a token another principal issued it judges
// the token's lifetime by its kind (§7.1): a standing token over 30 days
// and a reconnect token over 365 days are refused, an honest 365-day
// reconnect token is taken. Each case has the issuing side mint its
// tokens of one kind with the given lifetime.

const tokDay = 24 * time.Hour

// stretchKind makes a relay stub mint the tokens of kind (told apart by
// their quota) with lifetime life: TokStanding is a connection's standing
// token and a request token (first contact's hs.init and hs.resp carry
// one; any token but a reconnect token is held under the 30-day cap),
// TokReconnect a reconnect token.
func stretchKind(d *devFixture, kind string, life time.Duration) {
	d.relay.mu.Lock()
	defer d.relay.mu.Unlock()
	d.relay.stretch = func(ttl time.Duration, q *relayauth.Quota) time.Duration {
		if q == nil || q.Msgs == nil {
			return ttl
		}
		if kind == TokStanding && (*q.Msgs == PeerQuotaMsgs || *q.Msgs == RequestTokenQuotaMsgs) || kind == TokReconnect && *q.Msgs == handshake.ReconnectTokenQuotaMsgs {
			return life
		}
		return ttl
	}
}

func auditedIn(m *Manager, ev string) bool {
	for _, a := range m.st.Audit {
		if a.Event == ev {
			return true
		}
	}
	return false
}

type lifeCase struct {
	name   string
	kind   string
	life   time.Duration
	refuse bool
}

var standingOver = lifeCase{"31-day standing token", TokStanding, 31 * tokDay, true}

var reconnectCases = []lifeCase{
	{"366-day reconnect token", TokReconnect, 366 * tokDay, true},
	{"365-day reconnect token", TokReconnect, 365 * tokDay, false},
}

// First contact: the inviter takes the acceptor's standing token from its
// hs.init (hs_init_bad_token); the acceptor takes the inviter's from its
// hs.resp (hs_resp_bad_token); each takes the other's standing and
// reconnect tokens from its connection.approved (bad_connection_approved).
func TestTokenKindFirstContact(t *testing.T) {
	t.Run("hs.init "+standingOver.name, func(t *testing.T) {
		a, b := newVaultPair(t)
		_, link := a.linkFor(t, time.Hour)
		stretchKind(b, TokStanding, standingOver.life)
		b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
		pump(t, b, a)
		if !auditedIn(a.m, "hs_init_bad_token") || len(a.m.st.Connections) != 0 {
			t.Fatal("a first-contact hs.init's 31-day standing token was taken")
		}
	})
	t.Run("hs.resp "+standingOver.name, func(t *testing.T) {
		a, b := newVaultPair(t)
		_, link := a.linkFor(t, time.Hour)
		b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
		stretchKind(a, TokStanding, standingOver.life)
		pump(t, b, a)
		pump(t, a, b)
		if !auditedIn(b.m, "hs_resp_bad_token") {
			t.Fatal("an hs.resp's 31-day standing token was taken")
		}
	})
	for _, c := range append([]lifeCase{standingOver}, reconnectCases...) {
		t.Run("connection.approved "+c.name, func(t *testing.T) {
			a, b := newVaultPair(t)
			_, link := a.linkFor(t, time.Hour)
			r, _ := b.request(t, "connection.invite.accept", `{"link":"`+link+`"}`)
			cid := bodyStr(t, r, "connection_id")
			pump(t, b, a)
			pump(t, a, b)
			b.appInbox()
			pump(t, b, a)
			aPend := event(a.appInbox(), "connection.request.pending")
			stretchKind(a, c.kind, c.life)
			a.request(t, "connection.approve", `{"pending_id":"`+bodyStr(t, aPend, "pending_id")+`"}`)
			pump(t, a, b)
			if auditedIn(b.m, "bad_connection_approved") != c.refuse {
				t.Fatalf("connection.approved with a %s: refused %v, want %v", c.name, !c.refuse, c.refuse)
			}
			if c.refuse {
				return
			}
			b.request(t, "connection.approve", `{"connection_id":"`+cid+`"}`)
			pump(t, b, a)
			for _, p := range b.m.st.Connections {
				if p.State != PeerActive || p.Reconnect.Token == "" || p.Reconnect.Exp.Sub(time.Now()) < 364*tokDay {
					t.Fatalf("the honest 365-day reconnect token was not held: %+v", p.Reconnect)
				}
			}
		})
	}
}

// A reconnect: the responder takes the initiator's standing and reconnect
// tokens from its hs.init (reconnect_bad_token); the initiator keeps the
// responder's from its hs.resp as carried tokens, or none.
func TestTokenKindReconnect(t *testing.T) {
	for _, c := range append([]lifeCase{standingOver}, reconnectCases...) {
		t.Run("hs.init "+c.name, func(t *testing.T) {
			f := newR29Fx(t)
			stretchKind(f.d[1], c.kind, c.life)
			f.do(1, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			if f.deliver(1, 0, kHSInit) != 1 {
				t.Fatal("setup: no hs.init")
			}
			if f.audited(0, "reconnect_bad_token") != c.refuse {
				f.dump()
				t.Fatalf("a reconnect hs.init with a %s: refused %v, want %v", c.name, !c.refuse, c.refuse)
			}
		})
		t.Run("hs.resp "+c.name, func(t *testing.T) {
			f := newR29Fx(t)
			f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			stretchKind(f.d[1], c.kind, c.life)
			f.deliver(0, 1, kHSInit)
			if f.deliver(1, 0, kHSResp) != 1 {
				t.Fatal("setup: no hs.resp")
			}
			pd := f.p(0).Pending
			if pd == nil || pd.Carried == nil {
				f.dump()
				t.Fatal("setup: no pending epoch with carried tokens")
			}
			got := pd.Carried.Standing.Token
			if c.kind == TokReconnect {
				got = pd.Carried.Reconnect.Token
			}
			if (got == "") != c.refuse {
				t.Fatalf("an hs.resp with a %s: kept %v, want %v", c.name, got != "", !c.refuse)
			}
		})
	}
}

// relay.address.update (§3.4): the new address's standing and reconnect
// tokens.
func TestTokenKindAddressUpdate(t *testing.T) {
	for _, c := range append([]lifeCase{standingOver}, reconnectCases...) {
		t.Run(c.name, func(t *testing.T) {
			d := newDevFixture(t)
			td := d.asConnection(t, "c1", 0x74)
			p := d.m.st.Connections["c1"]
			own := d.m.keys.relay.Public().(ed25519.PublicKey)
			priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x95}, 32))
			pk := priv.Public().(ed25519.PublicKey)
			url, mb := "https://relay.example.org", relayauth.MailboxID(pk)
			now := time.Now()
			mint := func(jti string, life time.Duration) string {
				iat := now.Add(-time.Minute)
				tok, err := relayauth.MintToken(priv, relayauth.Claims{Iss: mb, Sub: relayauth.EncodeKey(own), Aud: url,
					Iat: iat, Exp: iat.Add(life), Jti: jti})
				if err != nil {
					t.Fatal(err)
				}
				return tok
			}
			st, rt := mint("upd-standing", 20*tokDay), mint("upd-reconnect", 300*tokDay)
			if c.kind == TokStanding {
				st = mint("upd-standing", c.life)
			} else {
				rt = mint("upd-reconnect", c.life)
			}
			body, err := json.Marshal(map[string]any{
				"relay":           map[string]string{"url": url, "mailbox": mb, "pk": base64.StdEncoding.EncodeToString(pk)},
				"token":           st,
				"reconnect_token": rt,
			})
			if err != nil {
				t.Fatal(err)
			}
			sendC(d, td, "relay.address.update", string(body))
			taken := p.Relay.Mailbox == mb && p.Standing.Token == st && p.Reconnect.Token == rt
			if taken == c.refuse {
				t.Fatalf("an address update with a %s: taken %v, want %v", c.name, taken, !c.refuse)
			}
		})
	}
}

// An unlock (§11.4): the app's fresh standing token for its mailbox.
func TestTokenKindUnlock(t *testing.T) {
	for _, c := range []lifeCase{standingOver, {"30-day standing token", TokStanding, 30 * tokDay, false}} {
		t.Run(c.name, func(t *testing.T) {
			d := newDevFixture(t)
			p := d.devPeer
			now := time.Now()
			iat := now.Add(-time.Minute)
			tok, err := relayauth.MintToken(d.devKey, relayauth.Claims{Iss: p.Relay.Mailbox,
				Sub: relayauth.EncodeKey(d.m.keys.relay.Public().(ed25519.PublicKey)), Aud: p.Relay.URL,
				Iat: iat, Exp: iat.Add(c.life), Jti: "unlock-standing"})
			if err != nil {
				t.Fatal(err)
			}
			d.withLock(func(m *Manager) {
				m.unlockTokens(&UnlockKey{IK: d.dev.Public().(ed25519.PublicKey)}, tok, now)
			})
			if (p.Standing.Token == tok) == c.refuse {
				t.Fatalf("an unlock with a %s: taken %v, want %v", c.name, p.Standing.Token == tok, !c.refuse)
			}
		})
	}
}
