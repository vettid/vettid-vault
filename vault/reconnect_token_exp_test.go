package vault

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/vms/peerwire"
)

// relay.token.issued: a reconnect token replaces the held one only if its
// exp is later (as §6.3.1 adopts a carried token), and no token is held
// whose lifetime exp - iat is over §7.1's cap for its kind (reconnect 365
// days, standing 30 days) or whose iat is in the future. Side 0 holds
// tokens from side 1; side 1 (or an old copy of it, side 2) sends them.

// tokenFrom mints a deposit token from side s's mailbox (s may be the copy,
// which holds side 1's relay key) for side 0, with the given iat and exp.
func (f *r29Fx) tokenFrom(s int, iat, exp time.Time, jti string) string {
	f.t.Helper()
	held := f.p(0).Relay // side 1's address on side 0's record
	tok, err := relayauth.MintToken(f.m(s).keys.relay, relayauth.Claims{Iss: held.Mailbox,
		Sub: relayauth.EncodeKey(f.m(0).keys.relay.Public().(ed25519.PublicKey)), Aud: held.URL,
		Iat: iat, Exp: exp, Jti: jti})
	if err != nil {
		f.t.Fatal(err)
	}
	return tok
}

// sendIssued has side s send side 0 relay.token.issued{kind, tok}.
func (f *r29Fx) sendIssued(s int, kind, tok string) {
	f.t.Helper()
	f.do(s, func(m *Manager, p *Peer) {
		m.sendTo(p, tokenIssuedType, json.RawMessage(peerwire.TokenIssuedBody(kind, tok)), f.clk)
	})
	if f.deliver(s, 0, kAny) == 0 {
		f.t.Fatal("setup: nothing delivered")
	}
}

// reissue has side 1 issue side 0 an honest token of kind, now.
func (f *r29Fx) reissue(kind string) {
	f.t.Helper()
	f.do(1, func(m *Manager, p *Peer) { m.issueTo(p, kind, f.clk) })
	if f.deliver(1, 0, kAny) == 0 {
		f.t.Fatal("setup: nothing delivered")
	}
}

func (f *r29Fx) auditedCount(s int, ev string) int {
	n := 0
	for _, a := range f.m(s).st.Audit {
		if a.Event == ev {
			n++
		}
	}
	return n
}

func TestReconnectTokenAdoptedOnlyIfLater(t *testing.T) {
	t.Run("later is adopted", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		f.advance(24 * time.Hour)
		f.reissue(TokReconnect)
		if f.p(0).Reconnect == held || !f.p(0).Reconnect.Exp.After(held.Exp) {
			t.Fatal("a reconnect token with a later exp was not adopted")
		}
		if f.audited(0, "issued_token_not_newer") || f.audited(0, "bad_issued_token") {
			t.Fatal("a later token audited as refused")
		}
	})
	t.Run("earlier is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		f.sendIssued(1, TokReconnect, f.tokenFrom(1, f.clk.Add(-time.Minute), held.Exp.Add(-24*time.Hour), "rc-earlier"))
		if f.p(0).Reconnect != held {
			t.Fatal("a reconnect token with an earlier exp replaced the held one")
		}
		if f.auditedCount(0, "issued_token_not_newer") != 1 {
			t.Fatal("the refusal was not audited")
		}
	})
	t.Run("same exp is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		f.sendIssued(1, TokReconnect, f.tokenFrom(1, f.clk.Add(-time.Minute), held.Exp, "rc-same"))
		if f.p(0).Reconnect != held {
			t.Fatal("a reconnect token with the same exp replaced the held one")
		}
		if f.auditedCount(0, "issued_token_not_newer") != 1 {
			t.Fatal("the refusal was not audited")
		}
	})
	t.Run("exp in the past is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		if !f.clk.Before(held.Exp) {
			t.Fatal("setup: the held token is not valid")
		}
		f.sendIssued(1, TokReconnect, f.tokenFrom(1, f.clk.Add(-2*time.Hour), f.clk.Add(-time.Hour), "rc-past"))
		if f.p(0).Reconnect != held || noReconnectToken(f.p(0), f.clk) {
			t.Fatal("an expired reconnect token replaced the valid held one")
		}
	})
	t.Run("old copy cannot shorten it", func(t *testing.T) {
		f := newR29Fx(t)
		f.startCopy(1, f.snapshot(1))
		held := f.p(0).Reconnect
		// the copy holds side 1's relay key and the current epoch's keys
		f.sendIssued(2, TokReconnect, f.tokenFrom(2, f.clk.Add(-time.Minute), f.clk.Add(time.Hour), "rc-copy"))
		if f.p(0).Reconnect != held {
			t.Fatal("an old copy's shorter-lived reconnect token replaced the held one")
		}
		if f.auditedCount(0, "issued_token_not_newer") != 1 {
			t.Fatal("the refusal was not audited")
		}
	})
	t.Run("none held: adopted", func(t *testing.T) {
		f := newR29Fx(t)
		f.do(0, func(_ *Manager, p *Peer) { p.Reconnect = HeldToken{} })
		f.reissue(TokReconnect)
		if f.p(0).Reconnect.Token == "" || noReconnectToken(f.p(0), f.clk) {
			t.Fatal("a reconnect token was not adopted with none held")
		}
	})
}

// A token whose exp - iat is over §7.1's cap for its kind, or whose iat is
// in the future, is refused (bad_issued_token), as the relay would refuse
// a deposit under it. Adopted, a far exp would win every later comparison
// and pin the held token for good.
func TestHeldTokenLifetimeAndIat(t *testing.T) {
	t.Run("far-future reconnect token, then an honest reissue", func(t *testing.T) {
		f := newR29Fx(t)
		f.startCopy(1, f.snapshot(1))
		held := f.p(0).Reconnect
		far := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
		f.sendIssued(2, TokReconnect, f.tokenFrom(2, f.clk.Add(-time.Minute), far, "rc-far"))
		if f.p(0).Reconnect != held || f.auditedCount(0, "bad_issued_token") != 1 {
			t.Fatal("a reconnect token with a far exp was not refused as bad_issued_token")
		}
		f.advance(24 * time.Hour)
		f.reissue(TokReconnect)
		if !f.p(0).Reconnect.Exp.After(held.Exp) {
			t.Fatal("the honest reissue was not adopted")
		}
	})
	t.Run("over 365 days is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		iat := f.clk.Add(-time.Minute)
		f.sendIssued(1, TokReconnect, f.tokenFrom(1, iat, iat.Add(366*24*time.Hour), "rc-366"))
		if f.p(0).Reconnect != held || f.auditedCount(0, "bad_issued_token") != 1 {
			t.Fatal("a 366-day reconnect token was not refused")
		}
	})
	t.Run("far-future standing token, then an honest reissue", func(t *testing.T) {
		f := newR29Fx(t)
		f.startCopy(1, f.snapshot(1))
		held := f.p(0).Standing
		iat := f.clk.Add(-time.Minute)
		f.sendIssued(2, TokStanding, f.tokenFrom(2, iat, iat.Add(31*24*time.Hour), "st-31d"))
		if f.p(0).Standing != held || f.auditedCount(0, "bad_issued_token") != 1 {
			t.Fatal("a 31-day standing token was not refused as bad_issued_token")
		}
		f.advance(24 * time.Hour)
		f.reissue(TokStanding)
		if !f.p(0).Standing.Exp.After(held.Exp) {
			t.Fatal("the honest standing reissue was not adopted")
		}
	})
	t.Run("future iat is refused", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		iat := f.clk.Add(time.Hour)
		f.sendIssued(1, TokReconnect, f.tokenFrom(1, iat, iat.Add(300*24*time.Hour), "rc-future-iat"))
		if f.p(0).Reconnect != held || f.auditedCount(0, "bad_issued_token") != 1 {
			t.Fatal("a reconnect token with an iat an hour ahead was not refused")
		}
	})
	t.Run("iat within the skew is adopted", func(t *testing.T) {
		f := newR29Fx(t)
		iat := f.clk.Add(time.Minute)
		tok := f.tokenFrom(1, iat, iat.Add(365*24*time.Hour), "rc-skew")
		f.sendIssued(1, TokReconnect, tok)
		if f.p(0).Reconnect.Token != tok {
			t.Fatal("a reconnect token with an iat a minute ahead was refused")
		}
	})
}

func TestIssuedTokenNits(t *testing.T) {
	t.Run("the held token offered again is not audited", func(t *testing.T) {
		f := newR29Fx(t)
		held := f.p(0).Reconnect
		f.sendIssued(1, TokReconnect, held.Token)
		if f.p(0).Reconnect != held || f.audited(0, "issued_token_not_newer") || f.audited(0, "bad_issued_token") {
			t.Fatal("the held reconnect token offered again was audited or changed the held one")
		}
	})
	t.Run("its jti offered again is not audited", func(t *testing.T) {
		f := newR29Fx(t)
		iat := f.clk.Add(4 * time.Minute)
		tok := f.tokenFrom(1, iat, iat.Add(365*24*time.Hour), "rc-jti")
		f.sendIssued(1, TokReconnect, tok)
		if f.p(0).Reconnect.Token != tok {
			t.Fatal("setup: not adopted")
		}
		f.sendIssued(1, TokReconnect, f.tokenFrom(1, iat, iat.Add(200*24*time.Hour), "rc-jti"))
		if f.p(0).Reconnect.Token != tok || f.audited(0, "issued_token_not_newer") {
			t.Fatal("a token with the held one's jti was audited or adopted")
		}
	})
	for _, c := range []struct {
		name string
		life time.Duration
	}{{"exp equal to iat is refused", 0}, {"exp before iat is refused", -time.Second}} {
		t.Run(c.name, func(t *testing.T) {
			f := newR29Fx(t)
			f.do(0, func(_ *Manager, p *Peer) { p.Reconnect = HeldToken{} })
			iat := f.clk.Add(4 * time.Minute)
			f.sendIssued(1, TokReconnect, f.tokenFrom(1, iat, iat.Add(c.life), "rc-empty"))
			if f.p(0).Reconnect.Token != "" || f.auditedCount(0, "bad_issued_token") != 1 {
				t.Fatal("a token with exp <= iat was not refused as bad_issued_token")
			}
		})
	}
}

// A reconnect's hs.init refused token_invalid or token_revoked drops the
// held reconnect token (a revoked one's jti recorded): otherwise a token
// with a later exp than any honest one (an old copy's) would stay held,
// refused by the relay, until its exp.
func TestRefusedReconnectTokenIsDropped(t *testing.T) {
	for _, code := range []string{CodeTokenInvalid, CodeTokenRevoked} {
		t.Run(code, func(t *testing.T) {
			f := newR29Fx(t)
			f.startCopy(1, f.snapshot(1))
			// The copy's reconnect token: valid in form, an exp later than
			// any honest reissue's, and refused by the relay.
			iat := f.clk.Add(4 * time.Minute)
			pin := f.tokenFrom(2, iat, iat.Add(365*24*time.Hour), "rc-pin")
			f.sendIssued(2, TokReconnect, pin)
			if f.p(0).Reconnect.Token != pin {
				t.Fatal("setup: the copy's reconnect token was not adopted")
			}
			status := 401
			if code == CodeTokenRevoked {
				status = 403
			}
			r := f.d[0].relay
			r.mu.Lock()
			r.check = func(mailbox, token string) error {
				if token == pin {
					return &relayclient.Error{Status: status, Code: code}
				}
				return nil
			}
			r.mu.Unlock()
			f.reissue(TokReconnect)
			if f.p(0).Reconnect.Token != pin {
				t.Fatal("setup: an honest reissue replaced the pinned token")
			}
			f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
			p := f.p(0)
			if p.Reconnect.Token != "" {
				t.Fatalf("the reconnect token refused %s is still held", code)
			}
			if !f.audited(0, "reconnect_"+code) || p.RC == nil || p.RC.Tries != 1 || p.State == PeerStale {
				f.dump()
				t.Fatalf("the hs.init refused %s is not one failed try", code)
			}
			_, err := f.m(0).heldToken(pin, p, TokReconnect)
			if code == CodeTokenRevoked && err != errRevokedHeld {
				t.Fatalf("the revoked token offered again: %v, want errRevokedHeld", err)
			}
			if code == CodeTokenInvalid && err != nil {
				t.Fatalf("token_invalid recorded the token as revoked: %v", err)
			}
			f.advance(time.Minute)
			f.reissue(TokReconnect)
			if f.p(0).Reconnect.Token == "" || f.p(0).Reconnect.Token == pin {
				t.Fatal("the next honest reconnect token was not adopted")
			}
			if code == CodeTokenRevoked {
				f.sendIssued(2, TokReconnect, pin)
				if f.p(0).Reconnect.Token == pin {
					t.Fatal("the revoked token was adopted again")
				}
			}
		})
	}
}

// A reconnect token adopted after the refused one was used (a newer one,
// adopted while the hs.init waited) is kept: only the refused token is
// dropped.
func TestRefusedReconnectTokenKeepsANewerOne(t *testing.T) {
	f := newR29Fx(t)
	old := f.p(0).Reconnect.Token
	iat := f.clk.Add(4 * time.Minute)
	newer := HeldToken{Token: f.tokenFrom(1, iat, iat.Add(365*24*time.Hour), "rc-newer"), Exp: iat.Add(365 * 24 * time.Hour)}
	r := f.d[0].relay
	r.mu.Lock()
	r.check = func(mailbox, token string) error {
		if token == old {
			f.p(0).Reconnect = newer // adopted while the hs.init waited
			return &relayclient.Error{Status: 401, Code: CodeTokenInvalid}
		}
		return nil
	}
	r.mu.Unlock()
	f.do(0, func(m *Manager, p *Peer) { m.startReconnect(p, f.clk) })
	if !f.audited(0, "reconnect_token_invalid") {
		f.dump()
		t.Fatal("setup: the hs.init was not refused token_invalid")
	}
	if f.p(0).Reconnect != newer {
		t.Fatal("the refusal of an older reconnect token dropped the newer one")
	}
}

// On the vault's own relay, a held token is also capped at the relay's
// advertised max_token_lifetime_seconds (the relay refuses one over it);
// a token for another relay is judged by §7.1's caps only.
func TestHeldTokenOwnRelayLimit(t *testing.T) {
	for _, own := range []bool{true, false} {
		f := newR29Fx(t)
		f.do(0, func(m *Manager, p *Peer) {
			if p.Relay.URL != m.st.Relay.URL {
				t.Fatal("setup: the pair is not on one relay")
			}
			m.limits.MaxTokenLifetimeSeconds = 200 * 86400
			p.Reconnect = HeldToken{} // so that only the cap decides
			if !own {
				m.st.Relay.URL = "https://other-relay.example.org"
			}
		})
		iat := f.clk.Add(4 * time.Minute)
		tok := f.tokenFrom(1, iat, iat.Add(300*24*time.Hour), "rc-over-limit")
		f.sendIssued(1, TokReconnect, tok)
		if (f.p(0).Reconnect.Token == tok) == own || f.audited(0, "bad_issued_token") != own {
			t.Fatalf("own relay %v: a 300-day reconnect token under a 200-day relay limit adopted %v", own, !own)
		}
	}
}
