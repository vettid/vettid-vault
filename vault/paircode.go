package vault

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/paircode"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Short pairing codes for desktops and agents (VAULT-MESSAGING 0.94.0
// §6.7.2): device.pair.create{form: "code"}. The code is a bearer secret
// for 10 minutes: it is never stored, logged or sent anywhere but in the
// sealed answer to the app (§13.6).

// PairCodeRelay is what a Relay offers for code claims (RELAY-PROTOCOL
// 0.14.0 §6.9.1). A Relay without it, or whose relay does not advertise
// pair_codes, makes no code pairing (claim_unavailable). Each call is one
// attempt; the vault decides what follows (§6.7.2).
type PairCodeRelay interface {
	// OffersPairCodes reports the relay's limits.pair_codes.
	OffersPairCodes() bool
	// PairCodeSalts lists the relay's lookup salts, unchecked.
	PairCodeSalts(ctx context.Context) ([]paircode.Salt, error)
	// PutPairCode creates the code claim claimID. A 409 is the relay code
	// "code_taken", a salt the relay refuses "bad_request" (RelayCode).
	PutPairCode(ctx context.Context, claimID, saltID string, tag, salt, blob []byte) (time.Time, error)
	// DeletePairCode deletes a code claim this vault created (idempotent).
	DeletePairCode(ctx context.Context, claimID string) error
}

// The limits of code pairings (§6.7.2; chosen, not in the card): 5 per
// vault per hour and 20 per day; a code_taken is retried with a new code
// at most 3 times.
const (
	PairCodesPerHour = 5
	PairCodesPerDay  = 20
	pairCodeRetries  = 3
)

// PairCodePermitWait is how long a code pairing waits for the heavy
// derivation permit before it answers busy (chosen; not in the spec: the
// capacity measure may tune it). Unlocks go first: the supervisor gives
// no permit while an unlock is in flight.
const PairCodePermitWait = 5 * time.Second // in all, for a request's derivations together (0.94.1)

// pairCodePermitWait is PairCodePermitWait (tests shorten it), and pcNow
// the clock the wait is measured by (tests replace it).
var (
	pairCodePermitWait = PairCodePermitWait
	pcNow              = time.Now
)

// pairCodeTokenTTL is the open token's lifetime: with its 60 s backdate
// (tokenBackdate), its exp, the bundle's, is the creation plus 600 s.
const pairCodeTokenTTL = paircode.TTL + tokenBackdate

var (
	errPairLimit = NewError("limit", "")
	errPairBusy  = NewError("busy", "")
	errPairRelay = NewError("relay_error", "")
)

// SeenSalt is an epoch's relay nonce the vault has seen in the last hours
// (§6.7.2: an epoch seen before must come with the same nonce).
type SeenSalt struct {
	Epoch int64  `json:"epoch"`
	Nonce []byte `json:"nonce"`
}

// codePermit takes the permit for a code pairing's two derivations,
// waiting up to PairCodePermitWait.
func (m *Manager) codePermit(ctx context.Context, deadline time.Time) (func(), bool) {
	// Fail closed: without a code permit of its own the vault takes the
	// heavy-derivation permit (the recovery wrap's); only with neither
	// (development, tests) are the derivations unadmitted.
	take := m.opt.CodePermit
	if take == nil {
		take = m.opt.HeavyPermit
	}
	if take == nil {
		return func() {}, true
	}
	for {
		if rel, ok := take(ctx); ok {
			return rel, true
		}
		if !pcNow().Before(deadline) {
			return nil, false
		}
		select {
		case <-ctx.Done():
			return nil, false
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// pairCodeIssuable prunes the issuance stamps and reports whether another
// code pairing is within the limits.
func (m *Manager) pairCodeIssuable(now time.Time) bool {
	kept := m.st.PairCodeIssued[:0]
	hour := 0
	for _, t := range m.st.PairCodeIssued {
		if now.Sub(t) < 24*time.Hour {
			kept = append(kept, t)
			if now.Sub(t) < time.Hour {
				hour++
			}
		}
	}
	m.st.PairCodeIssued = kept
	return hour < PairCodesPerHour && len(kept) < PairCodesPerDay
}

// cancelLiveCode ends the vault's live code pairing, if any, whatever its
// role (§6.7.2 "One live code per vault"): its claim deleted, its open
// token's jti denylisted, the pairing dropped.
func (m *Manager) cancelLiveCode(now time.Time) {
	for _, id := range sortedKeys(m.st.Invites) {
		inv := m.st.Invites[id]
		if inv == nil || !inv.Code || inv.Used {
			continue
		}
		m.endInvite(inv, now)
	}
}

// endInvite ends an unused invite: its open token's jti denylisted, its
// claim deleted, the invite dropped.
func (m *Manager) endInvite(inv *Invite, now time.Time) {
	if inv.OpenJTI != "" {
		m.denyJTI(inv.OpenJTI, now)
	}
	m.queueDeleteInviteClaim(inv, now)
	delete(m.st.Invites, inv.ID)
}

// queueDeleteInviteClaim queues the deletion of an invite's claim: a code
// claim's by its own route (RELAY-PROTOCOL §6.9.1), a link's as a claim
// (§6.9). Every place that deletes an invite's claim goes through here.
func (m *Manager) queueDeleteInviteClaim(inv *Invite, now time.Time) {
	if inv.ClaimID == "" {
		return
	}
	e := &OutboxEntry{ID: m.newID(now), Op: OpDeleteClaim, Value: inv.ClaimID, Created: now}
	if inv.Code {
		// A code claim lives at most the pairing's 10 minutes at the relay:
		// its deletion is retried until then (0.94.1).
		e.Op, e.NotAfter = OpDeletePairCode, inv.Exp.Add(time.Minute) // a minute past the claim's end at the relay
	}
	m.queue(e)
}

// noteSeenSalts records the checked list's nonces and drops those older
// than the previous hour.
func (m *Manager) noteSeenSalts(list []paircode.Salt, now time.Time) {
	cur := paircode.Epoch(now)
	kept := m.st.PairCodeSeen[:0]
	for _, s := range m.st.PairCodeSeen {
		if s.Epoch >= cur-1 {
			kept = append(kept, s)
		}
	}
	for _, e := range list {
		known := false
		for _, s := range kept {
			if s.Epoch == e.Epoch {
				known = true
			}
		}
		if !known && e.Epoch >= cur-1 {
			kept = append(kept, SeenSalt{Epoch: e.Epoch, Nonce: append([]byte(nil), e.Nonce...)})
		}
	}
	m.st.PairCodeSeen = kept
}

func (m *Manager) seenSalts() map[int64][]byte {
	seen := map[int64][]byte{}
	for _, s := range m.st.PairCodeSeen {
		seen[s.Epoch] = s.Nonce
	}
	return seen
}

// EventSaltsRefused is the audit event of a salt list a code pairing
// refused (§6.7.2), with the failed check as its ref.
const EventSaltsRefused = "pair_code.salts_refused"

// saltsRefused records a refused salt list (§6.7.2: audit and a distinct
// reason; no code, salt, nonce or tag) and answers claim_unavailable.
func (m *Manager) saltsRefused(reason string, now time.Time) error {
	m.auditRef(now, EventSaltsRefused, "", reason)
	return errClaim
}

// createCodePairing makes a code pairing for role (desktop or agent)
// after device.pair.create's own checks (§6.7.2 "Making a code pairing").
//
// It returns the answer and the body cached for a retransmission (§8.2),
// which leaves out the code: the response cache is saved state, and the
// code is never stored (§6.7.2, §13.6). An app that gets the cached copy
// has no code to show and asks for a new one.
func (m *Manager) createCodePairing(ctx context.Context, role, by string, now time.Time) (answer, cached []byte, err error) {
	purpose := map[string]string{KindAgent: paircode.PurposeAgent, KindDesktop: paircode.PurposeDesktop}[role]
	if purpose == "" {
		return nil, nil, errBadRequest
	}
	// 1. The issuance limit, then the live code pairing cancelled.
	if !m.pairCodeIssuable(now) {
		return nil, nil, errPairLimit
	}
	m.cancelLiveCode(now)
	pc, ok := m.relay.(PairCodeRelay)
	if !ok || !pc.OffersPairCodes() {
		return nil, nil, errClaim
	}
	r, err := paircode.CanonicalRelay(m.relay.BaseURL())
	if err != nil {
		return nil, nil, errClaim // a relay a code cannot name (an IP, plain http)
	}
	// The open token lives 660 s (600 s and its backdate), within the
	// relay's limit; the code claim's own 600 s is the relay's, fixed.
	if pairCodeTokenTTL > time.Duration(m.limits.OpenTokenMaxLifetimeSeconds)*time.Second {
		return nil, nil, errClaim
	}
	// 2. The salts, checked; the entry current by the vault's clock.
	listed, err := pc.PairCodeSalts(ctx)
	if err != nil {
		return nil, nil, errClaim // (0.94.1) not retried: the app falls back to the link
	}
	checked, err := paircode.CheckSalts(r, listed, now, m.seenSalts())
	var refused *paircode.RefusedError
	if errors.As(err, &refused) {
		return nil, nil, m.saltsRefused(refused.Reason, now)
	} else if err != nil {
		return nil, nil, m.saltsRefused(paircode.ReasonCount, now)
	}
	m.noteSeenSalts(checked, now)
	order := paircode.ForPut(checked, now)
	if len(order) == 0 {
		return nil, nil, m.saltsRefused(paircode.ReasonClock, now)
	}
	// 3. The open token first (its exp is the bundle's: no permit wait
	// comes between them), then the derivations, each under the heavy
	// permit (putCodeClaim): unlocks go first, and no permit is held
	// across a request to the relay.
	id, jti := m.newID(now), m.newID(now)
	tok, err := m.relay.MintOpenToken(pairCodeTokenTTL, jti)
	if err != nil {
		return nil, nil, errPairRelay
	}
	exp := now.UTC().Truncate(time.Second).Add(paircode.TTL)
	b := &invite.Bundle{Kind: role, InviteID: id, Remote: false,
		Vault: handshake.Principal{IK: m.keys.ik.Public().(ed25519.PublicKey), KEM: m.keys.kem.Public(), Relay: m.ownAddr()},
		Token: tok, Exp: exp} // no hint (§13.6)
	bj, err := b.Marshal()
	if err != nil {
		m.denyUnusedToken(jti, exp, now)
		return nil, nil, errUnavailable
	}
	defer suite.Wipe(bj) // it holds the open token

	// (0.94.1) One wait for room per request, for all its derivations.
	deadline := pcNow().Add(pairCodePermitWait)
	for try := 0; try <= pairCodeRetries; try++ {
		code, claimID, refusedFirst, err := m.putCodeClaim(ctx, pc, purpose, r, order, bj, deadline)
		if refusedFirst && len(order) > 1 {
			order = order[1:] // the relay refused that salt: later codes go to the other at once
		}
		switch {
		case err == nil:
			m.st.Invites[id] = &Invite{ID: id, Kind: role, Exp: exp, OpenJTI: jti, ClaimID: claimID, CreatedBy: by, Code: true}
			m.st.Issued = append(m.st.Issued, IssuedToken{JTI: jti, Kind: TokOpen, Sub: "*", Exp: exp})
			m.st.PairCodeIssued = append(m.st.PairCodeIssued, now)
			// The code goes into the answer as bytes (8 alphabet
			// characters need no escaping), never as a string, and the
			// vault's own copies are wiped.
			quoted := make([]byte, 0, paircode.Length+2)
			quoted = append(append(append(quoted, '"'), code...), '"')
			suite.Wipe(code)
			// Sized up front, so that no grown-out copy of the code is left
			// behind; the answer itself is wiped once sealed (depositOnce).
			out := strictjson.NewBuilder().Grow(256+len(id)+len(r)).String("pairing_id", id).Raw("code", quoted).
				String("exp", exp.Format(time.RFC3339)).String("r", r).Bytes()
			suite.Wipe(quoted)
			kept := strictjson.NewBuilder().String("pairing_id", id).
				String("exp", exp.Format(time.RFC3339)).String("r", r).Bytes()
			return out, kept, nil
		case errors.Is(err, errCodeTaken):
			continue // the relay deleted both claims: a new code and s_c
		case errors.Is(err, errSaltsRefusedAtPut):
			m.denyUnusedToken(jti, exp, now)
			return nil, nil, m.saltsRefused("put_refused", now)
		case claimID != "":
			// (0.94.1) A failed PUT (a 429, a 5xx, no answer: a lost 201
			// may hide in it) is not retried. The claim is deleted, retried
			// until the pairing's 10 minutes end, the token denylisted, and
			// the app falls back to the link.
			m.denyUnusedToken(jti, exp, now)
			m.queue(&OutboxEntry{ID: m.newID(now), Op: OpDeletePairCode, Value: claimID, Created: now, NotAfter: exp.Add(time.Minute)})
			return nil, nil, errClaim
		default:
			m.denyUnusedToken(jti, exp, now)
			return nil, nil, err
		}
	}
	m.denyUnusedToken(jti, exp, now)
	return nil, nil, errPairRelay
}

// denyUnusedToken denylists the open token of a code pairing that was not
// made: it was minted, and is never handed out.
func (m *Manager) denyUnusedToken(jti string, exp time.Time, now time.Time) {
	m.st.Issued = append(m.st.Issued, IssuedToken{JTI: jti, Kind: TokOpen, Sub: "*", Exp: exp})
	m.denyJTI(jti, now)
}

var (
	errCodeTaken         = errors.New("vault: code taken")
	errSaltsRefusedAtPut = errors.New("vault: the relay refused both salts")
)

// putCodeClaim makes a code, s_c and a claim id, seals the bundle under
// k_w and PUTs the claim under the first entry, then once under the other
// on a bad_request (§6.7.2 "Which entry a vault uses"). Each derivation
// runs under the heavy permit, taken for it and given back before any
// request to the relay (x, k_w and the first tag together; the other
// salt's tag on its own). It returns the code (the caller wipes it), the
// claim id, and whether the relay refused the first entry's salt. On an
// error whose outcome at the relay is not known, the claim id is
// returned too, for its deletion.
func (m *Manager) putCodeClaim(ctx context.Context, pc PairCodeRelay, purpose, r string, order []paircode.Salt,
	bundle []byte, deadline time.Time) (_ []byte, unknownClaim string, refusedFirst bool, err error) {
	code, err := paircode.NewCode()
	if err != nil {
		return nil, "", false, errUnavailable
	}
	defer func() {
		if err != nil {
			suite.Wipe(code) // only an answered code leaves here
		}
	}()
	sc, err := suite.RandomBytes(paircode.SaltSize)
	if err != nil {
		return nil, "", false, errUnavailable
	}
	claimID, err := paircode.NewClaimID()
	if err != nil {
		return nil, "", false, errUnavailable
	}
	var blob, tag []byte
	if err := m.underPermit(ctx, deadline, func() error {
		// x, then the tag: one derivation at a time.
		x, err := paircode.X(purpose, r, code, sc)
		if err != nil {
			return errUnavailable
		}
		kw, err := paircode.KW(x)
		suite.Wipe(x)
		if err != nil {
			return errUnavailable
		}
		blob, err = paircode.Seal(kw, purpose, r, claimID, sc, bundle)
		suite.Wipe(kw)
		if err != nil {
			return errUnavailable
		}
		if tag, err = paircode.Tag(purpose, r, code, order[0].SR); err != nil {
			return errUnavailable
		}
		return nil
	}); err != nil {
		return nil, "", false, err
	}
	for i, e := range order {
		if i >= 2 {
			break // at most 2 PUTs for the salt
		}
		if i > 0 {
			if err := m.underPermit(ctx, deadline, func() error {
				var err error
				if tag, err = paircode.Tag(purpose, r, code, e.SR); err != nil {
					return errUnavailable
				}
				return nil
			}); err != nil {
				return nil, "", refusedFirst, err
			}
		}
		_, err = pc.PutPairCode(ctx, claimID, e.SaltID, tag, sc, blob)
		suite.Wipe(tag)
		switch {
		case err == nil:
			return code, claimID, refusedFirst, nil
		case RelayCode(err) == "code_taken":
			return nil, "", refusedFirst, errCodeTaken // the relay deleted it
		case RelayCode(err) == "bad_request" && i+1 < len(order):
			refusedFirst = i == 0
			continue
		case RelayCode(err) == "bad_request":
			return nil, "", refusedFirst || i == 0, errSaltsRefusedAtPut
		default:
			return nil, claimID, refusedFirst, errPairRelay
		}
	}
	return nil, "", refusedFirst, errSaltsRefusedAtPut
}

// underPermit runs one code pairing's derivations under the heavy
// permit, waiting for it until the request's deadline (busy without).
func (m *Manager) underPermit(ctx context.Context, deadline time.Time, f func() error) error {
	rel, ok := m.codePermit(ctx, deadline)
	if !ok {
		return errPairBusy
	}
	defer rel()
	return f()
}

// unopenedPairing is the desktop or agent pairing pid that no device has
// opened yet (no hs.init), or nil.
func (m *Manager) unopenedPairing(pid string) *Invite {
	inv := m.st.Invites[pid]
	if inv == nil || inv.Used || inv.Transfer || inv.Kind != KindDesktop && inv.Kind != KindAgent {
		return nil
	}
	return inv
}
