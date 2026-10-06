package memberapitest

import (
	"context"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/vettid/vettid-vault/vms/altchan"
)

// App keys, setup codes and the account snapshot (MEMBER-API 2.0.0,
// VAULT-MESSAGING 0.15.0 §11.12, §11.13). Apps never sign in: each app
// request carries X-VettID-App, signed by the app key, and the stand-in
// checks it as the member API does (ts within 300 s, single-use nonce,
// the key allowed for the route on that vault, the signature). Setup
// codes, pending keys, claim keys and nonces live in memory here (the
// real API keeps them in its tables); the vault row's app_key is the one
// the parent writes from the enclave's reports.

const (
	appTSWindow     = 300 * time.Second
	appNonceWindow  = 600 * time.Second
	pendingKeyTTL   = time.Hour
	enrollCodeTTL   = 5 * time.Minute
	typedCeiling    = 800
	maxClaimKeys    = 10
	headerAppKey    = "X-VettID-App"
	unauthorizedMsg = "unauthorized"
)

// appKey is one public app key.
type appKey struct {
	der []byte
	kid string
	pub *ecdsa.PublicKey
}

func parseKey(b64 string) (*appKey, bool) {
	pub, der, err := altchan.ParseAppKey(b64)
	if err != nil {
		return nil, false
	}
	return &appKey{der: der, kid: altchan.AppKeyID(der), pub: pub}, true
}

// issuance is one setup code (§11.12.1).
type issuance struct {
	guid     string
	codeMAC  []byte
	expires  time.Time
	state    string // live, used, revoked
	issuedAt time.Time
	usedAt   time.Time
	typed    int
	blocked  bool
}

type pendingKey struct {
	key   *appKey
	until time.Time
}

// keyStore is the stand-in's memory for app keys and codes.
type keyStore struct {
	kCode       []byte
	issuances   map[string]*issuance // by hex HMAC(k_code, "qr" || 0 || secret)
	live        map[string]string    // guid → issuance key
	emails      map[string]string    // normalized email → guid
	nonces      map[string]time.Time // kid|nonce → seen
	pending     map[string]pendingKey
	claims      map[string][]*appKey // vault_id → claim keys
	recovering  map[string]*appKey   // vault_id → recovering key
	slotSigner  map[string]*appKey   // request_id → signing key
	slotAccount map[string][]byte
}

func (a *API) keys() *keyStore {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.ks == nil {
		k := make([]byte, 32)
		_, _ = rand.Read(k)
		a.ks = &keyStore{kCode: k, issuances: map[string]*issuance{}, live: map[string]string{}, emails: map[string]string{},
			nonces: map[string]time.Time{}, pending: map[string]pendingKey{}, claims: map[string][]*appKey{},
			recovering: map[string]*appKey{}, slotSigner: map[string]*appKey{}, slotAccount: map[string][]byte{}}
	}
	return a.ks
}

func (ks *keyStore) mac(parts ...string) []byte {
	m := hmac.New(sha256.New, ks.kCode)
	m.Write([]byte(strings.Join(parts, "\x00")))
	return m.Sum(nil)
}

// caller is who made a request: a portal session (app == nil) or an app
// key, of a kind.
type caller struct {
	guid string
	app  *appKey
	kind string // app_key, pending, claim, recovering, redeem
}

type callerCtxKey struct{}

func callerOf(ctx context.Context) *caller {
	c, _ := ctx.Value(callerCtxKey{}).(*caller)
	return c
}

// Email returns the member's email for the stand-in: Config.Email, or
// <guid>@example.org.
func (a *API) email(guid string) string {
	if a.cfg.Email != nil {
		return a.cfg.Email(guid)
	}
	return guid + "@example.org"
}

// route names a request's route for the key matrix (MEMBER-API "Two kinds
// of caller").
func route(method, path string) string {
	switch {
	case path == "/api/vault/enroll-code":
		return "enroll-code"
	case method == http.MethodPost && path == "/api/vault/enroll/redeem":
		return "redeem"
	case method == http.MethodGet && path == enclavePath:
		return "enclave"
	case method == http.MethodPost && path == "/api/vault/enroll":
		return "enroll"
	case method == http.MethodPost && path == "/api/vault/unlock":
		return "unlock"
	case method == http.MethodPost && path == "/api/vault/lock":
		return "lock"
	case method == http.MethodGet && path == "/api/vault/status":
		return "status"
	case method == http.MethodGet && strings.HasPrefix(path, requestsPathPrefix):
		return "requests"
	case method == http.MethodPost && path == "/api/vault/recovery/claim":
		return "claim"
	case method == http.MethodPost && path == "/api/vault/recovery/register":
		return "register"
	case strings.HasPrefix(path, "/api/vault/recovery"):
		return "recovery"
	}
	return ""
}

// sessionRoutes are the portal's (MEMBER-API 2.0.0): enclave, enroll,
// unlock and register take only signed requests.
var sessionRoutes = map[string]bool{"enroll-code": true, "lock": true, "status": true, "requests": true, "recovery": true}

// appRoutes is the key matrix: which key kinds may call a route.
var appRoutes = map[string][]string{
	"enclave":  {"app_key", "pending", "claim", "recovering"},
	"enroll":   {"pending"},
	"unlock":   {"app_key", "recovering"},
	"lock":     {"app_key", "recovering"},
	"status":   {"app_key", "recovering"},
	"requests": {"app_key", "pending", "claim", "recovering"},
	"register": {"claim"},
}

var errUnauthorized = vaultError(401, "unauthorized", "unauthorized", nil)

// authenticate finds the caller of r (raw: the exact body).
func (a *API) authenticate(ctx context.Context, r *http.Request, raw []byte, body map[string]any) (*caller, error) {
	rt := route(r.Method, r.URL.Path)
	hv := r.Header.Get(headerAppKey)
	if hv == "" {
		guid, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || guid == "" || !sessionRoutes[rt] {
			return nil, errUnauthorized
		}
		return &caller{guid: guid}, nil
	}
	req, sig, err := altchan.ParseAppHeader(hv)
	if err != nil {
		return nil, errUnauthorized
	}
	req.Method, req.Path, req.Query, req.Body = r.Method, r.URL.EscapedPath(), r.URL.RawQuery, raw
	now := a.cfg.Now()
	if d := now.Sub(time.Unix(req.TS, 0)); d > appTSWindow || d < -appTSWindow {
		return nil, errUnauthorized
	}
	ks := a.keys()
	c := &caller{}
	switch rt {
	case "redeem", "claim":
		s, _ := body["app_key"].(string)
		k, ok := parseKey(s)
		if !ok {
			return nil, errUnauthorized
		}
		want := ""
		if rt == "claim" {
			want, _ = body["vault_id"].(string)
		}
		if req.VaultID != want {
			return nil, errUnauthorized
		}
		c.app, c.kind = k, rt
	case "":
		return nil, errUnauthorized
	default:
		kinds := appRoutes[rt]
		if kinds == nil || !vaultIDRE.MatchString(req.VaultID) {
			return nil, errUnauthorized
		}
		g, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Vaults,
			Key: map[string]ddbtypes.AttributeValue{"vault_id": s(req.VaultID)}})
		if err != nil {
			return nil, err
		}
		v := parseVault(g.Item)
		if v == nil {
			return nil, errUnauthorized
		}
		c.guid = v.UserGUID
		cands := map[string][]*appKey{}
		if v.AppKey != nil {
			cands["app_key"] = []*appKey{v.AppKey}
		}
		a.mu.Lock()
		if p, ok := ks.pending[req.VaultID]; ok && now.Before(p.until) && (v.AppKey == nil || v.AppKey.kid != p.key.kid) {
			cands["pending"] = []*appKey{p.key}
		}
		cands["claim"] = append([]*appKey(nil), ks.claims[req.VaultID]...)
		if k := ks.recovering[req.VaultID]; k != nil {
			cands["recovering"] = []*appKey{k}
		}
		a.mu.Unlock()
		for _, kind := range kinds {
			for _, k := range cands[kind] {
				if k.kid == req.KID {
					c.app, c.kind = k, kind
				}
			}
		}
		if c.app == nil {
			return nil, errUnauthorized
		}
	}
	if c.app.kid != req.KID || !req.Verify(c.app.pub, c.app.der, sig) {
		return nil, errUnauthorized
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, t := range ks.nonces {
		if now.Sub(t) > appNonceWindow {
			delete(ks.nonces, k)
		}
	}
	nk := req.KID + "|" + req.Nonce
	if _, seen := ks.nonces[nk]; seen {
		return nil, errUnauthorized
	}
	ks.nonces[nk] = now
	return c, nil
}

// --- setup codes (§11.12.1) ---

func (a *API) origin(r *http.Request) string {
	if a.cfg.Origin != "" {
		return a.cfg.Origin
	}
	return "http://" + r.Host
}

// enrollCodeIssue is POST /api/vault/enroll-code (the portal).
func (a *API) enrollCodeIssue(guid, api string) (any, error) {
	secret := make([]byte, altchan.QRSecretSize)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	code, err := altchan.NewCode()
	if err != nil {
		return nil, err
	}
	ks := a.keys()
	now := a.cfg.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	if old := ks.issuances[ks.live[guid]]; old != nil && old.state == "live" {
		old.state = "revoked"
	}
	qs := base64.RawURLEncoding.EncodeToString(secret)
	key := hex.EncodeToString(ks.mac("qr", qs))
	ks.issuances[key] = &issuance{guid: guid, codeMAC: ks.mac("code", guid, code), expires: now.Add(enrollCodeTTL), state: "live", issuedAt: now}
	ks.live[guid] = key
	ks.emails[altchan.NormalizeEmail(a.email(guid))] = guid
	return map[string]any{"secret": qs, "code": altchan.FormatCode(code), "expires_at": isoS(now.Add(enrollCodeTTL).Unix()), "api": api}, nil
}

// enrollCodeGet is GET /api/vault/enroll-code.
func (a *API) enrollCodeGet(guid string) (any, error) {
	ks := a.keys()
	a.mu.Lock()
	defer a.mu.Unlock()
	is := ks.issuances[ks.live[guid]]
	if is == nil {
		return map[string]any{"enroll_code": nil}, nil
	}
	st := is.state
	if st == "live" && !a.cfg.Now().Before(is.expires) {
		st = "expired"
	}
	out := map[string]any{"state": st, "typed_blocked": is.blocked, "issued_at": isoS(is.issuedAt.Unix()), "expires_at": isoS(is.expires.Unix())}
	if st == "used" {
		out["used_at"] = isoS(is.usedAt.Unix())
	}
	return map[string]any{"enroll_code": out}, nil
}

// enrollCodeRevoke is DELETE /api/vault/enroll-code.
func (a *API) enrollCodeRevoke(guid string) (any, error) {
	ks := a.keys()
	a.mu.Lock()
	defer a.mu.Unlock()
	is := ks.issuances[ks.live[guid]]
	if is == nil || is.state != "live" || !a.cfg.Now().Before(is.expires) {
		return map[string]any{"revoked": false}, nil
	}
	is.state = "revoked"
	return map[string]any{"revoked": true}, nil
}

var errInvalidCode = vaultError(404, "invalid_code", "The code is not valid", nil)

// redeem is POST /api/vault/enroll/redeem (signed by the key being
// registered, an empty vault): every failure is 404 invalid_code.
func (a *API) redeem(ctx context.Context, c *caller, body map[string]any) (any, error) {
	secret, hasS := body["secret"].(string)
	email, hasE := body["email"].(string)
	code, hasC := body["code"].(string)
	if hasS == (hasE || hasC) || hasE != hasC {
		return nil, badRequest("exactly one of {secret} or {email, code}")
	}
	ks := a.keys()
	now := a.cfg.Now()
	a.mu.Lock()
	var is *issuance
	if hasS {
		is = ks.issuances[hex.EncodeToString(ks.mac("qr", secret))]
	} else {
		guid := ks.emails[altchan.NormalizeEmail(email)]
		nc, ok := altchan.NormalizeCode(code)
		cand := ks.issuances[ks.live[guid]]
		mac := ks.mac("code", guid, nc)
		if cand != nil && !cand.blocked {
			cand.typed++
			if cand.typed >= typedCeiling {
				cand.blocked = true
			}
		}
		if ok && cand != nil && !cand.blocked && subtle.ConstantTimeCompare(mac, cand.codeMAC) == 1 {
			is = cand
		}
	}
	if is == nil || is.state != "live" || !now.Before(is.expires) || ks.issuances[ks.live[is.guid]] != is {
		a.mu.Unlock()
		return nil, errInvalidCode
	}
	is.state, is.usedAt = "used", now
	guid := is.guid
	a.mu.Unlock()
	pointer, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return nil, err
	}
	v, err := a.vaultForEnrollment(ctx, guid, pointer, cur)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	ks.pending[v.VaultID] = pendingKey{key: c.app, until: now.Add(pendingKeyTTL)}
	a.mu.Unlock()
	return map[string]any{"vault_id": v.VaultID, "user_guid": guid, "email_hint": altchan.EmailHint(a.email(guid))}, nil
}

// --- recovery claim (§11.11.7) ---

func (a *API) recoveryClaim(ctx context.Context, c *caller, body map[string]any) (any, error) {
	vid, err := field(body, "vault_id", vaultIDRE, "32 lowercase hex")
	if err != nil {
		return nil, err
	}
	rid, err := field(body, "recovery_id", ulidRE, "a ULID")
	if err != nil {
		return nil, err
	}
	g, err := a.cfg.DDB.GetItem(ctx, &dynamodb.GetItemInput{TableName: &a.cfg.Tables.Vaults,
		Key: map[string]ddbtypes.AttributeValue{"vault_id": s(vid)}})
	if err != nil {
		return nil, err
	}
	v := active(parseVault(g.Item))
	if v == nil || v.Recovery == nil || v.Recovery.ID != rid {
		return nil, notFound("No such recovery")
	}
	if recoveryState(v.Recovery, a.recoveryNowS()) != "available" {
		return nil, vaultError(409, "recovery_not_available", "No recovery code is valid now", nil)
	}
	ks := a.keys()
	a.mu.Lock()
	cl := append(ks.claims[vid], c.app)
	if len(cl) > maxClaimKeys {
		cl = cl[len(cl)-maxClaimKeys:]
	}
	ks.claims[vid] = cl
	a.mu.Unlock()
	return map[string]any{"user_guid": v.UserGUID, "email_hint": altchan.EmailHint(a.email(v.UserGUID))}, nil
}

// registered records the recovering key: the key of the register whose
// slot came back recovery_registered (§11.11.7).
func (a *API) registeredBy(vaultID, requestID string) {
	ks := a.keys()
	a.mu.Lock()
	defer a.mu.Unlock()
	if k := ks.slotSigner[requestID]; k != nil {
		ks.recovering[vaultID] = k
	}
}

// --- the account snapshot (§11.13) ---

// Snapshot builds the member's account snapshot (MEMBER-API "Account
// snapshot to the vault").
func (a *API) Snapshot(guid string) []byte {
	b, _ := json.Marshal(map[string]any{"v": 1, "as_of": a.cfg.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"email_hint": altchan.EmailHint(a.email(guid)), "state": "member", "account_status": "active", "deletes_at": nil,
		"terms":        map[string]any{"needs_acceptance": false},
		"subscription": nil, "voting_rights": false})
	return b
}

// PushAccount sends the queue op account to the vault's live leaseholder
// (after an account change); without a live lease it sends nothing and
// returns "".
func (a *API) PushAccount(ctx context.Context, guid string) (string, error) {
	_, cur, err := a.currentVault(ctx, guid)
	if err != nil {
		return "", err
	}
	v := active(cur)
	if v == nil {
		return "", nil
	}
	holder, err := a.liveLease(ctx, v, a.nowS())
	if err != nil || holder == nil {
		return "", err
	}
	rid := a.newULID()
	ctx = context.WithValue(ctx, callerCtxKey{}, &caller{guid: guid})
	if err := a.enqueueWith(ctx, "account", guid, v, rid, holder, "", "", "", "", requestTTLS, nil); err != nil {
		return "", err
	}
	return rid, nil
}
