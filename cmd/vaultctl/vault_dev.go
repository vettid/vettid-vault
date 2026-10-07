//go:build devenclave

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/devenclave"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/features/all"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/altchan"
)

// Dev builds add the vault commands: a vault with a dev sealer whose key is
// kept next to the store, and the alternate channel through an in-process
// enclave with the TEST-ONLY fakes (internal/enclavetest). Never use these
// for anything but development.
func init() {
	commands["vault-create"] = command{"vault-create -store DIR -relay URL -pin PIN -app STATEFILE   (dev) create a vault, enrolling the app", cmdVaultCreate}
	commands["vault-run"] = command{"vault-run -store DIR -vault-id ID -pin PIN [-ws]   (dev) unlock and run a vault", cmdVaultRun}
}

func devSealer(dir string, create bool) (*devenclave.Sealer, error) {
	p := filepath.Join(dir, "dev-sealer.key")
	key, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) && create {
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(p, key, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return devenclave.NewSealer(key)
}

func cmdVaultCreate(ctx context.Context, _ *globals, args []string) error {
	fs := flag.NewFlagSet("vault-create", flag.ExitOnError)
	dir := fs.String("store", "", "store directory")
	relay := fs.String("relay", "", "relay base URL")
	pin := fs.String("pin", "", "PIN")
	appState := fs.String("app", "", "state file of the app to enroll")
	first := fs.String("first-name", "Dev", "the account's first name (the snapshot's, 0.18.0)")
	last := fs.String("last-name", "Member", "the account's last name")
	_ = fs.Parse(args)
	if *dir == "" || *relay == "" || *pin == "" || *appState == "" {
		return errors.New("-store, -relay, -pin and -app are required")
	}
	sealer, err := devSealer(*dir, true)
	if err != nil {
		return err
	}
	st, err := store.NewDir(*dir)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(*appState)
	if err != nil {
		return err
	}
	app, err := client.Load(client.Config{HTTP: httpClient}, b)
	if err != nil {
		return err
	}
	open, err := app.OpenToken()
	if err != nil {
		return err
	}
	ra := app.RelayAddr()
	m, err := devenclave.Create(ctx, vault.CreateParams{
		Options: vault.Options{Store: st, Sealer: sealer, Features: all.Dev()},
		PIN:     *pin, RelayURL: *relay, Provisional: true,
		// §11.5 (0.18.0): every vault holds the account's names.
		Account: enclavetest.Snapshot(time.Now(), *first, *last),
		App: &vault.EnrollApp{Name: "app", IK: app.IdentityKey(), KEM: app.KEMKey(),
			Relay: vault.PeerRelay{URL: ra.URL, Mailbox: ra.Mailbox, PK: ra.PK}, OpenToken: open},
	})
	if err != nil {
		return err
	}
	fmt.Println(m.VaultID())
	return m.Lock(ctx)
}

func cmdVaultRun(_ context.Context, _ *globals, args []string) error {
	fs := flag.NewFlagSet("vault-run", flag.ExitOnError)
	dir := fs.String("store", "", "store directory")
	id := fs.String("vault-id", "", "vault id")
	pin := fs.String("pin", "", "PIN")
	ws := fs.Bool("ws", false, "collect over WebSocket")
	_ = fs.Parse(args)
	sealer, err := devSealer(*dir, false)
	if err != nil {
		return err
	}
	st, err := store.NewDir(*dir)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	m, res, err := devenclave.Unlock(ctx, vault.UnlockParams{
		Options: vault.Options{Store: st, Sealer: sealer, WebSocket: *ws, Features: all.Dev()},
		VaultID: *id, PIN: *pin,
	})
	if err != nil {
		return err
	}
	fmt.Printf("unlocked %s (state_seq %d, header_seq %d); running until interrupted\n", *id, res.StateSeq, res.HeaderSeq)
	err = m.Run(ctx)
	if ctx.Err() != nil {
		return m.Lock(context.Background())
	}
	return err
}

// --- the alternate channel through an in-process enclave (dev) ---

func init() {
	commands["altchan-enroll"] = command{"altchan-enroll -store DIR -relay URL -guid GUID -pin PIN [-platform android|ios] [-releases 3[,4...]]   (dev) enroll this app through an in-process enclave (fake NSM and KMS, test roots), finish enrollment, lock", cmdAltEnroll}
	commands["altchan-unlock"] = command{"altchan-unlock -store DIR -relay URL -guid GUID -pin PIN [-releases 3,4] [-approve N] [-abandon] [-release N]   (dev) unlock through an in-process enclave and run the vault until interrupted", cmdAltUnlock}
}

// altFlags are the shared flags of the alternate-channel commands.
type altFlags struct {
	store, relay, guid, pin, platform, releases string
	seed                                        int
}

func (a *altFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.store, "store", "", "store directory (vault objects, fake KMS seed, routing)")
	fs.StringVar(&a.relay, "relay", "", "relay base URL")
	fs.StringVar(&a.guid, "guid", "", "member user_guid")
	fs.StringVar(&a.pin, "pin", "", "PIN")
	fs.StringVar(&a.platform, "platform", "android", "test device attestation: android or ios")
	fs.StringVar(&a.releases, "releases", "3", "running releases (comma-separated numbers; the last is the newest)")
	fs.IntVar(&a.seed, "attest-seed", 0x61, "test attestation key seed (1-255)")
}

// devWorld builds the in-process enclave world: a directory store, a fake
// KMS whose keys derive from a seed kept in the store, fake NSMs and the
// test manifest key. Everything here is TEST ONLY.
func (a *altFlags) devWorld() (*enclavetest.World, []uint64, error) {
	if a.store == "" || a.relay == "" || a.guid == "" || a.pin == "" {
		return nil, nil, errors.New("-store, -relay, -guid and -pin are required")
	}
	st, err := store.NewDir(a.store)
	if err != nil {
		return nil, nil, err
	}
	seedPath := filepath.Join(a.store, "dev-kms.seed")
	seed, err := os.ReadFile(seedPath)
	if errors.Is(err, os.ErrNotExist) {
		seed = make([]byte, 32)
		if _, err := rand.Read(seed); err != nil {
			return nil, nil, err
		}
		if err := os.WriteFile(seedPath, seed, 0o600); err != nil {
			return nil, nil, err
		}
	} else if err != nil {
		return nil, nil, err
	}
	w := enclavetest.NewWorld(time.Now, a.relay)
	w.Store = st
	w.KMS = enclavetest.NewFakeKMS(string(seed), enclavetest.TestNitroCA().Roots(), time.Now)
	w.VaultOptions = vault.Options{Relay: func(base string, key ed25519.PrivateKey) vault.Relay {
		return vault.NewClientRelay(base, key, nil, time.Now)
	}}
	w.Features = func() []vault.Feature { return all.Dev() }
	w.SetSerial(uint64(time.Now().Unix()))
	var nums []uint64
	for _, f := range strings.Split(a.releases, ",") {
		n, err := strconv.ParseUint(strings.TrimSpace(f), 10, 64)
		if err != nil || n == 0 || n > 15 {
			return nil, nil, errors.New("bad -releases")
		}
		nums = append(nums, n)
	}
	for _, n := range nums {
		w.AddRelease(enclavetest.Spec(n, "active"))
	}
	for _, n := range nums {
		if _, err := w.Start(n); err != nil {
			return nil, nil, err
		}
	}
	if b, err := os.ReadFile(filepath.Join(a.store, "dev-routing.json")); err == nil {
		var routes map[string]string
		if json.Unmarshal(b, &routes) == nil {
			for v, r := range routes {
				w.SetSealedRelease(v, r)
			}
		}
	}
	return w, nums, nil
}

func (a *altFlags) saveRoute(w *enclavetest.World, vaultID string) error {
	p := filepath.Join(a.store, "dev-routing.json")
	routes := map[string]string{}
	if b, err := os.ReadFile(p); err == nil {
		_ = json.Unmarshal(b, &routes)
	}
	if r := w.SealedRelease(vaultID); r != "" {
		routes[vaultID] = r
	}
	b, _ := json.Marshal(routes)
	return os.WriteFile(p, b, 0o600)
}

// attester returns the test attestation key; an iOS key's assertion
// counter is kept next to the device state so it increases across runs.
func (a *altFlags) attester(g *globals) (client.Attester, func()) {
	if a.platform != "ios" {
		return enclavetest.NewAndroidAttester(byte(a.seed), enclavetest.AndroidOptions{}), func() {}
	}
	at := enclavetest.NewIOSAttester(byte(a.seed), enclavetest.IOSOptions{})
	p := g.state + ".attest-counter"
	if b, err := os.ReadFile(p); err == nil {
		if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32); err == nil {
			at.SetCounter(uint32(n))
		}
	}
	return at, func() { _ = os.WriteFile(p, []byte(strconv.FormatUint(uint64(at.Counter()), 10)), 0o600) }
}

func loadWithTrust(g *globals, t client.Trust) (*client.Device, error) {
	b, err := os.ReadFile(g.state)
	if err != nil {
		return nil, err
	}
	return client.Load(client.Config{Trust: &t, HTTP: httpClient}, b)
}

func randomVaultID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func cmdAltEnroll(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("altchan-enroll", flag.ExitOnError)
	var a altFlags
	a.register(fs)
	_ = fs.Parse(args)
	w, _, err := a.devWorld()
	if err != nil {
		return err
	}
	defer w.Close()
	t := w.Trust()
	d, err := loadWithTrust(g, t)
	if err != nil {
		return err
	}
	desc, att, in, err := w.Enclave("", "")
	if err != nil {
		return err
	}
	_, m, err := d.VerifyManifest(w.Served(), t)
	if err != nil {
		return err
	}
	e, err := client.VerifyEnclave(desc, att, m, true, t, time.Now())
	if err != nil {
		return err
	}
	dev, keep := a.attester(g)
	req, err := d.BuildEnroll(a.guid, a.pin, e, m, dev)
	keep()
	if err != nil {
		return err
	}
	vid, err := randomVaultID()
	if err != nil {
		return err
	}
	resp, err := w.Post(ctx, in, enclave.OpEnroll, vid, a.guid, req)
	if err != nil {
		return err
	}
	r, err := d.OpenEnrollResult(resp.Envelope, req.RequestID)
	if err != nil {
		return err
	}
	if !r.OK {
		return fmt.Errorf("enrollment refused: %s", r.Code)
	}
	if err := d.AwaitEnrolled(ctx); err != nil {
		return err
	}
	if err := save(g, d); err != nil {
		return err
	}
	if err := d.CompleteEnrollment(ctx); err != nil {
		return err
	}
	// A vault is used only with a credential (§3.5.7).
	if err := d.CredentialCreate(ctx, devPassword()); err != nil {
		return fmt.Errorf("credential.create: %w", err)
	}
	if rr, err := d.Request(ctx, "vault.enroll.confirm", json.RawMessage(`{}`)); err != nil || !rr.OK() {
		return errors.New("vault.enroll.confirm failed")
	}
	if err := a.saveRoute(w, vid); err != nil {
		return err
	}
	fmt.Println(vid)
	return save(g, d)
}

func cmdAltUnlock(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("altchan-unlock", flag.ExitOnError)
	var a altFlags
	a.register(fs)
	approve := fs.Uint64("approve", 0, "approve a move to this release")
	abandon := fs.Bool("abandon", false, "abandon an unconfirmed move (with -release)")
	release := fs.Uint64("release", 0, "send the unlock to this release")
	_ = fs.Parse(args)
	w, _, err := a.devWorld()
	if err != nil {
		return err
	}
	defer w.Close()
	t := w.Trust()
	d, err := loadWithTrust(g, t)
	if err != nil {
		return err
	}
	rel := ""
	if *release != 0 {
		rel = enclavetest.Spec(*release, "").PCR0Hex()
	}
	desc, att, in, err := w.Enclave(d.VaultID(), rel)
	if err != nil {
		return err
	}
	_, m, err := d.VerifyManifest(w.Served(), t)
	if err != nil {
		return err
	}
	e, err := client.VerifyEnclave(desc, att, m, false, t, time.Now())
	if err != nil {
		return err
	}
	o := client.UnlockOptions{Abandon: *abandon}
	if *approve != 0 {
		o.Approve = &client.Approval{To: enclavetest.Spec(*approve, "").PCR0Hex(), ToRelease: *approve}
	}
	dev, keep := a.attester(g)
	req, err := d.BuildUnlock(a.guid, a.pin, e, m, dev, o)
	keep()
	if err != nil {
		return err
	}
	if req.ReleaseChanged {
		fmt.Println("note: the vault software was updated since the last unlock (§11.2 step 4)")
	}
	resp, err := w.Post(ctx, in, enclave.OpUnlock, d.VaultID(), a.guid, req)
	if err != nil {
		return err
	}
	r, err := d.OpenUnlockResult(resp.Envelope)
	if err != nil {
		return err
	}
	if err := save(g, d); err != nil {
		return err
	}
	if err := a.saveRoute(w, d.VaultID()); err != nil {
		return err
	}
	out := map[string]any{"ok": r.OK, "code": r.Code, "state_seq": r.StateSeq, "header_seq": r.HeaderSeq,
		"release_number": r.ReleaseNumber, "release_status": r.ReleaseStatus}
	if u := r.Update; u != nil {
		out["update"] = map[string]string{"to": u.To, "result": u.Result, "code": u.Code}
	}
	if r.CredentialBackup != nil {
		out["credential_backup"] = *r.CredentialBackup // a recovered app (§11.11.5 step 1)
	}
	printJSON(out)
	if !r.OK || in.Manager(d.VaultID()) == nil {
		if r.Code == "state_rollback" {
			fmt.Println("WARNING: the vault's stored state is older than state this device has already seen (§13.2)")
		}
		return nil
	}
	fmt.Println("unlocked; running until interrupted")
	sctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-sctx.Done()
	return nil
}

// --- the alternate channel through the member API (dev) ---

func init() {
	commands["api-enroll"] = command{"api-enroll -api URL -guid GUID -pin PIN [-platform android|ios]   (dev) enroll through the member API (test trust and device attestation), finish enrollment", cmdAPIEnroll}
	commands["api-unlock"] = command{"api-unlock -api URL -guid GUID -pin PIN [-approve N] [-abandon -release N]   (dev) unlock through the member API", cmdAPIUnlock}
	commands["api-lock"] = command{"api-lock -api URL -guid GUID   (dev) lock through the member API", cmdAPILock}
	commands["api-recover"] = command{"api-recover -api URL -guid GUID -pin PIN -qr QR_PAYLOAD [-platform android|ios]   (dev) a new app recovers the vault (§11.11.3, §11.11.5 steps 1-2): register with the portal's code, unlock, first handshake; then `credential recover` (credential_backup true) or `credential reset`", cmdAPIRecover}
	devHTTPFromEnv()
}

// devHTTPFromEnv configures the HTTP client from VAULTCTL_DEV_RESOLVE
// ("host=addr,...": dial addr for host) and trusts the TEST-ONLY TLS root
// (enclavetest) besides the system roots. Development builds only.
func devHTTPFromEnv() {
	spec := os.Getenv("VAULTCTL_DEV_RESOLVE")
	if spec == "" {
		return
	}
	res := map[string]string{}
	for _, kv := range strings.Split(spec, ",") {
		if h, a, ok := strings.Cut(kv, "="); ok {
			res[h] = a
		}
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	roots.AddCert(enclavetest.TestTLSCA().Cert)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	tr.ForceAttemptHTTP2 = true
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, _ := net.SplitHostPort(addr)
		if a, ok := res[host]; ok && port == "443" {
			addr = a
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	httpClient = &http.Client{Transport: tr, Timeout: 90 * time.Second}
}

type apiFlags struct {
	api, guid, pin, platform string
	seed                     int
	typed                    bool
}

func (a *apiFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&a.api, "api", "", "member API base URL")
	fs.StringVar(&a.guid, "guid", "", "member user_guid: the test portal's bearer token (setup codes); the app itself signs with its app key")
	fs.BoolVar(&a.typed, "typed", false, "api-enroll: redeem the typed code with the member's email instead of the QR secret")
	fs.StringVar(&a.pin, "pin", "", "PIN")
	fs.StringVar(&a.platform, "platform", "android", "test device attestation: android or ios")
	fs.IntVar(&a.seed, "attest-seed", 0x61, "test attestation key seed (1-255)")
}

// portal is the test portal's member session (setup codes, §11.12.1).
func (a *apiFlags) portal() *client.MemberAPI {
	guid := a.guid
	return &client.MemberAPI{Base: a.api, HTTP: httpClient, Authorize: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+guid) }}
}

// client is the app's member API client: every request signed by its app
// key (0.15.0, §11.12.2).
func (a *apiFlags) client(d *client.Device) (*client.MemberAPI, error) {
	return d.APIFor(a.api, httpClient)
}

// userGUID is the member id the app learned from the redeem or the claim
// (-guid before 0.15.0 state).
func (a *apiFlags) userGUID(d *client.Device) string {
	if g := d.UserGUID(); g != "" {
		return g
	}
	return a.guid
}

// testTrust is the TEST-ONLY trust of the dev stack: the test Nitro root
// and the test manifest key.
func testTrust() client.Trust {
	return client.Trust{NitroRoots: enclavetest.TestNitroCA().Roots(), ManifestKeys: []*ecdsa.PublicKey{&enclavetest.ManifestKey().PublicKey}}
}

func cmdAPIEnroll(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("api-enroll", flag.ExitOnError)
	var a apiFlags
	a.register(fs)
	_ = fs.Parse(args)
	if a.api == "" || a.guid == "" || a.pin == "" {
		return errors.New("-api, -guid and -pin are required")
	}
	t := testTrust()
	d, err := loadWithTrust(g, t)
	if err != nil {
		return err
	}
	// The portal issues a setup code; the app redeems it with its app
	// key (§11.12.1) and enrolls with the member id it names.
	code, err := a.portal().IssueEnrollCode(ctx)
	if err != nil {
		return fmt.Errorf("enroll-code: %w", err)
	}
	api, err := a.client(d)
	if err != nil {
		return err
	}
	qr, err := code.QR()
	if err != nil {
		return err
	}
	q, err := altchan.ParseEnrollQR(qr)
	if err != nil || q.API != strings.TrimRight(a.api, "/") {
		return fmt.Errorf("the setup code is for another member API (%s)", q.API)
	}
	var red *client.RedeemResult
	if a.typed {
		red, err = d.RedeemVia(ctx, api, "", a.guid+"@example.org", code.Code)
	} else {
		red, err = d.RedeemVia(ctx, api, q.SecretString(), "", "")
	}
	if err != nil {
		return fmt.Errorf("redeem: %w", err)
	}
	fmt.Fprintf(os.Stderr, "setting up a vault for %s\n", red.EmailHint)
	af := altFlags{platform: a.platform, seed: a.seed}
	dev, keep := af.attester(g)
	vid, r, err := d.EnrollVia(ctx, api, red.UserGUID, a.pin, t, dev)
	keep()
	if err != nil {
		return err
	}
	if !r.OK {
		return fmt.Errorf("enrollment refused: %s", r.Code)
	}
	if err := d.AwaitEnrolled(ctx); err != nil {
		return err
	}
	if err := save(g, d); err != nil {
		return err
	}
	if err := d.CompleteEnrollment(ctx); err != nil {
		return err
	}
	// A vault is used only with a credential (§3.5.7).
	if err := d.CredentialCreate(ctx, devPassword()); err != nil {
		return fmt.Errorf("credential.create: %w", err)
	}
	if rr, err := d.Request(ctx, "vault.enroll.confirm", json.RawMessage(`{}`)); err != nil || !rr.OK() {
		return errors.New("vault.enroll.confirm failed")
	}
	fmt.Println(vid)
	return save(g, d)
}

func cmdAPIUnlock(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("api-unlock", flag.ExitOnError)
	var a apiFlags
	a.register(fs)
	approve := fs.Uint64("approve", 0, "approve a move to this test release")
	abandon := fs.Bool("abandon", false, "abandon an unconfirmed move (with -release)")
	release := fs.Uint64("release", 0, "send the unlock to this test release")
	_ = fs.Parse(args)
	if a.api == "" || a.pin == "" {
		return errors.New("-api and -pin are required")
	}
	t := testTrust()
	d, err := loadWithTrust(g, t)
	if err != nil {
		return err
	}
	api, err := a.client(d)
	if err != nil {
		return err
	}
	o := client.UnlockOptions{Abandon: *abandon}
	if *approve != 0 {
		o.Approve = &client.Approval{To: enclavetest.Spec(*approve, "").PCR0Hex(), ToRelease: *approve}
	}
	rel := ""
	if *release != 0 {
		rel = enclavetest.Spec(*release, "").PCR0Hex()
	}
	af := altFlags{platform: a.platform, seed: a.seed}
	dev, keep := af.attester(g)
	r, err := d.UnlockVia(ctx, api, a.userGUID(d), a.pin, t, dev, o, rel)
	keep()
	if serr := save(g, d); err == nil {
		err = serr
	}
	if err != nil {
		return err
	}
	if r.ReleaseChanged {
		fmt.Fprintln(os.Stderr, "note: the vault software was updated since the last unlock (§11.2 step 4)")
	}
	out := map[string]any{"ok": r.OK, "code": r.Code, "state_seq": r.StateSeq, "header_seq": r.HeaderSeq,
		"release_number": r.ReleaseNumber, "release_status": r.ReleaseStatus, "update": r.Update, "update_code": r.UpdateCode,
		"instance_id": r.InstanceID}
	if r.CredentialBackup != nil {
		out["credential_backup"] = *r.CredentialBackup // a recovered app (§11.11.5 step 1)
	}
	printJSON(out)
	return nil
}

func cmdAPIRecover(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("api-recover", flag.ExitOnError)
	var a apiFlags
	a.register(fs)
	qrArg := fs.String("qr", "", "the recovery QR payload (from the portal, or devstack's /dev/recovery/code)")
	_ = fs.Parse(args)
	if a.api == "" || a.pin == "" || *qrArg == "" {
		return errors.New("-api, -pin and -qr are required")
	}
	qr, err := altchan.ParseRecoveryQR([]byte(*qrArg))
	if err != nil {
		return fmt.Errorf("-qr: %w", err)
	}
	t := testTrust()
	d, err := loadWithTrust(g, t)
	if err != nil {
		return err
	}
	af := altFlags{platform: a.platform, seed: a.seed}
	dev, keep := af.attester(g)
	defer keep()
	if qr.API != "" && qr.API != strings.TrimRight(a.api, "/") {
		return fmt.Errorf("the recovery code is for another member API (%s)", qr.API)
	}
	api, err := a.client(d)
	if err != nil {
		return err
	}
	// The new app claims the recovery with its app key (§11.11.7): the
	// answer names the member.
	if _, err := d.ClaimVia(ctx, api, qr); err != nil {
		return fmt.Errorf("claim: %w", err)
	}
	rr, slot, err := d.RecoveryRegisterVia(ctx, api, d.UserGUID(), qr, t, dev)
	if serr := save(g, d); err == nil {
		err = serr
	}
	if err != nil {
		return err
	}
	if !rr.OK {
		return fmt.Errorf("register refused: %s", rr.Code)
	}
	u, err := d.UnlockVia(ctx, api, d.UserGUID(), a.pin, t, dev, client.UnlockOptions{}, "")
	if serr := save(g, d); err == nil {
		err = serr
	}
	if err != nil {
		return err
	}
	if !u.OK {
		return fmt.Errorf("unlock refused: %s", u.Code)
	}
	if err := d.CompleteRecoveryHandshake(ctx); err != nil {
		return err
	}
	out := map[string]any{"registered": true, "slot_code": slot.Code, "vault_id": d.VaultID()}
	if u.CredentialBackup != nil {
		out["credential_backup"] = *u.CredentialBackup
	}
	printJSON(out)
	return save(g, d)
}

func cmdAPILock(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("api-lock", flag.ExitOnError)
	var a apiFlags
	a.register(fs)
	_ = fs.Parse(args)
	if a.api == "" {
		return errors.New("-api is required")
	}
	d, err := load(g)
	if err != nil {
		return err
	}
	api, err := a.client(d)
	if err != nil {
		return err
	}
	s, err := d.LockVia(ctx, api)
	if err != nil {
		return err
	}
	printJSON(map[string]any{"status": s.Status, "code": s.Code})
	return nil
}

// devPassword is the credential password of development enrollments:
// VAULTCTL_PASSWORD, or a fixed development value.
func devPassword() string {
	if p := os.Getenv("VAULTCTL_PASSWORD"); p != "" {
		return p
	}
	return "development password"
}
