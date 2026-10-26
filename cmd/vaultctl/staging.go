package main

// Staging automation (VAULT-RELEASES §3.1; owner decision 2026-10-27):
// an automated test enrolls and unlocks a staging app device without a
// phone, with an Android key attestation chain issued by the staging
// automation attestation CA, whose key is an AWS KMS key in the staging
// account. Release builds of vaultctl have these commands (they need no
// test code); they refuse anything but the staging channel, and a
// production image refuses the CA in any case (releasecfg).
//
//	vaultctl staging-ca-cert -kms-key KEY -until YYYY-MM-DD       (once, by the owner)
//	vaultctl -state app.json init -role app -name automation -relay https://relay.vettid.org
//	VAULTCTL_PORTAL_COOKIE=... VAULTCTL_PIN=... VAULTCTL_PASSWORD=... \
//	  vaultctl -state app.json staging-enroll -kms-key KEY
//	VAULTCTL_PIN=... vaultctl -state app.json staging-unlock

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/autoattest"
	"github.com/vettid/vettid-vault/internal/manifesttool"
	"github.com/vettid/vettid-vault/vms/altchan"
)

func init() {
	commands["staging-ca-cert"] = command{"staging-ca-cert -kms-key KEY -until YYYY-MM-DD [-region R]   (owner, once) the staging automation attestation CA certificate, self-signed by the KMS key; prints the channel file member", cmdStagingCACert}
	commands["staging-enroll"] = command{"staging-enroll -kms-key KEY [-config FILE] [-portal URL] [-manifest-url URL] [-version-code N]   enroll this app device on staging with the automation CA (reads VAULTCTL_PORTAL_COOKIE, VAULTCTL_PIN, VAULTCTL_PASSWORD)", cmdStagingEnroll}
	commands["staging-unlock"] = command{"staging-unlock [-config FILE] [-api URL] [-manifest-url URL]   unlock this staging app device's vault (reads VAULTCTL_PIN)", cmdStagingUnlock}
}

// The staging channel's public endpoints (VAULT-RELEASES §3.1; vettid.org
// lib/config.ts).
const (
	stagingPortal      = "https://account.staging.vettid.org"
	stagingManifestURL = "https://staging.vettid.org/.well-known/vettid/pcr-manifest.json"
	stagingZone        = "staging.vettid.org"
)

// stagingURL refuses any URL that is not https on staging.vettid.org or a
// host under it: these commands never talk to a production endpoint.
func stagingURL(what, s string) (string, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" {
		return "", fmt.Errorf("%s %q: not an https URL", what, s)
	}
	h := strings.ToLower(u.Hostname())
	if h != stagingZone && !strings.HasSuffix(h, "."+stagingZone) {
		return "", fmt.Errorf("%s %q is not a staging host (*.%s): refusing", what, s, stagingZone)
	}
	return strings.TrimRight(s, "/"), nil
}

// stagingChannel reads the staging channel file (-config, default the
// checkout's enclave/releasecfg/staging.json) and refuses any other
// channel, an incomplete file, and (with needCA) a file without an
// automation CA or past its end date.
func stagingChannel(path string, needCA bool, now time.Time) (*releasecfg.Config, error) {
	f, p, err := channelFile(releasecfg.ChannelStaging, path)
	if err != nil {
		return nil, err
	}
	if f.Config.Channel != releasecfg.ChannelStaging {
		return nil, fmt.Errorf("%s is not the staging channel's file: refusing", p)
	}
	c, err := f.Complete()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if needCA {
		if len(c.AutomationRoots()) == 0 {
			return nil, fmt.Errorf("%s has no automation_attestation: this staging release accepts no automation CA", p)
		}
		if err := c.CheckEndDates(now); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
	}
	return c, nil
}

// stagingTrust is what a staging app pins: the AWS Nitro root and the
// staging manifest keys (never the production ones).
func stagingTrust(c *releasecfg.Config) client.Trust {
	return client.Trust{NitroRoots: enclave.NitroRoots(), ManifestKeys: c.ManifestKeys}
}

// kmsCA is a crypto.Signer backed by an AWS KMS ECC_NIST_P256 SIGN_VERIFY
// key (ECDSA_SHA_256 over the digest, DER signature): the automation CA
// key never leaves KMS.
type kmsCA struct {
	ctx   context.Context
	api   manifesttool.KMSAPI
	keyID string
	pub   *ecdsa.PublicKey
}

func newKMSCA(ctx context.Context, api manifesttool.KMSAPI, keyID string) (*kmsCA, error) {
	pub, err := manifesttool.KMSSigner{API: api, KeyID: keyID}.Public(ctx)
	if err != nil {
		return nil, err
	}
	return &kmsCA{ctx: ctx, api: api, keyID: keyID, pub: pub}, nil
}

func (k *kmsCA) Public() crypto.PublicKey { return k.pub }

func (k *kmsCA) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 || len(digest) != 32 {
		return nil, errors.New("kms CA: only SHA-256 digests")
	}
	out, err := k.api.Sign(k.ctx, &kms.SignInput{KeyId: aws.String(k.keyID), Message: digest,
		MessageType: kmstypes.MessageTypeDigest, SigningAlgorithm: kmstypes.SigningAlgorithmSpecEcdsaSha256})
	if err != nil {
		return nil, fmt.Errorf("kms Sign: %w", err)
	}
	if len(out.Signature) == 0 {
		return nil, errors.New("kms Sign: empty signature")
	}
	return out.Signature, nil
}

// kmsClient is the KMS client of the caller's AWS credentials (AWS_PROFILE
// or the default chain) in region.
var kmsClient = func(ctx context.Context, region string) (manifesttool.KMSAPI, error) {
	ac, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, err
	}
	return kms.NewFromConfig(ac), nil
}

// kmsKeyFlag is -kms-key, defaulting to VAULTCTL_ATTEST_KMS_KEY.
func kmsKeyFlag(fs *flag.FlagSet) *string {
	return fs.String("kms-key", os.Getenv("VAULTCTL_ATTEST_KMS_KEY"), "the automation CA's KMS key (id, ARN or alias; default $VAULTCTL_ATTEST_KMS_KEY)")
}

func cmdStagingCACert(ctx context.Context, _ *globals, args []string) error {
	fs := flag.NewFlagSet("staging-ca-cert", flag.ContinueOnError)
	keyID := kmsKeyFlag(fs)
	untilS := fs.String("until", "", "the switch's end date, YYYY-MM-DD (UTC; STAGING-DEVELOPMENT-PLAN §2.5.5)")
	region := fs.String("region", "us-east-1", "the KMS key's region")
	if err := fs.Parse(args); err != nil {
		return err
	}
	until, err := time.Parse(time.DateOnly, *untilS)
	if *keyID == "" || err != nil {
		return errors.New("-kms-key and -until YYYY-MM-DD are required")
	}
	now := time.Now().UTC()
	if until.After(now.AddDate(0, 0, releasecfg.MaxAutomationDays)) || until.Before(now) {
		return fmt.Errorf("-until must be between today and %d days from now", releasecfg.MaxAutomationDays)
	}
	api, err := kmsClient(ctx, *region)
	if err != nil {
		return err
	}
	ca, err := newKMSCA(ctx, api, *keyID)
	if err != nil {
		return err
	}
	der, err := autoattest.NewCA(ca, now.Add(-time.Hour), until)
	if err != nil {
		return err
	}
	if err := pem.Encode(os.Stderr, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		return err
	}
	printJSON(map[string]any{"automation_attestation": map[string]any{
		"android_roots": []string{base64.StdEncoding.EncodeToString(der)}, "until": until.Format(time.DateOnly)}})
	return nil
}

// attestKeyPath is the automation device key's file, next to the state.
func attestKeyPath(g *globals) string { return g.state + ".attest-key" }

// deviceKey loads the automation device attestation key, or (create)
// makes one: a software P-256 key in a 0600 PEM file beside the state
// file. It is the key the vault records; unlocks sign with it.
func deviceKey(g *globals, create bool) (*ecdsa.PrivateKey, error) {
	p := attestKeyPath(g)
	b, err := os.ReadFile(p)
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil || blk.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("%s: not a PEM private key", p)
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok || ek.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%s: not a P-256 key", p)
		}
		return ek, nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	return k, nil
}

// developmentSigner is the staging file's development-class signer
// digest: the automation reports the automation signing certificate.
func developmentSigner(c *releasecfg.Config) ([]byte, error) {
	for _, s := range c.AndroidSigners {
		if s.Class == "development" {
			return s.Digest, nil
		}
	}
	return nil, errors.New("the staging file pins no development signer")
}

// automationCA returns the pinned automation root whose key is the KMS
// key's: the KMS key must be the CA this staging file names.
func automationCA(c *releasecfg.Config, pub *ecdsa.PublicKey) (*x509.Certificate, error) {
	for _, r := range c.AutomationRoots() {
		if rk, ok := r.PublicKey.(*ecdsa.PublicKey); ok && rk.Equal(pub) {
			return r, nil
		}
	}
	return nil, errors.New("the KMS key is not an automation CA the staging file pins")
}

// portalSession is the account site's member session for the portal's
// routes (MEMBER-API "Session model"): the browser's cookies, and the
// CSRF header every state-changing request needs.
func portalSession(base, cookie string) (*client.MemberAPI, error) {
	if cookie == "" || !strings.Contains(cookie, "=") || strings.ContainsAny(cookie, "\r\n") {
		return nil, errors.New("set VAULTCTL_PORTAL_COOKIE to the account site's Cookie header (vid_id=...; vid_rt=...)")
	}
	return &client.MemberAPI{Base: base, HTTP: httpClient, Authorize: func(r *http.Request) {
		r.Header.Set("Cookie", cookie)
		r.Header.Set("X-VettID-CSRF", "1")
	}}, nil
}

func pinEnv() (string, error) { return password("VAULTCTL_PIN") }

func cmdStagingEnroll(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("staging-enroll", flag.ContinueOnError)
	keyID := kmsKeyFlag(fs)
	cfgPath := fs.String("config", "", "the staging channel file (default enclave/releasecfg/staging.json)")
	portal := fs.String("portal", stagingPortal, "the staging account site (member session)")
	manifestURL := fs.String("manifest-url", stagingManifestURL, "the staging release manifest")
	versionCode := fs.Int64("version-code", 0, "the app version code to report (default the file's android_min_version_code)")
	region := fs.String("region", "", "the KMS key's region (default the file's seal_region)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyID == "" {
		return errors.New("-kms-key (or VAULTCTL_ATTEST_KMS_KEY) is required")
	}
	pin, err := pinEnv()
	if err != nil {
		return err
	}
	pw, err := password("VAULTCTL_PASSWORD")
	if err != nil {
		return err
	}
	c, err := stagingChannel(*cfgPath, true, time.Now())
	if err != nil {
		return err
	}
	portalURL, err := stagingURL("-portal", *portal)
	if err != nil {
		return err
	}
	mURL, err := stagingURL("-manifest-url", *manifestURL)
	if err != nil {
		return err
	}
	vc := *versionCode
	if vc == 0 {
		vc = int64(c.AndroidMinVersionCode)
	}
	if vc < int64(c.AndroidMinVersionCode) {
		return fmt.Errorf("-version-code %d is below the staging minimum %d", vc, c.AndroidMinVersionCode)
	}
	signer, err := developmentSigner(c)
	if err != nil {
		return err
	}
	rg := *region
	if rg == "" {
		rg = c.SealRegion
	}
	kapi, err := kmsClient(ctx, rg)
	if err != nil {
		return err
	}
	caKey, err := newKMSCA(ctx, kapi, *keyID)
	if err != nil {
		return err
	}
	caCert, err := automationCA(c, caKey.pub)
	if err != nil {
		return err
	}
	t := stagingTrust(c)
	d, err := loadTrusted(g, t)
	if err != nil {
		return err
	}
	if d.VaultID() != "" {
		return fmt.Errorf("%s already belongs to vault %s: use a fresh state file", g.state, d.VaultID())
	}
	key, err := deviceKey(g, true)
	if err != nil {
		return err
	}
	att := &autoattest.Attester{Key: key, CA: caCert, CAKey: caKey, Package: c.AndroidPackage, Signer: signer, VersionCode: vc}

	// The portal issues a setup code (MEMBER-API "Setup codes"); the app
	// redeems it with its app key (§11.12.1) and enrolls.
	ps, err := portalSession(portalURL, os.Getenv("VAULTCTL_PORTAL_COOKIE"))
	if err != nil {
		return err
	}
	code, err := ps.IssueEnrollCode(ctx)
	if err != nil {
		return fmt.Errorf("enroll-code: %w", err)
	}
	apiURL, err := stagingURL("the setup code's api", code.API)
	if err != nil {
		return err
	}
	qr, err := code.QR()
	if err != nil {
		return err
	}
	q, err := altchan.ParseEnrollQR(qr)
	if err != nil {
		return err
	}
	api, err := d.APIFor(apiURL, httpClient)
	if err != nil {
		return err
	}
	api.ManifestURL = mURL
	red, err := d.RedeemVia(ctx, api, q.SecretString(), "", "")
	if err != nil {
		return fmt.Errorf("redeem: %w", err)
	}
	fmt.Fprintf(os.Stderr, "setting up a staging vault for %s\n", red.EmailHint)
	vid, r, err := d.EnrollVia(ctx, api, red.UserGUID, pin, t, att)
	if serr := save(g, d); err == nil {
		err = serr
	}
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
	if err := d.CredentialCreate(ctx, pin, pw); err != nil {
		return fmt.Errorf("credential.create: %w", err)
	}
	if rr, err := d.Request(ctx, "vault.enroll.confirm", json.RawMessage(`{}`)); err != nil || !rr.OK() {
		return errors.New("vault.enroll.confirm failed")
	}
	fmt.Println(vid)
	return save(g, d)
}

func cmdStagingUnlock(ctx context.Context, g *globals, args []string) error {
	fs := flag.NewFlagSet("staging-unlock", flag.ContinueOnError)
	cfgPath := fs.String("config", "", "the staging channel file (default enclave/releasecfg/staging.json)")
	apiFlag := fs.String("api", stagingPortal, "the staging member API origin")
	manifestURL := fs.String("manifest-url", stagingManifestURL, "the staging release manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pin, err := pinEnv()
	if err != nil {
		return err
	}
	c, err := stagingChannel(*cfgPath, false, time.Now())
	if err != nil {
		return err
	}
	apiURL, err := stagingURL("-api", *apiFlag)
	if err != nil {
		return err
	}
	mURL, err := stagingURL("-manifest-url", *manifestURL)
	if err != nil {
		return err
	}
	t := stagingTrust(c)
	d, err := loadTrusted(g, t)
	if err != nil {
		return err
	}
	key, err := deviceKey(g, false)
	if err != nil {
		return fmt.Errorf("the automation device key: %w", err)
	}
	api, err := d.APIFor(apiURL, httpClient)
	if err != nil {
		return err
	}
	api.ManifestURL = mURL
	// An unlock only asserts with the device key: no CA signature.
	att := &autoattest.Attester{Key: key}
	r, err := d.UnlockVia(ctx, api, d.UserGUID(), pin, t, att, client.UnlockOptions{}, "")
	if serr := save(g, d); err == nil {
		err = serr
	}
	if err != nil {
		return err
	}
	printJSON(map[string]any{"ok": r.OK, "code": r.Code, "release_number": r.ReleaseNumber, "release_status": r.ReleaseStatus,
		"update": r.Update, "update_code": r.UpdateCode, "instance_id": r.InstanceID})
	if !r.OK {
		return fmt.Errorf("unlock refused: %s", r.Code)
	}
	return nil
}

// loadTrusted loads the device state with trust t.
func loadTrusted(g *globals, t client.Trust) (*client.Device, error) {
	b, err := os.ReadFile(g.state)
	if err != nil {
		return nil, fmt.Errorf("%w (run vaultctl -state %s init -role app ... first)", err, g.state)
	}
	return client.Load(client.Config{Trust: &t, HTTP: httpClient}, b)
}
