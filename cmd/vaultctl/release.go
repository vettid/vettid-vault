package main

// Release tooling (VAULT-RELEASES §6, §7, §10; docs/RELEASING.md):
// `vaultctl keycheck` and `vaultctl manifest`. Both run on the owner's
// machine with the owner's AWS credentials; neither is part of the
// enclave, so they may use the AWS SDK.

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/keycheck"
	"github.com/vettid/vettid-vault/internal/manifesttool"
	"github.com/vettid/vettid-vault/vms/manifest"
)

func init() {
	commands["keycheck"] = command{"keycheck -key-arn ARN -channel prod|staging -manifest FILE [-release N] [-config FILE] [-fixtures DIR] [-record DIR]   run the enclave's §11.10.7 check on a live release key; exit status = failing check number", cmdKeycheck}
	commands["manifest"] = command{"manifest render|check|digest|sign|import-sig ...   build, check and sign release manifests (vaultctl manifest -h)", cmdManifest}
}

// exitError carries a specific exit status.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// Exit statuses of keycheck: 1-8 the failing §11.10.7 check, 9 anything
// else (usage, configuration, AWS errors).
const keycheckOther = 9

// stringList is a repeatable flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// channelFile reads a channel's release constants: -config FILE, or
// enclave/releasecfg/<channel>.json in the current checkout.
func channelFile(channel, path string) (*releasecfg.File, string, error) {
	if path == "" {
		if channel != releasecfg.ChannelProd && channel != releasecfg.ChannelStaging {
			return nil, "", fmt.Errorf("unknown channel %q (prod or staging; the dev channel has no pinned constants, pass -pin keys)", channel)
		}
		path = filepath.Join("enclave", "releasecfg", channel+".json")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, path, err
	}
	f, err := releasecfg.Parse(b)
	if err != nil {
		return nil, path, fmt.Errorf("%s: %w", path, err)
	}
	if channel != "" && f.Config.Channel != channel {
		return nil, path, fmt.Errorf("%s is the %s channel's file, not %s's", path, f.Config.Channel, channel)
	}
	return f, path, nil
}

func cmdKeycheck(ctx context.Context, _ *globals, args []string) error {
	fs := flag.NewFlagSet("keycheck", flag.ContinueOnError)
	keyARN := fs.String("key-arn", "", "the release key's ARN (its manifest seal_key)")
	channel := fs.String("channel", "", "prod or staging: whose pinned constants to check with")
	cfgPath := fs.String("config", "", "channel file (default enclave/releasecfg/<channel>.json)")
	mfPath := fs.String("manifest", "", "the draft manifest bytes or the signed served document")
	release := fs.Uint64("release", 0, "the release whose key this is (default: the entry naming -key-arn)")
	fixtures := fs.String("fixtures", "", "check recorded DescribeKey/GetKeyPolicy/ListGrants responses in DIR instead of calling AWS")
	record := fs.String("record", "", "save the fetched responses in DIR")
	endpoint := fs.String("endpoint", "", "KMS endpoint (default https://kms.<pinned region>.amazonaws.com)")
	other := func(err error) error { return &exitError{keycheckOther, err} }
	if err := fs.Parse(args); err != nil {
		return other(err)
	}
	if *keyARN == "" || *mfPath == "" || (*channel == "" && *cfgPath == "") {
		return other(errors.New("-key-arn, -manifest and -channel (or -config) are required"))
	}
	f, path, err := channelFile(*channel, *cfgPath)
	if err != nil {
		return other(err)
	}
	cfg, err := f.Complete()
	if err != nil {
		return other(fmt.Errorf("%s: the channel's constants are not final, so there is nothing to check a key against: %w", path, err))
	}
	mb, err := os.ReadFile(*mfPath)
	if err != nil {
		return other(err)
	}
	m, signed, err := keycheck.LoadManifest(mb, cfg.ManifestKeys)
	if err != nil {
		return other(err)
	}
	target, err := keycheck.Target(m, *keyARN, *release)
	if err != nil {
		return other(err)
	}
	var resp *keycheck.Responses
	if *fixtures != "" {
		if resp, err = keycheck.Fixtures(*fixtures); err != nil {
			return other(err)
		}
	} else {
		ac, err := config.LoadDefaultConfig(ctx, config.WithRegion(cfg.SealRegion))
		if err != nil {
			return other(fmt.Errorf("AWS credentials: %w", err))
		}
		c := awskms.NewClient(httpClientOrDefault(), cfg.SealRegion, &awskms.CachedCredentials{Skew: time.Minute,
			Source: func(ctx context.Context) (awskms.Credentials, error) {
				cr, err := ac.Credentials.Retrieve(ctx)
				if err != nil {
					return awskms.Credentials{}, err
				}
				out := awskms.Credentials{AccessKeyID: cr.AccessKeyID, SecretAccessKey: cr.SecretAccessKey, SessionToken: cr.SessionToken}
				if cr.CanExpire {
					out.Expires = cr.Expires
				}
				return out, nil
			}})
		if *endpoint != "" {
			c.Endpoint = strings.TrimSuffix(*endpoint, "/")
		}
		if resp, err = keycheck.Fetch(ctx, c, *keyARN); err != nil {
			return other(err)
		}
	}
	if *record != "" {
		if err := resp.Record(*record); err != nil {
			return other(err)
		}
	}
	kind := "draft (unsigned)"
	if signed {
		kind = "signed"
	}
	res, err := keycheck.Run(cfg, m, target, *keyARN, resp)
	if n := keycheck.FailedCheck(err); n > 0 {
		fmt.Printf("keycheck: FAIL %s: release %d key %s, %s manifest serial %d, %s channel\n", err, target, *keyARN, kind, m.Serial, cfg.Channel)
		return &exitError{n, err}
	} else if err != nil {
		return other(err)
	}
	printJSON(map[string]any{"result": "pass", "key_arn": res.KeyARN, "policy_sha256": fmt.Sprintf("%x", res.PolicySHA256),
		"release": target, "channel": cfg.Channel, "manifest": kind, "manifest_serial": m.Serial,
		"manifest_sha256": manifest.SHA256Hex(m.Bytes)})
	return nil
}

func httpClientOrDefault() *http.Client {
	if httpClient != nil {
		return httpClient
	}
	return &http.Client{Timeout: 30 * time.Second}
}

const manifestUsage = `usage: vaultctl manifest SUBCOMMAND ...

  render -releases FILE (-serial N | -previous FILE) [-issued-at T] -out FILE
      render canonical manifest bytes (VAULT-MESSAGING §11.10.1) from a
      release list ({"releases":[...]}; candidates are left out); with
      -previous (the published manifest or served document) the serial is
      the previous one plus one and the successor rules are checked
  check -in FILE [-channel C | -config F | -pin F ...] [-previous FILE]
      parse strictly, require canonical bytes, print serial and sha256;
      a served document's signature must verify under the pinned keys
  digest -in FILE
      print the digest to sign: SHA-256("vettid/pcr-manifest/1" || 0x00 || bytes)
  sign -in FILE (-kms-key ARN | -key PEM) [-channel C | -config F | -pin F ...] -out FILE
      sign with KMS (key A) or a PEM test key, verify, write the served document
  import-sig -in FILE -sig FILE -signer-pub FILE [-channel C | -config F | -pin F ...] -out FILE
      import a signature made elsewhere (key B on its offline token: DER
      or r || s, as binary, hex, base64 or PEM), verify, write the served document

Pinned keys come from the channel file (-channel, -config) or -pin files
(P-256 SubjectPublicKeyInfo as PEM, base64 or hex).`

func cmdManifest(ctx context.Context, _ *globals, args []string) error {
	if len(args) == 0 {
		return manifestUsageErr()
	}
	sub, args := args[0], args[1:]
	fs := flag.NewFlagSet("manifest "+sub, flag.ContinueOnError)
	in := fs.String("in", "", "input manifest bytes or served document")
	out := fs.String("out", "", "output file")
	channel := fs.String("channel", "", "pinned manifest keys of this channel (prod or staging)")
	cfgPath := fs.String("config", "", "pinned manifest keys from this channel file")
	var pins stringList
	fs.Var(&pins, "pin", "pinned manifest public key file (repeatable)")
	releases := fs.String("releases", "", "release list (render)")
	serial := fs.Uint64("serial", 0, "serial (render)")
	previous := fs.String("previous", "", "the published manifest or served document (render, check)")
	issuedAt := fs.String("issued-at", "", "issued_at, RFC 3339 whole seconds UTC (render; default now)")
	kmsKey := fs.String("kms-key", "", "KMS key id or ARN (sign)")
	keyFile := fs.String("key", "", "PEM private key file, test keys only (sign)")
	sigFile := fs.String("sig", "", "signature file (import-sig)")
	signerPub := fs.String("signer-pub", "", "the signing key's public key file (import-sig)")
	fs.Usage = func() { fmt.Fprintln(os.Stderr, manifestUsage) }
	if err := fs.Parse(args); err != nil {
		return err
	}
	pinned := func() ([]*ecdsa.PublicKey, error) {
		var keys []*ecdsa.PublicKey
		if *channel != "" || *cfgPath != "" {
			f, path, err := channelFile(*channel, *cfgPath)
			if err != nil {
				return nil, err
			}
			if len(f.Config.ManifestKeys) == 0 {
				return nil, fmt.Errorf("%s pins no manifest key yet (placeholders)", path)
			}
			keys = append(keys, f.Config.ManifestKeys...)
		}
		for _, p := range pins {
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			k, err := manifesttool.ParsePublicKey(b)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", p, err)
			}
			keys = append(keys, k)
		}
		if len(keys) == 0 {
			return nil, errors.New("no pinned manifest keys: pass -channel, -config or -pin")
		}
		return keys, nil
	}
	// readManifest reads manifest bytes or a served document; a served
	// document is verified when keys are given.
	readManifest := func(path string, keys []*ecdsa.PublicKey) (*manifest.Manifest, bool, error) {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, false, err
		}
		if s, err := manifest.ParseServed(b); err == nil {
			if keys == nil {
				m, err := manifest.Parse(s.Manifest)
				return m, true, err
			}
			m, err := manifest.Verify(s, keys)
			return m, true, err
		}
		m, err := manifest.Parse(b)
		return m, false, err
	}
	write := func(b []byte) error {
		if *out == "" {
			return errors.New("-out is required")
		}
		return os.WriteFile(*out, b, 0o644)
	}

	switch sub {
	case "render":
		if *releases == "" || (*serial == 0) == (*previous == "") {
			return errors.New("render needs -releases and exactly one of -serial or -previous")
		}
		lb, err := os.ReadFile(*releases)
		if err != nil {
			return err
		}
		l, err := manifesttool.ParseList(lb)
		if err != nil {
			return err
		}
		at := time.Now().UTC()
		if *issuedAt != "" {
			if at, err = time.Parse("2006-01-02T15:04:05Z", *issuedAt); err != nil {
				return fmt.Errorf("-issued-at: %w", err)
			}
		}
		var prev *manifest.Manifest
		n := *serial
		if *previous != "" {
			if prev, _, err = readManifest(*previous, nil); err != nil {
				return fmt.Errorf("previous manifest: %w", err)
			}
			n = prev.Serial + 1
		}
		b, m, err := manifesttool.Render(l, n, at)
		if err != nil {
			return err
		}
		if prev != nil {
			if err := manifesttool.CheckSuccessor(prev, m); err != nil {
				return err
			}
		}
		if err := write(b); err != nil {
			return err
		}
		printJSON(manifesttool.Summarize(m))
		return nil
	case "check":
		if *in == "" {
			return errors.New("check needs -in")
		}
		var keys []*ecdsa.PublicKey
		if *channel != "" || *cfgPath != "" || len(pins) > 0 {
			var err error
			if keys, err = pinned(); err != nil {
				return err
			}
		}
		m, served, err := readManifest(*in, keys)
		if err != nil {
			return err
		}
		if served && keys == nil {
			return errors.New("a served document needs pinned keys to check its signature (-channel, -config or -pin)")
		}
		if !manifesttool.Canonical(m) {
			return errors.New("the manifest bytes are not canonical (unknown members or another member order)")
		}
		if *previous != "" {
			prev, _, err := readManifest(*previous, nil)
			if err != nil {
				return fmt.Errorf("previous manifest: %w", err)
			}
			if err := manifesttool.CheckSuccessor(prev, m); err != nil {
				return err
			}
		}
		s := manifesttool.Summarize(m)
		printJSON(map[string]any{"summary": s, "signed": served, "canonical": true})
		return nil
	case "digest":
		m, _, err := readManifest(*in, nil)
		if err != nil {
			return err
		}
		d := manifest.Digest(m.Bytes)
		printJSON(map[string]any{"label": manifest.Label, "digest_sha256": fmt.Sprintf("%x", d), "manifest_sha256": manifest.SHA256Hex(m.Bytes), "serial": m.Serial})
		return nil
	case "sign", "import-sig":
		keys, err := pinned()
		if err != nil {
			return err
		}
		m, served, err := readManifest(*in, nil)
		if err != nil {
			return err
		}
		if served {
			return errors.New("-in is already a served document; pass the manifest bytes")
		}
		var s *manifest.Served
		if sub == "sign" {
			var signer manifesttool.Signer
			switch {
			case *kmsKey != "" && *keyFile == "":
				ac, err := config.LoadDefaultConfig(ctx)
				if err != nil {
					return fmt.Errorf("AWS credentials: %w", err)
				}
				signer = manifesttool.KMSSigner{API: kms.NewFromConfig(ac), KeyID: *kmsKey}
			case *keyFile != "" && *kmsKey == "":
				b, err := os.ReadFile(*keyFile)
				if err != nil {
					return err
				}
				k, err := manifesttool.ParsePrivateKey(b)
				if err != nil {
					return err
				}
				signer = manifesttool.FileSigner{Key: k}
			default:
				return errors.New("sign needs exactly one of -kms-key or -key")
			}
			if s, err = manifesttool.Sign(ctx, signer, m.Bytes, keys); err != nil {
				return err
			}
		} else {
			if *sigFile == "" || *signerPub == "" {
				return errors.New("import-sig needs -sig and -signer-pub")
			}
			sb, err := os.ReadFile(*sigFile)
			if err != nil {
				return err
			}
			pb, err := os.ReadFile(*signerPub)
			if err != nil {
				return err
			}
			pub, err := manifesttool.ParsePublicKey(pb)
			if err != nil {
				return err
			}
			if s, err = manifesttool.Assemble(m.Bytes, manifesttool.DecodeBytes(sb), pub, keys); err != nil {
				return err
			}
		}
		if err := write(s.Marshal()); err != nil {
			return err
		}
		printJSON(map[string]any{"key_id": s.KeyID, "summary": manifesttool.Summarize(m)})
		return nil
	}
	return manifestUsageErr()
}

func manifestUsageErr() error {
	fmt.Fprintln(os.Stderr, manifestUsage)
	return errors.New("unknown or missing manifest subcommand")
}
