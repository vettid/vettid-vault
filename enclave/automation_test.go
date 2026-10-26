package enclave_test

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/enclave/releasecfg"
	"github.com/vettid/vettid-vault/internal/autoattest"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/pins"
)

// VAULT-RELEASES §3.1 (owner decision 2026-10-27): a staging image
// accepts its automation attestation CA beside the vendor roots, and only
// a staging image does. The CA here is the TEST Android CA standing in
// for it; every other check of §11.7 still applies (package, signer,
// security level, root of trust).
func TestReleaseConfigAutomationRoots(t *testing.T) {
	ca := enclavetest.TestAndroidCA()
	dev := enclavetest.AndroidSignerDev
	conf := func(channel string) *releasecfg.Config {
		return &releasecfg.Config{Channel: channel, AndroidPackage: releasecfg.AndroidPackages[releasecfg.ChannelStaging],
			AndroidSigners: []releasecfg.Signer{{Digest: dev[:], Class: devattest.ClassDevelopment}},
			Automation:     &releasecfg.Automation{AndroidRoots: []*x509.Certificate{ca.Root.Cert}, Until: time.Now().AddDate(0, 1, 0)}}
	}
	now := time.Now()
	var ch [32]byte
	ch[0] = 7
	chain := ca.Attest(enclavetest.TestKey(elliptic.P256(), 0x31), enclavetest.AndroidOptions{Challenge: ch, Package: "com.vettid.app.staging", Signers: [][]byte{dev[:]}})
	att := &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: chain}
	list := enclavetest.EmptyStatusList(now)

	st := enclave.ReleaseConfigFor(conf(releasecfg.ChannelStaging), "i-1", enclave.DefaultRelayURL).DeviceAttest
	if len(st.AndroidRoots) != len(pins.GoogleAttestationRoots())+1 {
		t.Fatalf("staging roots: %d", len(st.AndroidRoots))
	}
	b, err := devattest.VerifyAttest(st, att, ch, now, list)
	if err != nil {
		t.Fatalf("staging refused the automation chain: %v", err)
	}
	if b.SignerClass != devattest.ClassDevelopment {
		t.Fatalf("signer class %q", b.SignerClass)
	}
	// The vendor roots are untouched by the append.
	if again := enclave.ReleaseConfigFor(nil, "i-1", enclave.DefaultRelayURL).DeviceAttest; len(again.AndroidRoots) != len(pins.GoogleAttestationRoots()) {
		t.Fatalf("vendor roots changed: %d", len(again.AndroidRoots))
	}
	// Only the root differs: a wrong package, an unpinned signer, a
	// software key or an unlocked device is still refused on staging.
	for name, o := range map[string]enclavetest.AndroidOptions{
		"package":  {Challenge: ch, Package: "com.vettid.app", Signers: [][]byte{dev[:]}},
		"signer":   {Challenge: ch, Package: "com.vettid.app.staging"},
		"software": {Challenge: ch, Package: "com.vettid.app.staging", Signers: [][]byte{dev[:]}, SoftwareLevel: true},
		"unlocked": {Challenge: ch, Package: "com.vettid.app.staging", Signers: [][]byte{dev[:]}, Unlocked: true},
	} {
		a := &altchan.DeviceAttest{Platform: altchan.PlatformAndroid, Chain: ca.Attest(enclavetest.TestKey(elliptic.P256(), 0x31), o)}
		if _, err := devattest.VerifyAttest(st, a, ch, now, list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A configuration of any other channel ignores the roots, however it
	// was built: the chain does not end at a pinned root.
	for _, c := range []*releasecfg.Config{conf(releasecfg.ChannelProd), conf("")} {
		pol := enclave.ReleaseConfigFor(c, "i-1", enclave.DefaultRelayURL).DeviceAttest
		if len(pol.AndroidRoots) != len(pins.GoogleAttestationRoots()) {
			t.Fatalf("%q: roots %d", c.Channel, len(pol.AndroidRoots))
		}
		if _, err := devattest.VerifyAttest(pol, att, ch, now, list); !errors.Is(err, devattest.ErrRoot) {
			t.Fatalf("%q accepted the automation chain: %v", c.Channel, err)
		}
	}
}

// The embedded configuration: a production image never accepts more than
// the vendor roots. Run with -tags vettid_channel_prod /
// vettid_channel_staging by `make channels`.
func TestReleaseConfigAutomationEmbedded(t *testing.T) {
	cfg := enclave.ReleaseConfig("i-1", enclave.DefaultRelayURL)
	ch, c := releasecfg.Embedded()
	want := len(pins.GoogleAttestationRoots())
	if ch == releasecfg.ChannelStaging {
		want += len(c.AutomationRoots())
	}
	if got := len(cfg.DeviceAttest.AndroidRoots); got != want {
		t.Fatalf("channel %q: %d Android roots, want %d", ch, got, want)
	}
}

// The staging automation attester (internal/autoattest) with a local
// TEST CA key standing in for the KMS key: its chain passes the device
// policy built from the committed staging file plus the automation
// member, and fails the one built from the committed production file.
func TestAutomationAttesterAgainstChannelFiles(t *testing.T) {
	caKey := enclavetest.TestKey(elliptic.P256(), 0x5a)
	now := time.Now().UTC()
	until := now.AddDate(0, 6, 0)
	caDER, err := autoattest.NewCA(caKey, now.Add(-24*time.Hour), until)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	read := func(ch, extra string) []byte {
		b, err := os.ReadFile("releasecfg/" + ch + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if extra == "" {
			return b
		}
		return []byte(strings.TrimSuffix(strings.TrimSpace(string(b)), "}") + extra + "}")
	}
	member := `,"automation_attestation":{"android_roots":["` + base64.StdEncoding.EncodeToString(caDER) + `"],"until":"` + until.Format(time.DateOnly) + `"}`
	st, err := releasecfg.Check(releasecfg.ChannelStaging, read("staging", member))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CheckEndDates(now); err != nil {
		t.Fatal(err)
	}
	var dev []byte
	for _, sg := range st.AndroidSigners {
		if sg.Class == devattest.ClassDevelopment {
			dev = sg.Digest
		}
	}
	if dev == nil {
		t.Fatal("staging.json pins no development signer")
	}
	at := &autoattest.Attester{Key: enclavetest.TestKey(elliptic.P256(), 0x5b), CA: caCert, CAKey: caKey,
		Package: st.AndroidPackage, Signer: dev, VersionCode: int64(st.AndroidMinVersionCode)}
	var ch [32]byte
	ch[1] = 9
	att, err := at.Attest(ch)
	if err != nil {
		t.Fatal(err)
	}
	list := enclavetest.EmptyStatusList(now)
	pol := enclave.ReleaseConfigFor(st, "i-1", enclave.DefaultRelayURL).DeviceAttest
	b, err := devattest.VerifyAttest(pol, att, ch, now, list)
	if err != nil {
		t.Fatalf("the staging policy refused the automation chain: %v", err)
	}
	if b.SignerClass != devattest.ClassDevelopment {
		t.Fatalf("signer class %q", b.SignerClass)
	}
	// The unlock's device_assertion verifies with the recorded key.
	var uch [32]byte
	uch[2] = 3
	as, err := at.Assert(devattest.ForChallenge(uch))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devattest.VerifyAssertion(pol, b, as, devattest.ForChallenge(uch), 0, now, list); err != nil {
		t.Fatalf("assertion: %v", err)
	}
	// Every other check still applies: an older version code, another
	// package, an unpinned signer; and past the CA's end the chain is
	// refused (chain rule 7) and the attester refuses to issue.
	for name, edit := range map[string]func(a *autoattest.Attester){
		"version code": func(a *autoattest.Attester) { a.VersionCode = int64(st.AndroidMinVersionCode) - 1 },
		"package":      func(a *autoattest.Attester) { a.Package = "com.vettid.app" },
		"signer":       func(a *autoattest.Attester) { a.Signer = make([]byte, 32) },
	} {
		a := *at
		edit(&a)
		bad, err := a.Attest(ch)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := devattest.VerifyAttest(pol, bad, ch, now, list); !errors.Is(err, devattest.ErrApplication) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := devattest.VerifyAttest(pol, att, ch, caCert.NotAfter.Add(time.Second), enclavetest.EmptyStatusList(caCert.NotAfter.Add(time.Second))); !errors.Is(err, devattest.ErrChain) {
		t.Fatalf("after the end date: %v", err)
	}
	late := *at
	late.Now = func() time.Time { return caCert.NotAfter.Add(time.Second) }
	if _, err := late.Attest(ch); err == nil {
		t.Fatal("issued after the CA's end")
	}
	// Production: the member is malformed in prod.json, and the policy
	// built from prod.json (complete or not) does not accept the chain.
	if _, err := releasecfg.Parse(read("prod", member)); !errors.Is(err, releasecfg.ErrFormat) {
		t.Fatalf("prod.json with the member: %v", err)
	}
	pf, err := releasecfg.Parse(read("prod", ""))
	if err != nil {
		t.Fatal(err)
	}
	pc := pf.Config
	pc.Automation = st.Automation // even if a production configuration held it
	ppol := enclave.ReleaseConfigFor(&pc, "i-1", enclave.DefaultRelayURL).DeviceAttest
	if _, err := devattest.VerifyAttest(ppol, att, ch, now, list); !errors.Is(err, devattest.ErrRoot) {
		t.Fatalf("the production policy: %v", err)
	}
	// Nor with the production package and a production-pinned signer.
	prodAt := *at
	prodAt.Package, prodAt.Signer = pc.AndroidPackage, pc.AndroidSigners[0].Digest
	pa, err := prodAt.Attest(ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devattest.VerifyAttest(ppol, pa, ch, now, list); !errors.Is(err, devattest.ErrRoot) {
		t.Fatalf("the production policy, production identity: %v", err)
	}
}
