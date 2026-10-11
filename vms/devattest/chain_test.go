package devattest_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// goodKeyDescription returns an attestation extension the test policy
// accepts for the challenge: what a key attestation of the VettID app on
// a locked, verified device says. (Whoever signs a certificate writes its
// extensions; these bytes are no secret.)
func goodKeyDescription(t testing.TB, ch [32]byte) []byte {
	t.Helper()
	good := enclavetest.TestAndroidCA().Attest(enclavetest.TestKey(elliptic.P256(), 0x78), enclavetest.AndroidOptions{Challenge: ch})
	leaf, err := x509.ParseCertificate(good[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range leaf.Extensions {
		if e.Id.Equal(devattest.OIDKeyDescription) {
			return e.Value
		}
	}
	t.Fatal("no key description")
	return nil
}

// certOpts shape one test certificate.
type certOpts struct {
	serial     int64
	ca         bool // basicConstraints cA TRUE
	notCA      bool // basicConstraints cA FALSE (otherwise no basicConstraints)
	pathLen    int  // with ca: -1 none
	usage      x509.KeyUsage
	keyDesc    []byte // the attestation extension
	provision  bool   // the RKP provisioning information extension
	selfSigned bool
}

// issueCert issues a test certificate for pub under parent (DER).
func issueCert(t testing.TB, parent *x509.Certificate, parentKey crypto.Signer, pub crypto.PublicKey, o certOpts) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(o.serial), Subject: pkix.Name{CommonName: "TEST chain rules", SerialNumber: big.NewInt(o.serial).String()},
		NotBefore: now.AddDate(-1, 0, 0), NotAfter: now.AddDate(10, 0, 0), KeyUsage: o.usage}
	if o.ca {
		tmpl.BasicConstraintsValid, tmpl.IsCA = true, true
		tmpl.MaxPathLen, tmpl.MaxPathLenZero = o.pathLen, o.pathLen == 0
	} else if o.notCA {
		tmpl.BasicConstraintsValid = true
	}
	if o.keyDesc != nil {
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: devattest.OIDKeyDescription, Value: o.keyDesc})
	}
	if o.provision {
		// ProvisioningInfo is a CBOR map; {1: 3} (certificates issued).
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier(oidProvisioningInfo), Value: []byte{0xa1, 0x01, 0x03}})
	}
	if o.selfSigned {
		parent = tmpl
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func raws(cs ...*x509.Certificate) [][]byte {
	var out [][]byte
	for _, c := range cs {
		out = append(out, c.Raw)
	}
	return out
}

// checkChain runs a chain through both entry points: VerifyAttest (an
// enrollment, a transfer's hs.init, a recovery's register) and BindSigner
// (the stored chain of a vault enrolled before 0.27.0, with the binding
// such a release would have stored for it). want nil: both accept.
func checkChain(t *testing.T, name string, p *devattest.Policy, chain [][]byte, ch [32]byte, want error) {
	t.Helper()
	b, err := devattest.VerifyAttest(p, &altchan.DeviceAttest{Platform: "android", Chain: chain}, ch, now, fresh())
	if want == nil && err != nil || want != nil && !errors.Is(err, want) {
		t.Errorf("%s: VerifyAttest: %v, want %v", name, err, want)
	}
	if err == nil && (b.Signer == "" || len(b.Serials) != len(chain)) {
		t.Errorf("%s: binding %+v", name, b)
	}
	nb, err := devattest.BindSigner(p, bindingOf(t, nil, chain), chain)
	if want == nil && err != nil || want != nil && !errors.Is(err, want) {
		t.Errorf("%s: BindSigner: %v, want %v", name, err, want)
	}
	if err == nil && nb.Signer == "" {
		t.Errorf("%s: bound without a signer", name)
	}
}

// The demonstrated attack and its regression test: a chain extended below
// a genuinely attested key. The phone's own attestation is genuine (and
// here refused: its bootloader is unlocked); its Keystore key then signs a
// certificate for a software key, with an attestation extension that says
// everything the policy wants. Before the fix this was accepted, and the
// software key was bound with the signer the extension named.
func TestAndroidChainExtendedBelowAttestedKey(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	kd := goodKeyDescription(t, ch)
	soft, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]enclavetest.AndroidOptions{
		"unlocked phone":        {Unlocked: true, Challenge: challenge("anything")},
		"locked phone":          {Challenge: challenge("anything")},
		"another app's key":     {Package: "com.example.other", Challenge: challenge("anything")},
		"software-level key":    {SoftwareLevel: true, Challenge: challenge("anything")},
		"this very attestation": {Challenge: ch},
	} {
		attested := enclavetest.TestKey(elliptic.P256(), 0x77)
		genuine := enclavetest.TestAndroidCA().Attest(attested, o)
		parent, err := x509.ParseCertificate(genuine[0])
		if err != nil {
			t.Fatal(err)
		}
		forged := issueCert(t, parent, attested, soft.Public(), certOpts{serial: 1, keyDesc: kd, usage: x509.KeyUsageDigitalSignature})
		checkChain(t, name, p, append([][]byte{forged.Raw}, genuine...), ch, devattest.ErrChain)
		// The same with a claim to be a CA in between, at either depth.
		mid := issueCert(t, parent, attested, soft.Public(), certOpts{serial: 2, ca: true, pathLen: -1, usage: x509.KeyUsageCertSign})
		deep := issueCert(t, mid, soft, soft.Public(), certOpts{serial: 3, keyDesc: kd, usage: x509.KeyUsageDigitalSignature})
		checkChain(t, name+", through a CA certificate", p, append(raws(deep, mid), genuine...), ch, devattest.ErrChain)
		// The forged certificate anywhere else breaks the signatures.
		checkChain(t, name+", forged second", p, [][]byte{genuine[0], forged.Raw, genuine[1], genuine[2]}, ch, devattest.ErrChain)
		checkChain(t, name+", forged third", p, [][]byte{genuine[0], genuine[1], forged.Raw, genuine[2]}, ch, devattest.ErrChain)
		checkChain(t, name+", forged last", p, append(append([][]byte(nil), genuine...), forged.Raw), ch, devattest.ErrChain)
		// A leaf without the extension above an attested key.
		plain := issueCert(t, parent, attested, soft.Public(), certOpts{serial: 4, usage: x509.KeyUsageDigitalSignature})
		checkChain(t, name+", no extension on the leaf", p, append([][]byte{plain.Raw}, genuine...), ch, devattest.ErrChain)
	}
}

// The chain rules one by one, on a test PKI built for each case under its
// own pinned root.
func TestAndroidChainRules(t *testing.T) {
	ch := challenge("enroll")
	kd := goodKeyDescription(t, ch)
	key := func(seed byte) *ecdsa.PrivateKey { return enclavetest.TestKey(elliptic.P256(), seed) }
	rootKey, k1, k2, k3, leafKey := key(0x81), key(0x82), key(0x83), key(0x84), key(0x85)
	root := issueCert(t, nil, rootKey, rootKey.Public(), certOpts{serial: 1, ca: true, pathLen: -1, usage: x509.KeyUsageCertSign, selfSigned: true})
	p := enclavetest.Policy()
	p.AndroidRoots = []*x509.Certificate{root}
	ca := certOpts{ca: true, pathLen: -1, usage: x509.KeyUsageCertSign}
	with := func(o certOpts, edit func(*certOpts)) certOpts { edit(&o); return o }
	leafOf := func(parent *x509.Certificate, parentKey crypto.Signer) *x509.Certificate {
		return issueCert(t, parent, parentKey, leafKey.Public(), certOpts{serial: 100, keyDesc: kd, usage: x509.KeyUsageDigitalSignature})
	}
	// chainOf issues root -> opts[0] -> opts[1] ... -> leaf and returns
	// the chain, leaf first.
	chainOf := func(opts ...certOpts) []*x509.Certificate {
		keys := []*ecdsa.PrivateKey{k1, k2, k3}
		parent, parentKey := root, crypto.Signer(rootKey)
		out := []*x509.Certificate{root}
		for i, o := range opts {
			o.serial = int64(10 + i)
			c := issueCert(t, parent, parentKey, keys[i].Public(), o)
			out = append([]*x509.Certificate{c}, out...)
			parent, parentKey = c, keys[i]
		}
		return append([]*x509.Certificate{leafOf(parent, parentKey)}, out...)
	}
	for name, tc := range map[string]struct {
		chain []*x509.Certificate
		want  error
	}{
		// Shapes of real chains.
		"factory: intermediate, attestation certificate": {chainOf(ca, ca), nil},
		"attestation certificate with pathLen 0":         {chainOf(ca, with(ca, func(o *certOpts) { o.pathLen = 0 })), nil},
		"remotely provisioned: provisioning info above the leaf": {chainOf(with(ca, func(o *certOpts) { o.pathLen = 2 }), ca,
			with(ca, func(o *certOpts) { o.provision = true })), nil},
		"provisioning info on a factory-length chain":     {chainOf(ca, with(ca, func(o *certOpts) { o.provision = true })), nil},
		"attestation certificate straight under the root": {chainOf(ca), nil},
		// Older devices: the attestation certificate says cA FALSE and
		// digitalSignature only (Pixel 2, Sony Xperia 10 III). Accepted,
		// as before; it carries no attestation extension.
		"old device: attestation certificate not a CA":     {chainOf(ca, certOpts{notCA: true, usage: x509.KeyUsageDigitalSignature}), nil},
		"attestation certificate without basicConstraints": {chainOf(ca, certOpts{usage: x509.KeyUsageDigitalSignature}), nil},
		"CA certificates without a keyUsage":               {chainOf(with(ca, func(o *certOpts) { o.usage = 0 }), with(ca, func(o *certOpts) { o.usage = 0 })), nil},
		"path length exactly used":                         {chainOf(with(ca, func(o *certOpts) { o.pathLen = 2 }), with(ca, func(o *certOpts) { o.pathLen = 1 }), ca), nil},

		// Rule: the attestation extension on the leaf only.
		"attestation extension on the certificate above the leaf (a CA)": {chainOf(ca, with(ca, func(o *certOpts) { o.keyDesc = kd })), devattest.ErrChain},
		"attestation extension on an intermediate":                       {chainOf(with(ca, func(o *certOpts) { o.keyDesc = kd }), ca), devattest.ErrChain},
		"attestation and provisioning extensions above the leaf":         {chainOf(ca, with(ca, func(o *certOpts) { o.keyDesc, o.provision = kd, true })), devattest.ErrChain},

		// Rule: above the attestation certificate, CAs only.
		"intermediate not a CA":                            {chainOf(certOpts{notCA: true, usage: x509.KeyUsageDigitalSignature}, ca), devattest.ErrChain},
		"intermediate without basicConstraints":            {chainOf(certOpts{usage: x509.KeyUsageCertSign}, ca), devattest.ErrChain},
		"intermediate CA without keyCertSign":              {chainOf(with(ca, func(o *certOpts) { o.usage = x509.KeyUsageDigitalSignature }), ca), devattest.ErrChain},
		"second of three not a CA":                         {chainOf(ca, certOpts{notCA: true}, ca), devattest.ErrChain},
		"non-CA certificate with the extension, two below": {chainOf(ca, certOpts{keyDesc: kd, usage: x509.KeyUsageDigitalSignature}, ca), devattest.ErrChain},

		// Rule: path lengths.
		"intermediate pathLen 0, one CA below it": {chainOf(with(ca, func(o *certOpts) { o.pathLen = 0 }), ca), devattest.ErrChain},
		"intermediate pathLen 1, two below it":    {chainOf(with(ca, func(o *certOpts) { o.pathLen = 1 }), ca, ca), devattest.ErrChain},
		"second pathLen 0, one below it":          {chainOf(ca, with(ca, func(o *certOpts) { o.pathLen = 0 }), ca), devattest.ErrChain},
	} {
		checkChain(t, name, p, raws(tc.chain...), ch, tc.want)
	}
	// A root with a path length (as the roots of some real chains).
	short := issueCert(t, nil, rootKey, rootKey.Public(), certOpts{serial: 2, ca: true, pathLen: 1, usage: x509.KeyUsageCertSign, selfSigned: true})
	i1 := issueCert(t, short, rootKey, k1.Public(), with(ca, func(o *certOpts) { o.serial = 10 }))
	i2 := issueCert(t, i1, k1, k2.Public(), with(ca, func(o *certOpts) { o.serial = 11 }))
	checkChain(t, "root pathLen 1, one CA below it", p, raws(leafOf(i1, k1), i1, short), ch, nil)
	checkChain(t, "root pathLen 1, two CAs below it", p, raws(leafOf(i2, k2), i2, i1, short), ch, devattest.ErrChain)

	// Duplicates and additions to a good chain.
	good := chainOf(ca, ca) // leaf, attestation certificate, intermediate, root
	l, a, i, r := good[0], good[1], good[2], good[3]
	otherKey := key(0x86)
	other := issueCert(t, nil, otherKey, otherKey.Public(), certOpts{serial: 3, ca: true, pathLen: -1, usage: x509.KeyUsageCertSign, selfSigned: true})
	cross := issueCert(t, other, otherKey, rootKey.Public(), with(ca, func(o *certOpts) { o.serial = 4 })) // the pinned root's key, certified by another root
	for name, tc := range map[string]struct {
		chain []*x509.Certificate
		want  error
	}{
		"leaf twice":                         {[]*x509.Certificate{l, l, a, i, r}, devattest.ErrChain},
		"attestation certificate twice":      {[]*x509.Certificate{l, a, a, i, r}, devattest.ErrChain},
		"intermediate twice":                 {[]*x509.Certificate{l, a, i, i, r}, devattest.ErrChain},
		"another root appended":              {[]*x509.Certificate{l, a, i, r, other}, devattest.ErrChain},
		"another root in place of the root":  {[]*x509.Certificate{l, a, i, other}, devattest.ErrChain},
		"the pinned key under another root":  {[]*x509.Certificate{l, a, i, cross, other}, devattest.ErrRoot},
		"the pinned key, not self-signed":    {[]*x509.Certificate{l, a, i, cross}, devattest.ErrRoot},
		"no root":                            {[]*x509.Certificate{l, a, i}, devattest.ErrRoot},
		"leaf and root only":                 {[]*x509.Certificate{l, r}, devattest.ErrChain},
		"an unrelated certificate prepended": {[]*x509.Certificate{other, l, a, i, r}, devattest.ErrChain},
		// The pinned root repeated at the end verifies as before: it
		// adds a certificate the release already trusts, and nothing else.
		"the pinned root twice": {[]*x509.Certificate{l, a, i, r, r}, nil},
	} {
		checkChain(t, name, p, raws(tc.chain...), ch, tc.want)
	}
	// Eleven certificates: refused for its length, as before.
	long := raws(l, a, i, r)
	for len(long) < 11 {
		long = append(long, r.Raw)
	}
	checkChain(t, "eleven certificates", p, long, ch, devattest.ErrFormat)
}

// App Attest has no such gap: the chain is validated by the standard
// library from the credential certificate, so a credential certificate
// issued by another attested (non-CA) credential key is refused, though
// everything else about the attestation is right.
func TestIOSChainExtendedBelowAttestedKey(t *testing.T) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	a := enclavetest.NewIOSAttester(0x73, enclavetest.IOSOptions{Under: enclavetest.TestKey(elliptic.P256(), 0x74)})
	da, err := a.Attest(ch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := devattest.VerifyAttest(p, da, ch, now, nil); !errors.Is(err, devattest.ErrChain) {
		t.Fatalf("a credential certificate issued by an attested key: %v", err)
	}
	// The same key attested by the App Attest CA is accepted.
	g := enclavetest.NewIOSAttester(0x73, enclavetest.IOSOptions{})
	gda, _ := g.Attest(ch)
	if _, err := devattest.VerifyAttest(p, gda, ch, now, nil); err != nil {
		t.Fatal(err)
	}
}

// fuzzChain builds a chain from a good one and two fuzzed blobs: shape
// picks where the blobs go (replacing, inserted before, or appended).
func fuzzChain(good [][]byte, extra [][]byte, a, b []byte, shape uint8) [][]byte {
	pick := func(x []byte, sel uint8) []byte {
		// A blob of one byte names a certificate of the corpus; anything
		// else is the certificate itself.
		if len(x) == 1 {
			all := append(append([][]byte(nil), good...), extra...)
			return all[int(x[0])%len(all)]
		}
		return x
	}
	a, b = pick(a, 0), pick(b, 1)
	chain := append([][]byte(nil), good...)
	pos := int(shape&0x0f) % (len(chain) + 1)
	switch (shape >> 4) & 3 {
	case 0: // replace one
		if pos < len(chain) {
			chain[pos] = a
		}
	case 1: // insert one
		chain = append(chain[:pos], append([][]byte{a}, chain[pos:]...)...)
	case 2: // insert two
		chain = append(chain[:pos], append([][]byte{a, b}, chain[pos:]...)...)
	default: // replace one, append one
		if pos < len(chain) {
			chain[pos] = a
		}
		chain = append(chain, b)
	}
	if shape&0x40 != 0 && len(chain) > 1 {
		chain = chain[1:]
	}
	return chain
}

// fuzzCorpus is a good chain for the challenge and certificates an
// attacker with an attested key can make: one for a software key with a
// good attestation extension, and CA-flagged ones.
func fuzzCorpus(t testing.TB, ch [32]byte) (good [][]byte, extra [][]byte) {
	attested := enclavetest.TestKey(elliptic.P256(), 0x61)
	good = enclavetest.TestAndroidCA().Attest(attested, enclavetest.AndroidOptions{Challenge: ch})
	parent, err := x509.ParseCertificate(good[0])
	if err != nil {
		t.Fatal(err)
	}
	kd := goodKeyDescription(t, ch)
	soft := enclavetest.TestKey(elliptic.P256(), 0x79)
	forged := issueCert(t, parent, attested, soft.Public(), certOpts{serial: 1, keyDesc: kd, usage: x509.KeyUsageDigitalSignature})
	mid := issueCert(t, parent, attested, soft.Public(), certOpts{serial: 2, ca: true, pathLen: -1, usage: x509.KeyUsageCertSign})
	deep := issueCert(t, mid, soft, soft.Public(), certOpts{serial: 3, keyDesc: kd, usage: x509.KeyUsageDigitalSignature})
	return good, raws(forged, mid, deep)
}

// checkAccepted is the fuzz targets' invariant: whatever was accepted is
// a chain whose first certificate alone carries the attestation
// extension, whose key is the bound key, and whose other certificates
// above the attestation certificate are CAs.
func checkAccepted(t *testing.T, b *devattest.Binding, chain [][]byte) {
	t.Helper()
	if len(b.Serials) != len(chain) || b.Signer == "" {
		t.Fatalf("binding %+v for %d certificates", b, len(chain))
	}
	for i, der := range chain {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("accepted an unparsable certificate %d", i)
		}
		n := 0
		for _, e := range c.Extensions {
			if e.Id.Equal(devattest.OIDKeyDescription) {
				n++
			}
		}
		switch {
		case i == 0 && (n != 1 || string(c.RawSubjectPublicKeyInfo) != string(b.PublicKey)):
			t.Fatalf("leaf: %d attestation extensions, or another key bound", n)
		case i > 0 && n != 0:
			t.Fatalf("accepted an attestation extension on certificate %d", i)
		case i > 1 && !(c.BasicConstraintsValid && c.IsCA):
			t.Fatalf("accepted a non-CA certificate %d", i)
		}
	}
}

// FuzzAndroidChain fuzzes the chain verifier through VerifyAttest with
// certificates replaced, inserted and appended at every position.
func FuzzAndroidChain(f *testing.F) {
	p := enclavetest.Policy()
	ch := challenge("enroll")
	good, extra := fuzzCorpus(f, ch)
	list := fresh()
	for mode := 0; mode < 8; mode++ { // every way of placing, at every position
		for pos := 0; pos <= len(good); pos++ {
			for sel := byte(0); sel < byte(len(good)+len(extra)); sel++ {
				f.Add([]byte{sel}, []byte{sel + 1}, uint8(mode<<4|pos))
			}
		}
	}
	f.Add(extra[0], good[0], uint8(0x10))
	f.Add(extra[2], extra[1], uint8(0x20))
	f.Fuzz(func(t *testing.T, a, b []byte, shape uint8) {
		chain := fuzzChain(good, extra, a, b, shape)
		got, err := devattest.VerifyAttest(p, &altchan.DeviceAttest{Platform: "android", Chain: chain}, ch, now, list)
		if err != nil {
			return
		}
		checkAccepted(t, got, chain)
	})
}

// FuzzBindSigner fuzzes BindSigner (the chain an app re-sends at unlock
// for a vault enrolled before 0.27.0): whatever chain binds the stored
// key is one the rules accept, for that key and those serials.
func FuzzBindSigner(f *testing.F) {
	p := enclavetest.Policy()
	ch := challenge("enrolled long ago")
	good, extra := fuzzCorpus(f, ch)
	full, err := devattest.VerifyAttest(p, &altchan.DeviceAttest{Platform: "android", Chain: good}, ch, now, fresh())
	if err != nil {
		f.Fatal(err)
	}
	old := *full
	old.Signer, old.SignerClass = "", ""
	for mode := 0; mode < 8; mode++ {
		for pos := 0; pos <= len(good); pos++ {
			sel := byte(mode + pos)
			f.Add([]byte{sel}, []byte{sel + 2}, uint8(mode<<4|pos), false)
			f.Add([]byte{sel + 3}, []byte{sel + 4}, uint8(mode<<4|pos), true)
		}
	}
	f.Add(good[0], good[1], uint8(0), true)
	f.Fuzz(func(t *testing.T, a, b []byte, shape uint8, stored bool) {
		chain := fuzzChain(good, extra, a, b, shape)
		bound := &old
		if stored {
			// The binding an earlier release would hold had it accepted
			// this very chain: its leaf key and its serials.
			bound = &devattest.Binding{Platform: "android"}
			for i, der := range chain {
				c, err := x509.ParseCertificate(der)
				if err != nil {
					return
				}
				if i == 0 {
					bound.PublicKey = c.RawSubjectPublicKeyInfo
				}
				bound.Serials = append(bound.Serials, c.SerialNumber.Text(16))
			}
		}
		got, err := devattest.BindSigner(p, bound, chain)
		if err != nil {
			return
		}
		checkAccepted(t, got, chain)
		if string(got.PublicKey) != string(bound.PublicKey) || len(got.Serials) != len(bound.Serials) {
			t.Fatal("bound another key or other serials")
		}
	})
}
