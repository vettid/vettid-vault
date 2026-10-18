package enclavetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"math/big"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/cbor"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/devattest"
	"github.com/vettid/vettid-vault/vms/nitro"
)

// Test app identity (TEST ONLY).
const (
	AndroidPackage = "com.vettid.app"
	IOSAppID       = "TESTTEAM00.com.vettid.app"
)

// AndroidSigner is the test app-signing certificate digest, pinned by the
// test policy with class vettid.
var AndroidSigner = sha256.Sum256([]byte("VettID TEST ONLY app signing certificate"))

// AndroidSignerPlay and AndroidSignerDev are further test signing
// certificate digests (0.27.0, §11.7.1). The test policy does not pin
// them; a test that needs a second signer adds one with PinSigner.
var (
	AndroidSignerPlay = sha256.Sum256([]byte("VettID TEST ONLY Play app-signing certificate"))
	AndroidSignerDev  = sha256.Sum256([]byte("VettID TEST ONLY development signing certificate"))
)

// PinSigner returns a copy of p that also pins digest with class.
func PinSigner(p *devattest.Policy, digest [32]byte, class string) *devattest.Policy {
	out := *p
	out.AndroidSigners = append(append([]devattest.Signer(nil), p.AndroidSigners...), devattest.Signer{Digest: digest[:], Class: class})
	return &out
}

// UnpinSigner returns a copy of p without digest.
func UnpinSigner(p *devattest.Policy, digest [32]byte) *devattest.Policy {
	out := *p
	out.AndroidSigners = nil
	for _, s := range p.AndroidSigners {
		if string(s.Digest) != string(digest[:]) {
			out.AndroidSigners = append(out.AndroidSigners, s)
		}
	}
	return &out
}

// --- minimal DER writer for the attestation extension ---

func tlv(tag []byte, content ...[]byte) []byte {
	var c []byte
	for _, x := range content {
		c = append(c, x...)
	}
	out := append([]byte(nil), tag...)
	n := len(c)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n <= 0xff:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, c...)
}

func dSeq(c ...[]byte) []byte { return tlv([]byte{0x30}, c...) }
func dSet(c ...[]byte) []byte { return tlv([]byte{0x31}, c...) }
func dOct(b []byte) []byte    { return tlv([]byte{0x04}, b) }
func dBool(v bool) []byte {
	b := byte(0)
	if v {
		b = 0xff
	}
	return tlv([]byte{0x01}, []byte{b})
}
func dInt(v int64) []byte  { b, _ := asn1.Marshal(v); return b }
func dEnum(v int64) []byte { b := dInt(v); b[0] = 0x0a; return b }
func dNull() []byte        { return []byte{0x05, 0x00} }

// dExp writes [tag] EXPLICIT (context, constructed), with high-tag form.
func dExp(tag int, inner []byte) []byte {
	if tag < 31 {
		return tlv([]byte{0xa0 | byte(tag)}, inner)
	}
	var num []byte
	for t := tag; t > 0; t >>= 7 {
		num = append([]byte{byte(t & 0x7f)}, num...)
	}
	for i := 0; i < len(num)-1; i++ {
		num[i] |= 0x80
	}
	return tlv(append([]byte{0xbf}, num...), inner)
}

// AndroidOptions shape a test key attestation. The zero value (after
// defaults) is a valid StrongBox P-256 signing key of the test app on a
// locked, verified device.
type AndroidOptions struct {
	Challenge        [32]byte
	Version          int64
	AttestSecurity   int64 // default StrongBox (2)
	KeymintSecurity  int64
	SoftwareLevel    bool // both levels Software (0)
	Purposes         []int64
	Algorithm        int64
	Curve            int64
	Origin           int64
	Unlocked         bool
	BootState        int64
	BootKey          []byte // RootOfTrust.verifiedBootKey (default 32 zero bytes)
	NoRootOfTrust    bool
	Package          string
	Signers          [][]byte
	ExtraPackage     string // a second package in the application id
	AppIDInHardware  bool
	SoftwarePurposes bool // properties only in the software-enforced list
	// MutateKeyDescription, if set, rewrites the encoded key description
	// before it is signed into the leaf (malformed-input tests).
	MutateKeyDescription func([]byte) []byte
}

func (o *AndroidOptions) defaults() {
	if o.Version == 0 {
		o.Version = 300
	}
	if o.AttestSecurity == 0 {
		o.AttestSecurity = 2
	}
	if o.KeymintSecurity == 0 {
		o.KeymintSecurity = 2
	}
	if o.SoftwareLevel {
		o.AttestSecurity, o.KeymintSecurity = 0, 0
	}
	if o.Purposes == nil {
		o.Purposes = []int64{2}
	}
	if o.Algorithm == 0 {
		o.Algorithm = 3
	}
	if o.Curve == 0 {
		o.Curve = 1
	}
	if o.Package == "" {
		o.Package = AndroidPackage
	}
	if o.Signers == nil {
		o.Signers = [][]byte{AndroidSigner[:]}
	}
}

func keyDescription(o AndroidOptions) []byte {
	o.defaults()
	var purposes [][]byte
	for _, p := range o.Purposes {
		purposes = append(purposes, dInt(p))
	}
	pkgs := [][]byte{dSeq(dOct([]byte(o.Package)), dInt(1))}
	if o.ExtraPackage != "" {
		pkgs = append(pkgs, dSeq(dOct([]byte(o.ExtraPackage)), dInt(1)))
	}
	var sigs [][]byte
	for _, s := range o.Signers {
		sigs = append(sigs, dOct(s))
	}
	appID := dExp(709, dOct(dSeq(dSet(pkgs...), dSet(sigs...))))
	props := [][]byte{
		dExp(1, dSet(purposes...)),
		dExp(2, dInt(o.Algorithm)),
		dExp(3, dInt(256)),
		dExp(5, dSet(dInt(4))),
		dExp(10, dInt(o.Curve)),
		dExp(503, dNull()),
		dExp(702, dInt(o.Origin)),
	}
	bootKey := o.BootKey
	if bootKey == nil {
		bootKey = make([]byte, 32)
	}
	if !o.NoRootOfTrust {
		props = append(props, dExp(704, dSeq(dOct(bootKey), dBool(!o.Unlocked), dEnum(o.BootState), dOct(make([]byte, 32)))))
	}
	props = append(props, dExp(705, dInt(140000)), dExp(706, dInt(202609)))
	sw := [][]byte{dExp(701, dInt(1790000000000))}
	hw := props
	if o.SoftwarePurposes {
		sw, hw = append(sw, props...), nil
	}
	if o.AppIDInHardware {
		hw = append(hw, appID)
	} else {
		sw = append(sw, appID)
	}
	return dSeq(dInt(o.Version), dEnum(o.AttestSecurity), dInt(o.Version), dEnum(o.KeymintSecurity),
		dOct(o.Challenge[:]), dOct(nil), dSeq(sw...), dSeq(hw...))
}

// AndroidCA is a TEST-ONLY stand-in for Google's attestation PKI.
type AndroidCA struct {
	Root, Inter *CA
	serial      int64
	mu          sync.Mutex
}

var (
	androidOnce sync.Once
	androidCA   *AndroidCA
)

// TestAndroidCA returns the shared test Android attestation PKI.
func TestAndroidCA() *AndroidCA {
	androidOnce.Do(func() {
		root := NewRootCA("TEST Android attestation root", TestKey(elliptic.P384(), 0x41))
		androidCA = &AndroidCA{Root: root, Inter: root.SubCA("TEST Android attestation intermediate", 2, TestKey(elliptic.P256(), 0x42)), serial: 1000}
	})
	return androidCA
}

// Attest returns a certificate chain (leaf first) attesting key.
func (ca *AndroidCA) Attest(key *ecdsa.PrivateKey, o AndroidOptions) [][]byte {
	kd := keyDescription(o)
	if o.MutateKeyDescription != nil {
		kd = o.MutateKeyDescription(kd)
	}
	ca.mu.Lock()
	ca.serial++
	s := ca.serial
	ca.mu.Unlock()
	leaf := ca.Inter.Issue(&x509.Certificate{SerialNumber: big.NewInt(s), Subject: pkix.Name{CommonName: "Android Keystore Key"},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: devattest.OIDKeyDescription, Value: kd}}}, key.Public())
	return [][]byte{leaf.Raw, ca.Inter.Cert.Raw, ca.Root.Cert.Raw}
}

// AndroidSign signs msg with ECDSA-SHA256 (DER), as Android Keystore does.
func AndroidSign(key *ecdsa.PrivateKey, msg []byte) []byte {
	h := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		panic(err)
	}
	return sig
}

// AppleCA is a TEST-ONLY stand-in for Apple's App Attest PKI.
type AppleCA struct {
	Root, Inter *CA
	mu          sync.Mutex
	serial      int64
}

var (
	appleOnce sync.Once
	appleCA   *AppleCA
)

// TestAppleCA returns the shared test App Attest PKI.
func TestAppleCA() *AppleCA {
	appleOnce.Do(func() {
		root := NewRootCA("TEST Apple App Attestation Root CA", TestKey(elliptic.P384(), 0x51))
		appleCA = &AppleCA{Root: root, Inter: root.SubCA("TEST Apple App Attestation CA 1", 2, TestKey(elliptic.P384(), 0x52)), serial: 1000}
	})
	return appleCA
}

// IOSOptions shape a test App Attest attestation.
type IOSOptions struct {
	Develop    bool   // development environment aaguid
	AppID      string // default IOSAppID
	Counter    uint32 // must be 0 in a real attestation
	WrongNonce bool
	// MutateNonceExt, if set, rewrites the encoded nonce extension before
	// it is signed into the leaf (malformed-input tests).
	MutateNonceExt func([]byte) []byte
	// Under, if set, is another App Attest key: the credential
	// certificate is then issued by that key instead of the App Attest
	// CA, and that key's own genuine (non-CA) credential certificate
	// follows it in x5c (a chain extended below an attested key).
	Under *ecdsa.PrivateKey
	// ED sets the authenticator data's extension-data flag (0x80) in the
	// attestation and in every assertion, with flags 0xc0 (AT|ED) as iOS 27
	// sends them: AT is set in assertions too, which carry no attested
	// credential data.
	ED bool
	// ExtensionData is appended to the authenticator data after the COSE
	// key (attestation) or the counter (assertion), whether or not ED is
	// set. A real device sends AppleExtensions() with ED.
	ExtensionData []byte
	// MutateAuthData, if set, rewrites the authenticator data after the
	// nonce (attestation) or the signature (assertion) was computed over
	// it (tamper tests).
	MutateAuthData func([]byte) []byte
	// Flags, if not zero, replaces the authenticator data flags (before
	// the nonce or signature is computed).
	Flags byte
}

// AppleExtensions returns a TEST extensions map shaped like the one iOS 27
// appends to App Attest authenticator data: a 62-byte definite-length CBOR
// map with Apple's two keys. The keys are Apple's; the values are made up.
func AppleExtensions() []byte {
	var e cbor.Encoder
	e.Map(2).Text("apple_bundle_version_01").Text("1.0").Text("apple_validation_category_01").Text("01")
	return e.Bytes()
}

// IOSAppleExtensions is IOSOptions for an attester that sends the
// extensions as iOS 27 does: ED set, AppleExtensions() appended.
func IOSAppleExtensions(o IOSOptions) IOSOptions {
	o.ED, o.ExtensionData = true, AppleExtensions()
	return o
}

func iosFlags(o IOSOptions, attestation bool) byte {
	switch {
	case o.Flags != 0:
		return o.Flags
	case o.ED:
		return 0x40 | 0x80
	case attestation:
		return 0x40 | 0x01
	default:
		return 0x01
	}
}

func point(key *ecdsa.PrivateKey) []byte {
	p, err := key.PublicKey.Bytes()
	if err != nil {
		panic(err)
	}
	return p
}

// IOSKeyID returns the App Attest key id: SHA-256 of the public point.
func IOSKeyID(key *ecdsa.PrivateKey) []byte {
	h := sha256.Sum256(point(key))
	return h[:]
}

// Attest returns an App Attest attestation object for key with
// clientDataHash cdh.
func (ca *AppleCA) Attest(key *ecdsa.PrivateKey, cdh [32]byte, o IOSOptions) []byte {
	if o.AppID == "" {
		o.AppID = IOSAppID
	}
	keyID := IOSKeyID(key)
	rp := sha256.Sum256([]byte(o.AppID))
	aaguid := devattest.AAGUIDProduction[:]
	if o.Develop {
		aaguid = []byte("appattestdevelop")
	}
	pt := point(key)
	var ck cbor.Encoder
	ck.Map(5).Int(1).Int(2).Int(3).Int(-7).Int(-1).Int(1).Int(-2).ByteString(pt[1:33]).Int(-3).ByteString(pt[33:])
	ad := append([]byte(nil), rp[:]...)
	ad = append(ad, iosFlags(o, true))
	ad = binary.BigEndian.AppendUint32(ad, o.Counter)
	ad = append(ad, aaguid...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(keyID)))
	ad = append(ad, keyID...)
	ad = append(ad, ck.Bytes()...)
	ad = append(ad, o.ExtensionData...)
	h := sha256.New()
	h.Write(ad)
	h.Write(cdh[:])
	nonce := h.Sum(nil)
	if o.WrongNonce {
		nonce[0] ^= 1
	}
	ext := dSeq(dExp(1, dOct(nonce)))
	if o.MutateNonceExt != nil {
		ext = o.MutateNonceExt(ext)
	}
	if o.MutateAuthData != nil {
		ad = o.MutateAuthData(ad)
	}
	ca.mu.Lock()
	ca.serial++
	s := ca.serial
	ca.mu.Unlock()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(s), Subject: pkix.Name{CommonName: "TEST App Attest credential"},
		KeyUsage:        x509.KeyUsageDigitalSignature,
		ExtraExtensions: []pkix.Extension{{Id: devattest.OIDAppAttestNonce, Value: ext}}}
	x5c := [][]byte{nil, ca.Inter.Cert.Raw}
	if o.Under == nil {
		x5c[0] = ca.Inter.Issue(tmpl, key.Public()).Raw
	} else {
		under := ca.Inter.Issue(&x509.Certificate{SerialNumber: big.NewInt(s + 500000), Subject: pkix.Name{CommonName: "TEST App Attest credential (issuing)"},
			KeyUsage:        x509.KeyUsageDigitalSignature,
			ExtraExtensions: []pkix.Extension{{Id: devattest.OIDAppAttestNonce, Value: ext}}}, o.Under.Public())
		x5c = [][]byte{(&CA{Cert: under, Key: o.Under}).Issue(tmpl, key.Public()).Raw, under.Raw, ca.Inter.Cert.Raw}
	}
	var att cbor.Encoder
	st := att.Map(3).Text("fmt").Text("apple-appattest").
		Text("attStmt").Map(2).Text("x5c").Array(len(x5c))
	for _, c := range x5c {
		st.ByteString(c)
	}
	att.Text("receipt").ByteString([]byte("TEST receipt")).
		Text("authData").ByteString(ad)
	return att.Bytes()
}

// IOSAssert returns an App Attest assertion with the given counter.
func IOSAssert(key *ecdsa.PrivateKey, appID string, counter uint32, cdh [32]byte) []byte {
	return IOSAssertWith(key, IOSOptions{AppID: appID}, counter, cdh)
}

// IOSAssertWith returns an App Attest assertion with the given counter,
// shaped by o's AppID, ED, ExtensionData and MutateAuthData.
func IOSAssertWith(key *ecdsa.PrivateKey, o IOSOptions, counter uint32, cdh [32]byte) []byte {
	appID := o.AppID
	if appID == "" {
		appID = IOSAppID
	}
	rp := sha256.Sum256([]byte(appID))
	ad := append([]byte(nil), rp[:]...)
	ad = append(ad, iosFlags(o, false))
	ad = binary.BigEndian.AppendUint32(ad, counter)
	ad = append(ad, o.ExtensionData...)
	h := sha256.New()
	h.Write(ad)
	h.Write(cdh[:])
	nonce := h.Sum(nil)
	d := sha256.Sum256(nonce)
	sig, err := ecdsa.SignASN1(rand.Reader, key, d[:])
	if err != nil {
		panic(err)
	}
	if o.MutateAuthData != nil {
		ad = o.MutateAuthData(ad)
	}
	var e cbor.Encoder
	e.Map(2).Text("signature").ByteString(sig).Text("authenticatorData").ByteString(ad)
	return e.Bytes()
}

// TestGrapheneOSBootKey is the TEST-ONLY verified boot key fingerprint the
// test policy allows with verifiedBootState SelfSigned.
var TestGrapheneOSBootKey = sha256.Sum256([]byte("vettid test grapheneos verified boot key"))

// Policy returns the TEST-ONLY device attestation policy: the test Android
// and Apple roots and the test app identity.
func Policy() *devattest.Policy {
	return &devattest.Policy{
		AndroidRoots:   []*x509.Certificate{TestAndroidCA().Root.Cert},
		AndroidPackage: AndroidPackage,
		AndroidSigners: []devattest.Signer{{Digest: AndroidSigner[:], Class: devattest.ClassVettID}},
		// The test allowlist for SelfSigned boot (GrapheneOS, §11.7).
		AndroidSelfSignedBootKeys: [][]byte{TestGrapheneOSBootKey[:]},
		IOSRoots:                  nitro.Pool(TestAppleCA().Root.Cert),
		IOSAppID:                  IOSAppID,
	}
}

// EmptyStatusList returns a status list with no entries fetched at t.
func EmptyStatusList(t time.Time) *devattest.StatusList {
	l, err := devattest.ParseStatusList([]byte(`{"entries":{}}`), t)
	if err != nil {
		panic(err)
	}
	return l
}

// Attester is a TEST-ONLY app device: a hardware attestation key and the
// platform's attestation and assertion formats.
type Attester struct {
	platform string
	key      *ecdsa.PrivateKey
	android  AndroidOptions
	ios      IOSOptions
	mu       sync.Mutex
	counter  uint32
}

// NewAndroidAttester returns a test Android device whose key scalar is 32
// bytes of seed.
func NewAndroidAttester(seed byte, o AndroidOptions) *Attester {
	return &Attester{platform: altchan.PlatformAndroid, key: TestKey(elliptic.P256(), seed), android: o}
}

// NewIOSAttester returns a test iOS device whose key scalar is 32 bytes of
// seed.
func NewIOSAttester(seed byte, o IOSOptions) *Attester {
	return &Attester{platform: altchan.PlatformIOS, key: TestKey(elliptic.P256(), seed), ios: o}
}

// Platform returns "android" or "ios".
func (a *Attester) Platform() string { return a.platform }

// Attest produces device_attest for the challenge.
func (a *Attester) Attest(challenge [32]byte) (*altchan.DeviceAttest, error) {
	switch a.platform {
	case altchan.PlatformAndroid:
		o := a.android
		if o.Challenge == ([32]byte{}) {
			o.Challenge = challenge
		}
		return &altchan.DeviceAttest{Platform: a.platform, Chain: TestAndroidCA().Attest(a.key, o)}, nil
	default:
		return &altchan.DeviceAttest{Platform: a.platform, KeyID: IOSKeyID(a.key), Attestation: TestAppleCA().Attest(a.key, challenge, a.ios)}, nil
	}
}

// Assert signs with the attested key.
func (a *Attester) Assert(s devattest.Signed) (*altchan.DeviceAssertion, error) {
	switch a.platform {
	case altchan.PlatformAndroid:
		return &altchan.DeviceAssertion{Platform: a.platform, Sig: AndroidSign(a.key, s.Message)}, nil
	default:
		a.mu.Lock()
		a.counter++
		c := a.counter
		a.mu.Unlock()
		return &altchan.DeviceAssertion{Platform: a.platform, Assertion: IOSAssertWith(a.key, a.ios, c, s.ClientDataHash)}, nil
	}
}

// Key returns the attestation key (tests that forge signatures).
func (a *Attester) Key() crypto.Signer { return a.key }

// SetCounter sets the App Attest counter of the next assertion minus one
// (tools running across processes keep it increasing).
func (a *Attester) SetCounter(c uint32) {
	a.mu.Lock()
	a.counter = c
	a.mu.Unlock()
}

// Counter returns the last App Attest counter used.
func (a *Attester) Counter() uint32 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counter
}
