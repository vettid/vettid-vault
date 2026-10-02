package devattest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"time"

	"github.com/vettid/vettid-vault/internal/der"
	"github.com/vettid/vettid-vault/vms/suite"
)

// OIDKeyDescription is the Android key attestation extension
// (1.3.6.1.4.1.11129.2.1.17).
var OIDKeyDescription = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Security levels and other KeyMint values used in the checks.
const (
	secSoftware   = 0
	secTEE        = 1
	secStrongBox  = 2
	purposeSign   = 2
	purposeVerify = 3
	algEC         = 3
	curveP256     = 1
	originGen     = 0
	bootVerified  = 0
	digestSHA256  = 4
)

// AuthorizationList tags (KeyMint).
const (
	tagPurpose       = 1
	tagAlgorithm     = 2
	tagKeySize       = 3
	tagDigest        = 5
	tagECCurve       = 10
	tagOrigin        = 702
	tagRootOfTrust   = 704
	tagAttestationID = 709
)

// keyDescription holds the fields the policy checks.
type keyDescription struct {
	version         int64
	attestSecurity  int64
	keymintSecurity int64
	challenge       []byte
	sw, hw          authList
}

type authList struct {
	elems map[uint64]der.Element // tag -> the explicitly tagged inner element
}

func parseAuthList(e der.Element) (authList, error) {
	al := authList{elems: map[uint64]der.Element{}}
	if !e.Is(der.ClassUniversal, der.TagSequence) || !e.Constructed {
		return al, ErrFormat
	}
	r, _ := e.Children()
	for !r.Empty() {
		t, err := r.Next()
		if err != nil || t.Class != der.ClassContext || !t.Constructed {
			return al, ErrFormat
		}
		if _, dup := al.elems[t.Number]; dup {
			return al, ErrFormat
		}
		in, err := t.Children()
		if err != nil {
			return al, ErrFormat
		}
		v, err := in.Next()
		if err != nil || !in.Empty() {
			return al, ErrFormat
		}
		al.elems[t.Number] = v
	}
	return al, nil
}

func (a authList) int(tag uint64) (int64, bool, error) {
	e, ok := a.elems[tag]
	if !ok {
		return 0, false, nil
	}
	v, err := der.Int(e)
	return v, true, err
}

func (a authList) intSet(tag uint64) ([]int64, bool, error) {
	e, ok := a.elems[tag]
	if !ok {
		return nil, false, nil
	}
	if !e.Is(der.ClassUniversal, der.TagSet) {
		return nil, true, ErrFormat
	}
	r, _ := e.Children()
	var out []int64
	for !r.Empty() {
		x, err := r.Next()
		if err != nil {
			return nil, true, ErrFormat
		}
		v, err := der.Int(x)
		if err != nil {
			return nil, true, ErrFormat
		}
		out = append(out, v)
	}
	return out, true, nil
}

func parseKeyDescription(b []byte) (*keyDescription, error) {
	r := der.NewReader(b)
	seq, err := r.Expect(der.ClassUniversal, der.TagSequence, true)
	if err != nil || !r.Empty() {
		return nil, ErrFormat
	}
	c, _ := seq.Children()
	kd := &keyDescription{}
	ints := []*int64{&kd.version, &kd.attestSecurity, nil, &kd.keymintSecurity}
	for _, p := range ints {
		e, err := c.Next()
		if err != nil {
			return nil, ErrFormat
		}
		v, err := der.Int(e)
		if err != nil {
			return nil, ErrFormat
		}
		if p != nil {
			*p = v
		}
	}
	e, err := c.Next()
	if err != nil {
		return nil, ErrFormat
	}
	if kd.challenge, err = der.OctetString(e); err != nil {
		return nil, ErrFormat
	}
	if e, err = c.Next(); err != nil { // uniqueId
		return nil, ErrFormat
	}
	if _, err := der.OctetString(e); err != nil {
		return nil, ErrFormat
	}
	for _, dst := range []*authList{&kd.sw, &kd.hw} {
		e, err := c.Next()
		if err != nil {
			return nil, ErrFormat
		}
		if *dst, err = parseAuthList(e); err != nil {
			return nil, err
		}
	}
	if !c.Empty() {
		return nil, ErrFormat
	}
	return kd, nil
}

// rootOfTrust checks RootOfTrust: deviceLocked true, verifiedBootState
// Verified.
func checkRootOfTrust(e der.Element) error {
	if !e.Is(der.ClassUniversal, der.TagSequence) {
		return ErrFormat
	}
	r, _ := e.Children()
	vbk, err := r.Next()
	if err != nil {
		return ErrFormat
	}
	if _, err := der.OctetString(vbk); err != nil {
		return ErrFormat
	}
	lk, err := r.Next()
	if err != nil {
		return ErrFormat
	}
	locked, err := der.Bool(lk)
	if err != nil {
		return ErrFormat
	}
	st, err := r.Next()
	if err != nil {
		return ErrFormat
	}
	state, err := der.Int(st)
	if err != nil {
		return ErrFormat
	}
	if !locked || state != bootVerified {
		return ErrRootOfTrust
	}
	return nil
}

// checkApplicationID parses AttestationApplicationId and requires every
// package to be the VettID app and every signing digest to be pinned.
func checkApplicationID(p *Policy, e der.Element) error {
	oct, err := der.OctetString(e)
	if err != nil {
		return ErrFormat
	}
	r := der.NewReader(oct)
	seq, err := r.Expect(der.ClassUniversal, der.TagSequence, true)
	if err != nil || !r.Empty() {
		return ErrFormat
	}
	c, _ := seq.Children()
	infos, err := c.Expect(der.ClassUniversal, der.TagSet, true)
	if err != nil {
		return ErrFormat
	}
	digests, err := c.Expect(der.ClassUniversal, der.TagSet, true)
	if err != nil || !c.Empty() {
		return ErrFormat
	}
	ir, _ := infos.Children()
	n := 0
	for !ir.Empty() {
		pi, err := ir.Expect(der.ClassUniversal, der.TagSequence, true)
		if err != nil {
			return ErrFormat
		}
		pr, _ := pi.Children()
		ne, err := pr.Next()
		if err != nil {
			return ErrFormat
		}
		name, err := der.OctetString(ne)
		if err != nil {
			return ErrFormat
		}
		ve, err := pr.Next()
		if err != nil || !pr.Empty() {
			return ErrFormat
		}
		if _, err := der.Int(ve); err != nil {
			return ErrFormat
		}
		if !suite.Equal(name, []byte(p.AndroidPackage)) {
			return ErrApplication
		}
		n++
	}
	if n == 0 {
		return ErrApplication
	}
	dr, _ := digests.Children()
	n = 0
	for !dr.Empty() {
		de, err := dr.Next()
		if err != nil {
			return ErrFormat
		}
		d, err := der.OctetString(de)
		if err != nil {
			return ErrFormat
		}
		ok := false
		for _, s := range p.AndroidSigners {
			if len(s) == sha256.Size && suite.Equal(d, s) {
				ok = true
			}
		}
		if !ok {
			return ErrApplication
		}
		n++
	}
	if n == 0 {
		return ErrApplication
	}
	return nil
}

func validAt(c *x509.Certificate, now time.Time) bool {
	return !now.Before(c.NotBefore) && !now.After(c.NotAfter)
}

func verifyAndroid(p *Policy, chainDER [][]byte, challenge [32]byte, now time.Time) (*Binding, error) {
	if p.AndroidPackage == "" || len(p.AndroidSigners) == 0 || len(p.AndroidRoots) == 0 {
		return nil, ErrPlatform
	}
	if len(chainDER) == 0 || len(chainDER) > 10 {
		return nil, ErrFormat
	}
	chain := make([]*x509.Certificate, len(chainDER))
	for i, b := range chainDER {
		c, err := x509.ParseCertificate(b)
		if err != nil {
			return nil, ErrFormat
		}
		chain[i] = c
	}
	// Each certificate is signed by the next; the last is a pinned root
	// (compared by public key, as Google recommends).
	for i := 0; i+1 < len(chain); i++ {
		if err := chain[i+1].CheckSignature(chain[i].SignatureAlgorithm, chain[i].RawTBSCertificate, chain[i].Signature); err != nil {
			return nil, ErrChain
		}
	}
	last := chain[len(chain)-1]
	pinned := false
	for _, r := range p.AndroidRoots {
		if suite.Equal(last.RawSubjectPublicKeyInfo, r.RawSubjectPublicKeyInfo) {
			pinned = true
		}
	}
	if !pinned || last.CheckSignature(last.SignatureAlgorithm, last.RawTBSCertificate, last.Signature) != nil {
		return nil, ErrRoot
	}
	for _, c := range chain {
		if !validAt(c, now) {
			return nil, ErrChain
		}
	}
	leaf := chain[0]
	var ext []byte
	for _, e := range leaf.Extensions {
		if e.Id.Equal(OIDKeyDescription) {
			if ext != nil {
				return nil, ErrFormat
			}
			ext = e.Value
		}
	}
	if ext == nil {
		return nil, ErrFormat
	}
	kd, err := parseKeyDescription(ext)
	if err != nil {
		return nil, err
	}
	min := p.AndroidMinVersion
	if min == 0 {
		min = 3
	}
	if kd.version < min {
		return nil, ErrSecurityLevel
	}
	hwLevel := func(l int64) bool { return l == secTEE || l == secStrongBox }
	if !hwLevel(kd.attestSecurity) || !hwLevel(kd.keymintSecurity) {
		return nil, ErrSecurityLevel
	}
	if !suite.Equal(kd.challenge, challenge[:]) {
		return nil, ErrChallenge
	}
	// Key properties, all hardware-enforced: a generated (non-imported,
	// non-exportable) EC P-256 signing key.
	hw := kd.hw
	purposes, ok, err := hw.intSet(tagPurpose)
	if err != nil || !ok {
		return nil, ErrKeyProperties
	}
	sign := false
	for _, pu := range purposes {
		switch pu {
		case purposeSign:
			sign = true
		case purposeVerify:
		default:
			return nil, ErrKeyProperties
		}
	}
	if !sign {
		return nil, ErrKeyProperties
	}
	if alg, ok, err := hw.int(tagAlgorithm); err != nil || !ok || alg != algEC {
		return nil, ErrKeyProperties
	}
	if cv, ok, err := hw.int(tagECCurve); err != nil || (ok && cv != curveP256) {
		return nil, ErrKeyProperties
	}
	if ks, ok, err := hw.int(tagKeySize); err != nil || (ok && ks != 256) {
		return nil, ErrKeyProperties
	}
	if ds, ok, err := hw.intSet(tagDigest); err != nil || ok && !containsInt(ds, digestSHA256) {
		return nil, ErrKeyProperties
	}
	if og, ok, err := hw.int(tagOrigin); err != nil || !ok || og != originGen {
		return nil, ErrKeyProperties
	}
	rot, ok := hw.elems[tagRootOfTrust]
	if !ok {
		return nil, ErrRootOfTrust
	}
	if err := checkRootOfTrust(rot); err != nil {
		return nil, err
	}
	aid, ok := hw.elems[tagAttestationID]
	if !ok {
		if aid, ok = kd.sw.elems[tagAttestationID]; !ok {
			return nil, ErrApplication
		}
	}
	if err := checkApplicationID(p, aid); err != nil {
		return nil, err
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, ErrKeyProperties
	}
	b := &Binding{Platform: "android", PublicKey: append([]byte(nil), leaf.RawSubjectPublicKeyInfo...)}
	for _, c := range chain {
		b.Serials = append(b.Serials, c.SerialNumber.Text(16))
	}
	return b, nil
}

func containsInt(s []int64, v int64) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func verifyAndroidSig(b *Binding, msg, sig []byte) error {
	k, err := x509.ParsePKIXPublicKey(b.PublicKey)
	if err != nil {
		return ErrFormat
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return ErrFormat
	}
	h := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(pub, h[:], sig) {
		return ErrSignature
	}
	return nil
}
