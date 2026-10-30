package votewire

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// The Sigstore bundle check (VAULT-MESSAGING §10.19.4 step 6; BALLOT-PROTOCOL
// §8.5 "Rekor profile"), standard library only, for the one profile the
// service vault's anchor package produces: a v0.3 bundle holding one
// Rekor v1 `hashedrekord` 0.0.1 entry made with an ECDSA P-256 anchor key
// (no certificate), its inclusion proof, checkpoint and signed entry
// timestamp, and one RFC 3161 token (ECDSA with SHA-256) over the
// signature, whose certificates come only from the pinned trusted root.
//
// The errors map to the spec's outcomes:
//
//	ErrAnchorKey  the key is not among the accepted anchor keys   -> checking (service_list)
//	ErrAnchor     the digest or signature contradicts the document,
//	              or the bundle is malformed                       -> rejected (anchor)
//	ErrAnchorLate the verified timestamp is after the time allowed -> rejected (anchor; late for an extension)
//	ErrBundleRoot nothing verifies against the pinned roots       -> checking (trust_root)
//	ErrBundleClock the stamp is ahead of the vault's own clock    -> checking (trust_root)
var (
	ErrAnchorKey = errors.New("votewire: bundle key is not an accepted anchor key")
	ErrAnchor    = errors.New("votewire: bundle contradicts the document")
	// ErrAnchorLate: the stamp verifies but is after the time allowed.
	ErrAnchorLate  = errors.New("votewire: bundle timestamp is too late")
	ErrBundleRoot  = errors.New("votewire: bundle does not verify against the pinned roots")
	ErrBundleClock = errors.New("votewire: bundle timestamp is ahead of this vault's clock")
)

// Skews (VAULT-MESSAGING design, owner 2026-10-30): the timestamp may be
// at most this long before the log's integratedTime and this long ahead of
// the vault's clock.
const (
	StampBeforeLog = 10 * time.Minute
	StampAhead     = 5 * time.Minute
	maxProofHashes = 64
)

// BundleInfo is what a verified bundle established.
type BundleInfo struct {
	LogIndex       int64
	IntegratedTime int64
	GenTime        time.Time
	AnchorKey      []byte // SPKI DER
}

type tlogEntry struct {
	LogIndex string `json:"logIndex"`
	LogID    struct {
		KeyID []byte `json:"keyId"`
	} `json:"logId"`
	KindVersion struct {
		Kind    string `json:"kind"`
		Version string `json:"version"`
	} `json:"kindVersion"`
	IntegratedTime   string `json:"integratedTime"`
	InclusionPromise struct {
		SET []byte `json:"signedEntryTimestamp"`
	} `json:"inclusionPromise"`
	InclusionProof struct {
		LogIndex   string   `json:"logIndex"`
		RootHash   []byte   `json:"rootHash"`
		TreeSize   string   `json:"treeSize"`
		Hashes     [][]byte `json:"hashes"`
		Checkpoint struct {
			Envelope string `json:"envelope"`
		} `json:"checkpoint"`
	} `json:"inclusionProof"`
	Body []byte `json:"canonicalizedBody"`
}

type bundleDoc struct {
	MediaType            string `json:"mediaType"`
	VerificationMaterial struct {
		TLogEntries               []tlogEntry `json:"tlogEntries"`
		TimestampVerificationData struct {
			RFC3161 []struct {
				Signed []byte `json:"signedTimestamp"`
			} `json:"rfc3161Timestamps"`
		} `json:"timestampVerificationData"`
	} `json:"verificationMaterial"`
	MessageSignature struct {
		MessageDigest struct {
			Algorithm string `json:"algorithm"`
			Digest    []byte `json:"digest"`
		} `json:"messageDigest"`
		Signature []byte `json:"signature"`
	} `json:"messageSignature"`
}

func atoi(s string) (int64, bool) {
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil && n >= 0 && strconv.FormatInt(n, 10) == s
}

// VerifyBundle checks bundle for doc. accepted are the SPKI DER of the
// service's accepted anchor keys; roots the pinned trusted roots; notAfter
// the latest time the timestamp may carry; now the vault's clock.
func VerifyBundle(doc, bundle []byte, accepted [][]byte, roots []*TrustRoot, notAfter, now time.Time) (*BundleInfo, error) {
	if len(bundle) == 0 || len(bundle) > MaxBundle {
		return nil, ErrAnchor
	}
	if _, err := strictjson.ParseObject(bundle); err != nil {
		return nil, ErrAnchor
	}
	var b bundleDoc
	if err := json.Unmarshal(bundle, &b); err != nil {
		return nil, ErrAnchor
	}
	vm := &b.VerificationMaterial
	if b.MediaType != "application/vnd.dev.sigstore.bundle.v0.3+json" || len(vm.TLogEntries) != 1 ||
		len(vm.TimestampVerificationData.RFC3161) != 1 {
		return nil, ErrAnchor
	}
	e := &vm.TLogEntries[0]
	if e.KindVersion.Kind != "hashedrekord" || e.KindVersion.Version != "0.0.1" {
		return nil, ErrAnchor
	}
	logIndex, ok1 := atoi(e.LogIndex)
	integrated, ok2 := atoi(e.IntegratedTime)
	if !ok1 || !ok2 || len(e.Body) == 0 || len(e.Body) > MaxBundle {
		return nil, ErrAnchor
	}

	// The entry's own record of what was signed and by which key.
	digest, sig, spki, err := parseRekorBody(e.Body)
	if err != nil {
		return nil, ErrAnchor
	}
	known := false
	for _, k := range accepted {
		known = known || eq(k, spki)
	}
	if !known {
		return nil, ErrAnchorKey
	}

	// Contradiction under a key the list names: ErrAnchor.
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, ErrAnchor
	}
	ek, ok := pub.(*ecdsa.PublicKey)
	if !ok || ek.Curve != elliptic.P256() {
		return nil, ErrAnchor
	}
	dh := H(doc)
	if b.MessageSignature.MessageDigest.Algorithm != "SHA2_256" || !eq(b.MessageSignature.MessageDigest.Digest, dh) ||
		!eq(digest, dh) || !eq(sig, b.MessageSignature.Signature) || !ecdsa.VerifyASN1(ek, dh, sig) {
		return nil, ErrAnchor
	}

	// Against the pinned roots: the newest first (a newer root is the
	// likelier to hold the keys), older ones so that older bundles verify.
	var lastErr error = ErrBundleRoot
	for i := len(roots) - 1; i >= 0; i-- {
		gen, err := verifyAgainst(roots[i], &b, e.Body, logIndex, integrated, sig, now)
		if err != nil {
			if errors.Is(err, ErrBundleClock) {
				lastErr = err
			}
			continue
		}
		if gen.After(notAfter) {
			return nil, ErrAnchorLate
		}
		return &BundleInfo{LogIndex: logIndex, IntegratedTime: integrated, GenTime: gen, AnchorKey: append([]byte{}, spki...)}, nil
	}
	return nil, lastErr
}

// parseRekorBody reads the hashedrekord 0.0.1 body: the document digest,
// the DER signature and the DER SPKI of the key.
func parseRekorBody(body []byte) (digest, sig, spki []byte, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	if v, err := o.String("apiVersion"); err != nil || v != "0.0.1" {
		return nil, nil, nil, ErrAnchor
	}
	if v, err := o.String("kind"); err != nil || v != "hashedrekord" {
		return nil, nil, nil, ErrAnchor
	}
	spec, err := o.Object("spec")
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	data, err := spec.Object("data")
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	hash, err := data.Object("hash")
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	if a, err := hash.String("algorithm"); err != nil || a != "sha256" {
		return nil, nil, nil, ErrAnchor
	}
	hv, err := hash.String("value")
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	if digest, err = hex.DecodeString(hv); err != nil || len(digest) != HashLen || hex.EncodeToString(digest) != hv {
		return nil, nil, nil, ErrAnchor
	}
	sg, err := spec.Object("signature")
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	if sig, err = sg.Base64("content", -1); err != nil {
		return nil, nil, nil, ErrAnchor
	}
	pk, err := sg.Object("publicKey")
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	pemBytes, err := pk.Base64("content", -1)
	if err != nil {
		return nil, nil, nil, ErrAnchor
	}
	blk, rest := pem.Decode(pemBytes)
	if blk == nil || blk.Type != "PUBLIC KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, nil, ErrAnchor
	}
	return digest, sig, blk.Bytes, nil
}

// verifyAgainst checks the log entry (inclusion, checkpoint, signed entry
// timestamp) and the RFC 3161 token against one trusted root, and returns
// the token's time.
func verifyAgainst(tr *TrustRoot, b *bundleDoc, body []byte, logIndex, integrated int64, sig []byte, now time.Time) (time.Time, error) {
	e := &b.VerificationMaterial.TLogEntries[0]
	it := time.Unix(integrated, 0).UTC()
	var lg *TLog
	for i := range tr.Logs {
		if eq(tr.Logs[i].LogID, e.LogID.KeyID) && valid(it, tr.Logs[i].Start, tr.Logs[i].End) {
			lg = &tr.Logs[i]
		}
	}
	if lg == nil {
		return time.Time{}, ErrBundleRoot
	}
	if err := verifyLog(lg, e, body, logIndex, integrated); err != nil {
		return time.Time{}, err
	}
	gen, err := verifyTimestamp(tr, b.VerificationMaterial.TimestampVerificationData.RFC3161[0].Signed, H(sig), now)
	if err != nil {
		return time.Time{}, err
	}
	if gen.Before(it.Add(-StampBeforeLog)) {
		return time.Time{}, ErrBundleRoot
	}
	return gen, nil
}

func verifyLog(lg *TLog, e *tlogEntry, body []byte, logIndex, integrated int64) error {
	ip := &e.InclusionProof
	idx, ok1 := atoi(ip.LogIndex)
	size, ok2 := atoi(ip.TreeSize)
	if !ok1 || !ok2 || idx >= size || len(ip.Hashes) > maxProofHashes || len(ip.RootHash) != HashLen {
		return ErrBundleRoot
	}
	if !VerifyProof(ip.RootHash, body, uint64(idx), uint64(size), ip.Hashes) {
		return ErrBundleRoot
	}
	if err := verifyCheckpoint(lg, ip.Checkpoint.Envelope, uint64(size), ip.RootHash); err != nil {
		return err
	}
	// The signed entry timestamp (Rekor v1): ECDSA over the canonical JSON
	// of body, integratedTime, logID and logIndex.
	ek, ok := lg.Key.(*ecdsa.PublicKey)
	if !ok || len(e.InclusionPromise.SET) == 0 {
		return ErrBundleRoot
	}
	payload := `{"body":"` + base64.StdEncoding.EncodeToString(body) + `","integratedTime":` + strconv.FormatInt(integrated, 10) +
		`,"logID":"` + hex.EncodeToString(lg.LogID) + `","logIndex":` + strconv.FormatInt(logIndex, 10) + `}`
	if !ecdsa.VerifyASN1(ek, H([]byte(payload)), e.InclusionPromise.SET) {
		return ErrBundleRoot
	}
	return nil
}

// verifyCheckpoint checks a signed note (c2sp.org/signed-note) holding a
// transparency log checkpoint: origin, tree size, root hash, a blank line,
// then "— <name> <base64(4-byte key hint ‖ signature)>" lines. The hint is
// the first 4 bytes of the log id, and the signature is the log key's over
// the note text (ECDSA P-256 with SHA-256, or Ed25519).
func verifyCheckpoint(lg *TLog, env string, size uint64, root []byte) error {
	if len(env) > 8192 {
		return ErrBundleRoot
	}
	i := strings.Index(env, "\n\n")
	if i < 0 {
		return ErrBundleRoot
	}
	text, sigs := env[:i+1], env[i+2:]
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return ErrBundleRoot
	}
	if n, err := strconv.ParseUint(lines[1], 10, 64); err != nil || n != size || strconv.FormatUint(n, 10) != lines[1] {
		return ErrBundleRoot
	}
	if r, err := base64.StdEncoding.DecodeString(lines[2]); err != nil || !eq(r, root) {
		return ErrBundleRoot
	}
	for _, line := range strings.Split(strings.TrimSuffix(sigs, "\n"), "\n") {
		const dash = "— "
		if !strings.HasPrefix(line, dash) {
			continue
		}
		name, b64, ok := strings.Cut(line[len(dash):], " ")
		if !ok || name == "" || !strings.HasPrefix(lines[0], name) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(raw) <= 4 || !eq(raw[:4], lg.LogID[:4]) {
			continue
		}
		switch k := lg.Key.(type) {
		case *ecdsa.PublicKey:
			if ecdsa.VerifyASN1(k, H([]byte(text)), raw[4:]) {
				return nil
			}
		case ed25519.PublicKey:
			if ed25519.Verify(k, []byte(text), raw[4:]) {
				return nil
			}
		}
	}
	return ErrBundleRoot
}

// RFC 3161 / CMS object identifiers.
var (
	oidSignedData  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSHA256      = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMsgDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// one reads one DER element, returning it and the rest.
func one(b []byte) (asn1.RawValue, []byte, bool) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	return rv, rest, err == nil
}

// sequence returns the elements inside a constructed element of the given
// class and tag.
func children(rv asn1.RawValue) ([]asn1.RawValue, bool) {
	if !rv.IsCompound {
		return nil, false
	}
	var out []asn1.RawValue
	b := rv.Bytes
	for len(b) > 0 {
		c, rest, ok := one(b)
		if !ok {
			return nil, false
		}
		out = append(out, c)
		b = rest
	}
	return out, true
}

type algID struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// verifyTimestamp checks a TimeStampResp holding a token over imprint (the
// SHA-256 of the signature) against the root's timestamp authorities, and
// returns its genTime.
func verifyTimestamp(tr *TrustRoot, resp []byte, imprint []byte, now time.Time) (time.Time, error) {
	bad := time.Time{}
	if len(resp) == 0 || len(resp) > MaxBundle {
		return bad, ErrBundleRoot
	}
	top, rest, ok := one(resp)
	if !ok || len(rest) != 0 || top.Tag != asn1.TagSequence || !top.IsCompound {
		return bad, ErrBundleRoot
	}
	kids, ok := children(top)
	if !ok || len(kids) != 2 {
		return bad, ErrBundleRoot
	}
	// PKIStatusInfo: granted (0) or granted with modifications (1).
	st, ok := children(kids[0])
	if !ok || len(st) < 1 {
		return bad, ErrBundleRoot
	}
	var status int
	if r, err := asn1.Unmarshal(st[0].FullBytes, &status); err != nil || len(r) != 0 || status > 1 {
		return bad, ErrBundleRoot
	}
	// ContentInfo { signedData, [0] SignedData }
	ci, ok := children(kids[1])
	if !ok || len(ci) != 2 {
		return bad, ErrBundleRoot
	}
	var oid asn1.ObjectIdentifier
	if r, err := asn1.Unmarshal(ci[0].FullBytes, &oid); err != nil || len(r) != 0 || !oid.Equal(oidSignedData) {
		return bad, ErrBundleRoot
	}
	if ci[1].Class != asn1.ClassContextSpecific || ci[1].Tag != 0 {
		return bad, ErrBundleRoot
	}
	sdv, rest, ok := one(ci[1].Bytes)
	if !ok || len(rest) != 0 {
		return bad, ErrBundleRoot
	}
	sd, ok := children(sdv)
	if !ok || len(sd) < 4 {
		return bad, ErrBundleRoot
	}
	// sd: version, digestAlgorithms, encapContentInfo, [0] certificates?, [1] crls?, signerInfos
	encap, ok := children(sd[2])
	if !ok || len(encap) != 2 {
		return bad, ErrBundleRoot
	}
	if r, err := asn1.Unmarshal(encap[0].FullBytes, &oid); err != nil || len(r) != 0 || !oid.Equal(oidTSTInfo) {
		return bad, ErrBundleRoot
	}
	if encap[1].Class != asn1.ClassContextSpecific || encap[1].Tag != 0 {
		return bad, ErrBundleRoot
	}
	var eContent []byte
	if r, err := asn1.Unmarshal(encap[1].Bytes, &eContent); err != nil || len(r) != 0 {
		return bad, ErrBundleRoot
	}
	signers := sd[len(sd)-1]
	if signers.Class != asn1.ClassUniversal || signers.Tag != asn1.TagSet {
		return bad, ErrBundleRoot
	}
	sis, ok := children(signers)
	if !ok || len(sis) != 1 {
		return bad, ErrBundleRoot
	}

	// TSTInfo: version, policy, messageImprint, serialNumber, genTime.
	tst, rest, ok := one(eContent)
	if !ok || len(rest) != 0 {
		return bad, ErrBundleRoot
	}
	tk, ok := children(tst)
	if !ok || len(tk) < 5 {
		return bad, ErrBundleRoot
	}
	var ver int
	if r, err := asn1.Unmarshal(tk[0].FullBytes, &ver); err != nil || len(r) != 0 || ver != 1 {
		return bad, ErrBundleRoot
	}
	var mi struct {
		Alg  algID
		Hash []byte
	}
	if r, err := asn1.Unmarshal(tk[2].FullBytes, &mi); err != nil || len(r) != 0 || !mi.Alg.Algorithm.Equal(oidSHA256) || !eq(mi.Hash, imprint) {
		return bad, ErrBundleRoot
	}
	var gen time.Time
	if r, err := asn1.Unmarshal(tk[4].FullBytes, &gen); err != nil || len(r) != 0 || tk[4].Tag != asn1.TagGeneralizedTime {
		return bad, ErrBundleRoot
	}
	gen = gen.UTC()

	// SignerInfo: version, sid, digestAlgorithm, [0] signedAttrs, sigAlg, signature.
	si, ok := children(sis[0])
	if !ok || len(si) < 6 {
		return bad, ErrBundleRoot
	}
	var siVer int
	if r, err := asn1.Unmarshal(si[0].FullBytes, &siVer); err != nil || len(r) != 0 || siVer != 1 {
		return bad, ErrBundleRoot
	}
	var dalg, salg algID
	if r, err := asn1.Unmarshal(si[2].FullBytes, &dalg); err != nil || len(r) != 0 || !dalg.Algorithm.Equal(oidSHA256) {
		return bad, ErrBundleRoot
	}
	attrs := si[3]
	if attrs.Class != asn1.ClassContextSpecific || attrs.Tag != 0 || !attrs.IsCompound {
		return bad, ErrBundleRoot
	}
	if r, err := asn1.Unmarshal(si[4].FullBytes, &salg); err != nil || len(r) != 0 || !salg.Algorithm.Equal(oidECDSASHA256) {
		return bad, ErrBundleRoot
	}
	var sigBytes []byte
	if r, err := asn1.Unmarshal(si[5].FullBytes, &sigBytes); err != nil || len(r) != 0 {
		return bad, ErrBundleRoot
	}
	// Signed attributes: contentType = TSTInfo and messageDigest = H(eContent).
	acs, ok := children(attrs)
	if !ok {
		return bad, ErrBundleRoot
	}
	var haveCT, haveMD bool
	for _, a := range acs {
		var at struct {
			Type   asn1.ObjectIdentifier
			Values asn1.RawValue
		}
		if r, err := asn1.Unmarshal(a.FullBytes, &at); err != nil || len(r) != 0 {
			return bad, ErrBundleRoot
		}
		vals, ok := children(at.Values)
		if !ok || len(vals) != 1 {
			continue
		}
		switch {
		case at.Type.Equal(oidContentType):
			var v asn1.ObjectIdentifier
			if r, err := asn1.Unmarshal(vals[0].FullBytes, &v); err == nil && len(r) == 0 && v.Equal(oidTSTInfo) {
				haveCT = true
			}
		case at.Type.Equal(oidMsgDigest):
			var v []byte
			if r, err := asn1.Unmarshal(vals[0].FullBytes, &v); err == nil && len(r) == 0 && eq(v, H(eContent)) {
				haveMD = true
			}
		}
	}
	if !haveCT || !haveMD {
		return bad, ErrBundleRoot
	}
	// The signature is over the attributes as a SET OF (tag 0x31).
	signed := append([]byte{}, attrs.FullBytes...)
	signed[0] = 0x31

	// The signing certificate comes from the root's authorities (the token
	// carries none): the one the sid names, in a chain valid at genTime.
	var sid struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}
	if r, err := asn1.Unmarshal(si[1].FullBytes, &sid); err != nil || len(r) != 0 {
		return bad, ErrBundleRoot
	}
	for _, ta := range tr.TSAs {
		if !valid(gen, ta.Start, ta.End) {
			continue
		}
		leaf := ta.Chain[0]
		if !eq(leaf.RawIssuer, sid.Issuer.FullBytes) || leaf.SerialNumber.Cmp(sid.Serial) != 0 {
			continue
		}
		if tsaChainOK(ta, gen) != nil {
			continue
		}
		pk, ok := leaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || !ecdsa.VerifyASN1(pk, H(signed), sigBytes) {
			continue
		}
		if gen.After(now.Add(StampAhead)) {
			return bad, ErrBundleClock
		}
		return gen, nil
	}
	return bad, ErrBundleRoot
}

// tsaChainOK checks the authority's chain at t: the leaf is for time
// stamping only, with the extended key usage critical (RFC 3161 §2.3).
func tsaChainOK(ta TSA, t time.Time) error {
	leaf := ta.Chain[0]
	roots, inter := x509.NewCertPool(), x509.NewCertPool()
	if len(ta.Chain) == 1 {
		roots.AddCert(leaf)
	} else {
		roots.AddCert(ta.Chain[len(ta.Chain)-1])
		for _, c := range ta.Chain[1 : len(ta.Chain)-1] {
			inter.AddCert(c)
		}
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: t,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}}); err != nil {
		return ErrBundleRoot
	}
	if len(leaf.ExtKeyUsage) != 1 || leaf.ExtKeyUsage[0] != x509.ExtKeyUsageTimeStamping {
		return ErrBundleRoot
	}
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(oidExtKeyUsage) {
			if !ext.Critical {
				return ErrBundleRoot
			}
			return nil
		}
	}
	return ErrBundleRoot
}
