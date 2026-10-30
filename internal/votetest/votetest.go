// Package votetest builds what a service, the votes site and Sigstore
// would send a vault (VAULT-MESSAGING §10.19), for tests of the vote
// feature: a service identity, proposals with their tags and record
// proofs, extensions, the service list, and Sigstore bundles verified by
// a pinned test root. Test code only: nothing outside tests imports it.
package votetest

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"sort"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/vms/suite"
	"github.com/vettid/vettid-vault/vms/votewire"
)

// Authority is a stand-in for Sigstore: a Rekor log, a timestamp authority
// and the trusted root that pins them.
type Authority struct {
	rekor   *ecdsa.PrivateKey
	rekorID []byte
	tsa     *ecdsa.PrivateKey
	tsaCert *x509.Certificate
	tsaCA   *x509.Certificate
	// RootJSON is the pinned trusted root; Roots its parse.
	RootJSON []byte
	Roots    []*votewire.TrustRoot
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// NewAuthority returns an authority whose certificates are valid around
// now.
func NewAuthority(now time.Time) *Authority { return NewAuthorityEKU(now, nil) }

// NewAuthorityEKU is NewAuthority with extra extended key usages on the
// timestamp authority's certificate (tests of the EKU rule).
func NewAuthorityEKU(now time.Time, extra []asn1.ObjectIdentifier) *Authority {
	a := &Authority{}
	a.rekor = must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	rekorDER := must(x509.MarshalPKIXPublicKey(&a.rekor.PublicKey))
	a.rekorID = votewire.H(rekorDER)
	caKey := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	a.tsa = must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	nb, na := now.Add(-48*time.Hour), now.Add(48*time.Hour)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-tsa-ca"}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER := must(x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey))
	a.tsaCA = must(x509.ParseCertificate(caDER))
	eku := must(asn1.Marshal(append([]asn1.ObjectIdentifier{{1, 3, 6, 1, 5, 5, 7, 3, 8}}, extra...)))
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(0x1234abcd), Subject: pkix.Name{CommonName: "test-tsa"}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 37}, Critical: true, Value: eku}}}
	leafDER := must(x509.CreateCertificate(rand.Reader, leafTmpl, a.tsaCA, &a.tsa.PublicKey, caKey))
	a.tsaCert = must(x509.ParseCertificate(leafDER))
	root := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
		"tlogs": []any{map[string]any{"baseUrl": "https://rekor.test", "hashAlgorithm": "SHA2_256",
			"publicKey": map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(rekorDER), "keyDetails": "PKIX_ECDSA_P256_SHA_256",
				"validFor": map[string]any{"start": nb.UTC().Format(time.RFC3339)}},
			"logId": map[string]any{"keyId": base64.StdEncoding.EncodeToString(a.rekorID)}}},
		"timestampAuthorities": []any{map[string]any{"uri": "https://tsa.test",
			"certChain": map[string]any{"certificates": []any{map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(leafDER)},
				map[string]any{"rawBytes": base64.StdEncoding.EncodeToString(caDER)}}},
			"validFor": map[string]any{"start": nb.UTC().Format(time.RFC3339)}}},
	}
	a.RootJSON = must(json.Marshal([]any{root}))
	a.Roots = must(votewire.ParseTrustRoots(a.RootJSON))
	return a
}

// AnchorKey is a service's ECDSA P-256 anchor key.
type AnchorKey struct {
	Priv *ecdsa.PrivateKey
	SPKI []byte
}

// NewAnchorKey returns a fresh anchor key.
func NewAnchorKey() *AnchorKey {
	k := must(ecdsa.GenerateKey(elliptic.P256(), rand.Reader))
	return &AnchorKey{Priv: k, SPKI: must(x509.MarshalPKIXPublicKey(&k.PublicKey))}
}

// Cert is anchor_cert: Sign(ik, LabelAnchorKey, H(SPKI)).
func (k *AnchorKey) Cert(ik ed25519.PrivateKey) []byte {
	return must(suite.Sign(ik, votewire.LabelAnchorKey, votewire.H(k.SPKI)))
}

// Bundle anchors doc: a Rekor entry under key and an RFC 3161 token, both
// made at time at, as a Sigstore bundle.
func (a *Authority) Bundle(doc []byte, key *AnchorKey, at time.Time) []byte {
	return a.BundleStamped(doc, key, at, at)
}

// BundleStamped is Bundle with the token's time apart from the entry's.
func (a *Authority) BundleStamped(doc []byte, key *AnchorKey, logAt, stampAt time.Time) []byte {
	dh := votewire.H(doc)
	sig := must(ecdsa.SignASN1(rand.Reader, key.Priv, dh))
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: key.SPKI})
	body := must(json.Marshal(map[string]any{"apiVersion": "0.0.1", "kind": "hashedrekord", "spec": map[string]any{
		"data":      map[string]any{"hash": map[string]any{"algorithm": "sha256", "value": hex.EncodeToString(dh)}},
		"signature": map[string]any{"content": base64.StdEncoding.EncodeToString(sig), "publicKey": map[string]any{"content": base64.StdEncoding.EncodeToString(pemKey)}}}}))
	leafHash := votewire.LeafHash(body)
	// A one-entry log: the root is the entry's leaf hash.
	const size = 1
	text := "rekor.test - 1\n" + strconv.Itoa(size) + "\n" + base64.StdEncoding.EncodeToString(leafHash) + "\n"
	cpSig := must(ecdsa.SignASN1(rand.Reader, a.rekor, votewire.H([]byte(text))))
	env := text + "\n— rekor.test " + base64.StdEncoding.EncodeToString(append(append([]byte{}, a.rekorID[:4]...), cpSig...)) + "\n"
	it := logAt.Unix()
	setPayload := `{"body":"` + base64.StdEncoding.EncodeToString(body) + `","integratedTime":` + strconv.FormatInt(it, 10) +
		`,"logID":"` + hex.EncodeToString(a.rekorID) + `","logIndex":0}`
	set := must(ecdsa.SignASN1(rand.Reader, a.rekor, votewire.H([]byte(setPayload))))
	b64 := base64.StdEncoding.EncodeToString
	bundle := map[string]any{
		"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
		"verificationMaterial": map[string]any{
			"publicKey": map[string]any{"hint": b64(votewire.H(key.SPKI))},
			"tlogEntries": []any{map[string]any{
				"logIndex": "0", "logId": map[string]any{"keyId": b64(a.rekorID)},
				"kindVersion": map[string]any{"kind": "hashedrekord", "version": "0.0.1"}, "integratedTime": strconv.FormatInt(it, 10),
				"inclusionPromise": map[string]any{"signedEntryTimestamp": b64(set)},
				"inclusionProof": map[string]any{"logIndex": "0", "rootHash": b64(leafHash), "treeSize": strconv.Itoa(size),
					"hashes": []any{}, "checkpoint": map[string]any{"envelope": env}},
				"canonicalizedBody": b64(body)}},
			"timestampVerificationData": map[string]any{"rfc3161Timestamps": []any{map[string]any{"signedTimestamp": b64(a.timestamp(votewire.H(sig), stampAt))}}},
		},
		"messageSignature": map[string]any{"messageDigest": map[string]any{"algorithm": "SHA2_256", "digest": b64(dh)}, "signature": b64(sig)},
	}
	return must(json.Marshal(bundle))
}

func der(class, tag int, constructed bool, content []byte) []byte {
	return must(asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: constructed, Bytes: content}))
}

func seq(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return der(asn1.ClassUniversal, asn1.TagSequence, true, b)
}

func set(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return der(asn1.ClassUniversal, asn1.TagSet, true, b)
}

func oid(o ...int) []byte { return must(asn1.Marshal(asn1.ObjectIdentifier(o))) }

// timestamp builds a TimeStampResp over imprint for time t, signed by the
// authority's key (ECDSA with SHA-256, no certificates in the token).
func (a *Authority) timestamp(imprint []byte, t time.Time) []byte {
	sha256 := seq(oid(2, 16, 840, 1, 101, 3, 4, 2, 1), []byte{5, 0})
	tst := seq(must(asn1.Marshal(1)), oid(1, 3, 6, 1, 4, 1, 57264, 2),
		seq(sha256, must(asn1.Marshal(imprint))), must(asn1.Marshal(77)),
		must(asn1.MarshalWithParams(t.UTC(), "generalized")))
	econtent := der(asn1.ClassContextSpecific, 0, true, must(asn1.Marshal(tst)))
	encap := seq(oid(1, 2, 840, 113549, 1, 9, 16, 1, 4), econtent)
	attrs := [][]byte{
		seq(oid(1, 2, 840, 113549, 1, 9, 3), set(oid(1, 2, 840, 113549, 1, 9, 16, 1, 4))),
		seq(oid(1, 2, 840, 113549, 1, 9, 4), set(must(asn1.Marshal(votewire.H(tst))))),
	}
	signedSet := set(attrs...)
	sig := must(ecdsa.SignASN1(rand.Reader, a.tsa, votewire.H(signedSet)))
	implicit := append([]byte{0xA0}, signedSet[1:]...)
	sid := seq(a.tsaCert.RawIssuer, must(asn1.Marshal(a.tsaCert.SerialNumber)))
	si := seq(must(asn1.Marshal(1)), sid, sha256, implicit, seq(oid(1, 2, 840, 10045, 4, 3, 2)), must(asn1.Marshal(sig)))
	sd := seq(must(asn1.Marshal(3)), set(sha256), encap, set(si))
	ci := seq(oid(1, 2, 840, 113549, 1, 7, 2), der(asn1.ClassContextSpecific, 0, true, sd))
	return seq(seq(must(asn1.Marshal(0))), ci)
}

// Service is a service as the vault sees it: an identity key, an anchor key
// and the documents it signs.
type Service struct {
	IK     ed25519.PrivateKey
	Anchor *AnchorKey
	Auth   *Authority
}

// NewService returns a service with fresh keys, anchored by auth.
func NewService(auth *Authority) *Service {
	_, ik, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	return &Service{IK: ik, Anchor: NewAnchorKey(), Auth: auth}
}

// Pub is the identity key's public half.
func (s *Service) Pub() ed25519.PublicKey { return s.IK.Public().(ed25519.PublicKey) }

// Vote is a proposal as the service holds it, with the tags of its
// electorate and the secret of one member.
type Vote struct {
	ID       string
	Doc      []byte
	Sig      []byte
	Hash     []byte
	Proposal *votewire.Proposal
	Tags     [][]byte // sorted
	Secret   []byte   // the member's record_secret
	Tag      []byte
	Index    int
}

// VoteSpec says what to build.
type VoteSpec struct {
	ID               string // a ULID; default a fixed one
	Opens, Closes    time.Time
	Eligible         int // default 3
	Edit             func(p *votewire.Proposal)
	NoBundleKey      bool // sign the Rekor entry with an anchor key the list will not name
	Stamp            time.Time
	LogAt            time.Time
	Secret           []byte
	ExtraChoiceCount int
}

// NewVote builds a proposal of s for an electorate of Eligible members,
// the last-made secret being the member's.
func (s *Service) NewVote(sp VoteSpec) *Vote {
	if sp.ID == "" {
		sp.ID = "01JBQZ0000000000000000000A"
	}
	if sp.Eligible == 0 {
		sp.Eligible = 3
	}
	v := &Vote{ID: sp.ID}
	secret := sp.Secret
	if secret == nil {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			panic(err)
		}
	}
	v.Secret = secret
	v.Tag = must(votewire.RecordTag(sp.ID, secret))
	v.Tags = [][]byte{v.Tag}
	for i := 1; i < sp.Eligible; i++ {
		o := make([]byte, 32)
		if _, err := rand.Read(o); err != nil {
			panic(err)
		}
		v.Tags = append(v.Tags, must(votewire.RecordTag(sp.ID, o)))
	}
	sort.Slice(v.Tags, func(i, j int) bool { return string(v.Tags[i]) < string(v.Tags[j]) })
	for i, t := range v.Tags {
		if string(t) == string(v.Tag) {
			v.Index = i
		}
	}
	p := &votewire.Proposal{V: 1, ProposalID: sp.ID, Service: s.Pub(), Title: "Adopt the budget", Text: "The text.",
		Choices: []votewire.Choice{{ID: "yes", Label: "Yes"}, {ID: "no", Label: "No"}, {ID: "abstain", Label: "Abstain"}},
		Quorum:  votewire.Quorum{Text: "none", MinBallots: 0}, RecordAt: sp.Opens.Unix() - 100, OpensAt: sp.Opens.Unix(), ClosesAt: sp.Closes.Unix(),
		Eligible: int64(sp.Eligible), RecordRoot: votewire.Root(v.Tags), OutageRule: "none"}
	if sp.Edit != nil {
		sp.Edit(p)
	}
	v.Proposal = p
	v.Doc = must(votewire.EncodeDocument(p))
	v.Hash = votewire.H(v.Doc)
	v.Sig = must(suite.Sign(s.IK, votewire.LabelProposal, votewire.ProposalSigMsg(v.Doc)))
	return v
}

// Msg returns the vote.proposal body for the member, with a bundle made at
// at.
func (s *Service) Msg(v *Vote, at time.Time) []byte {
	return s.MsgWithBundle(v, s.Auth.Bundle(v.Doc, s.Anchor, at))
}

// MsgWithBundle is Msg with a given bundle.
func (s *Service) MsgWithBundle(v *Vote, bundle []byte) []byte {
	path := must(votewire.Proof(v.Tags, v.Index))
	m := &votewire.ProposalMsg{Proposal: v.Doc, ProposalSig: v.Sig, Bundle: bundle, RecordSecret: v.Secret,
		RecordProof: &votewire.RecordProof{Index: uint64(v.Index), TreeSize: uint64(len(v.Tags)), Path: path}}
	return m.Marshal()
}

// Extension builds the n-th extension of v to closes, with its message.
//
// Its outage starts at opens_at and lasts three days: valid for any new
// close within the 24 h total (the service's rule, 0.81.1).
func (s *Service) Extension(v *Vote, n int64, closes time.Time, at time.Time) (doc, msg []byte) {
	return s.ExtensionOutage(v, n, closes, at, 0, 0)
}

// ExtensionOutage is Extension with a chosen outage (from, to as unix
// seconds; zero: derived from the proposal's window and the new close).
func (s *Service) ExtensionOutage(v *Vote, n int64, closes time.Time, at time.Time, from, to int64) (doc, msg []byte) {
	if from == 0 {
		from = v.Proposal.OpensAt
		to = from + 3*86400 // long enough for any new close within the 24 h total
	}
	e := &votewire.Extension{V: 1, ProposalID: v.ID, N: n, ClosesAt: closes.Unix(), Outage: votewire.Outage{From: from, To: to, Source: "https://status.test/"}}
	doc = must(votewire.EncodeDocument(e))
	sig := must(suite.Sign(s.IK, votewire.LabelExtended, must(votewire.DocSigMsg(v.Hash, doc))))
	m := &votewire.ExtendedMsg{ProposalID: v.ID, Extension: doc, ExtensionSig: sig, Bundle: s.Auth.Bundle(doc, s.Anchor, at)}
	return doc, m.Marshal()
}

// List builds a service list of the given entries and signs it with site;
// previous is the hash of the earlier list (zeros for the first).
func List(site ed25519.PrivateKey, version int64, previous []byte, svcs ...*Service) (doc, sig []byte) {
	if previous == nil {
		previous = make([]byte, 32)
	}
	l := &votewire.ServiceList{V: 1, Version: version, Previous: previous, Services: []votewire.ServiceEntry{}}
	for _, s := range svcs {
		l.Services = append(l.Services, votewire.ServiceEntry{ServiceID: hex.EncodeToString(votewire.H(s.Pub())[:16]), Name: "Test org",
			IKs: [][]byte{s.Pub()}, AnchorKeys: []votewire.AnchorKey{{Key: s.Anchor.SPKI, AnchorCert: s.Anchor.Cert(s.IK), IK: s.Pub()}}})
	}
	doc = must(votewire.EncodeDocument(l))
	sig = must(suite.Sign(site, votewire.LabelServiceList, votewire.H(doc)))
	return doc, sig
}
