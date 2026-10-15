// Package attwire holds the wire and at-rest formats of message
// attachments (VAULT-MESSAGING 0.32.0 §10.5.1, release A): the release
// constants, type sniffing, the at-rest object of each stored attachment
// and its store keys, and strict parsers of the device and peer views.
// Everything here is a pure function of its inputs.
package attwire

import (
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Release constants of release A (§10.5.1 "Constants"). Byte counts that
// depend on the relay (attachment_max_bytes) are computed from its
// advertised max_blob_bytes (envelope.MaxBlobContent).
const (
	KindPhoto        = "photo"
	ThumbMaxBytes    = 32768
	PhotoMaxSide     = 8192
	StorageMax       = 1 << 30 // attachment_storage
	CountMax         = 4096    // attachments
	PeerStorageMax   = 256 << 20
	PeerAcceptMax    = 64 // peer_attachments: count per rolling 24 h
	PeerAcceptBytes  = 256 << 20
	PeerReuploadMax  = 64 // peer_reuploads
	PeerReuploadByte = 256 << 20
	VaultTransfers   = 2 // attachment_transfers per vault
	DeviceFetches    = 2 // attachment_fetches per device
	Reoffers         = 3 // attachment_reoffers
	MimeMaxBytes     = 64
	NameMaxBytes     = 255

	Window        = 7 * 24 * time.Hour  // attachment_window
	MissingWindow = 30 * 24 * time.Hour // missing_window
	MissingFirst  = 10 * time.Minute    // missing_backoff, first
	MissingMax    = 24 * time.Hour      // missing_backoff, at most
	MissingTurn   = 24 * time.Hour      // missing_turn
	RollingWindow = 24 * time.Hour      // the rolling budgets
)

// ReferenceMaxBlob is vettid.org's max_blob_bytes, and ReferenceMaxContent
// the attachment_max_bytes it gives (§10.5.1).
const (
	ReferenceMaxBlob    = 8388608
	ReferenceMaxContent = 8257532
)

// MaxThumbObject is the largest thumbnail object (VAULT-HOST-PROTOCOL §9).
var MaxThumbObject = envelope.BlobLen(ThumbMaxBytes)

// Photo types accepted by sniffing (§10.5.1 "Sniffing").
const (
	MimeJPEG = "image/jpeg"
	MimePNG  = "image/png"
	MimeWEBP = "image/webp"
)

// Sniff decides the type from the content's first bytes and nothing else;
// "" when it is not one of photo_types. No other parsing of the content is
// done: no image decoder runs in the enclave.
func Sniff(b []byte) string {
	switch {
	case len(b) >= 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF:
		return MimeJPEG
	case len(b) >= 8 && string(b[:8]) == "\x89PNG\r\n\x1a\n":
		return MimePNG
	case len(b) >= 12 && string(b[:4]) == "RIFF" && string(b[8:12]) == "WEBP":
		return MimeWEBP
	}
	return ""
}

// Parts of an attachment's at-rest objects.
const (
	PartContent = "c"
	PartThumb   = "t"
)

// LabelAtt is the at-rest object's AAD label (§10.5.1 "At rest").
const LabelAtt = "vettid/vms/2/att"

// ObjectAAD is "vettid/vms/2/att" || 0x00 || vault_id || 0x00 || att_id ||
// 0x00 || part || 0x00 || ver, with att_id the canonical (upper case) ULID.
func ObjectAAD(vaultID, attID, part string, ver byte) []byte {
	b := make([]byte, 0, len(LabelAtt)+len(vaultID)+len(attID)+len(part)+5)
	b = append(b, LabelAtt...)
	b = append(b, 0)
	b = append(b, vaultID...)
	b = append(b, 0)
	b = append(b, attID...)
	b = append(b, 0)
	b = append(b, part...)
	b = append(b, 0)
	return append(b, ver)
}

// SealObject seals one at-rest object: 0x01 || nonce || XChaCha20-Poly1305(
// k_att, nonce, aad, framed), framed as a blob's plaintext (§5.5).
func SealObject(kAtt []byte, vaultID, attID, part string, content []byte) ([]byte, error) {
	if !envelope.ValidULID(attID) || (part != PartContent && part != PartThumb) {
		return nil, errBad
	}
	return envelope.SealFramed(kAtt, ObjectAAD(vaultID, attID, part, envelope.BlobVersion), content)
}

// OpenObject opens an at-rest object written by SealObject.
func OpenObject(kAtt []byte, vaultID, attID, part string, obj []byte) ([]byte, error) {
	if len(obj) == 0 || !envelope.ValidULID(attID) {
		return nil, errBad
	}
	return envelope.OpenFramed(kAtt, ObjectAAD(vaultID, attID, part, obj[0]), obj)
}

// ContentKey and ThumbKey are the store keys of an attachment's objects:
// vaults/<vault_id>/att/<lowercase att_id> and the same with ".t". Store
// keys allow lower case only (VAULT-HOST-PROTOCOL §5.2).
func ContentKey(vaultID, attID string) string {
	return "vaults/" + vaultID + "/att/" + strings.ToLower(attID)
}

// ThumbKey is the thumbnail object's store key.
func ThumbKey(vaultID, attID string) string { return ContentKey(vaultID, attID) + ".t" }

// Prefix is the store prefix of a vault's attachment objects (P15).
func Prefix(vaultID string) string { return "vaults/" + vaultID + "/att/" }

var errBad = errors.New("attwire: malformed")

// ErrMalformed is a view that does not have the shape of §10.5.1.
var ErrMalformed = errBad

// ErrKind is a well-formed attachment of a kind this version does not
// accept (refused with reason type from a peer, bad_request from a
// device).
var ErrKind = errors.New("attwire: unknown kind")

// ErrThumbType is a thumbnail that is not one of photo_types.
var ErrThumbType = errors.New("attwire: thumbnail type")

// Blob is §5.5's claim-check reference.
type Blob struct {
	ID     string
	Key    []byte
	SHA256 [32]byte
	Size   int
	Mime   string
	Name   string
	// HasName: name was present.
	HasName bool
}

// JSON renders the reference ({id, key, sha256, size, mime, name?}).
func (b *Blob) JSON() []byte {
	j := strictjson.NewBuilder().String("id", b.ID).Base64("key", b.Key).Base64("sha256", b.SHA256[:]).
		Uint("size", uint64(b.Size)).String("mime", b.Mime)
	if b.HasName {
		j.String("name", b.Name)
	}
	return j.Bytes()
}

// ParseBlob parses a blob reference strictly; maxContent is
// attachment_max_bytes.
func ParseBlob(o strictjson.Object, maxContent int) (*Blob, error) {
	b := &Blob{}
	var err error
	if b.ID, err = o.String("id"); err != nil || !envelope.ValidULID(b.ID) {
		return nil, errBad
	}
	if b.Key, err = o.Base64("key", 32); err != nil {
		return nil, errBad
	}
	sum, err := o.Base64("sha256", 32)
	if err != nil {
		return nil, errBad
	}
	copy(b.SHA256[:], sum)
	size, err := o.Uint("size", 1, uint64(max(maxContent, 1)))
	if err != nil {
		return nil, errBad
	}
	b.Size = int(size)
	if b.Mime, err = o.String("mime"); err != nil || len(b.Mime) == 0 || len(b.Mime) > MimeMaxBytes || !printable(b.Mime) {
		return nil, errBad
	}
	if b.Name, b.HasName, err = o.OptString("name"); err != nil || b.HasName && !validName(b.Name) {
		return nil, errBad
	}
	return b, nil
}

func printable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

func validName(s string) bool {
	if len(s) == 0 || len(s) > NameMaxBytes || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Thumb decodes and checks a thumbnail: base64, 1 to thumb_max_bytes
// decoded, one of photo_types by sniffing (ErrThumbType otherwise).
func Thumb(o strictjson.Object) ([]byte, error) {
	s, err := o.String("thumb")
	if err != nil || len(s) > (ThumbMaxBytes+2)/3*4 {
		return nil, errBad
	}
	t, err := strictjson.DecodeStd(s, -1)
	if err != nil || len(t) == 0 || len(t) > ThumbMaxBytes {
		return nil, errBad
	}
	if Sniff(t) == "" {
		return nil, ErrThumbType
	}
	return t, nil
}

func dims(o strictjson.Object) (int, int, error) {
	w, err1 := o.Uint("width", 1, PhotoMaxSide)
	h, err2 := o.Uint("height", 1, PhotoMaxSide)
	if err1 != nil || err2 != nil {
		return 0, 0, errBad
	}
	return int(w), int(h), nil
}

// DeviceSend is a parsed device send view: {blob, kind, width, height,
// thumb}.
type DeviceSend struct {
	Blob          *Blob
	Kind          string
	Width, Height int
	Thumb         []byte
}

// ParseDeviceSend parses message.send's attachment from a device. A
// well-formed attachment of another kind is ErrKind; a thumbnail of
// another type ErrThumbType (both bad_request).
func ParseDeviceSend(o strictjson.Object, maxContent int) (*DeviceSend, error) {
	d := &DeviceSend{}
	bo, err := o.Object("blob")
	if err != nil {
		return nil, errBad
	}
	if d.Blob, err = ParseBlob(bo, maxContent); err != nil {
		return nil, err
	}
	if d.Kind, err = o.String("kind"); err != nil {
		return nil, errBad
	}
	if d.Width, d.Height, err = dims(o); err != nil {
		return nil, err
	}
	if d.Thumb, err = Thumb(o); err != nil {
		return nil, err
	}
	if d.Kind != KindPhoto {
		return nil, ErrKind
	}
	return d, nil
}

// PeerView is a parsed peer view: {blob?, kind, size, width, height,
// thumb, expires_at?}.
type PeerView struct {
	Blob          *Blob // nil when the sender uploaded none
	Expires       time.Time
	Kind          string
	Size          int
	Width, Height int
	Thumb         []byte
	// ThumbBad: the thumbnail decoded but is not one of photo_types (the
	// attachment is refused with reason type).
	ThumbBad bool
}

// ParsePeerView parses a peer vault's attachment (which may be malicious)
// strictly. ErrMalformed is dropped and audited; a view of another kind
// is returned with Kind set and only its valid members (refused with
// reason type), and a photo whose thumbnail has another type with
// ThumbBad.
func ParsePeerView(o strictjson.Object, maxContent int) (*PeerView, error) {
	v := &PeerView{}
	var err error
	if v.Kind, err = o.String("kind"); err != nil || v.Kind == "" || len(v.Kind) > 32 {
		return nil, errBad
	}
	if v.Kind != KindPhoto {
		// Another kind (a later version's file) is refused with reason
		// type, whatever members it has: only what is valid is kept for
		// the device view (§10.5.1 "Kinds").
		if n, err := o.Uint("size", 1, uint64(max(maxContent, 1))); err == nil {
			v.Size = int(n)
		}
		if w, h, err := dims(o); err == nil {
			v.Width, v.Height = w, h
		}
		// A blob it names is deleted by the refusal: its id only.
		if bo, err := o.Object("blob"); err == nil {
			if id, err := bo.String("id"); err == nil && envelope.ValidULID(id) {
				v.Blob = &Blob{ID: id}
			}
		}
		return v, nil
	}
	size, err := o.Uint("size", 1, uint64(max(maxContent, 1)))
	if err != nil {
		return nil, errBad
	}
	v.Size = int(size)
	if v.Width, v.Height, err = dims(o); err != nil {
		return nil, err
	}
	v.Thumb, err = Thumb(o)
	switch {
	case errors.Is(err, ErrThumbType):
		v.ThumbBad = true
	case err != nil:
		return nil, errBad
	}
	braw, hasBlob, err := o.OptObjectRaw("blob")
	if err != nil {
		return nil, errBad
	}
	es, hasExp, err := o.OptString("expires_at")
	if err != nil || hasBlob != hasExp {
		return nil, errBad // blob and expires_at come together (§10.5.1)
	}
	if hasBlob {
		bo, err := strictjson.AsObject(braw)
		if err != nil {
			return nil, errBad
		}
		if v.Blob, err = ParseBlob(bo, maxContent); err != nil || v.Blob.Size != v.Size {
			return nil, errBad
		}
		if v.Expires, err = envelope.ParseTS(es); err != nil {
			return nil, errBad
		}
	}
	return v, nil
}

// PeerViewJSON renders a peer view.
func PeerViewJSON(b *Blob, expires time.Time, kind string, size, width, height int, thumb []byte) []byte {
	j := strictjson.NewBuilder()
	if b != nil {
		j.Raw("blob", b.JSON())
	}
	j.String("kind", kind).Uint("size", uint64(size)).Uint("width", uint64(width)).Uint("height", uint64(height)).
		Base64("thumb", thumb)
	if b != nil {
		j.String("expires_at", envelope.FormatTS(expires))
	}
	return j.Bytes()
}
