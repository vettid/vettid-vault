package attwire

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/envelope"
)

var jpeg = append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, bytes.Repeat([]byte{7}, 60)...)

func TestSniff(t *testing.T) {
	webp := append(append([]byte("RIFF"), 1, 2, 3, 4), []byte("WEBPVP8 ")...)
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0}
	for b, want := range map[string]string{string(jpeg): MimeJPEG, string(png): MimePNG, string(webp): MimeWEBP,
		"GIF89a": "", "\xFF\xD8": "", "RIFF1234WAVE": "", "": "", "<svg": ""} {
		if got := Sniff([]byte(b)); got != want {
			t.Errorf("Sniff(%q) = %q, want %q", b, got, want)
		}
	}
}

func TestObjectRoundTrip(t *testing.T) {
	k := bytes.Repeat([]byte{9}, 32)
	id := "01JB2Z6V9K3M4N5P6Q7R8S9T60"
	o, err := SealObject(k, "v1", id, PartContent, jpeg)
	if err != nil {
		t.Fatal(err)
	}
	if len(o) != envelope.BlobLen(len(jpeg)) {
		t.Fatal("padded length")
	}
	got, err := OpenObject(k, "v1", id, PartContent, o)
	if err != nil || !bytes.Equal(got, jpeg) {
		t.Fatal("round trip")
	}
	// The part, the vault and the attachment are bound by the AAD.
	for _, c := range [][3]string{{"v1", id, PartThumb}, {"v2", id, PartContent}, {"v1", "01JB2Z6V9K3M4N5P6Q7R8S9T61", PartContent}} {
		if _, err := OpenObject(k, c[0], c[1], c[2], o); err == nil {
			t.Errorf("opened as %v", c)
		}
	}
	if _, err := SealObject(k, "v1", strings.ToLower(id), PartContent, jpeg); err == nil {
		t.Error("lower-case att_id accepted in the AAD")
	}
	if ContentKey("v1", id) != "vaults/v1/att/01jb2z6v9k3m4n5p6q7r8s9t60" || ThumbKey("v1", id) != ContentKey("v1", id)+".t" {
		t.Error("store keys")
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func blobJSON(size int) string {
	return `{"id":"01JB2Z6V9K3M4N5P6Q7R8S9T70","key":"` + b64(make([]byte, 32)) + `","sha256":"` + b64(make([]byte, 32)) +
		`","size":` + itoa(size) + `,"mime":"image/jpeg"}`
}

func itoa(n int) string { return strconv.Itoa(n) }

func parse(t *testing.T, s string) strictjson.Object {
	t.Helper()
	o, err := strictjson.ParseObject([]byte(s))
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return o
}

func TestParseDeviceSend(t *testing.T) {
	th := b64(jpeg)
	ok := `{"blob":` + blobJSON(100) + `,"kind":"photo","width":10,"height":20,"thumb":"` + th + `"}`
	d, err := ParseDeviceSend(parse(t, ok), ReferenceMaxContent)
	if err != nil || d.Blob.Size != 100 || d.Width != 10 || !bytes.Equal(d.Thumb, jpeg) {
		t.Fatalf("%v %+v", err, d)
	}
	cases := map[string]error{
		`{"blob":` + blobJSON(100) + `,"kind":"file","width":10,"height":20,"thumb":"` + th + `"}`:                                                                             ErrKind,
		`{"blob":` + blobJSON(100) + `,"kind":"photo","width":10,"height":20,"thumb":"` + b64([]byte("GIF89a")) + `"}`:                                                         ErrThumbType,
		`{"blob":` + blobJSON(ReferenceMaxContent+1) + `,"kind":"photo","width":10,"height":20,"thumb":"` + th + `"}`:                                                          ErrMalformed,
		`{"blob":` + blobJSON(100) + `,"kind":"photo","width":8193,"height":20,"thumb":"` + th + `"}`:                                                                          ErrMalformed,
		`{"blob":` + blobJSON(100) + `,"kind":"photo","width":0,"height":20,"thumb":"` + th + `"}`:                                                                             ErrMalformed,
		`{"blob":` + blobJSON(100) + `,"kind":"photo","width":10,"height":20,"thumb":""}`:                                                                                      ErrMalformed,
		`{"blob":` + blobJSON(100) + `,"kind":"photo","width":10,"height":20,"thumb":"` + b64(append(append([]byte(nil), jpeg[:3]...), make([]byte, ThumbMaxBytes)...)) + `"}`: ErrMalformed,
		`{"kind":"photo","width":10,"height":20,"thumb":"` + th + `"}`:                                                                                                         ErrMalformed,
	}
	for s, want := range cases {
		if _, err := ParseDeviceSend(parse(t, s), ReferenceMaxContent); !errors.Is(err, want) {
			t.Errorf("%.80s...: %v, want %v", s, err, want)
		}
	}
}

func TestParsePeerView(t *testing.T) {
	th := b64(jpeg)
	with := `{"blob":` + blobJSON(100) + `,"kind":"photo","size":100,"width":1,"height":1,"thumb":"` + th + `","expires_at":"2026-10-08T12:00:00.000Z"}`
	v, err := ParsePeerView(parse(t, with), ReferenceMaxContent)
	if err != nil || v.Blob == nil || v.Size != 100 || v.Expires.IsZero() {
		t.Fatalf("%v %+v", err, v)
	}
	without := `{"kind":"photo","size":100,"width":1,"height":1,"thumb":"` + th + `"}`
	if v, err := ParsePeerView(parse(t, without), ReferenceMaxContent); err != nil || v.Blob != nil {
		t.Fatal("without blob")
	}
	if v, err := ParsePeerView(parse(t, `{"kind":"video","size":100,"width":1,"height":1,"thumb":"`+th+`"}`), ReferenceMaxContent); err != nil || v.Kind != "video" {
		t.Fatal("other kind is returned for a refusal")
	}
	// Another kind needs neither dimensions nor a thumbnail: refused
	// (type), not dropped as malformed.
	if v, err := ParsePeerView(parse(t, `{"kind":"file","size":100}`), ReferenceMaxContent); err != nil || v.Kind != "file" || v.Size != 100 {
		t.Fatalf("another kind without photo members: %v", err)
	}
	// The blob it names is kept by id, so that the refusal deletes it.
	if v, err := ParsePeerView(parse(t, `{"kind":"file","blob":{"id":"01JB2Z6V9K3M4N5P6Q7R8S9T70"}}`), ReferenceMaxContent); err != nil || v.Blob == nil || v.Blob.ID != "01JB2Z6V9K3M4N5P6Q7R8S9T70" {
		t.Fatalf("another kind's blob: %v", err)
	}
	if v, err := ParsePeerView(parse(t, `{"kind":"photo","size":100,"width":1,"height":1,"thumb":"`+b64([]byte("<svg/>"))+`"}`), ReferenceMaxContent); err != nil || !v.ThumbBad {
		t.Fatal("thumbnail type")
	}
	for _, s := range []string{
		`{"blob":` + blobJSON(100) + `,"kind":"photo","size":100,"width":1,"height":1,"thumb":"` + th + `"}`,                                        // blob without expires_at
		`{"kind":"photo","size":100,"width":1,"height":1,"thumb":"` + th + `","expires_at":"2026-10-08T12:00:00.000Z"}`,                             // expires_at without blob
		`{"blob":` + blobJSON(99) + `,"kind":"photo","size":100,"width":1,"height":1,"thumb":"` + th + `","expires_at":"2026-10-08T12:00:00.000Z"}`, // sizes differ
		`{"kind":"photo","size":` + itoa(ReferenceMaxContent+1) + `,"width":1,"height":1,"thumb":"` + th + `"}`,                                     // oversized
		`{"kind":"photo","size":100,"width":1,"height":1}`,                                                                                          // no thumbnail
		`{"blob":` + blobJSON(100) + `,"kind":"photo","size":100,"width":1,"height":1,"thumb":"` + th + `","expires_at":"2026-10-08T12:00:00Z"}`,    // ts form
	} {
		if _, err := ParsePeerView(parse(t, s), ReferenceMaxContent); !errors.Is(err, ErrMalformed) {
			t.Errorf("accepted %.90s", s)
		}
	}
	// The rendered view parses back.
	b := &Blob{ID: "01JB2Z6V9K3M4N5P6Q7R8S9T70", Key: make([]byte, 32), Size: 5, Mime: "image/png"}
	if _, err := ParsePeerView(parse(t, string(PeerViewJSON(b, v.Expires, KindPhoto, 5, 2, 3, jpeg))), ReferenceMaxContent); err != nil {
		t.Fatal(err)
	}
}

func FuzzParsePeerView(f *testing.F) {
	f.Add([]byte(`{"kind":"photo","size":100,"width":1,"height":1,"thumb":"` + b64(jpeg) + `"}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := strictjson.ParseObject(b)
		if err != nil {
			return
		}
		v, err := ParsePeerView(o, ReferenceMaxContent)
		if err != nil {
			return
		}
		if v.Kind != KindPhoto {
			if v.Blob != nil && (len(v.Blob.Key) > 0 || !envelope.ValidULID(v.Blob.ID)) || len(v.Thumb) > 0 || v.Size > ReferenceMaxContent || v.Width > PhotoMaxSide {
				t.Fatalf("another kind kept invalid members: %+v", v)
			}
			return
		}
		if v.Size < 1 || v.Size > ReferenceMaxContent || len(v.Thumb) > ThumbMaxBytes || v.Width < 1 || v.Width > PhotoMaxSide ||
			v.Blob != nil && v.Blob.Size != v.Size {
			t.Fatalf("invalid view accepted: %+v", v)
		}
	})
}

func FuzzUnframe(f *testing.F) {
	fr, _ := envelope.Frame(jpeg)
	f.Add(fr)
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := envelope.Unframe(b)
		if err != nil {
			return
		}
		re, _ := envelope.Frame(c)
		if !bytes.Equal(re, b) {
			t.Fatal("accepted a framing that does not re-frame identically")
		}
	})
}
