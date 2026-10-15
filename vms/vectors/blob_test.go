package vectors

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

func TestBlobVectors(t *testing.T)       { checkBlobVectors(t, Dir) }
func TestAttachmentVectors(t *testing.T) { checkAttachmentVectors(t, Dir) }

// The §16 values VAULT-MESSAGING 0.32.0 computed with libsodium (PyNaCl
// 1.6.2), which the Go implementation must reproduce byte for byte.
const (
	specBlobHex   = "014242424242424242424242424242424242424242424242428bc717db7fb8a445febbaabd807a58775e41934164fe8ddcfe8093c4c77c2064248d7c6ef71c3ec55301e7618822969b753ca385"
	specBlobSHA   = "c156a871b2f92daf27207407440629c2d0f3c2190508ef17ab799e8d5a923920"
	specBlobSHA64 = "wVaocbL5La8nIHQHRAYpwtDzwhkFCO8Xq3mejVqSOSA="
	specAttAAD    = "7665747469642f766d732f322f61747400746573742d7661756c742d303030310030314a42325a3656394b334d344e35503651375238533954363000630001"
	specAttObject = "014444444444444444444444444444444444444444444444445a4d753936452827c31a13e25a09270008056b278ab92e665d38321504e5bb799b843807a69b25394581e7b1c74a02a67ba26917"
	specAttKey    = "vaults/test-vault-0001/att/01jb2z6v9k3m4n5p6q7r8s9t60"
)

// padmeRef is Padmé computed the long way (floating-point free, from the
// definition), to check envelope.Padme.
func padmeRef(l int) int {
	e := 0
	for 1<<(e+1) <= l {
		e++
	}
	s := 0
	for 1<<s <= e {
		s++
	}
	z := e - s
	m := 1 << z
	return (l + m - 1) / m * m
}

// openByHand opens a blob with chacha20poly1305 directly (independent of
// envelope's code) and returns the framed plaintext.
func openByHand(t *testing.T, key, b []byte) []byte {
	a, err := chacha20poly1305.NewX(key)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := a.Open(nil, b[1:25], b[25:], append([]byte("vettid/vms/2/blob\x00"), b[0]))
	if err != nil {
		t.Fatalf("blob does not open: %v", err)
	}
	return pt
}

func checkBlobVectors(t *testing.T, dir string) {
	d := load(t, dir, "blob.json")
	key, nonce, content := d.hex("key_hex"), d.hex("nonce_hex"), d.hex("content_hex")
	if d.str("label") != "vettid/vms/2/blob" || d.num("version") != 1 {
		t.Fatal("label or version")
	}
	if !bytes.Equal(key, bytes.Repeat([]byte{0x41}, 32)) || !bytes.Equal(nonce, bytes.Repeat([]byte{0x42}, 24)) || hex.EncodeToString(content) != BlobContentHex {
		t.Fatal("inputs differ from §16")
	}
	blob := d.hex("blob_hex")
	if !bytes.Equal(blob[1:25], nonce) || blob[0] != 1 {
		t.Fatal("layout")
	}
	// Independent of envelope: the framing and the AEAD by hand.
	framed := d.hex("framed_hex")
	want := make([]byte, padmeRef(4+len(content)))
	binary.BigEndian.PutUint32(want, uint32(len(content)))
	copy(want[4:], content)
	eq(t, "framed", framed, want)
	eq(t, "opened by hand", openByHand(t, key, blob), framed)
	eq(t, "aad", d.hex("aad_hex"), []byte("vettid/vms/2/blob\x00\x01"))
	sum := sha256.Sum256(blob)
	eq(t, "sha256", sum[:], d.hex("sha256_hex"))
	eq(t, "sha256 b64", sum[:], d.b64("sha256_b64"))
	if d.num("blob_len") != len(blob) || len(blob) != 41+len(framed) || d.num("padme") != len(framed) {
		t.Fatal("lengths")
	}
	// The library opens it, and the spec's libsodium values match.
	got, err := envelope.OpenBlob(blob, key, sum, len(content))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "content", got, content)
	if dir == Dir {
		eq(t, "§16 blob (libsodium)", blob, mustHex(specBlobHex))
		eq(t, "§16 sha256 (libsodium)", sum[:], mustHex(specBlobSHA))
		if d.str("sha256_b64") != specBlobSHA64 {
			t.Error("§16 sha256 b64")
		}
	}
	// Reference numbers (§10.5.1, VAULT-HOST-PROTOCOL §9).
	ref := d.sub("reference")
	if ref.num("attachment_max_bytes") != 8257532 || envelope.MaxBlobContent(ref.num("max_blob_bytes")) != 8257532 ||
		ref.num("largest_blob_len") != 8257577 || ref.num("largest_thumb_object_len") != 34857 {
		t.Error("reference numbers")
	}
	var samples []struct{ L, Padme int }
	if err := json.Unmarshal(d.m["padme_samples"], &samples); err != nil || len(samples) == 0 {
		t.Fatal("padme_samples")
	}
	for _, s := range samples {
		if envelope.Padme(s.L) != s.Padme || padmeRef(s.L) != s.Padme {
			t.Errorf("Padme(%d) = %d, ref %d, file %d", s.L, envelope.Padme(s.L), padmeRef(s.L), s.Padme)
		}
	}
	for l := 2; l < 1<<16; l++ {
		if envelope.Padme(l) != padmeRef(l) {
			t.Fatalf("Padme(%d)", l)
		}
	}
	var fails []struct {
		Name, Why, Error string
		BlobHex          string `json:"blob_hex"`
		SHA256Hex        string `json:"sha256_hex"`
		Size             int
	}
	if err := json.Unmarshal(d.m["must_fail"], &fails); err != nil || len(fails) < 5 {
		t.Fatal("must_fail")
	}
	wantErr := map[string]error{"sha256": envelope.ErrBlobHash, "version": envelope.ErrBlobVersion, "framing": envelope.ErrBlobFrame, "size": envelope.ErrBlobSize}
	for _, f := range fails {
		var s [32]byte
		copy(s[:], mustHex(f.SHA256Hex))
		_, err := envelope.OpenBlob(mustHex(f.BlobHex), key, s, f.Size)
		if we := wantErr[f.Error]; we == nil || !errors.Is(err, we) {
			t.Errorf("%s: %v, want %s", f.Name, err, f.Error)
		}
	}
}

func checkAttachmentVectors(t *testing.T, dir string) {
	d := load(t, dir, "attachment.json")
	key, content := d.hex("k_att_hex"), d.hex("content_hex")
	vid, att := d.str("vault_id"), d.str("att_id")
	if !bytes.Equal(key, bytes.Repeat([]byte{0x43}, 32)) || vid != BlobVaultID || att != BlobAttID || d.str("label") != "vettid/vms/2/att" {
		t.Fatal("inputs differ from §16")
	}
	var objs []struct {
		Part      string
		NonceHex  string `json:"nonce_hex"`
		AADHex    string `json:"aad_hex"`
		ObjectHex string `json:"object_hex"`
		ObjectLen int    `json:"object_len"`
		StoreKey  string `json:"store_key"`
	}
	if err := json.Unmarshal(d.m["objects"], &objs); err != nil || len(objs) != 2 {
		t.Fatal("objects")
	}
	for _, o := range objs {
		aad := []byte("vettid/vms/2/att\x00" + vid + "\x00" + att + "\x00" + o.Part + "\x00\x01")
		eq(t, o.Part+" aad", mustHex(o.AADHex), aad)
		ob := mustHex(o.ObjectHex)
		if ob[0] != 1 || !bytes.Equal(ob[1:25], mustHex(o.NonceHex)) || len(ob) != o.ObjectLen {
			t.Fatalf("%s layout", o.Part)
		}
		a, _ := chacha20poly1305.NewX(key)
		framed, err := a.Open(nil, ob[1:25], ob[25:], aad)
		if err != nil {
			t.Fatalf("%s does not open by hand", o.Part)
		}
		eq(t, o.Part+" framed", framed, d.hex("framed_hex"))
		got, err := attwire.OpenObject(key, vid, att, o.Part, ob)
		if err != nil {
			t.Fatal(err)
		}
		eq(t, o.Part+" content", got, content)
		wantKey := attwire.ContentKey(vid, att)
		if o.Part == "t" {
			wantKey = attwire.ThumbKey(vid, att)
		}
		if o.StoreKey != wantKey {
			t.Errorf("%s store key %s", o.Part, o.StoreKey)
		}
		// Another part's or vault's AAD does not open it.
		if _, err := attwire.OpenObject(key, vid+"x", att, o.Part, ob); err == nil {
			t.Errorf("%s opened under another vault id", o.Part)
		}
		if dir == Dir && o.Part == "c" {
			eq(t, "§16 aad (libsodium)", aad, mustHex(specAttAAD))
			eq(t, "§16 object (libsodium)", ob, mustHex(specAttObject))
			if o.StoreKey != specAttKey {
				t.Error("§16 store key")
			}
		}
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
