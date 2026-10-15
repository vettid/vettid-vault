//go:build vmsvectors

package vectors

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// genBlob builds blob.json (§5.5, 0.32.0): the versioned, padded blob
// sealed through envelope.SealBlobWithKey with the nonce scripted, and
// blobs that MUST fail, each built by hand so that only the property it
// tests is wrong (its sha256 is that of its own bytes, so that every one
// but the flipped byte passes the hash check and fails later).
func genBlob() (obj, error) {
	key := rep(KeyBlob, suite.KeySize)
	nonce := rep(NonceBlob, suite.XNonceSize)
	content, _ := hex.DecodeString(BlobContentHex)
	framed, err := envelope.Frame(content)
	if err != nil {
		return nil, err
	}
	var blob []byte
	if err := with(newScript(nonce), func() (err error) {
		blob, err = envelope.SealBlobWithKey(key, content)
		return err
	}); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(blob)
	aad := append([]byte(suite.LabelBlob+"\x00"), envelope.BlobVersion)

	// seal seals framed bytes under the vector key and nonce with the
	// version byte ver (in the AAD and the first byte).
	seal := func(ver byte, framed []byte) ([]byte, error) {
		a := append([]byte(suite.LabelBlob+"\x00"), ver)
		ct, err := suite.SealX(key, nonce, a, framed)
		if err != nil {
			return nil, err
		}
		return append(append([]byte{ver}, nonce...), ct...), nil
	}
	bad := func(name, why, err string, b []byte, sum []byte) obj {
		if sum == nil {
			s := sha256.Sum256(b)
			sum = s[:]
		}
		return obj{{"name", name}, {"why", why}, {"blob_hex", hx(b)}, {"sha256_hex", hx(sum)}, {"size", len(content)}, {"error", err}}
	}
	var fails []obj
	flipped := append([]byte(nil), blob...)
	flipped[len(flipped)/2] ^= 0x01
	fails = append(fails, bad("flipped_byte", "one byte of the blob flipped: refused by the sha256 check, before decryption", "sha256", flipped, sum[:]))
	if b, err := seal(0x02, framed); err == nil {
		fails = append(fails, bad("unknown_version", "version byte 0x02 (also in the AAD): refused before decryption", "version", b, nil))
	} else {
		return nil, err
	}
	over := append(append([]byte(nil), framed...), make([]byte, 4)...) // 40 bytes: not Padme(33)
	if b, err := seal(envelope.BlobVersion, over); err == nil {
		fails = append(fails, bad("over_padded", "framed plaintext of 40 bytes where Padme(4 + 29) = 36", "framing", b, nil))
	} else {
		return nil, err
	}
	nz := append([]byte(nil), framed...)
	nz[len(nz)-1] = 0x01
	if b, err := seal(envelope.BlobVersion, nz); err == nil {
		fails = append(fails, bad("nonzero_padding", "the last padding byte is 0x01", "framing", b, nil))
	} else {
		return nil, err
	}
	long := append([]byte(nil), framed...)
	binary.BigEndian.PutUint32(long, uint32(len(framed)-envelope.FrameHeader+1)) // 33: beyond the 32 bytes after the length
	if b, err := seal(envelope.BlobVersion, long); err == nil {
		fails = append(fails, bad("len_beyond_framed", "len = 33, more than the framed length less 4 (32)", "framing", b, nil))
	} else {
		return nil, err
	}
	if b, err := seal(envelope.BlobVersion, framed); err == nil {
		fails = append(fails, bad("size_mismatch", "a well-formed blob whose content is 29 bytes, received with size 30", "size", b, nil))
		fails[len(fails)-1][4] = member{"size", len(content) + 1}
	} else {
		return nil, err
	}
	return obj{
		{"description", "VAULT-MESSAGING 0.32.0 §5.5 claim-check blob, version 0x01, Padmé padding (TEST ONLY)"},
		{"label", suite.LabelBlob},
		{"version", int(envelope.BlobVersion)},
		{"key_hex", hx(key)},
		{"nonce_hex", hx(nonce)},
		{"content_hex", hx(content)},
		{"size", len(content)},
		{"padme", envelope.Padme(envelope.FrameHeader + len(content))},
		{"framed_hex", hx(framed)},
		{"aad_hex", hx(aad)},
		{"blob_hex", hx(blob)},
		{"blob_len", len(blob)},
		{"sha256_hex", hx(sum[:])},
		{"sha256_b64", b64(sum[:])},
		{"reference", obj{
			{"max_blob_bytes", attwire.ReferenceMaxBlob},
			{"attachment_max_bytes", envelope.MaxBlobContent(attwire.ReferenceMaxBlob)},
			{"largest_blob_len", envelope.BlobLen(envelope.MaxBlobContent(attwire.ReferenceMaxBlob))},
			{"thumb_max_bytes", attwire.ThumbMaxBytes},
			{"largest_thumb_object_len", envelope.BlobLen(attwire.ThumbMaxBytes)},
		}},
		{"padme_samples", padmeSamples()},
		{"must_fail", fails},
	}, nil
}

// padmeSamples are Padmé values at a few lengths (L = 4 + content length).
func padmeSamples() []obj {
	var out []obj
	for _, l := range []int{5, 33, 100, 1000, 32772, 1 << 20, 8257536, 8257537} {
		out = append(out, obj{{"l", l}, {"padme", envelope.Padme(l)}})
	}
	return out
}

// genAttachment builds attachment.json (§10.5.1, 0.32.0): the at-rest
// object for parts "c" and "t" through attwire.SealObject, nonces
// scripted, with their AADs and store keys.
func genAttachment() (obj, error) {
	key := rep(KeyAtt, suite.KeySize)
	content, _ := hex.DecodeString(BlobContentHex)
	framed, err := envelope.Frame(content)
	if err != nil {
		return nil, err
	}
	part := func(p string, nonceByte byte, storeKey string) (obj, error) {
		var o []byte
		if err := with(newScript(rep(nonceByte, suite.XNonceSize)), func() (err error) {
			o, err = attwire.SealObject(key, BlobVaultID, BlobAttID, p, content)
			return err
		}); err != nil {
			return nil, err
		}
		return obj{{"part", p}, {"nonce_hex", hx(rep(nonceByte, suite.XNonceSize))},
			{"aad_hex", hx(attwire.ObjectAAD(BlobVaultID, BlobAttID, p, envelope.BlobVersion))},
			{"object_hex", hx(o)}, {"object_len", len(o)}, {"store_key", storeKey}}, nil
	}
	c, err := part(attwire.PartContent, NonceAtt, attwire.ContentKey(BlobVaultID, BlobAttID))
	if err != nil {
		return nil, err
	}
	t, err := part(attwire.PartThumb, NonceAttT, attwire.ThumbKey(BlobVaultID, BlobAttID))
	if err != nil {
		return nil, err
	}
	return obj{
		{"description", "VAULT-MESSAGING 0.32.0 §10.5.1 at-rest attachment objects (TEST ONLY); att_id upper case in the AAD, lower case in the store key"},
		{"label", attwire.LabelAtt},
		{"k_att_hex", hx(key)},
		{"vault_id", BlobVaultID},
		{"att_id", BlobAttID},
		{"content_hex", hx(content)},
		{"framed_hex", hx(framed)},
		{"objects", []obj{c, t}},
	}, nil
}
