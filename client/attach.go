package client

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/attwire"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Attachments (VAULT-MESSAGING 0.32.0 §10.5.1): the reference app's side.
// The app seals a photo as a §5.5 blob under a fresh key and uploads it to
// its vault's own mailbox under its standing token; to show one it asks
// its vault, fetches the blob the vault uploaded to its own mailbox,
// deletes it there and keeps the photo in memory only.

// ErrBlob is a blob that failed the checks of §5.5.
var ErrBlob = errors.New("client: blob failed its checks")

// UploadAttachment seals content and uploads it to the vault's mailbox.
// It returns the blob reference to put in message.send's attachment.
func (d *Device) UploadAttachment(ctx context.Context, content []byte, mime string) (*attwire.Blob, error) {
	d.mu.Lock()
	v := d.st.Vault
	if v == nil || v.Token == "" {
		d.mu.Unlock()
		return nil, ErrNotPaired
	}
	url, mailbox, token := v.RelayURL, v.Mailbox, v.Token
	d.mu.Unlock()
	return d.UploadBlobRaw(ctx, url, mailbox, token, content, mime)
}

// UploadBlobRaw seals content and uploads it to any mailbox under token
// (tests: a peer's mailbox, wrong tokens).
func (d *Device) UploadBlobRaw(ctx context.Context, url, mailbox, token string, content []byte, mime string) (*attwire.Blob, error) {
	blob, key, sum, err := envelope.SealBlob(content)
	if err != nil {
		return nil, err
	}
	id, _, err := d.relayClient(url).PutBlob(ctx, mailbox, token, blob)
	if err != nil {
		return nil, err
	}
	return &attwire.Blob{ID: id, Key: key, SHA256: sum, Size: len(content), Mime: mime}, nil
}

// UploadBytes uploads data as is (tests of a malicious sender).
func (d *Device) UploadBytes(ctx context.Context, data []byte) (string, error) {
	d.mu.Lock()
	v := d.st.Vault
	if v == nil || v.Token == "" {
		d.mu.Unlock()
		return "", ErrNotPaired
	}
	url, mailbox, token := v.RelayURL, v.Mailbox, v.Token
	d.mu.Unlock()
	id, _, err := d.relayClient(url).PutBlob(ctx, mailbox, token, data)
	return id, err
}

// SendAttachmentBody is message.send's body with a photo attachment.
func SendAttachmentBody(conn, text string, hasText bool, b *attwire.Blob, width, height int, thumb []byte) json.RawMessage {
	att := strictjson.NewBuilder().Raw("blob", b.JSON()).String("kind", attwire.KindPhoto).
		Uint("width", uint64(width)).Uint("height", uint64(height)).Base64("thumb", thumb).Bytes()
	j := strictjson.NewBuilder().String("connection_id", conn)
	if hasText {
		j.String("text", text)
	}
	return j.Raw("attachment", att).Bytes()
}

// FetchAttachment reads the blob reference of a message.attachment.get
// answer, fetches the blob from the device's own mailbox, deletes it there
// whether or not it passes, and checks it (§5.5): the photo, in memory.
func (d *Device) FetchAttachment(ctx context.Context, answer json.RawMessage) ([]byte, string, error) {
	o, err := strictjson.ParseObject(answer)
	if err != nil {
		return nil, "", err
	}
	bo, err := o.Object("blob")
	if err != nil {
		return nil, "", err
	}
	b, err := attwire.ParseBlob(bo, attwire.ReferenceMaxContent)
	if err != nil {
		return nil, "", err
	}
	data, err := d.own.GetBlob(ctx, b.ID)
	if err != nil {
		return nil, "", err
	}
	_ = d.own.DeleteBlob(ctx, b.ID)
	content, err := envelope.OpenBlob(data, b.Key, b.SHA256, b.Size)
	if err != nil {
		return nil, "", ErrBlob
	}
	if attwire.Sniff(content) == "" {
		return nil, "", ErrBlob
	}
	return content, b.Mime, nil
}

// BlobDigest is SHA-256 of content (tests compare photos by it).
func BlobDigest(content []byte) [32]byte { return sha256.Sum256(content) }
