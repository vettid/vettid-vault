package peerwire

import (
	"crypto/ed25519"
	"errors"

	"github.com/vettid/vettid-relay/relayauth"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Relay-key rotation bodies (VAULT-MESSAGING §3.4.1 rule U, §3.4.2 RK5 and
// RK14, §10 registry). Parse and build only: nothing sends or acts on them
// yet.
const (
	TypeRelayAddressUpdate = "relay.address.update"
	TypeRelayMailboxClosed = "relay.mailbox.closed"
)

// ErrRelayBody is a malformed relay.address.update or relay.mailbox.closed
// body.
var ErrRelayBody = errors.New("peerwire: malformed relay rotation body")

// AddressUpdate is a relay.address.update body:
//
//	{relay: {url, mailbox, pk}, token, reconnect_token?, relay_links, rotations?}
//
// relay_links (0.90.3; "links" before) are the signed relay links from the
// sender's key for the recipient to its current key (rule U, 1 to 32);
// rotations are its identity links (0.90.0 RK5), an empty array read as
// absent (0.90.3). Parsing checks the form only; Verify checks the chain.
type AddressUpdate struct {
	Relay          handshake.RelayAddr
	Token          string
	ReconnectToken string // "" when absent
	Links          []*handshake.RelayLink
	Rotations      []*handshake.Rotation
}

// Marshal encodes the body in the registry's member order.
func (u *AddressUpdate) Marshal() ([]byte, error) {
	if err := u.validate(); err != nil {
		return nil, err
	}
	b := strictjson.NewBuilder().
		Raw("relay", handshake.MarshalRelayAddr(u.Relay)).
		String("token", u.Token)
	if u.ReconnectToken != "" {
		b.String("reconnect_token", u.ReconnectToken)
	}
	b.Raw("relay_links", handshake.MarshalRelayLinks(u.Links))
	if len(u.Rotations) > 0 {
		out := []byte{'['}
		for i, r := range u.Rotations {
			if i > 0 {
				out = append(out, ',')
			}
			out = append(out, r.Marshal()...)
		}
		b.Raw("rotations", append(out, ']'))
	}
	return b.Bytes(), nil
}

func (u *AddressUpdate) validate() error {
	if err := u.validateForm(); err != nil {
		return err
	}
	if len(u.Links) == 0 || len(u.Links) > handshake.MaxRelayLinks {
		return ErrRelayBody
	}
	return nil
}

// validateForm applies every rule of validate but the links'.
func (u *AddressUpdate) validateForm() error {
	if handshake.ValidateRelayAddr(u.Relay) != nil || !handshake.ValidToken(u.Token) {
		return ErrRelayBody
	}
	if u.ReconnectToken != "" && !handshake.ValidToken(u.ReconnectToken) {
		return ErrRelayBody
	}
	if len(u.Rotations) > handshake.MaxRotations {
		return ErrRelayBody
	}
	return nil
}

// ParseAddressUpdate parses a relay.address.update body strictly: duplicate
// members, non-canonical base64, wrong key and signature lengths, a relay
// address whose mailbox is not its key's, a malformed token, or 0 or more
// than 32 links are refused. Unknown members are ignored (§10.1). The
// signatures and the chain are not checked here (Verify).
func ParseAddressUpdate(body []byte) (*AddressUpdate, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrRelayBody
	}
	u := &AddressUpdate{}
	ro, err := o.Object("relay")
	if err != nil {
		return nil, ErrRelayBody
	}
	if u.Relay, err = handshake.ParseRelayAddr(ro); err != nil {
		return nil, ErrRelayBody
	}
	if u.Token, err = o.String("token"); err != nil {
		return nil, ErrRelayBody
	}
	if t, ok, err := o.OptString("reconnect_token"); err != nil || ok && t == "" {
		return nil, ErrRelayBody
	} else {
		u.ReconnectToken = t
	}
	arr, err := o.Array("relay_links")
	if err != nil {
		return nil, ErrRelayBody
	}
	// A link's form failure keeps handshake.ErrRelayLink (relay_unlinked),
	// but only if every other member is well formed (malformed wins); both
	// are fixed sentinels (§13.6: no input data in errors).
	var linkErr error
	if u.Links, err = handshake.ParseRelayLinks(arr); err != nil {
		linkErr = errors.Join(ErrRelayBody, handshake.ErrRelayLink)
	}
	rots, _, err := o.OptArray("rotations") // (0.90.3) [] is read as absent: Rotations stays nil
	if err != nil || len(rots) > handshake.MaxRotations {
		return nil, ErrRelayBody
	}
	for _, raw := range rots {
		r, err := handshake.ParseRotation(raw)
		if err != nil {
			return nil, ErrRelayBody
		}
		u.Rotations = append(u.Rotations, r)
	}
	if err := u.validateForm(); err != nil {
		return nil, err
	}
	if linkErr != nil {
		return nil, linkErr
	}
	if err := u.validate(); err != nil {
		return nil, err
	}
	return u, nil
}

// Verify checks the update's relay links as rule U does: each verifies,
// they connect sender (the collect sender, the key the update was
// deposited with) to relay.pk, and there are 1 to 32 of them. It returns
// handshake.ErrRelayLink otherwise (refused relay_unlinked). Rule C, the
// skipped prefix, rollback and the tokens are the receiver's.
func (u *AddressUpdate) Verify(sender ed25519.PublicKey) error {
	return handshake.VerifyRelayChain(sender, u.Relay.PK, u.Links)
}

// MailboxClosed is a relay.mailbox.closed body (0.90.0 §3.4.2 RK14):
// {mailbox, last_msg_id}. LastMsgID is "" for JSON null (no message was
// collected from that mailbox).
type MailboxClosed struct {
	Mailbox   string
	LastMsgID string
}

// Marshal encodes {mailbox, last_msg_id}.
func (c *MailboxClosed) Marshal() ([]byte, error) {
	if !relayauth.ValidMailboxID(c.Mailbox) || c.LastMsgID != "" && !envelope.ValidULID(c.LastMsgID) {
		return nil, ErrRelayBody
	}
	b := strictjson.NewBuilder().String("mailbox", c.Mailbox)
	if c.LastMsgID == "" {
		b.Raw("last_msg_id", []byte("null"))
	} else {
		b.String("last_msg_id", c.LastMsgID)
	}
	return b.Bytes(), nil
}

// ParseMailboxClosed parses a relay.mailbox.closed body strictly: mailbox
// is a mailbox id (RELAY-PROTOCOL §3.2: 26 lowercase base32 characters),
// last_msg_id is present and either null or a relay msg_id (a ULID, 26
// Crockford base32 characters, upper case, exactly as the relay issued it,
// RELAY-PROTOCOL §1). Unknown members are ignored (§10.1).
func ParseMailboxClosed(body []byte) (*MailboxClosed, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, ErrRelayBody
	}
	c := &MailboxClosed{}
	if c.Mailbox, err = o.String("mailbox"); err != nil || !relayauth.ValidMailboxID(c.Mailbox) {
		return nil, ErrRelayBody
	}
	raw, ok := o["last_msg_id"]
	if !ok {
		return nil, ErrRelayBody
	}
	if string(raw) != "null" {
		if c.LastMsgID, err = strictjson.AsString(raw); err != nil || !envelope.ValidULID(c.LastMsgID) {
			return nil, ErrRelayBody
		}
	}
	return c, nil
}
