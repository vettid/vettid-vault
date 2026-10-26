package peerwire

import "github.com/vettid/vettid-vault/internal/strictjson"

// A connection's lifecycle (§6.4, §7.4): connection.approved carries the
// approving member's vault's standing and reconnect tokens for the peer,
// sent once, under the handshake's epoch, on the peer's request token;
// connection.declined ends a request (or, after activation, the
// connection); connection.removed ends an active connection.
const (
	TypeConnectionApproved = "connection.approved"
	TypeConnectionDeclined = "connection.declined"
	TypeConnectionRemoved  = "connection.removed"
)

// ConnectionApprovedBody is a connection.approved body: {token,
// reconnect_token}.
func ConnectionApprovedBody(token, reconnectToken string) []byte {
	return strictjson.NewBuilder().String("token", token).String("reconnect_token", reconnectToken).Bytes()
}

// ParseConnectionApproved parses a connection.approved body: both tokens
// are required strings (check them with VerifyHeldToken); other members
// are ignored.
func ParseConnectionApproved(body []byte) (token, reconnectToken string, err error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return "", "", ErrBody
	}
	token, err1 := o.String("token")
	reconnectToken, err2 := o.String("reconnect_token")
	if err1 != nil || err2 != nil {
		return "", "", ErrBody
	}
	return token, reconnectToken, nil
}

// ConnectionDeclinedBody is a connection.declined body: {}.
func ConnectionDeclinedBody() []byte { return []byte(`{}`) }

// ConnectionRemovedBody is a connection.removed body: {}.
func ConnectionRemovedBody() []byte { return []byte(`{}`) }

// ParseConnectionDeclined parses a connection.declined body: an object,
// whose members are ignored.
func ParseConnectionDeclined(body []byte) error { return parseEmpty(body) }

// ParseConnectionRemoved parses a connection.removed body: an object,
// whose members are ignored.
func ParseConnectionRemoved(body []byte) error { return parseEmpty(body) }

func parseEmpty(body []byte) error {
	if _, err := strictjson.ParseObject(body); err != nil {
		return ErrBody
	}
	return nil
}
