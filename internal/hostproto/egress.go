package hostproto

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// Egress connections (enclave → parent, one per outbound TCP connection)
// start with
//
//	version 0x01 || len (1) || host || port (2, big-endian)
//
// which the parent answers with one byte (EgressOK, EgressRefused or
// EgressFailed). After EgressOK the connection carries the TCP stream to
// host:port unchanged; TLS runs inside it, end to end from the enclave.
const (
	EgressVersion = 0x01
	EgressOK      = 0x00
	EgressRefused = 0x01
	EgressFailed  = 0x02
)

// Egress errors.
var (
	ErrEgressHeader  = errors.New("hostproto: bad egress header")
	ErrEgressRefused = errors.New("hostproto: egress refused by the parent")
	ErrEgressFailed  = errors.New("hostproto: parent could not reach the host")
)

// EgressHeader encodes an egress request.
func EgressHeader(host string, port uint16) ([]byte, error) {
	if len(host) == 0 || len(host) > 253 {
		return nil, ErrEgressHeader
	}
	b := []byte{EgressVersion, byte(len(host))}
	b = append(b, host...)
	return binary.BigEndian.AppendUint16(b, port), nil
}

// ReadEgressHeader reads an egress request (the parent's side).
func ReadEgressHeader(r io.Reader) (string, uint16, error) {
	var h [2]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return "", 0, err
	}
	if h[0] != EgressVersion || h[1] == 0 {
		return "", 0, ErrEgressHeader
	}
	b := make([]byte, int(h[1])+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return "", 0, err
	}
	return string(b[:h[1]]), binary.BigEndian.Uint16(b[h[1]:]), nil
}

// OpenEgress sends the egress request on conn and waits for the answer
// (the enclave's side).
func OpenEgress(conn net.Conn, host string, port uint16) error {
	h, err := EgressHeader(host, port)
	if err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write(h); err != nil {
		return err
	}
	var ans [1]byte
	if _, err := io.ReadFull(conn, ans[:]); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Time{})
	switch ans[0] {
	case EgressOK:
		return nil
	case EgressRefused:
		return ErrEgressRefused
	}
	return ErrEgressFailed
}
