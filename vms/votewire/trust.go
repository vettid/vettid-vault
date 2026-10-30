package votewire

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
)

// A pinned Sigstore trusted root (VAULT-MESSAGING §11.10.8
// `vote_trust_roots`): the protojson TrustedRoot of Sigstore's TUF
// repository (dev.sigstore.trustedroot.v1.TrustedRoot). Only `tlogs` (the
// Rekor logs) and `timestampAuthorities` are read; every other member
// (certificateAuthorities, ctlogs, mediaType) is ignored, so a release may
// pin the file as Sigstore publishes it or trimmed to those two.

// ErrTrustRootFormat is returned for a trusted root that cannot be used.
var ErrTrustRootFormat = errors.New("votewire: malformed trusted root")

// Limits on what a pinned root may hold.
const (
	maxTLogs = 16
	maxTSAs  = 16
	maxChain = 6
)

// TLog is one transparency log of a trusted root.
type TLog struct {
	LogID []byte // SHA-256 of the key's DER (logId.keyId)
	Key   any    // *ecdsa.PublicKey (P-256) or ed25519.PublicKey
	Start time.Time
	End   time.Time // zero: still valid
}

// TSA is one timestamp authority of a trusted root: its chain, leaf first.
type TSA struct {
	Chain []*x509.Certificate
	Start time.Time
	End   time.Time // zero: still valid
}

// TrustRoot is the usable part of one pinned trusted root.
type TrustRoot struct {
	Logs []TLog
	TSAs []TSA
}

// valid reports whether t is inside [start, end] (end zero: open).
func valid(t, start, end time.Time) bool {
	return !t.Before(start) && (end.IsZero() || !t.After(end))
}

func parseValidFor(o strictjson.Object) (start, end time.Time, err error) {
	vf, ok, err := o.OptObjectRaw("validFor")
	if err != nil || !ok {
		return start, end, ErrTrustRootFormat
	}
	vo, err := strictjson.AsObject(vf)
	if err != nil {
		return start, end, ErrTrustRootFormat
	}
	s, err := vo.String("start")
	if err != nil {
		return start, end, ErrTrustRootFormat
	}
	if start, err = time.Parse(time.RFC3339, s); err != nil {
		return start, end, ErrTrustRootFormat
	}
	if e, present, err := vo.OptString("end"); err != nil {
		return start, end, ErrTrustRootFormat
	} else if present {
		if end, err = time.Parse(time.RFC3339, e); err != nil || end.Before(start) {
			return start, end, ErrTrustRootFormat
		}
	}
	return start, end, nil
}

// ParseTrustRoot parses one pinned trusted root.
func ParseTrustRoot(raw []byte) (*TrustRoot, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, ErrTrustRootFormat
	}
	tr := &TrustRoot{}
	logs, err := o.Array("tlogs")
	if err != nil || len(logs) > maxTLogs {
		return nil, ErrTrustRootFormat
	}
	for _, r := range logs {
		lo, err := strictjson.AsObject(r)
		if err != nil {
			return nil, ErrTrustRootFormat
		}
		pk, err := lo.Object("publicKey")
		if err != nil {
			return nil, ErrTrustRootFormat
		}
		der, err := pk.Base64("rawBytes", -1)
		if err != nil {
			return nil, ErrTrustRootFormat
		}
		var l TLog
		k, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, ErrTrustRootFormat
		}
		ek, isECDSA := k.(*ecdsa.PublicKey)
		if !isECDSA {
			// Only Rekor v1 logs (ECDSA P-256) are used by this profile;
			// the root also lists newer logs with Ed25519 keys.
			continue
		}
		if ek.Curve != elliptic.P256() {
			return nil, ErrTrustRootFormat
		}
		l.Key = ek
		id, err := lo.Object("logId")
		if err != nil {
			return nil, ErrTrustRootFormat
		}
		if l.LogID, err = id.Base64("keyId", HashLen); err != nil {
			return nil, ErrTrustRootFormat
		}
		// The log id is the hash of the key, so a key cannot be pinned
		// under another key's id.
		if !eq(l.LogID, H(der)) {
			return nil, ErrTrustRootFormat
		}
		if l.Start, l.End, err = parseValidFor(pk); err != nil {
			return nil, err
		}
		tr.Logs = append(tr.Logs, l)
	}
	tsas, err := o.Array("timestampAuthorities")
	if err != nil || len(tsas) > maxTSAs {
		return nil, ErrTrustRootFormat
	}
	for _, r := range tsas {
		to, err := strictjson.AsObject(r)
		if err != nil {
			return nil, ErrTrustRootFormat
		}
		cc, err := to.Object("certChain")
		if err != nil {
			return nil, ErrTrustRootFormat
		}
		certs, err := cc.Array("certificates")
		if err != nil || len(certs) == 0 || len(certs) > maxChain {
			return nil, ErrTrustRootFormat
		}
		var t TSA
		for _, c := range certs {
			co, err := strictjson.AsObject(c)
			if err != nil {
				return nil, ErrTrustRootFormat
			}
			der, err := co.Base64("rawBytes", -1)
			if err != nil {
				return nil, ErrTrustRootFormat
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, ErrTrustRootFormat
			}
			t.Chain = append(t.Chain, cert)
		}
		if t.Start, t.End, err = parseValidFor(to); err != nil {
			return nil, err
		}
		tr.TSAs = append(tr.TSAs, t)
	}
	if len(tr.Logs) == 0 || len(tr.TSAs) == 0 {
		return nil, ErrTrustRootFormat
	}
	return tr, nil
}

// ParseTrustRoots parses the release constant: an array of trusted roots,
// newest last.
func ParseTrustRoots(raw []byte) ([]*TrustRoot, error) {
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) == 0 || len(arr) > 8 {
		return nil, ErrTrustRootFormat
	}
	out := make([]*TrustRoot, 0, len(arr))
	for _, r := range arr {
		tr, err := ParseTrustRoot(r)
		if err != nil {
			return nil, err
		}
		out = append(out, tr)
	}
	return out, nil
}
