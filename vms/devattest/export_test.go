package devattest

import "time"

// CheckKeyDescription runs the key-description checks on raw extension
// bytes (fuzzing only).
func CheckKeyDescription(p *Policy, b []byte) error {
	kd, err := parseKeyDescription(b)
	if err != nil {
		return err
	}
	if rot, ok := kd.hw.elems[tagRootOfTrust]; ok {
		_ = checkRootOfTrust(p, rot)
	}
	for _, l := range []authList{kd.sw, kd.hw} {
		if aid, ok := l.elems[tagAttestationID]; ok {
			_, _ = checkApplicationID(p, aid)
		}
		_, _, _ = l.intSet(tagPurpose)
		_, _, _ = l.int(tagAlgorithm)
	}
	return nil
}

// CheckKeyDescriptionStrict runs the same checks as CheckKeyDescription
// and returns the first error from any of them (regression tests).
func CheckKeyDescriptionStrict(p *Policy, b []byte) error {
	kd, err := parseKeyDescription(b)
	if err != nil {
		return err
	}
	if rot, ok := kd.hw.elems[tagRootOfTrust]; ok {
		if err := checkRootOfTrust(p, rot); err != nil {
			return err
		}
	}
	for _, l := range []authList{kd.sw, kd.hw} {
		if aid, ok := l.elems[tagAttestationID]; ok {
			if _, err := checkApplicationID(p, aid); err != nil {
				return err
			}
		}
		for _, tag := range []uint64{tagPurpose, tagDigest} {
			if _, _, err := l.intSet(tag); err != nil {
				return err
			}
		}
	}
	return nil
}

// ParseNonceExt exposes the App Attest nonce extension parser.
var ParseNonceExt = parseNonceExt

// CheckAndroidChain runs the chain rules alone (no key description, no
// status list): the pinned root, the signatures, the CA and extension
// placement rules and the path validation. now nil: as BindSigner.
func CheckAndroidChain(p *Policy, chain [][]byte, now *time.Time) error {
	_, err := checkAndroidChain(p, chain, now)
	return err
}

// ParseKeyDescription reports whether raw extension bytes parse.
func ParseKeyDescription(b []byte) error {
	_, err := parseKeyDescription(b)
	return err
}

// ParseAuthData reports whether authenticator data parses as an
// attestation's (attested) or an assertion's.
func ParseAuthData(b []byte, attested bool) error {
	_, err := parseAuthData(b, attested)
	return err
}
