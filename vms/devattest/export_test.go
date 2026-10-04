package devattest

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
			_ = checkApplicationID(p, aid)
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
			if err := checkApplicationID(p, aid); err != nil {
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
