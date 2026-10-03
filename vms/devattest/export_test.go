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
