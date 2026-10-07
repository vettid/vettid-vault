package suite

import (
	"encoding/hex"
	"strings"
)

// IKFingerprint is the fingerprint of a vault's identity key that apps
// show in a connection's details (VAULT-MESSAGING 0.18.0, §10.8):
// SHA-256("vettid/vms/2/ik-fp" || ik), ik the 32 raw bytes.
func IKFingerprint(ik []byte) [HashSize]byte { return LabeledHash(LabelIKFP, ik) }

// FormatIKFingerprint is the fingerprint as shown: its first 16 bytes in
// lowercase hex, in 8 groups of 4 digits separated by spaces (§10.8,
// vector in §16).
func FormatIKFingerprint(ik []byte) string {
	fp := IKFingerprint(ik)
	h := hex.EncodeToString(fp[:16])
	g := make([]string, 0, 8)
	for i := 0; i < len(h); i += 4 {
		g = append(g, h[i:i+4])
	}
	return strings.Join(g, " ")
}
