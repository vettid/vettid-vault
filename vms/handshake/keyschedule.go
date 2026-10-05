package handshake

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/vettid/vettid-vault/vms/suite"
)

// Schedule holds every value of the §6.3 key schedule for one handshake.
// It is secret and redacts itself when formatted.
type Schedule struct {
	suite.Redacted
	Ks, Ke     []byte // 32 bytes each
	Th1, Th    [32]byte
	PRK        []byte // 32 bytes
	KI2R, KR2I []byte // 32 bytes each
	KidI2R     suite.Kid
	KidR2I     suite.Kid
	RK         []byte // 32 bytes
	EpochID    [suite.EpochIDSize]byte
}

// Th1 returns SHA-256("vettid/vms/2/th1" || env_init).
func Th1(envInit []byte) [32]byte { return suite.LabeledHash(suite.LabelTh1, envInit) }

// Th returns SHA-256("vettid/vms/2/th" || env_init || resp_header), where
// resp_header is hs.resp bytes[0:1140].
func Th(envInit, respHeader []byte) [32]byte {
	return suite.LabeledHash(suite.LabelTh, envInit, respHeader)
}

func expand(prk []byte, label string, th []byte, n int) ([]byte, error) {
	info := make([]byte, 0, len(label)+len(th))
	info = append(append(info, label...), th...)
	return hkdf.Expand(sha256.New, prk, string(info), n)
}

// DeriveSchedule runs §6.3 from K_s, K_e and the transcript hashes.
func DeriveSchedule(ks, ke []byte, th1, th [32]byte) (*Schedule, error) {
	if len(ks) != suite.KeySize || len(ke) != suite.KeySize {
		return nil, suite.ErrKeySize
	}
	ikm := make([]byte, 0, 2*suite.KeySize)
	ikm = append(append(ikm, ke...), ks...) // ikm = K_e || K_s
	defer suite.Wipe(ikm)
	prk, err := hkdf.Extract(sha256.New, ikm, []byte(suite.LabelSession))
	if err != nil {
		return nil, err
	}
	s := &Schedule{
		Ks:  append([]byte(nil), ks...),
		Ke:  append([]byte(nil), ke...),
		Th1: th1, Th: th, PRK: prk,
	}
	fail := func(err error) (*Schedule, error) { s.Destroy(); return nil, err }
	if s.KI2R, err = expand(prk, suite.LabelI2R, th[:], suite.KeySize); err != nil {
		return fail(err)
	}
	if s.KR2I, err = expand(prk, suite.LabelR2I, th[:], suite.KeySize); err != nil {
		return fail(err)
	}
	k, err := expand(prk, suite.LabelKidI2R, th[:], suite.KidSize)
	if err != nil {
		return fail(err)
	}
	copy(s.KidI2R[:], k)
	if k, err = expand(prk, suite.LabelKidR2I, th[:], suite.KidSize); err != nil {
		return fail(err)
	}
	copy(s.KidR2I[:], k)
	if s.RK, err = expand(prk, suite.LabelRK, th[:], suite.KeySize); err != nil {
		return fail(err)
	}
	e, err := expand(prk, suite.LabelEpoch, th[:], suite.EpochIDSize)
	if err != nil {
		return fail(err)
	}
	copy(s.EpochID[:], e)
	return s, nil
}

// Destroy wipes the schedule's secrets.
func (s *Schedule) Destroy() {
	if s == nil {
		return
	}
	for _, b := range [][]byte{s.Ks, s.Ke, s.PRK, s.KI2R, s.KR2I, s.RK} {
		suite.Wipe(b)
	}
}

// SASCommit returns the commitment to the initiator's SAS nonce (§6.3,
// 0.10.3): SHA-256("vettid/vms/2/sas-commit" || n_I).
func SASCommit(nI []byte) [32]byte { return suite.LabeledHash(suite.LabelSASCommit, nI) }

// CheckSASCommit reports, in constant time, whether n_I opens commit.
func CheckSASCommit(commit, nI []byte) bool {
	c := SASCommit(nI)
	return len(nI) == SASNonceSize && subtle.ConstantTimeCompare(c[:], commit) == 1
}

// SAS computes the short authentication string (§6.3, 0.10.3):
// uint32be(HKDF-Expand(prk, "vettid/vms/2/sas" || th || n_I || n_R, 4))
// mod 1,000,000, as 6 zero-padded digits. It exists only once both nonces
// are fixed: at the initiator after sig_R verifies, at the responder after
// hs.fin and the commitment check.
func SAS(prk []byte, th [32]byte, nI, nR []byte) (string, error) {
	if len(prk) != suite.KeySize {
		return "", suite.ErrKeySize
	}
	if len(nI) != SASNonceSize || len(nR) != SASNonceSize {
		return "", ErrBody
	}
	info := make([]byte, 0, len(suite.LabelSAS)+len(th)+2*SASNonceSize)
	info = append(append(append(append(info, suite.LabelSAS...), th[:]...), nI...), nR...)
	b, err := hkdf.Expand(sha256.New, prk, string(info), 4)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", binary.BigEndian.Uint32(b)%1000000), nil
}

// SignResp returns sig_R = Ed25519(ik_R, "vettid/vms/2/sig-resp" || th).
func SignResp(ikR ed25519.PrivateKey, th [32]byte) ([]byte, error) {
	return suite.Sign(ikR, suite.LabelSigResp, th[:])
}

// SignFin returns sig_I = Ed25519(ik_I, "vettid/vms/2/sig-fin" || th).
func SignFin(ikI ed25519.PrivateKey, th [32]byte) ([]byte, error) {
	return suite.Sign(ikI, suite.LabelSigFin, th[:])
}

// VerifyResp checks sig_R.
func VerifyResp(ikR ed25519.PublicKey, th [32]byte, sig []byte) error {
	return suite.Verify(ikR, suite.LabelSigResp, th[:], sig)
}

// VerifyFin checks sig_I.
func VerifyFin(ikI ed25519.PublicKey, th [32]byte, sig []byte) error {
	return suite.Verify(ikI, suite.LabelSigFin, th[:], sig)
}
