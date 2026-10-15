package recovery

import "github.com/vettid/vettid-vault/vms/suite"

// Params are Argon2id parameters as the sealed header keeps them
// (§11.14.1, §11.14.3): {alg: "argon2id", t, m (KiB), p, salt (16 bytes)}.
type Params struct {
	Alg       string `json:"alg"`
	Time      uint32 `json:"t"`
	MemoryKiB uint32 `json:"m"`
	Threads   uint8  `json:"p"`
	Salt      []byte `json:"salt"`
}

// The specified parameters. Release builds use exactly these; a build with
// the test-only tag vettid_testcost lowers the floors and the parameters
// handed out (testcost.go), so that tests can arm vaults without 1 GiB per
// derivation. check-tcb refuses a release build with that tag, and the
// enclave refuses to start in one (TestCost).
const (
	HeavyTime      = 3
	HeavyMemoryKiB = 1024 * 1024 // 1 GiB
	UnlockTime     = 3
	UnlockMemKiB   = 64 * 1024 // 64 MiB
	SaltSize       = 16
)

func newParams(t, m uint32) (Params, error) {
	salt, err := suite.RandomBytes(SaltSize)
	if err != nil {
		return Params{}, err
	}
	return Params{Alg: "argon2id", Time: t, MemoryKiB: m, Threads: 1, Salt: salt}, nil
}

// NewHeavyParams returns the recovery wrap's parameters with a fresh salt
// (production: t = 3, m = 1 GiB, p = 1).
func NewHeavyParams() (Params, error) { return newParams(heavyTime, heavyMemKiB) }

// NewUnlockParams returns the unlock key's parameters with a fresh salt
// (production: t = 3, m = 64 MiB, p = 1).
func NewUnlockParams() (Params, error) { return newParams(unlockTime, unlockMemKiB) }

// HeavyMemoryBytes is what one heavy derivation needs, for the permit.
func HeavyMemoryBytes() uint64 { return uint64(heavyMemKiB) * 1024 }

func (p Params) shape() bool {
	return p.Alg == "argon2id" && p.Threads >= 1 && p.Threads <= 4 && len(p.Salt) == SaltSize && p.Time <= 10 && p.MemoryKiB <= 4*1024*1024
}

// checkHeavy refuses parameters below t = 3, m = 1 GiB (§11.14.3), or the
// test build's floor.
func (p Params) checkHeavy() error {
	if !p.shape() || p.Time < heavyFloorTime || p.MemoryKiB < heavyFloorMemKiB {
		return ErrParams
	}
	return nil
}

func (p Params) checkUnlock() error {
	if !p.shape() || p.Time < unlockFloorTime || p.MemoryKiB < unlockFloorMemKiB {
		return ErrParams
	}
	return nil
}

// ValidHeavy reports whether p may be used for a recovery wrap.
func (p Params) ValidHeavy() bool { return p.checkHeavy() == nil }

// ValidUnlock reports whether p may be used for an unlock key.
func (p Params) ValidUnlock() bool { return p.checkUnlock() == nil }
