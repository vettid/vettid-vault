package supervisor

import (
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/paircode"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// The heavy-derivation permit (VAULT-MESSAGING 0.33.0 §11.14.3,
// VAULT-RELEASES 0.1.28 §8.8): one at a time, given only while free
// memory is at least the memory-pressure floor plus 1.2 times the
// derivation's need (1.2 GiB at release parameters). No room is
// reserved: without a permit the vault answers busy before anything is
// changed or spent. A permit not returned ends after heavyLease (a vault
// process that died holding it).
const heavyLease = 2 * time.Minute

type heavyPermit struct {
	mu     sync.Mutex
	holder string // vault id
	until  time.Time
	avail  func() uint64
	floor  func() uint64
	now    func() time.Time
	// opening reports whether a vault process is opening (an unlock, an
	// enrolment, a recovery in flight); nil: never. A code pairing's
	// permit is not given meanwhile: unlocks go first (0.94.0 §6.7.2).
	opening func() bool
}

func heavyNeed() uint64 { return recovery.HeavyMemoryBytes() * 6 / 5 }

// codeNeed is what a code pairing's derivation needs (0.94.0 §6.7.2:
// Argon2id at 256 MiB, one at a time), with the same 1.2 margin.
func codeNeed() uint64 { return uint64(paircode.ArgonMemoryKiB) * 1024 * 6 / 5 }

// roomLocked reports whether memory allows a derivation now.
func (h *heavyPermit) roomLocked() bool { return h.roomFor(heavyNeed()) }

func (h *heavyPermit) roomFor(need uint64) bool {
	a := h.avail()
	return a != 0 && a >= h.floor()+need
}

func (h *heavyPermit) freeLocked() bool {
	if h.holder != "" && h.now().After(h.until) {
		h.holder = ""
	}
	return h.holder == ""
}

// acquire gives the permit to vault id, or refuses.
func (h *heavyPermit) acquire(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.freeLocked() || !h.roomLocked() {
		return false
	}
	h.holder, h.until = id, h.now().Add(heavyLease)
	return true
}

// acquireCode gives vault id the permit for a code pairing's derivation:
// the same single permit as the recovery wrap's (one heavy derivation at a
// time), with room for 256 MiB above the floor, and never while a vault
// process is opening (unlocks go first). It reserves nothing: refused, the
// vault waits a little and then answers busy.
func (h *heavyPermit) acquireCode(id string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.freeLocked() || !h.roomFor(codeNeed()) || h.opening != nil && h.opening() {
		return false
	}
	h.holder, h.until = id, h.now().Add(heavyLease)
	return true
}

// release returns vault id's permit.
func (h *heavyPermit) release(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.holder == id {
		h.holder = ""
	}
}

// free reports whether a permit could be given now (Stats heavy_kdf_free).
func (h *heavyPermit) free() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.freeLocked() && h.roomLocked()
}
