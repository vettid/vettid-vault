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
	// Lock order: heavy.mu, then (in opening) procHost.mu; nothing takes
	// them the other way round.
	opening func() bool
	// waiter is until when a refused acquire (a recovery wrap, a transfer
	// approval, a PIN change, a recovery open) still waits: no code permit
	// is given meanwhile, so a short wait is not lost to code pollers.
	// Each refused poll moves it on.
	waiter time.Time
}

// waiterHold is how long a refused acquire keeps code permits back
// (chosen; not in the spec: longer than its 250 ms poll).
const waiterHold = 2 * time.Second

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
func (h *heavyPermit) acquire(id string) bool { return h.try(id) == permitGiven }

// The answers to an ask for the permit.
type permitAnswer int

const (
	permitGiven  permitAnswer = iota
	permitHeld                // another holds it: worth waiting a little
	permitNoRoom              // memory is short: busy now, no wait
)

// try is acquire with its answer: a refusal because another holds the
// permit leaves the waiter mark (code permits wait behind it); one for
// lack of room does not, and the asker answers busy at once.
func (h *heavyPermit) try(id string) permitAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.roomLocked() {
		return permitNoRoom
	}
	if !h.freeLocked() {
		h.waiter = h.now().Add(waiterHold)
		return permitHeld
	}
	h.holder, h.until, h.waiter = id, h.now().Add(heavyLease), time.Time{}
	return permitGiven
}

// acquireCode gives vault id the permit for a code pairing's derivation:
// the same single permit as the recovery wrap's (one heavy derivation at a
// time), with room for 256 MiB above the floor, and never while a vault
// process is opening (unlocks go first). It reserves nothing: refused, the
// vault waits a little and then answers busy.
func (h *heavyPermit) acquireCode(id string) bool { return h.tryCode(id) == permitGiven }

// tryCode is acquireCode with its answer: no room is busy now (§6.7.2);
// another holder, a waiter or an open is worth waiting for.
func (h *heavyPermit) tryCode(id string) permitAnswer {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.roomFor(codeNeed()) {
		return permitNoRoom
	}
	if !h.freeLocked() || h.now().Before(h.waiter) || h.opening != nil && h.opening() {
		return permitHeld
	}
	h.holder, h.until = id, h.now().Add(heavyLease)
	return permitGiven
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
