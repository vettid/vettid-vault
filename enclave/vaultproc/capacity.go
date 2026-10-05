package vaultproc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/suite"
)

// maxCapacityState bounds a synthetic vault's state (64 MiB).
const maxCapacityState = 64 << 20

// capacityVault is a synthetic vault of the self-test's capacity
// measurement (docs/SMOKE.md): in a process started and hardened exactly
// like a vault's, it does what an unlocking vault does to its memory (one
// Argon2id at the release's parameters, then decrypting its state) and
// what an unlocked one does at rest (holds the state, a channel round trip
// every long-poll period). Its key is derived from a fixed test PIN and a
// fresh salt, its state is random: no member data, nothing reported but
// sizes and times.
type capacityVault struct {
	mu       sync.Mutex
	unlocked bool
	state    []byte
}

func (cv *capacityVault) handle(ch channel, done <-chan struct{}, f [][]byte) [][]byte {
	if len(f) != 2 {
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	var st selftest.CapacityStats
	switch string(f[0]) {
	case "unlock":
		n, err := strconv.Atoi(string(f[1]))
		if err != nil || n < 0 || n > maxCapacityState {
			return hostproto.Strings(hostproto.StatusInvalid)
		}
		cv.mu.Lock()
		defer cv.mu.Unlock()
		if cv.unlocked { // one unlock per process, as for a vault
			return hostproto.Strings(hostproto.StatusInvalid)
		}
		cv.unlocked = true
		t0 := time.Now()
		kdf, err := vault.DefaultKDF()
		if err != nil {
			return hostproto.Strings(hostproto.StatusError)
		}
		k := argon2.IDKey([]byte("selftest-not-a-pin"), kdf.Salt, kdf.Time, kdf.MemoryKiB, kdf.Threads, 32)
		st.KDFMicros = time.Since(t0).Microseconds()
		if n > 0 {
			s, err := openState(k, n)
			if err != nil {
				suite.Wipe(k)
				return hostproto.Strings(hostproto.StatusError)
			}
			cv.state = s
			go idleLoop(ch, done, s, vault.LongPollWait)
		}
		suite.Wipe(k)
	case "stats":
	default:
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	st.RSS, st.PeakRSS = procStatus("VmRSS"), procStatus("VmHWM")
	st.PSS = procField("/proc/self/smaps_rollup", "Pss")
	st.Private = procField("/proc/self/smaps_rollup", "Private_Clean") + procField("/proc/self/smaps_rollup", "Private_Dirty")
	st.CPUMicros = cpuMicros()
	b, _ := json.Marshal(st)
	return [][]byte{[]byte(hostproto.StatusOK), b}
}

// openState makes n bytes of random state, seals it under key as the
// stored state is, and decrypts it into the buffer the vault keeps (the
// ciphertext is garbage afterwards, as after a real load).
func openState(key []byte, n int) ([]byte, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, n)
	if _, err := rand.Read(pt); err != nil {
		return nil, err
	}
	nonce := make([]byte, g.NonceSize())
	ct := g.Seal(nil, nonce, pt, nil)
	suite.Wipe(pt)
	return g.Open(nil, nonce, ct, nil)
}

// idleLoop is an unlocked vault at rest: one channel round trip per
// long-poll period (a real vault's long poll goes through the supervisor
// the same way) and a read of its state, until the channel closes.
func idleLoop(ch channel, done <-chan struct{}, state []byte, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	var sum byte
	for {
		select {
		case <-done:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), every)
			_, _ = ch.call(ctx, vaultipc.KindStatusList)
			cancel()
			for i := 0; i < len(state); i += 4096 {
				sum ^= state[i]
			}
			_ = sum
		}
	}
}
