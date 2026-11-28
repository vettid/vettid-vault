package vaultproc

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/paircode"
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
			go func() {
				// A panic ends the capacity process as an error, not a crash
				// with no code (GOTRACEBACK=none): it holds no vault and has
				// no log of its own, so the supervisor's "ended, error" is
				// all that is said of it.
				defer func() {
					if r := recover(); r != nil {
						os.Exit(ExitError)
					}
				}()
				idleLoop(ch, done, s, vault.LongPollWait)
			}()
		}
		suite.Wipe(k)
	case "code":
		// A code pairing's two derivations (VAULT-MESSAGING 0.94.1
		// §6.7.2), each under the supervisor's code permit as a vault asks
		// for it, within one wait for the request.
		cv.code(ch, &st)
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

// capacityRelay is the relay name the synthetic code derivations bind
// (any canonical one: nothing is sent to it).
const capacityRelay = "https://relay.selftest.vettid.test"

// code runs a code pairing's derivations as a vault does: x (and k_w),
// then the tag, each under its own code permit asked for and released by
// the vault's own functions (vault.PollCodePermit, vault.RunUnderPermit:
// the waits within one PairCodePermitWait for the request, busy at once on
// no room, the memory returned before each release). The code, salts and
// inputs are random: nothing of a member.
func (cv *capacityVault) code(ch channel, st *selftest.CapacityStats) {
	take := codePermit(ch)
	deadline := time.Now().Add(vault.PairCodePermitWait)
	var wait time.Duration
	code, err := paircode.NewCode()
	if err != nil {
		st.Code = "error"
		return
	}
	defer suite.Wipe(code)
	salt := func() []byte {
		b := make([]byte, paircode.SaltSize)
		_, _ = rand.Read(b)
		return b
	}
	// derive runs one derivation under its own permit: its time, or why
	// there was none ("busy", "no_room", "error").
	derive := func(f func() ([]byte, error)) (int64, string) {
		w0 := time.Now()
		rel, ok, noRoom := vault.PollCodePermit(context.Background(), take, deadline)
		wait += time.Since(w0)
		if !ok {
			if noRoom {
				return 0, "no_room"
			}
			return 0, "busy"
		}
		st.GrantedAtsMs = append(st.GrantedAtsMs, time.Now().UnixMilli())
		var us int64
		err := vault.RunUnderPermit(rel, func() error {
			d0 := time.Now()
			k, err := f()
			us = time.Since(d0).Microseconds()
			suite.Wipe(k)
			return err
		})
		if err != nil {
			return us, "error"
		}
		return us, ""
	}
	var why string
	if st.XMicros, why = derive(func() ([]byte, error) { return paircode.X(paircode.PurposeDesktop, capacityRelay, code, salt()) }); why == "" {
		st.TagMicros, why = derive(func() ([]byte, error) { return paircode.Tag(paircode.PurposeDesktop, capacityRelay, code, salt()) })
	}
	st.WaitMicros = wait.Microseconds()
	st.Code = "done"
	if why != "" {
		st.Code = why
	}
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
