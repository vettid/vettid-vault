package vaultproc

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/vettid/vettid-vault/enclave/cms"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/seccomp"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/suite"
)

// SelftestArg follows Arg for a self-test vault process.
const SelftestArg = "-selftest"

// SelftestMain is a vault process in self-test mode (docs/SMOKE.md): it
// hardens itself exactly as a vault process does, then answers one
// KindSelftest request with what it observed. It never reports a key or
// plaintext: only booleans, sizes, ids and limits.
func SelftestMain() {
	Harden()
	f := os.NewFile(ChannelFD, "vault-channel")
	c, err := net.FileConn(f)
	f.Close()
	if err != nil {
		os.Exit(ExitChannel)
	}
	serr := seccomp.Install()
	os.Exit(serveSelftest(c, serr))
}

func serveSelftest(c net.Conn, seccompErr error) int {
	done := make(chan struct{})
	var conn *hostproto.Conn
	conn = hostproto.NewConn(c, func(ctx context.Context, f *hostproto.Frame) [][]byte {
		if f.Kind != vaultipc.KindSelftest || len(f.Fields) != 1 {
			return hostproto.Strings(hostproto.StatusInvalid)
		}
		r := runSelftest(ctx, channel{c: conn}, string(f.Fields[0]), seccompErr)
		b, _ := json.Marshal(r)
		return [][]byte{[]byte(hostproto.StatusOK), b}
	}, nil)
	go func() { <-conn.Done(); close(done) }()
	<-done
	return ExitLocked
}

func procStatus(field string) uint64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), field+":"); ok {
			kb, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(rest), " kB"), 10, 64)
			if err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}

func runSelftest(ctx context.Context, ch channel, keyARN string, seccompErr error) *selftest.VaultResult {
	res := &selftest.VaultResult{}
	add := func(name string, ok, req bool, detail string) {
		res.Checks = append(res.Checks, selftest.Check{Name: name, OK: ok, Required: req, Detail: detail})
	}
	res.UID, res.GID = os.Getuid(), os.Getgid()
	d, err := Dumpable()
	add("vault_process.not_dumpable", err == nil && d == 0, true, fmt.Sprintf("dumpable=%d", d))
	add("vault_process.seccomp_installed", seccompErr == nil, true, errString(seccompErr))
	for name, err := range forbidden() {
		add("vault_process.seccomp_refuses_"+name, errors.Is(err, errEPERM), true, errString(err))
	}
	for name, v := range limits() {
		add("vault_process.rlimit_"+name, v.ok, true, v.detail)
	}
	add("vault_process.minimal_environment", len(os.Environ()) <= 3, true, fmt.Sprintf("%d variables", len(os.Environ())))
	if fds, err := os.ReadDir("/proc/self/fd"); err == nil {
		add("vault_process.open_fds", true, false, fmt.Sprintf("%d", len(fds)))
	}

	// KMS Recipient round trip, entirely inside this process: the data key
	// is unwrapped with a key the supervisor never sees.
	ok, detail := kmsRoundTrip(ctx, ch, keyARN)
	add("vault_process.kms_recipient_round_trip", ok, true, detail)

	// One unlock-like Argon2id with the default (production) parameters.
	kdf, err := vault.DefaultKDF()
	if err == nil {
		k := argon2.IDKey([]byte("selftest-not-a-pin"), kdf.Salt, kdf.Time, kdf.MemoryKiB, kdf.Threads, 32)
		suite.Wipe(k)
	}
	res.PeakRSS = procStatus("VmHWM")
	add("vault_process.argon2id_default", err == nil, true, fmt.Sprintf("t=%d m=%dKiB peak_rss=%d", kdf.Time, kdf.MemoryKiB, res.PeakRSS))
	return res
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func kmsRoundTrip(ctx context.Context, ch channel, arn string) (bool, string) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return false, "rsa"
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return false, "rsa"
	}
	att, err := ch.attest(vaultipc.KindAttestRecipient, der)
	if err != nil {
		return false, "attestation of the Recipient key failed"
	}
	k := chanKMS{ch: ch}
	blob, cfr, err := k.GenerateDataKey(ctx, arn, att)
	if err != nil {
		return false, "GenerateDataKey failed"
	}
	dk, err := cms.Unwrap(cfr, key)
	if err != nil || len(dk) != 32 {
		return false, "unwrapping the GenerateDataKey answer failed"
	}
	defer suite.Wipe(dk)
	cfr2, err := k.Decrypt(ctx, arn, blob, att)
	if err != nil {
		return false, "Decrypt failed"
	}
	dk2, err := cms.Unwrap(cfr2, key)
	if err != nil {
		return false, "unwrapping the Decrypt answer failed"
	}
	defer suite.Wipe(dk2)
	if subtle.ConstantTimeCompare(dk, dk2) != 1 {
		return false, "not equal"
	}
	return true, "equal"
}
