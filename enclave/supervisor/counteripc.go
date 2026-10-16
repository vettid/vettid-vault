package supervisor

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vms/recovery"
)

// counterPrefix returns the vault prefix recovery/v1/<32 hex>/ of key, or
// "" if key is not under one.
func counterPrefix(key string) string {
	rest, ok := strings.CutPrefix(key, recovery.CounterPrefixRoot)
	if !ok || len(rest) < 33 || rest[32] != '/' {
		return ""
	}
	for i := 0; i < 32; i++ {
		if c := rest[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return ""
		}
	}
	return recovery.CounterPrefixRoot + rest[:33]
}

// mayCounter admits key for this process: under recovery/v1/<tag>/, and
// the first tag a process names is the only one it may use (its vault's;
// it cannot compute another vault's names, and this keeps it from using
// one it has seen).
func (p *vproc) mayCounter(key string) bool {
	pfx := counterPrefix(key)
	if pfx == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.counterPrefix == "" {
		p.counterPrefix = pfx
	}
	return p.counterPrefix == pfx
}

// counterCall forwards one KindCounter call (VAULT-HOST-PROTOCOL §8.1).
func (p *vproc) counterCall(ctx context.Context, f [][]byte) [][]byte {
	b := p.h.s.counterBucket()
	if b == nil || len(f) != 4 || !p.mayCounter(string(f[1])) {
		return deny()
	}
	key := string(f[1])
	errOut := hostproto.Strings(hostproto.StatusError)
	switch string(f[0]) {
	case vaultipc.CounterList:
		l, err := b.List(ctx, key)
		if err != nil {
			return errOut
		}
		j, err := json.Marshal(l)
		if err != nil {
			return errOut
		}
		return [][]byte{[]byte(hostproto.StatusOK), j}
	case vaultipc.CounterPutCreate, vaultipc.CounterPut:
		until, err := time.Parse(time.RFC3339Nano, string(f[3]))
		if err != nil || len(f[2]) > 64 {
			return deny()
		}
		if string(f[0]) == vaultipc.CounterPut {
			v, err := b.Put(ctx, key, f[2], until)
			if err != nil {
				return errOut
			}
			return hostproto.Strings(hostproto.StatusOK, v)
		}
		st, v, err := b.PutCreate(ctx, key, f[2], until)
		if err != nil {
			return errOut
		}
		return hostproto.Strings(hostproto.StatusOK, strconv.Itoa(st), v)
	case vaultipc.CounterGetRetention:
		r, err := b.GetRetention(ctx, key, string(f[2]))
		if err != nil {
			return errOut
		}
		return hostproto.Strings(hostproto.StatusOK, r.Mode, r.Until.UTC().Format(time.RFC3339Nano))
	case vaultipc.CounterGetVersion:
		body, err := b.GetVersion(ctx, key, string(f[2]))
		if err != nil {
			return errOut
		}
		return [][]byte{[]byte(hostproto.StatusOK), body}
	}
	return deny()
}

func (p *vproc) heavyCall(f [][]byte) [][]byte {
	h := p.h.s.heavy
	if len(f) != 1 || h == nil {
		return deny()
	}
	switch string(f[0]) {
	case vaultipc.HeavyAcquire:
		if h.acquire(p.vaultID) {
			return hostproto.Strings(hostproto.StatusOK, "1")
		}
		return hostproto.Strings(hostproto.StatusOK, "0")
	case vaultipc.HeavyRelease:
		h.release(p.vaultID)
		return hostproto.Strings(hostproto.StatusOK, "1")
	}
	return deny()
}
