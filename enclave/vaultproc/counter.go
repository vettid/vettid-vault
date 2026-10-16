package vaultproc

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault/counter"
)

// chanCounter is the recovery attempt counter's bucket through the
// supervisor, which signs each call and sends it to the pinned bucket
// (VAULT-HOST-PROTOCOL 0.1.10 §8.1). Any failure of the channel or of the
// call is counter.ErrUnknown: the counter decides what it means.
type chanCounter struct{ ch channel }

var _ counter.Bucket = chanCounter{}

func (c chanCounter) call(ctx context.Context, op, key string, a, b []byte, outs int) ([][]byte, error) {
	r, err := c.ch.call(ctx, vaultipc.KindCounter, []byte(op), []byte(key), a, b)
	if err != nil || !ok(r, 1+outs) {
		return nil, counter.ErrUnknown
	}
	return r[1:], nil
}

func (c chanCounter) List(ctx context.Context, prefix string) (counter.Listing, error) {
	r, err := c.call(ctx, vaultipc.CounterList, prefix, nil, nil, 1)
	if err != nil {
		return counter.Listing{}, err
	}
	var l counter.Listing
	if json.Unmarshal(r[0], &l) != nil {
		return counter.Listing{}, counter.ErrUnknown
	}
	return l, nil
}

func until(t time.Time) []byte { return []byte(t.UTC().Format(time.RFC3339Nano)) }

func (c chanCounter) PutCreate(ctx context.Context, key string, body []byte, u time.Time) (int, string, error) {
	r, err := c.call(ctx, vaultipc.CounterPutCreate, key, body, until(u), 2)
	if err != nil {
		return 0, "", err
	}
	st, err := strconv.Atoi(string(r[0]))
	if err != nil {
		return 0, "", counter.ErrUnknown
	}
	return st, string(r[1]), nil
}

func (c chanCounter) Put(ctx context.Context, key string, body []byte, u time.Time) (string, error) {
	r, err := c.call(ctx, vaultipc.CounterPut, key, body, until(u), 1)
	if err != nil {
		return "", err
	}
	return string(r[0]), nil
}

func (c chanCounter) GetRetention(ctx context.Context, key, version string) (counter.Retention, error) {
	r, err := c.call(ctx, vaultipc.CounterGetRetention, key, []byte(version), nil, 2)
	if err != nil {
		return counter.Retention{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, string(r[1]))
	if err != nil {
		return counter.Retention{}, counter.ErrUnknown
	}
	return counter.Retention{Mode: string(r[0]), Until: t}, nil
}

func (c chanCounter) GetVersion(ctx context.Context, key, version string) ([]byte, error) {
	r, err := c.call(ctx, vaultipc.CounterGetVersion, key, []byte(version), nil, 1)
	if err != nil {
		return nil, err
	}
	return r[0], nil
}

// heavyPermit asks the supervisor for the heavy-derivation permit
// (§11.14.3) and returns its release, or ok false.
func heavyPermit(ch channel) func(ctx context.Context) (func(), bool) {
	return func(ctx context.Context) (func(), bool) {
		r, err := ch.call(ctx, vaultipc.KindHeavyPermit, []byte(vaultipc.HeavyAcquire))
		if err != nil || !ok(r, 2) || string(r[1]) != "1" {
			return nil, false
		}
		return func() { _, _ = ch.call(context.Background(), vaultipc.KindHeavyPermit, []byte(vaultipc.HeavyRelease)) }, true
	}
}
