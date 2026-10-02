package vaultproc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/devattest"
)

// chanTimeout bounds one request over the channel (a relay long-poll is
// 25 s).
const chanTimeout = 90 * time.Second

var errChan = errors.New("vaultproc: supervisor request failed")

type channel struct{ c *hostproto.Conn }

func (ch channel) call(ctx context.Context, k hostproto.Kind, f ...[]byte) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, chanTimeout)
	defer cancel()
	r, err := ch.c.Call(ctx, k, f...)
	if err != nil || len(r) == 0 {
		return nil, errChan
	}
	return r, nil
}

func ok(r [][]byte, n int) bool { return len(r) == n && string(r[0]) == hostproto.StatusOK }

// chanStore is the vault's object store through the supervisor, which
// scopes it to this vault (§12.4).
type chanStore struct{ ch channel }

var _ store.Store = chanStore{}

func (s chanStore) Get(ctx context.Context, key string) ([]byte, store.Version, error) {
	if !store.ValidKey(key) {
		return nil, "", store.ErrKey
	}
	r, err := s.ch.call(ctx, vaultipc.KindStoreGet, []byte(key))
	if err != nil {
		return nil, "", err
	}
	if string(r[0]) == hostproto.StatusNotFound {
		return nil, "", store.ErrNotFound
	}
	if !ok(r, 3) || len(r[2]) == 0 {
		return nil, "", errChan
	}
	return append([]byte(nil), r[1]...), store.Version(r[2]), nil
}

// Put never abandons a write half way (see supervisor.hostStore).
func (s chanStore) Put(ctx context.Context, key string, data []byte, ifMatch store.Version) (store.Version, error) {
	if !store.ValidKey(key) {
		return "", store.ErrKey
	}
	r, err := s.ch.call(context.WithoutCancel(ctx), vaultipc.KindStorePut, []byte(key), data, []byte(ifMatch))
	if err != nil {
		return "", err
	}
	if string(r[0]) == hostproto.StatusConflict {
		return "", store.ErrConflict
	}
	if !ok(r, 2) || len(r[1]) == 0 {
		return "", errChan
	}
	return store.Version(r[1]), nil
}

func (s chanStore) Delete(ctx context.Context, key string, ifMatch store.Version) error {
	if !store.ValidKey(key) {
		return store.ErrKey
	}
	r, err := s.ch.call(context.WithoutCancel(ctx), vaultipc.KindStoreDelete, []byte(key), []byte(ifMatch))
	if err != nil {
		return err
	}
	switch string(r[0]) {
	case hostproto.StatusOK:
		return nil
	case hostproto.StatusNotFound:
		return store.ErrNotFound
	case hostproto.StatusConflict:
		return store.ErrConflict
	}
	return errChan
}

// chanKMS forwards KMS calls; the data keys come back encrypted to this
// process's own Recipient key.
type chanKMS struct{ ch channel }

func (k chanKMS) do(ctx context.Context, op, arn string, a, b []byte, outs int) ([][]byte, error) {
	r, err := k.ch.call(ctx, vaultipc.KindKMS, []byte(op), []byte(arn), a, b)
	if err != nil {
		return nil, err
	}
	if !ok(r, 3) {
		return nil, errChan
	}
	return r[1 : 1+outs], nil
}

func (k chanKMS) GenerateDataKey(ctx context.Context, arn string, att []byte) ([]byte, []byte, error) {
	r, err := k.do(ctx, vaultipc.KMSGenerateDataKey, arn, att, nil, 2)
	if err != nil {
		return nil, nil, err
	}
	return r[0], r[1], nil
}

func (k chanKMS) Decrypt(ctx context.Context, arn string, blob, att []byte) ([]byte, error) {
	r, err := k.do(ctx, vaultipc.KMSDecrypt, arn, blob, att, 1)
	if err != nil {
		return nil, err
	}
	return r[0], nil
}

func (k chanKMS) read(ctx context.Context, op, arn string) ([]byte, error) {
	r, err := k.do(ctx, op, arn, nil, nil, 1)
	if err != nil {
		return nil, err
	}
	return r[0], nil
}

func (k chanKMS) DescribeKey(ctx context.Context, arn string) ([]byte, error) {
	return k.read(ctx, vaultipc.KMSDescribeKey, arn)
}

func (k chanKMS) GetKeyPolicy(ctx context.Context, arn string) ([]byte, error) {
	return k.read(ctx, vaultipc.KMSGetKeyPolicy, arn)
}

func (k chanKMS) ListGrants(ctx context.Context, arn string) ([]byte, error) {
	return k.read(ctx, vaultipc.KMSListGrants, arn)
}

func (ch channel) attest(kind hostproto.Kind, f ...[]byte) ([]byte, error) {
	r, err := ch.call(context.Background(), kind, f...)
	if err != nil {
		return nil, err
	}
	if !ok(r, 2) || len(r[1]) == 0 {
		return nil, errChan
	}
	return r[1], nil
}

// chanTransport carries the vault's relay requests (built and signed in
// this process) to the supervisor's shared egress (§12.2).
type chanTransport struct{ ch channel }

func (t chanTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		b, err := io.ReadAll(io.LimitReader(req.Body, vaultipc.MaxBody+1))
		req.Body.Close()
		if err != nil || len(b) > vaultipc.MaxBody {
			return nil, errChan
		}
		body = b
	}
	h := req.Header.Clone()
	if h == nil {
		h = http.Header{}
	}
	r, err := t.ch.call(req.Context(), vaultipc.KindHTTP, []byte(req.Method), []byte(req.URL.String()), vaultipc.EncodeHeaders(h), body)
	if err != nil {
		return nil, err
	}
	if !ok(r, 4) {
		return nil, errChan
	}
	code, err := strconv.Atoi(string(r[1]))
	if err != nil || code < 100 || code > 599 {
		return nil, errChan
	}
	rh, err := vaultipc.DecodeHeaders(r[2])
	if err != nil {
		return nil, errChan
	}
	return &http.Response{StatusCode: code, Status: strconv.Itoa(code) + " " + http.StatusText(code), Proto: "HTTP/2.0", ProtoMajor: 2,
		Header: rh, Body: io.NopCloser(bytes.NewReader(r[3])), ContentLength: int64(len(r[3])), Request: req}, nil
}

// statusLists fetches the supervisor's cached Google status list and
// keeps it for a minute.
type statusLists struct {
	ch   channel
	mu   sync.Mutex
	at   time.Time
	list *devattest.StatusList
}

func (s *statusLists) get() *devattest.StatusList {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.list != nil && time.Since(s.at) < time.Minute {
		return s.list
	}
	r, err := s.ch.call(context.Background(), vaultipc.KindStatusList)
	if err != nil || !ok(r, 3) {
		return s.list
	}
	t, err := time.Parse(time.RFC3339Nano, string(r[2]))
	if err != nil {
		return s.list
	}
	l, err := devattest.ParseStatusList(r[1], t)
	if err != nil {
		return s.list
	}
	s.list, s.at = l, time.Now()
	return l
}
