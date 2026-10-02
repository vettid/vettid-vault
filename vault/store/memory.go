package store

import (
	"context"
	"strconv"
	"sync"
)

// Memory is an in-memory Store, safe for concurrent use.
type Memory struct {
	mu   sync.Mutex
	objs map[string]memObj
	gen  uint64
}

type memObj struct {
	data []byte
	ver  Version
}

// NewMemory returns an empty store.
func NewMemory() *Memory { return &Memory{objs: map[string]memObj{}} }

// Get implements Store.
func (m *Memory) Get(_ context.Context, key string) ([]byte, Version, error) {
	if !ValidKey(key) {
		return nil, "", ErrKey
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objs[key]
	if !ok {
		return nil, "", ErrNotFound
	}
	return append([]byte(nil), o.data...), o.ver, nil
}

// Put implements Store.
func (m *Memory) Put(_ context.Context, key string, data []byte, ifMatch Version) (Version, error) {
	if !ValidKey(key) {
		return "", ErrKey
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.objs[key].ver != ifMatch {
		return "", ErrConflict
	}
	m.gen++
	v := Version(strconv.FormatUint(m.gen, 10))
	m.objs[key] = memObj{data: append([]byte(nil), data...), ver: v}
	return v, nil
}

// Delete implements Store.
func (m *Memory) Delete(_ context.Context, key string, ifMatch Version) error {
	if !ValidKey(key) {
		return ErrKey
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	o, ok := m.objs[key]
	if !ok {
		return ErrNotFound
	}
	if o.ver != ifMatch {
		return ErrConflict
	}
	delete(m.objs, key)
	return nil
}
