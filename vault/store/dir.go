//go:build unix

package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// Dir is a Store on a local filesystem directory. Conditional writes are
// atomic across processes: each object has a lock file held with flock(2)
// for the read-compare-write, and the data is replaced with an atomic
// rename. The version is a random tag written alongside the data, so it
// changes on every write.
type Dir struct {
	root string
}

// NewDir returns a store rooted at dir (created if missing, mode 0700).
func NewDir(dir string) (*Dir, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Dir{root: dir}, nil
}

// File layout: <key>.obj holds "<version>\n<data>"; <key>.lock is the lock.

func (d *Dir) paths(key string) (obj, lock string) {
	p := filepath.Join(d.root, filepath.FromSlash(key))
	return p + ".obj", p + ".lock"
}

func (d *Dir) lock(key string) (func(), error) {
	_, lp := d.paths(key)
	if err := os.MkdirAll(filepath.Dir(lp), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lp, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}

func (d *Dir) read(key string) ([]byte, Version, error) {
	op, _ := d.paths(key)
	b, err := os.ReadFile(op)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	i := bytes.IndexByte(b, '\n')
	if i <= 0 {
		return nil, "", errors.New("store: corrupt object")
	}
	return b[i+1:], Version(b[:i]), nil
}

// Get implements Store.
func (d *Dir) Get(_ context.Context, key string) ([]byte, Version, error) {
	if !ValidKey(key) {
		return nil, "", ErrKey
	}
	unlock, err := d.lock(key)
	if err != nil {
		return nil, "", err
	}
	defer unlock()
	return d.read(key)
}

// Put implements Store.
func (d *Dir) Put(_ context.Context, key string, data []byte, ifMatch Version) (Version, error) {
	if !ValidKey(key) {
		return "", ErrKey
	}
	unlock, err := d.lock(key)
	if err != nil {
		return "", err
	}
	defer unlock()
	_, cur, err := d.read(key)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return "", err
	}
	if cur != ifMatch {
		return "", ErrConflict
	}
	var tag [12]byte
	if _, err := rand.Read(tag[:]); err != nil {
		return "", err
	}
	v := Version(hex.EncodeToString(tag[:]))
	op, _ := d.paths(key)
	tmp := op + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	_, err = f.Write(append(append([]byte(v), '\n'), data...))
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, op); err != nil {
		return "", err
	}
	return v, nil
}

// Delete implements Store.
func (d *Dir) Delete(_ context.Context, key string, ifMatch Version) error {
	if !ValidKey(key) {
		return ErrKey
	}
	unlock, err := d.lock(key)
	if err != nil {
		return err
	}
	defer unlock()
	_, cur, err := d.read(key)
	if err != nil {
		return err
	}
	if cur != ifMatch {
		return ErrConflict
	}
	op, _ := d.paths(key)
	return os.Remove(op)
}
