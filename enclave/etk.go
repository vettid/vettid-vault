package enclave

import (
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

// ETK lifetimes (§11.2, §11.6).
const (
	ETKLifetime = 24 * time.Hour // descriptor not_after
	// ETKRotate is when a new ETK replaces the current one, before its
	// descriptor expires.
	ETKRotate = 23 * time.Hour
	// ETKGrace is how long the previous ETK stays valid after rotation.
	ETKGrace = time.Hour
	// MaxSkew bounds a request's inner ts against enclave time.
	MaxSkew = 5 * time.Minute
	// maxSeen bounds the replay set per ETK; beyond it the ETK refuses
	// new requests (fail closed) until it rotates.
	maxSeen = 1 << 20
)

// etk is one enclave transport key with its descriptor, attestation and
// replay set. The private key never leaves enclave memory.
type etk struct {
	key      *suite.PrivateKey
	created  time.Time
	notAfter time.Time
	retired  time.Time // zero while current
	desc     []byte
	att      []byte
	seen     map[string]struct{}
}

func (e *etk) usable(now time.Time) bool {
	if now.After(e.notAfter) {
		return false
	}
	return e.retired.IsZero() || now.Before(e.retired.Add(ETKGrace))
}

func (e *etk) destroy() {
	if e.key != nil {
		e.key.Destroy()
		e.key = nil
	}
	e.seen = nil
}

// newETK generates an ETK and its attested descriptor (§11.2):
// user_data = SHA-256("vettid/vms/2/etk" || descriptor_bytes).
func (in *Instance) newETK(now time.Time) (*etk, error) {
	k, err := suite.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	na := now.UTC().Truncate(time.Second).Add(ETKLifetime)
	desc := altchan.MarshalDescriptor(in.cfg.InstanceID, k.Public(), in.meas.PCR0, na)
	ud := altchan.ETKUserData(desc)
	att, err := in.nsm.Attest(ud[:], nil, nil)
	if err != nil {
		k.Destroy()
		return nil, err
	}
	return &etk{key: k, created: now, notAfter: na, desc: desc, att: att, seen: map[string]struct{}{}}, nil
}

// RotateETK replaces the current ETK; the previous one stays valid for
// ETKGrace (§11.2).
func (in *Instance) RotateETK() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.rotateLocked(in.now())
}

func (in *Instance) rotateLocked(now time.Time) error {
	e, err := in.newETK(now)
	if err != nil {
		return err
	}
	for _, old := range in.etks {
		if old.retired.IsZero() {
			old.retired = now
		}
	}
	in.etks = append(in.etks, e)
	in.pruneLocked(now)
	return nil
}

// pruneLocked destroys ETKs past their grace period or lifetime; every
// request sealed to them becomes undecryptable (§11.6).
func (in *Instance) pruneLocked(now time.Time) {
	keep := in.etks[:0]
	for _, e := range in.etks {
		if e.usable(now) {
			keep = append(keep, e)
		} else {
			e.destroy()
		}
	}
	in.etks = keep
}

// Maintain rotates the ETK when due and destroys expired ones. The
// supervisor calls it periodically (at least every few minutes).
func (in *Instance) Maintain() error {
	in.mu.Lock()
	defer in.mu.Unlock()
	now := in.now()
	in.pruneLocked(now)
	if cur := in.currentLocked(); cur == nil || now.Sub(cur.created) >= ETKRotate {
		return in.rotateLocked(now)
	}
	return nil
}

func (in *Instance) currentLocked() *etk {
	for i := len(in.etks) - 1; i >= 0; i-- {
		if in.etks[i].retired.IsZero() {
			return in.etks[i]
		}
	}
	return nil
}

// Descriptor returns the current descriptor bytes and its attestation
// document, which the parent publishes to the instance registry (§11.1).
func (in *Instance) Descriptor() (desc, attestation []byte) {
	in.mu.Lock()
	defer in.mu.Unlock()
	cur := in.currentLocked()
	if cur == nil {
		return nil, nil
	}
	return append([]byte(nil), cur.desc...), append([]byte(nil), cur.att...)
}

func (in *Instance) lookupETK(kid suite.Kid, now time.Time) *etk {
	for _, e := range in.etks {
		if e.key != nil && e.key.Public().Kid().Equal(kid) && e.usable(now) {
			return e
		}
	}
	return nil
}
