package suite

import "sync"

// MaxOffer bounds the length of a `suites` offer.
const MaxOffer = 8

// Supported reports whether this implementation speaks suite s.
func Supported(s int) bool { return s == int(Suite2) }

// Check accepts suite s against a record's pinned suite (§4.1, §13.4):
// suite 1 is never accepted, suites below the pin are rejected as a
// downgrade, and unknown suites are rejected as unsupported. A zero pin
// means nothing has been negotiated yet.
func Check(s int, pinned uint8) error {
	switch {
	case s == int(Suite1):
		return ErrSuite1
	case s < int(Suite2) || s > 255:
		return ErrUnsupportedSuite
	case s < int(pinned):
		return ErrDowngrade
	case !Supported(s):
		return ErrUnsupportedSuite
	}
	return nil
}

// ValidateOffer checks the wire form of an hs.init `suites` list: 1 to
// MaxOffer entries, strictly ascending, each in [2, 255]. Suite 1 (or 0)
// anywhere in the list rejects the whole offer: a conforming sender never
// sends it. Unknown suites above 2 are allowed (forward compatibility) and
// simply not chosen.
func ValidateOffer(suites []int) error {
	if len(suites) == 0 || len(suites) > MaxOffer {
		return ErrBadOffer
	}
	for i, s := range suites {
		if s == int(Suite1) {
			return ErrSuite1
		}
		if s < int(Suite2) || s > 255 {
			return ErrBadOffer
		}
		if i > 0 && s <= suites[i-1] {
			return ErrBadOffer
		}
	}
	return nil
}

// Negotiate picks the highest suite in the offer that this implementation
// supports and that is not below the pin.
func Negotiate(offered []int, pinned uint8) (uint8, error) {
	if err := ValidateOffer(offered); err != nil {
		return 0, err
	}
	for i := len(offered) - 1; i >= 0; i-- {
		if Check(offered[i], pinned) == nil {
			return uint8(offered[i]), nil
		}
	}
	return 0, ErrNoCommonSuite
}

// CheckChosen verifies a responder's chosen suite: it must be one the
// initiator offered, supported, and not below the pin. Because sig_R
// covers th, which covers the initiator's whole hs.init including the
// offer, stripping suites from the offer is detected by the signature.
func CheckChosen(chosen int, offered []int, pinned uint8) error {
	if err := Check(chosen, pinned); err != nil {
		return err
	}
	for _, s := range offered {
		if s == chosen {
			return nil
		}
	}
	return ErrNoCommonSuite
}

// Pin records the highest suite negotiated with a peer (§13.4). The zero
// value has nothing pinned. It is safe for concurrent use.
type Pin struct {
	mu sync.Mutex
	v  uint8
}

// NewPin returns a pin restored from stored state.
func NewPin(v uint8) *Pin { return &Pin{v: v} }

// Value returns the pinned suite (0 if none).
func (p *Pin) Value() uint8 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.v
}

// Accept checks s against the pin without changing it.
func (p *Pin) Accept(s int) error { return Check(s, p.Value()) }

// Raise records a successfully negotiated suite. The pin never decreases.
func (p *Pin) Raise(s uint8) error {
	if err := Check(int(s), 0); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if s > p.v {
		p.v = s
	}
	return nil
}
