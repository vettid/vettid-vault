package vault

// The audit search's names (VAULT-MESSAGING 0.20.0, §10.9): audit.list's
// q matches the current names of an entry's connection, device and item,
// as the vault holds them when it answers.

// DeviceLister is implemented by hosts that list the owner's devices as
// device.list does (§10.3), whatever their state. The Manager implements
// it.
type DeviceLister interface {
	ListedDevice(id string) (PeerInfo, bool)
}

// ListedDevice returns an owner device as device.list lists it: any
// paired device, also one without an access session, pending or
// recovering. On a host without DeviceLister it is PairedDevice.
func (s *Session) ListedDevice(id string) (PeerInfo, bool) {
	if h, ok := s.host.(DeviceLister); ok {
		return h.ListedDevice(id)
	}
	return s.host.PairedDevice(id)
}

func (h managerHost) ListedDevice(id string) (PeerInfo, bool) {
	p, ok := h.m.st.Devices[id]
	if !ok {
		return PeerInfo{}, false
	}
	return info(p), true
}
