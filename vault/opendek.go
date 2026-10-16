package vault

import (
	"github.com/vettid/vettid-vault/vms/recovery"
	"github.com/vettid/vettid-vault/vms/suite"
)

// How an unlock reached the DEK (§11.14.2).
const (
	openCurrent     = iota // the current wrap, no `next` part
	openCurrentDrop        // the current wrap while a `next` part exists: it is dropped
	openPromote            // the `next` wrap, the state under DEK_1: step 3 at this unlock
	openComplete           // the `next` wrap, the state under DEK_0: a PIN change or a new secret is completed
)

type opened struct {
	code string
	mode int
	dek  []byte // the DEK the state is under
	dek1 []byte // openPromote, openComplete: DEK_1
	uk   []byte // the unlock key of the wrap that opened
}

func (o *opened) wipe() {
	suite.Wipe(o.dek)
	suite.Wipe(o.dek1)
	suite.Wipe(o.uk)
}

// openDEK applies §11.14.1 and §11.14.2 at an unlock: the secret must
// match secret_check or, while a `next` part exists, secret_check_next
// (device_secret otherwise, decided before the PIN); then the wrap whose
// DEK version the state names is tried first. A PIN that opens no wrap is
// bad_pin. A secret and PIN superseded by a replacement whose state is
// stored are device_secret; the new phone of a transfer or recovery whose
// state write is not stored is transfer_incomplete.
func openDEK(h *Header, pin string, secret []byte, vaultID string, stateVer uint64) opened {
	cur, _ := recovery.SecretCheck(h.Pepper, vaultID, secret)
	curMatch := cur != nil && suite.Equal(cur, h.SecretCheck)
	nx := h.Next
	nxMatch := nx != nil && cur != nil && suite.Equal(cur, nx.SecretCheck)
	if !curMatch && !nxMatch {
		return opened{code: CodeDeviceSecret}
	}
	tryCur := func() ([]byte, []byte, bool) {
		uk, err := deriveUnlockKey(pin, secret, h.KDF, h.Pepper, vaultID)
		if err != nil {
			return nil, nil, false
		}
		d, err := recovery.OpenDEK(uk, h.DEKWrap, vaultID, h.DEKVersion)
		if err != nil {
			suite.Wipe(uk)
			return nil, nil, false
		}
		return d, uk, true
	}
	tryNext := func() ([]byte, []byte, []byte, bool) {
		uk, err := deriveUnlockKey(pin, secret, nx.KDF, h.Pepper, vaultID)
		if err != nil {
			return nil, nil, nil, false
		}
		d0, d1, err := recovery.OpenDEKNext(uk, nx.DEKWrapNext, vaultID, nx.DEKVersion)
		if err != nil {
			suite.Wipe(uk)
			return nil, nil, nil, false
		}
		return d0, d1, uk, true
	}
	if nx != nil && stateVer != h.DEKVersion && stateVer != nx.DEKVersion || nx == nil && stateVer != h.DEKVersion {
		return opened{code: CodeRollback} // header and state do not belong together
	}
	opensSomething := false
	if nxMatch && stateVer == nx.DEKVersion {
		if d0, d1, uk, ok := tryNext(); ok {
			suite.Wipe(d0)
			return opened{mode: openPromote, dek: d1, dek1: append([]byte(nil), d1...), uk: uk}
		}
	}
	if curMatch {
		if d, uk, ok := tryCur(); ok {
			if stateVer == h.DEKVersion {
				mode := openCurrent
				if nx != nil {
					mode = openCurrentDrop
				}
				return opened{mode: mode, dek: d, uk: uk}
			}
			suite.Wipe(d)
			suite.Wipe(uk)
			opensSomething = true // superseded: the replacement's state is stored
		}
	}
	if nxMatch && stateVer == h.DEKVersion {
		if d0, d1, uk, ok := tryNext(); ok {
			switch nx.Reason {
			case ReplacePIN, ReplaceRenew:
				return opened{mode: openComplete, dek: d0, dek1: d1, uk: uk}
			}
			suite.Wipe(d0)
			suite.Wipe(d1)
			suite.Wipe(uk)
			return opened{code: CodeTransferIncomplete}
		}
	}
	if opensSomething {
		return opened{code: CodeDeviceSecret}
	}
	return opened{code: CodeBadPIN}
}
