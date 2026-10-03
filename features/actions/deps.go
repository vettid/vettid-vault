package actions

import (
	"crypto/ed25519"
	"time"

	"github.com/vettid/vettid-vault/features/audit"
	"github.com/vettid/vettid-vault/features/grants"
	"github.com/vettid/vettid-vault/features/wallet"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/envelope"
)

// Deps are the features the built-in actions run through (§10.14). A nil
// field makes the actions that need it answer `unavailable`.
type Deps struct {
	// Grants makes the one-use grants of items.share, and records those
	// received (§10.12).
	Grants GrantIssuer
	// Audit gives audit.recent a connection's own entries (§10.9).
	Audit AuditSource
	// Keys is the credential's unlock window: critical actions are
	// approved only by an app while it is open (§3.5.3).
	Keys KeyUser
	// Wallet runs wallet.request-address and wallet.request-payment
	// (§10.18).
	Wallet WalletActions
}

// WalletActions is the wallet feature (wallet.Feature).
type WalletActions interface {
	RequestAddress(s *vault.Session, conn, walletID string) (network, address string, err error)
	Pay(s *vault.Session, in *envelope.Inner, p wallet.PayParams) (txid string, members func(*strictjson.Builder), err error)
}

// GrantIssuer is the grants feature (grants.Feature).
type GrantIssuer interface {
	IssueForAction(s *vault.Session, conn, invocationID string, items []grants.Item, uses uint64, ttl time.Duration) ([]grants.Descriptor, error)
	ReceiveFromAction(s *vault.Session, conn, invocationID string, descs []grants.Descriptor)
}

// AuditSource is the audit log (audit.Feature).
type AuditSource interface {
	ForConnection(conn string, limit int) []audit.ConnEntry
}

// KeyUser gives access to the credential unlock window (critical actions).
type KeyUser interface {
	UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool)
}
