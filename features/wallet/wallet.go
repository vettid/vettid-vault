// Package wallet is the member's Bitcoin wallet (VAULT-MESSAGING §10.18):
// BIP86 (P2TR, the default for new wallets) and BIP84 (P2WPKH) accounts
// of one recovery phrase, which is a critical item
// (§10.7: envelope-encrypted under an item key that only the Protean
// Credential holds), receive addresses derived from the account's public
// key without the password, and PSBT signing as a credential operation
// per spend from an app within the credential's unlock window. It also
// runs the shared actions wallet.request-address and
// wallet.request-payment (§10.14).
//
// Chain access (OWNER DECISION, §10.18): the vault never talks to a
// chain. The member's app queries its own chain source and hands the
// vault a PSBT with the full previous transactions; the vault checks what
// it signs (its own inputs and change by re-derivation, amounts from the
// previous transactions, a fee cap, an exact payee for payment requests)
// and returns the signed transaction for the app to broadcast. ChainSource
// is where vault-side chain access (an allowlisted chain API) would plug
// in; no release configures one.
//
// Ported from vettid.dev's wallet_handler.go, bitcoin.go and
// wallet_mnemonic.go: per-wallet BIP39 phrases in the credential, BIP84
// P2WPKH and password-gated signing are kept; the vault-side coin
// selection, fee estimation and mempool.space calls through the parent's
// HTTP proxy, the single reused address (change sent back to it), the
// hand-written BIP32/BIP143/bech32 code (now btcd), the profile
// publication of wallets and the btc-* peer events are dropped.
package wallet

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/features/credential"
	"github.com/vettid/vettid-vault/features/items"
	"github.com/vettid/vettid-vault/features/itemspec"
	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vault"
	"github.com/vettid/vettid-vault/vms/btc"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// Limits (§10.18).
const (
	MaxWallets     = 16
	MaxAddresses   = 2000 // issued per wallet, both chains
	MaxHistory     = 200
	MaxLabel       = 128
	MaxUsed        = 256
	DefaultList    = 100
	MaxList        = 500
	EntropyBytes   = 32 // 24 words
	Category       = "crypto_wallet"
	Template       = "wallet.btc"
	LabelPhrase    = "Recovery phrase"
	LabelPassword  = "Passphrase"
	maxPSBTBase64  = (btc.MaxPSBT + 2) / 3 * 4
	defaultNetwork = btc.Mainnet
)

// Credential is the credential feature: wallet operations are credential
// operations (§3.5.3), and spending needs the unlock window.
type Credential interface {
	Operate(s *vault.Session, in *envelope.Inner, need int, check func(*credential.Payload) error,
		op func(*credential.Inner, *credential.Payload) error) (*credential.OpResult, error)
	UseKey(now time.Time, ttl time.Duration) (ed25519.PrivateKey, bool)
}

// Items is the items feature: a wallet's recovery phrase is a critical
// item. Its methods must not call back into this feature.
type Items interface {
	NewCriticalItem(s *vault.Session, inner *credential.Inner, name, category, template string, tags []string,
		fields []items.NewField) (string, []string, func(), func(), error)
	UseCriticalValues(s *vault.Session, inner *credential.Inner, itemID string) (map[string]json.RawMessage, func(), error)
	CriticalExists(itemID string) bool
}

// Unspent is an unspent output a ChainSource reports.
type Unspent struct {
	TxID      string
	Vout      uint32
	Amount    int64
	Script    []byte
	Confirmed bool
}

// ChainSource is chain access from inside the vault (option b of the
// chain-access decision, §10.18). No release configures one: the enclave
// reaches only the relay, KMS and the attestation status list (§12.2),
// and the member's app is the chain source.
type ChainSource interface {
	Unspent(ctx context.Context, network string, scripts [][]byte) ([]Unspent, error)
	Broadcast(ctx context.Context, network string, tx []byte) error
}

// Options configure the feature.
type Options struct {
	// Networks the vault accepts for new wallets; nil means mainnet,
	// testnet and signet (release); development adds regtest.
	Networks []string
	// Chain is vault-side chain access; nil in every release.
	Chain ChainSource
}

// Addr is an issued address.
type Addr struct {
	Type    string    `json:"type"` // btc.P2WPKH or btc.P2TR
	Chain   uint32    `json:"chain"`
	Index   uint32    `json:"index"`
	Address string    `json:"address"`
	Label   string    `json:"label,omitempty"`
	Conn    string    `json:"conn,omitempty"` // issued to this connection (wallet.request-address)
	Issued  time.Time `json:"issued"`
	Used    bool      `json:"used,omitempty"`
}

// Payee is one external output of a signed transaction.
type Payee struct {
	Address string `json:"address"`
	Amount  int64  `json:"amount"`
}

// Tx is a transaction the vault signed.
type Tx struct {
	TxID       string    `json:"txid"`
	At         time.Time `json:"at"`
	Sending    int64     `json:"sending"`
	Change     int64     `json:"change"`
	Fee        int64     `json:"fee"`
	Payees     []Payee   `json:"payees,omitempty"`
	Conn       string    `json:"conn,omitempty"`
	Invocation string    `json:"invocation,omitempty"`
}

// ConnAddr is the address a connection was given (wallet.request-address).
type ConnAddr struct {
	Type  string `json:"type"`
	Index uint32 `json:"index"`
}

// Wallet is one recovery phrase's accounts: BIP86 (P2TR) and BIP84
// (P2WPKH), their public halves and bookkeeping. Its recovery phrase is
// the critical item with the same id.
type Wallet struct {
	ID          string `json:"id"` // the critical item's id
	Version     uint64 `json:"version"`
	Name        string `json:"name"`
	Network     string `json:"network"`
	Fingerprint string `json:"fingerprint"`
	// XPubs are the account keys by address type.
	XPubs map[string]string `json:"xpubs"`
	// AddressType is the account new receive addresses come from
	// (wallet.address.new without type, wallet.request-address).
	AddressType string               `json:"address_type"`
	PhraseField string               `json:"phrase_field"`
	PassField   string               `json:"pass_field"`
	Next        map[string][2]uint32 `json:"next"`
	Addrs       []Addr               `json:"addrs,omitempty"`
	ConnAddr    map[string]ConnAddr  `json:"conn_addr,omitempty"`
	History     []Tx                 `json:"history,omitempty"`
	Created     time.Time            `json:"created"`
}

type state struct {
	Wallets map[string]*Wallet `json:"wallets"`
}

// Feature implements vault.Feature, vault.ConnectionRemovedObserver and
// items.ItemGuard.
type Feature struct {
	mu    sync.Mutex
	opt   Options
	cred  Credential
	items Items
	st    state

	gmu   sync.Mutex // guards owned only (a leaf lock: ItemInUse is called with the items feature's lock held)
	owned map[string]bool
}

// New returns the feature.
func New(cred Credential, it Items, o Options) *Feature {
	if o.Networks == nil {
		o.Networks = []string{btc.Mainnet, btc.Testnet, btc.Signet}
	}
	return &Feature{opt: o, cred: cred, items: it, st: state{Wallets: map[string]*Wallet{}}, owned: map[string]bool{}}
}

var (
	apps   = []string{vault.KindApp}
	owners = []string{vault.KindApp, vault.KindDesktop}
)

var (
	errBad      = vault.NewError("bad_request", "")
	errNotFound = vault.NewError("not_found", "")
	errLimit    = vault.NewError("limit", "")
	errLocked   = vault.NewError("credential_locked", "")
	errInternal = vault.NewError("internal", "")
	errUnavail  = vault.NewError("unavailable", "")
	errForbid   = vault.NewError("forbidden", "")
)

func psbtError(err error) error {
	var pe *btc.PSBTError
	if errors.As(err, &pe) {
		return vault.NewError("invalid_psbt", pe.Reason)
	}
	return vault.NewError("invalid_psbt", "malformed")
}

// Name implements vault.Feature.
func (f *Feature) Name() string { return "wallet" }

// Types implements vault.Feature. Creating a wallet and signing are app
// only (credential operations); reading, receive addresses and inspection
// are open to desktops within their access session (§6.8); agents get
// nothing (no wallet type is delegable, §10.11).
func (f *Feature) Types() []vault.TypeSpec {
	return []vault.TypeSpec{
		{Type: "wallet.create", Request: true, From: apps},
		{Type: "wallet.list", Request: true, From: owners},
		{Type: "wallet.get", Request: true, From: owners},
		// Which account receives (after the app scanned an imported
		// phrase's accounts, §10.18).
		{Type: "wallet.update", Request: true, From: owners},
		{Type: "wallet.address.new", Request: true, From: owners},
		{Type: "wallet.address.list", Request: true, From: owners},
		{Type: "wallet.address.used", Request: true, From: owners},
		{Type: "wallet.psbt.inspect", Request: true, From: owners},
		{Type: "wallet.sign", Request: true, From: apps},
		{Type: "wallet.history", Request: true, From: owners},
		{Type: "wallet.balance", Request: true, From: owners},
	}
}

// Load implements vault.Feature.
func (f *Feature) Load(raw json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	st := state{}
	if err := json.Unmarshal(raw, &st); err != nil {
		return err
	}
	if st.Wallets == nil {
		st.Wallets = map[string]*Wallet{}
	}
	f.st = st
	f.syncOwned()
	return nil
}

// Save implements vault.Feature.
func (f *Feature) Save() (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return json.Marshal(f.st)
}

func (f *Feature) syncOwned() {
	f.gmu.Lock()
	defer f.gmu.Unlock()
	f.owned = map[string]bool{}
	for id := range f.st.Wallets {
		f.owned[id] = true
	}
}

// ItemInUse implements items.ItemGuard: a wallet's item changes only
// through the wallet.
func (f *Feature) ItemInUse(id string) bool {
	f.gmu.Lock()
	defer f.gmu.Unlock()
	return f.owned[id]
}

// prune drops wallets whose item is gone (item.delete or
// credential.delete of the member's recovery phrase).
func (f *Feature) prune(s *vault.Session) {
	if f.items == nil {
		return
	}
	changed := false
	for _, id := range sortedKeys(f.st.Wallets) {
		if f.items.CriticalExists(id) {
			continue
		}
		delete(f.st.Wallets, id)
		changed = true
		s.SyncEvent("wallet.deleted", strictjson.NewBuilder().String("wallet_id", id).Bytes())
		s.Record(vault.Activity{Kind: "wallet.deleted", Ref: id, Audit: true})
	}
	if changed {
		f.syncOwned()
	}
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Handle implements vault.Handler.
func (f *Feature) Handle(_ context.Context, s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune(s)
	switch in.Type {
	case "wallet.create":
		return f.create(s, in)
	case "wallet.list":
		return f.list(in.Body)
	case "wallet.get":
		w, err := f.wallet(in.Body)
		if err != nil {
			return nil, err
		}
		return f.view(w).Bytes(), nil
	case "wallet.update":
		return f.update(s, in.Body)
	case "wallet.address.new":
		return f.addressNew(s, in.Body)
	case "wallet.address.list":
		return f.addressList(in.Body)
	case "wallet.address.used":
		return f.addressUsed(s, in.Body)
	case "wallet.psbt.inspect":
		return f.inspect(in.Body)
	case "wallet.sign":
		return f.sign(s, in)
	case "wallet.history":
		return f.history(in.Body)
	case "wallet.balance":
		return f.balance(s, in.Body)
	}
	return nil, vault.NewError("unsupported_type", "")
}

func (f *Feature) networkAllowed(n string) bool {
	for _, x := range f.opt.Networks {
		if x == n {
			return true
		}
	}
	return false
}

// AddressTypes are the wallet's account types, in a fixed order.
var addressTypes = [...]string{btc.P2TR, btc.P2WPKH} // read-only

func (w *Wallet) account(typ string) (*btc.Account, error) {
	x, ok := w.XPubs[typ]
	if !ok {
		return nil, errBad
	}
	return btc.ParseAccount(w.Network, typ, w.Fingerprint, x)
}

func (w *Wallet) accounts() ([]*btc.Account, error) {
	out := []*btc.Account{}
	for _, t := range addressTypes {
		if _, ok := w.XPubs[t]; !ok {
			continue
		}
		a, err := w.account(t)
		if err != nil {
			return nil, errInternal
		}
		out = append(out, a)
	}
	return out, nil
}

func validType(t string) bool { return t == btc.P2TR || t == btc.P2WPKH }

func (f *Feature) wallet(body []byte) (*Wallet, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	return f.walletOf(o)
}

func (f *Feature) walletOf(o strictjson.Object) (*Wallet, error) {
	id, err := o.String("wallet_id")
	if err != nil || !envelope.ValidULID(id) {
		return nil, errBad
	}
	w := f.st.Wallets[id]
	if w == nil {
		return nil, errNotFound
	}
	return w, nil
}

// --- create (§10.18) ---

// CreateRequest is a parsed wallet.create body (outside the sealed
// payload).
type CreateRequest struct {
	Name        string
	Network     string
	AddressType string
	Tags        json.RawMessage
}

// ParseCreate parses wallet.create's outer members strictly.
func ParseCreate(body []byte) (*CreateRequest, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	r := &CreateRequest{Network: defaultNetwork, AddressType: btc.P2TR}
	if r.Name, err = o.String("name"); err != nil || r.Name == "" || len(r.Name) > 128 || !printable(r.Name) {
		return nil, errBad
	}
	if n, present, err := o.OptString("network"); err != nil {
		return nil, errBad
	} else if present {
		if _, ok := btc.LookupNetwork(n); !ok {
			return nil, errBad
		}
		r.Network = n
	}
	if t, present, err := o.OptString("address_type"); err != nil || present && !validType(t) {
		return nil, errBad
	} else if present {
		r.AddressType = t
	}
	if o.Has("item_id") || o.Has("fields") {
		return nil, errBad
	}
	return r, nil
}

func printable(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Import is the optional sealed `item` of wallet.create: an existing
// recovery phrase to import.
type Import struct {
	Mnemonic   string
	Passphrase string
}

// ParseImport parses the sealed `item` of wallet.create strictly.
func ParseImport(raw []byte) (*Import, error) {
	o, err := strictjson.ParseObject(raw)
	if err != nil {
		return nil, errBad
	}
	m, err := o.String("mnemonic")
	if err != nil {
		return nil, errBad
	}
	im := &Import{}
	if im.Mnemonic, err = btc.NormalizeMnemonic(m); err != nil {
		return nil, errBad
	}
	p, _, err := o.OptString("passphrase")
	if err != nil || !btc.ValidPassphrase(p) {
		return nil, errBad
	}
	im.Passphrase = p
	return im, nil
}

func (f *Feature) create(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	if s.From().Kind != vault.KindApp || s.From().Recovering {
		return nil, errForbid
	}
	if f.items == nil || f.cred == nil {
		return nil, errUnavail
	}
	r, err := ParseCreate(in.Body)
	if err != nil {
		return nil, err
	}
	if !f.networkAllowed(r.Network) {
		return nil, errBad
	}
	if len(f.st.Wallets) >= MaxWallets {
		return nil, errLimit
	}
	o, _ := strictjson.ParseObject(in.Body)
	var tags []string
	if arr, present, err := o.OptArray("tags"); err != nil {
		return nil, errBad
	} else if present {
		if tags, err = itemspec.ParseTags(arr, 0, itemspec.MaxTags, true); err != nil || itemspec.HasTag(tags, itemspec.ProfileTag) {
			return nil, errBad
		}
	}
	n, _ := btc.LookupNetwork(r.Network)
	var w *Wallet
	var commit, abort func()
	op := func(inner *credential.Inner, p *credential.Payload) error {
		mnemonic, pass := "", ""
		if p.Item != nil {
			im, err := ParseImport(p.Item)
			if err != nil {
				return err
			}
			mnemonic, pass = im.Mnemonic, im.Passphrase
		} else {
			ent, err := suite.RandomBytes(EntropyBytes)
			if err != nil {
				return errInternal
			}
			m, err := btc.NewMnemonic(ent)
			suite.Wipe(ent)
			if err != nil {
				return errInternal
			}
			mnemonic = m
		}
		seed, err := btc.Seed(mnemonic, pass)
		if err != nil {
			return errInternal
		}
		xpubs := map[string]string{}
		fp := ""
		for _, t := range addressTypes {
			acct, err := btc.NewAccount(seed, n, t)
			if err != nil {
				suite.Wipe(seed)
				return errInternal
			}
			xpubs[t], fp = acct.XPub, acct.FingerprintHex()
		}
		suite.Wipe(seed)
		id, fids, c, a, err := f.items.NewCriticalItem(s, inner, r.Name, Category, Template, tags,
			[]items.NewField{{Label: LabelPhrase, Kind: "password", Value: mnemonic}, {Label: LabelPassword, Kind: "password", Value: pass}})
		if err != nil {
			return err
		}
		if len(fids) != 2 {
			a()
			return errInternal
		}
		commit, abort = c, a
		w = &Wallet{ID: id, Version: 1, Name: r.Name, Network: r.Network, Fingerprint: fp, XPubs: xpubs, AddressType: r.AddressType,
			PhraseField: fids[0], PassField: fids[1], Next: map[string][2]uint32{}, ConnAddr: map[string]ConnAddr{},
			Created: s.Now().UTC().Truncate(time.Millisecond)}
		return nil
	}
	res, err := f.cred.Operate(s, in, credential.NeedOptItem, nil, op)
	if err != nil {
		if abort != nil {
			abort()
		}
		return nil, err
	}
	commit()
	f.st.Wallets[w.ID] = w
	f.syncOwned()
	s.SyncEvent("wallet.changed", strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).Bytes())
	s.Record(vault.Activity{Kind: "wallet.created", Ref: w.ID, Audit: true})
	b := f.view(w)
	res.Members(b)
	return b.Bytes(), nil
}

// --- views ---

func pathOf(n btc.Network, typ string, chain, index uint32) string {
	return btc.PathString([]uint32{0x80000000 + btc.PurposeOf(typ), 0x80000000 + n.CoinType, 0x80000000, chain, index})
}

func (f *Feature) view(w *Wallet) *strictjson.Builder {
	b := strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).String("name", w.Name).
		String("network", w.Network).String("fingerprint", w.Fingerprint).String("address_type", w.AddressType)
	arr := []byte{'['}
	accts, _ := w.accounts()
	for i, a := range accts {
		if i > 0 {
			arr = append(arr, ',')
		}
		nx := w.Next[a.Type]
		arr = append(arr, strictjson.NewBuilder().String("type", a.Type).String("path", btc.PathString(a.AccountPath())).
			String("xpub", a.XPub).
			Raw("descriptors", strictjson.NewBuilder().String("receive", a.Descriptor(0)).String("change", a.Descriptor(1)).Bytes()).
			Uint("next_receive", uint64(nx[0])).Uint("next_change", uint64(nx[1])).Bytes()...)
	}
	return b.Raw("accounts", append(arr, ']')).String("created_at", envelope.FormatTS(w.Created))
}

func (f *Feature) list(body []byte) (json.RawMessage, error) {
	if _, err := strictjson.ParseObject(body); err != nil {
		return nil, errBad
	}
	arr := []byte{'['}
	for i, id := range sortedKeys(f.st.Wallets) {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, f.view(f.st.Wallets[id]).Bytes()...)
	}
	return strictjson.NewBuilder().Raw("wallets", append(arr, ']')).Bytes(), nil
}

// Update is a parsed wallet.update body.
type Update struct {
	WalletID    string
	Version     uint64
	AddressType string
}

// ParseUpdate parses wallet.update strictly.
func ParseUpdate(body []byte) (*Update, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	u := &Update{}
	if u.WalletID, err = o.String("wallet_id"); err != nil || !envelope.ValidULID(u.WalletID) {
		return nil, errBad
	}
	if u.Version, err = o.Uint("version", 1, strictjson.MaxSafeInteger); err != nil {
		return nil, errBad
	}
	if u.AddressType, err = o.String("address_type"); err != nil || !validType(u.AddressType) {
		return nil, errBad
	}
	return u, nil
}

// update sets the account that receives (address_type).
func (f *Feature) update(s *vault.Session, body []byte) (json.RawMessage, error) {
	u, err := ParseUpdate(body)
	if err != nil {
		return nil, err
	}
	w := f.st.Wallets[u.WalletID]
	if w == nil {
		return nil, errNotFound
	}
	if u.Version != w.Version {
		return nil, vault.NewError("conflict", "")
	}
	w.AddressType = u.AddressType
	w.Version++
	s.SyncEvent("wallet.changed", strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).Bytes())
	return strictjson.NewBuilder().Uint("version", w.Version).Bytes(), nil
}

// --- addresses ---

func (w *Wallet) addr(typ string, chain, index uint32) *Addr {
	for i := range w.Addrs {
		if w.Addrs[i].Type == typ && w.Addrs[i].Chain == chain && w.Addrs[i].Index == index {
			return &w.Addrs[i]
		}
	}
	return nil
}

// issue derives and records the next address of a chain.
func (w *Wallet) issue(typ string, chain uint32, label, conn string, now time.Time) (*Addr, error) {
	if w.Next == nil {
		w.Next = map[string][2]uint32{}
	}
	nx := w.Next[typ]
	if len(w.Addrs) >= MaxAddresses || nx[chain] >= btc.MaxIndex {
		return nil, errLimit
	}
	a, err := w.account(typ)
	if err != nil {
		return nil, err
	}
	idx := nx[chain]
	addr, _, err := a.Address(chain, idx)
	if err != nil {
		return nil, errInternal
	}
	w.Addrs = append(w.Addrs, Addr{Type: typ, Chain: chain, Index: idx, Address: addr, Label: label, Conn: conn, Issued: now.UTC().Truncate(time.Millisecond)})
	nx[chain] = idx + 1
	w.Next[typ] = nx
	w.Version++
	return &w.Addrs[len(w.Addrs)-1], nil
}

func (f *Feature) addrJSON(w *Wallet, a *Addr) []byte {
	n, _ := btc.LookupNetwork(w.Network)
	b := strictjson.NewBuilder().String("address", a.Address).String("type", a.Type).Uint("index", uint64(a.Index)).Bool("change", a.Chain == 1).
		String("path", pathOf(n, a.Type, a.Chain, a.Index))
	if a.Label != "" {
		b.String("label", a.Label)
	}
	if a.Conn != "" {
		b.String("connection_id", a.Conn)
	}
	return b.Bool("used", a.Used).String("issued_at", envelope.FormatTS(a.Issued)).Bytes()
}

func (f *Feature) addressNew(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	chain := uint32(0)
	if o.Has("change") {
		c, err := o.Bool("change")
		if err != nil {
			return nil, errBad
		}
		if c {
			chain = 1
		}
	}
	typ, err := typeOf(o, w)
	if err != nil {
		return nil, err
	}
	label, _, err := o.OptString("label")
	if err != nil || len(label) > MaxLabel || !printable(label) {
		return nil, errBad
	}
	a, err := w.issue(typ, chain, label, "", s.Now())
	if err != nil {
		return nil, err
	}
	s.SyncEvent("wallet.changed", strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).Bytes())
	return f.addrJSON(w, a), nil
}

// typeOf parses an optional `type` (default: the wallet's address type).
func typeOf(o strictjson.Object, w *Wallet) (string, error) {
	t, present, err := o.OptString("type")
	if err != nil || present && !validType(t) {
		return "", errBad
	}
	if !present {
		return w.AddressType, nil
	}
	return t, nil
}

func (f *Feature) addressList(body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	chain := uint32(0)
	if o.Has("change") {
		c, err := o.Bool("change")
		if err != nil {
			return nil, errBad
		}
		if c {
			chain = 1
		}
	}
	typ, err := typeOf(o, w)
	if err != nil {
		return nil, err
	}
	after, hasAfter, err := o.OptUint("after", 0, btc.MaxIndex)
	if err != nil {
		return nil, errBad
	}
	limit, present, err := o.OptUint("limit", 1, MaxList)
	if err != nil {
		return nil, errBad
	}
	if !present {
		limit = DefaultList
	}
	var sel []*Addr
	for i := range w.Addrs {
		a := &w.Addrs[i]
		if a.Type == typ && a.Chain == chain && (!hasAfter || uint64(a.Index) > after) {
			sel = append(sel, a)
		}
	}
	sort.Slice(sel, func(i, j int) bool { return sel[i].Index < sel[j].Index })
	arr := []byte{'['}
	n := 0
	for _, a := range sel {
		if uint64(n) == limit {
			break
		}
		if n > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, f.addrJSON(w, a)...)
		n++
	}
	b := strictjson.NewBuilder().Raw("addresses", append(arr, ']'))
	if n < len(sel) {
		b.Uint("next", uint64(sel[n-1].Index))
	}
	return b.Bytes(), nil
}

// addressUsed records the app's chain observations: addresses that have
// received funds. A connection's address that is used is replaced at its
// next request (§10.14).
func (f *Feature) addressUsed(s *vault.Session, body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	arr, err := o.Array("addresses")
	if err != nil || len(arr) == 0 || len(arr) > MaxUsed {
		return nil, errBad
	}
	n, _ := btc.LookupNetwork(w.Network)
	marked := 0
	for _, raw := range arr {
		var a string
		if json.Unmarshal(raw, &a) != nil {
			return nil, errBad
		}
		c, err := btc.CheckAddress(n, a)
		if err != nil {
			return nil, errBad
		}
		for i := range w.Addrs {
			if w.Addrs[i].Address == c && !w.Addrs[i].Used {
				w.Addrs[i].Used = true
				marked++
			}
		}
	}
	if marked > 0 {
		w.Version++
		s.SyncEvent("wallet.changed", strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).Bytes())
	}
	return strictjson.NewBuilder().Uint("marked", uint64(marked)).Uint("version", w.Version).Bytes(), nil
}

// --- PSBTs ---

func parsePSBT(o strictjson.Object) ([]byte, error) {
	p, err := o.String("psbt")
	if err != nil || p == "" || len(p) > maxPSBTBase64 {
		return nil, errBad
	}
	raw, err := strictjson.DecodeStd(p, -1)
	if err != nil {
		return nil, errBad
	}
	return raw, nil
}

func summaryJSON(n btc.Network, sum *btc.Summary) *strictjson.Builder {
	ins := []byte{'['}
	for i, in := range sum.Inputs {
		if i > 0 {
			ins = append(ins, ',')
		}
		ins = append(ins, strictjson.NewBuilder().String("txid", in.TxID).Uint("vout", uint64(in.Vout)).
			Uint("amount_sats", uint64(in.Amount)).String("type", in.Type).String("path", pathOf(n, in.Type, in.Chain, in.Index)).Bytes()...)
	}
	outs := []byte{'['}
	for i, o := range sum.Outputs {
		if i > 0 {
			outs = append(outs, ',')
		}
		b := strictjson.NewBuilder().String("address", o.Address).Uint("amount_sats", uint64(o.Amount)).Bool("change", o.Change)
		if o.Change {
			b.String("type", o.Type).String("path", pathOf(n, o.Type, o.Chain, o.Index))
		}
		outs = append(outs, b.Bytes()...)
	}
	return strictjson.NewBuilder().String("txid", sum.TxID).Raw("inputs", append(ins, ']')).Raw("outputs", append(outs, ']')).
		Uint("total_in_sats", uint64(sum.TotalIn)).Uint("sending_sats", uint64(sum.Sending)).Uint("change_sats", uint64(sum.Change)).
		Uint("fee_sats", uint64(sum.Fee)).Uint("vsize", uint64(sum.VSize))
}

func (f *Feature) inspect(body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	raw, err := parsePSBT(o)
	if err != nil {
		return nil, err
	}
	a, err := w.accounts()
	if err != nil {
		return nil, errInternal
	}
	sum, err := btc.Inspect(a, raw)
	if err != nil {
		return nil, psbtError(err)
	}
	n, _ := btc.LookupNetwork(w.Network)
	return summaryJSON(n, sum).Bytes(), nil
}

// signed is what a successful spend produced.
type signed struct {
	tx  []byte
	sum *btc.Summary
	res *credential.OpResult
}

// spend is one credential operation that signs a checked PSBT with the
// wallet's recovery phrase (§10.18): the app, the unlock window, the UTK
// payload bound to the wallet and the PSBT's hash (and, for a payment
// request, to the invocation), the item re-keyed with the use and the
// CEK rotated.
func (f *Feature) spend(s *vault.Session, in *envelope.Inner, w *Wallet, raw []byte, payTo string, amount int64, invocation string) (*signed, error) {
	if s.From().Kind != vault.KindApp || s.From().Recovering {
		return nil, errForbid
	}
	if f.cred == nil || f.items == nil {
		return nil, errUnavail
	}
	if _, ok := f.cred.UseKey(s.Now(), s.Settings().UnlockTTL()); !ok {
		return nil, errLocked // spending is a critical action: the member's app in the unlock window
	}
	a, err := w.accounts()
	if err != nil {
		return nil, errInternal
	}
	sum, err := btc.Inspect(a, raw)
	if err != nil {
		return nil, psbtError(err)
	}
	if payTo != "" {
		if err := sum.PayCheck(payTo, amount); err != nil {
			return nil, psbtError(err)
		}
	}
	h := sha256.Sum256(raw)
	need := credential.NeedItemID | credential.NeedHash
	if invocation != "" {
		need = credential.NeedItemID | credential.NeedRequest
	}
	check := func(p *credential.Payload) error {
		if p.ItemID != w.ID || !suite.Equal(p.PayloadHash, h[:]) || invocation != "" && p.RequestID != invocation {
			return errBad // the password authorises this PSBT of this wallet (and this payment request) only
		}
		return nil
	}
	var tx []byte
	var commit func()
	op := func(inner *credential.Inner, _ *credential.Payload) error {
		vals, c, err := f.items.UseCriticalValues(s, inner, w.ID)
		if err != nil {
			return err
		}
		defer func() {
			for _, v := range vals {
				suite.Wipe(v)
			}
		}()
		var phrase, pass string
		if json.Unmarshal(vals[w.PhraseField], &phrase) != nil || json.Unmarshal(vals[w.PassField], &pass) != nil {
			return errInternal
		}
		phrase, err = btc.NormalizeMnemonic(phrase)
		if err != nil {
			return errInternal
		}
		seed, err := btc.Seed(phrase, pass)
		if err != nil {
			return errInternal
		}
		defer suite.Wipe(seed)
		if tx, err = btc.Sign(a, sum, seed); err != nil {
			return psbtError(err)
		}
		commit = c
		return nil
	}
	res, err := f.cred.Operate(s, in, need, check, op)
	if err != nil {
		return nil, err
	}
	commit() // the item's new ciphertext (the item key rotated with the use)
	f.recordSpend(s, w, sum, "", invocation)
	return &signed{tx: tx, sum: sum, res: res}, nil
}

// recordSpend keeps the transaction in the history, marks spent and
// change addresses and moves the next indices past what the PSBT used.
func (f *Feature) recordSpend(s *vault.Session, w *Wallet, sum *btc.Summary, conn, invocation string) {
	now := s.Now().UTC().Truncate(time.Millisecond)
	tx := Tx{TxID: sum.TxID, At: now, Sending: sum.Sending, Change: sum.Change, Fee: sum.Fee, Conn: conn, Invocation: invocation}
	for _, o := range sum.Outputs {
		if !o.Change {
			tx.Payees = append(tx.Payees, Payee{Address: o.Address, Amount: o.Amount})
			continue
		}
		if o.Index >= w.Next[o.Type][o.Chain] && len(w.Addrs) < MaxAddresses {
			for w.Next[o.Type][o.Chain] <= o.Index {
				if _, err := w.issue(o.Type, o.Chain, "", "", now); err != nil {
					break
				}
			}
		}
		if a := w.addr(o.Type, o.Chain, o.Index); a != nil {
			a.Used = true
		}
	}
	for _, in := range sum.Inputs {
		if a := w.addr(in.Type, in.Chain, in.Index); a != nil {
			a.Used = true
		}
	}
	w.History = append(w.History, tx)
	if len(w.History) > MaxHistory {
		w.History = append([]Tx(nil), w.History[len(w.History)-MaxHistory:]...)
	}
	w.Version++
	s.SyncEvent("wallet.signed", strictjson.NewBuilder().String("wallet_id", w.ID).String("txid", sum.TxID).Bytes())
	s.Record(vault.Activity{Kind: "wallet.signed", Ref: sum.TxID, Audit: true, Feed: true})
}

func (f *Feature) sign(s *vault.Session, in *envelope.Inner) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return nil, errBad
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	raw, err := parsePSBT(o)
	if err != nil {
		return nil, err
	}
	broadcast := false
	if o.Has("broadcast") {
		if broadcast, err = o.Bool("broadcast"); err != nil {
			return nil, errBad
		}
	}
	if broadcast && f.opt.Chain == nil {
		return nil, errUnavail // the app broadcasts (§10.18)
	}
	out, err := f.spend(s, in, w, raw, "", 0, "")
	if err != nil {
		return nil, err
	}
	n, _ := btc.LookupNetwork(w.Network)
	b := summaryJSON(n, out.sum).String("tx", hex.EncodeToString(out.tx))
	if broadcast {
		b.Bool("broadcast", f.opt.Chain.Broadcast(s.Context(), w.Network, out.tx) == nil)
	}
	out.res.Members(b)
	return b.Bytes(), nil
}

func (f *Feature) history(body []byte) (json.RawMessage, error) {
	o, err := strictjson.ParseObject(body)
	if err != nil {
		return nil, errBad
	}
	w, err := f.walletOf(o)
	if err != nil {
		return nil, err
	}
	limit, present, err := o.OptUint("limit", 1, MaxHistory)
	if err != nil {
		return nil, errBad
	}
	if !present {
		limit = 50
	}
	arr := []byte{'['}
	n := uint64(0)
	for i := len(w.History) - 1; i >= 0 && n < limit; i-- {
		t := w.History[i]
		if n > 0 {
			arr = append(arr, ',')
		}
		ps := []byte{'['}
		for k, p := range t.Payees {
			if k > 0 {
				ps = append(ps, ',')
			}
			ps = append(ps, strictjson.NewBuilder().String("address", p.Address).Uint("amount_sats", uint64(p.Amount)).Bytes()...)
		}
		b := strictjson.NewBuilder().String("txid", t.TxID).String("at", envelope.FormatTS(t.At)).Uint("sending_sats", uint64(t.Sending)).
			Uint("change_sats", uint64(t.Change)).Uint("fee_sats", uint64(t.Fee)).Raw("payees", append(ps, ']'))
		if t.Conn != "" {
			b.String("connection_id", t.Conn)
		}
		if t.Invocation != "" {
			b.String("invocation_id", t.Invocation)
		}
		arr = append(arr, b.Bytes()...)
		n++
	}
	return strictjson.NewBuilder().Raw("transactions", append(arr, ']')).Bytes(), nil
}

// balance sums what a vault-side chain source reports for the wallet's
// issued addresses; without one (every release) it is `unavailable` and
// the app computes balances from its own chain source.
func (f *Feature) balance(s *vault.Session, body []byte) (json.RawMessage, error) {
	w, err := f.wallet(body)
	if err != nil {
		return nil, err
	}
	if f.opt.Chain == nil {
		return nil, errUnavail
	}
	scripts := [][]byte{}
	for _, ad := range w.Addrs {
		a, err := w.account(ad.Type)
		if err != nil {
			continue
		}
		if _, sc, err := a.Address(ad.Chain, ad.Index); err == nil {
			scripts = append(scripts, sc)
		}
	}
	us, err := f.opt.Chain.Unspent(s.Context(), w.Network, scripts)
	if err != nil {
		return nil, errUnavail
	}
	var conf, unconf uint64
	for _, u := range us {
		if u.Amount <= 0 {
			continue
		}
		if u.Confirmed {
			conf += uint64(u.Amount)
		} else {
			unconf += uint64(u.Amount)
		}
	}
	return strictjson.NewBuilder().Uint("confirmed_sats", conf).Uint("unconfirmed_sats", unconf).Bytes(), nil
}

// ConnectionRemoved implements vault.ConnectionRemovedObserver: the
// connection's current address assignments go (the addresses stay).
func (f *Feature) ConnectionRemoved(_ *vault.Session, conn string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, w := range f.st.Wallets {
		delete(w.ConnAddr, conn)
	}
}

// --- shared actions (§10.14) ---

// RequestAddress runs wallet.request-address for connection conn on the
// configured wallet: the connection's current receive address, or a new
// one once the app has reported it used.
func (f *Feature) RequestAddress(s *vault.Session, conn, walletID string) (network, address string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune(s)
	w := f.st.Wallets[walletID]
	if w == nil {
		return "", "", errNotFound
	}
	if ca, ok := w.ConnAddr[conn]; ok && ca.Type == w.AddressType {
		if a := w.addr(ca.Type, 0, ca.Index); a != nil && !a.Used {
			return w.Network, a.Address, nil
		}
	}
	a, err := w.issue(w.AddressType, 0, "", conn, s.Now())
	if err != nil {
		return "", "", err
	}
	if w.ConnAddr == nil {
		w.ConnAddr = map[string]ConnAddr{}
	}
	w.ConnAddr[conn] = ConnAddr{Type: a.Type, Index: a.Index}
	s.SyncEvent("wallet.changed", strictjson.NewBuilder().String("wallet_id", w.ID).Uint("version", w.Version).Bytes())
	s.Record(vault.Activity{Kind: "wallet.address_issued", ConnectionID: conn, Ref: w.ID, Direction: "out", Audit: true})
	return w.Network, a.Address, nil
}

// PayParams are a wallet.request-payment invocation's parameters.
type PayParams struct {
	WalletID   string
	Conn       string
	Invocation string
	Address    string
	Amount     int64
}

// Pay signs, in the member's approval of a wallet.request-payment
// invocation (action.respond from an app in the unlock window, with the
// PSBT and the credential), a PSBT that pays exactly the requested amount
// to the requested address and nothing to anyone else but the wallet.
// It returns the txid and the response members for the app (the summary,
// the signed transaction and the credential's).
func (f *Feature) Pay(s *vault.Session, in *envelope.Inner, p PayParams) (string, func(*strictjson.Builder), error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.prune(s)
	w := f.st.Wallets[p.WalletID]
	if w == nil {
		return "", nil, errNotFound
	}
	n, _ := btc.LookupNetwork(w.Network)
	addr, err := btc.CheckAddress(n, p.Address)
	if err != nil {
		return "", nil, psbtError(&btc.PSBTError{Reason: "payee_network"})
	}
	o, err := strictjson.ParseObject(in.Body)
	if err != nil {
		return "", nil, errBad
	}
	raw, err := parsePSBT(o)
	if err != nil {
		return "", nil, err
	}
	out, err := f.spend(s, in, w, raw, addr, p.Amount, p.Invocation)
	if err != nil {
		return "", nil, err
	}
	w.History[len(w.History)-1].Conn = p.Conn
	return out.sum.TxID, func(b *strictjson.Builder) {
		b.Raw("summary", summaryJSON(n, out.sum).Bytes()).String("tx", hex.EncodeToString(out.tx))
		out.res.Members(b)
	}, nil
}

// Wallets returns copies of the wallets (tests and tools).
func (f *Feature) Wallets() []Wallet {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []Wallet{}
	for _, id := range sortedKeys(f.st.Wallets) {
		out = append(out, *f.st.Wallets[id])
	}
	return out
}
