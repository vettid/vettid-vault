package client

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"time"

	"github.com/vettid/vettid-vault/internal/strictjson"
	"github.com/vettid/vettid-vault/vms/callwire"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// V4 batch 2 operations (VAULT-MESSAGING §6.8, §10.3, §10.4, §10.10):
// access sessions and approvals, the block list, connection metadata,
// member authentication and calls.

// --- access sessions and approvals (§6.8) ---

// SessionRequest asks the vault for an access session (desktops and
// agents); seconds 0 means the default. It returns the request id.
func (d *Device) SessionRequest(ctx context.Context, seconds int) (string, error) {
	body := map[string]any{}
	if seconds > 0 {
		body["seconds"] = seconds
	}
	o, err := d.Op(ctx, "device.session.request", body)
	if err != nil {
		return "", err
	}
	return o.String("request_id")
}

// SessionApprove approves a desktop's or agent's request (apps); seconds 0
// keeps the requested length. It returns the session's expiry.
func (d *Device) SessionApprove(ctx context.Context, requestID string, seconds int) (time.Time, error) {
	body := map[string]any{"request_id": requestID}
	if seconds > 0 {
		body["seconds"] = seconds
	}
	o, err := d.Op(ctx, "device.session.approve", body)
	if err != nil {
		return time.Time{}, err
	}
	s, err := o.String("expires_at")
	if err != nil {
		return time.Time{}, err
	}
	return envelope.ParseTS(s)
}

// SessionDeny denies a request (apps).
func (d *Device) SessionDeny(ctx context.Context, requestID string) error {
	_, err := d.Op(ctx, "device.session.deny", map[string]any{"request_id": requestID})
	return err
}

// SessionEnd ends an access session: an app names the device, a desktop
// or agent passes "" for its own.
func (d *Device) SessionEnd(ctx context.Context, deviceID string) error {
	body := map[string]any{}
	if deviceID != "" {
		body["device_id"] = deviceID
	}
	_, err := d.Op(ctx, "device.session.end", body)
	return err
}

// ApprovalDecide approves or denies a held request (apps). It returns the
// held request's result ("ok" or its error code).
func (d *Device) ApprovalDecide(ctx context.Context, approvalID string, approve bool) (string, error) {
	o, err := d.Op(ctx, "approval.decide", map[string]any{"approval_id": approvalID, "approve": approve})
	if err != nil {
		return "", err
	}
	return o.String("result")
}

// --- connections (§10.4) ---

// BlockConnection blocks a connection (removing it).
func (d *Device) BlockConnection(ctx context.Context, connectionID, note string) (string, error) {
	return d.block(ctx, map[string]any{"connection_id": connectionID}, note)
}

// BlockPending blocks the sender of a pending connection request.
func (d *Device) BlockPending(ctx context.Context, pendingID, note string) (string, error) {
	return d.block(ctx, map[string]any{"pending_id": pendingID}, note)
}

func (d *Device) block(ctx context.Context, body map[string]any, note string) (string, error) {
	if note != "" {
		body["note"] = note
	}
	o, err := d.Op(ctx, "block.add", body)
	if err != nil {
		return "", err
	}
	return o.String("block_id")
}

// BlockRemove lifts a block.
func (d *Device) BlockRemove(ctx context.Context, blockID string) error {
	_, err := d.Op(ctx, "block.remove", map[string]any{"block_id": blockID})
	return err
}

// BlockList lists the block list.
func (d *Device) BlockList(ctx context.Context) (strictjson.Object, error) {
	return d.Op(ctx, "block.list", nil)
}

// ConnectionUpdate changes the owner's metadata about a connection (alias,
// note, tags, favorite, archived) at version; it returns the new version.
func (d *Device) ConnectionUpdate(ctx context.Context, connectionID string, version uint64, set map[string]any) (uint64, error) {
	body := map[string]any{"connection_id": connectionID, "version": version}
	for k, v := range set {
		body[k] = v
	}
	o, err := d.Op(ctx, "connection.update", body)
	if err != nil {
		return 0, err
	}
	return o.Uint("version", 1, strictjson.MaxSafeInteger)
}

// AuthRequest asks a connection's member to authenticate; it returns the
// request id. The verdict arrives as connection.authenticate.result.
func (d *Device) AuthRequest(ctx context.Context, connectionID, context string) (string, error) {
	body := map[string]any{"connection_id": connectionID}
	if context != "" {
		body["context"] = context
	}
	o, err := d.Op(ctx, "connection.authenticate.request", body)
	if err != nil {
		return "", err
	}
	return o.String("request_id")
}

// AuthApprove signs a pending challenge with the credential key; the app
// first opens the unlock window with CredentialUnlock (§3.5.3).
func (d *Device) AuthApprove(ctx context.Context, requestID string) error {
	_, err := d.Op(ctx, "connection.authenticate.approve", map[string]any{"request_id": requestID})
	return err
}

// AuthDeny refuses a pending challenge.
func (d *Device) AuthDeny(ctx context.Context, requestID string) error {
	_, err := d.Op(ctx, "connection.authenticate.deny", map[string]any{"request_id": requestID})
	return err
}

// --- calls (§10.10) ---

// ErrCall is a call message the device cannot use.
var ErrCall = errors.New("client: invalid call message")

// Call is this device's side of a call.
type Call struct {
	ID      string
	Conn    string
	ICE     *callwire.ICEConfig
	key     *suite.PrivateKey // the caller's ephemeral KEM key
	Key     []byte            // k_call, once agreed
	Offer   *envelope.Inner   // the incoming offer (callee)
	Started time.Time
}

// Destroy wipes the call's keys.
func (c *Call) Destroy() {
	if c.key != nil {
		c.key.Destroy()
	}
	suite.Wipe(c.Key)
}

func (d *Device) vaultIK() (ed25519.PublicKey, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.st.Vault == nil {
		return nil, ErrNotPaired
	}
	return append(ed25519.PublicKey(nil), d.st.Vault.IK...), nil
}

// verifyICE checks the ICE configuration in a body against the vault's ik.
func (d *Device) verifyICE(o strictjson.Object, callID string) (*callwire.ICEConfig, error) {
	ik, err := d.vaultIK()
	if err != nil {
		return nil, err
	}
	cfg, err1 := o.Base64("ice_config", -1)
	sig, err2 := o.Base64("ice_sig", ed25519.SignatureSize)
	if err1 != nil || err2 != nil {
		return nil, ErrCall
	}
	return callwire.VerifyICE(ik, cfg, sig, callID, d.cfg.Now())
}

// CallStart places a call: a fresh ephemeral KEM key, the SDP offer, and
// the vault-signed ICE configuration, checked.
func (d *Device) CallStart(ctx context.Context, connectionID, media, sdp string) (*Call, error) {
	sk, err := callwire.NewOfferKey()
	if err != nil {
		return nil, err
	}
	cid, err := envelope.NewULID(d.cfg.Now())
	if err != nil {
		return nil, err
	}
	ek := sk.Public().Bytes()
	esig, err := callwire.SignShare(d.ik, callwire.ShareMessage(callwire.RoleOffer, cid, media, ek))
	if err != nil {
		return nil, err
	}
	o, err := d.Op(ctx, "call.start", map[string]any{"connection_id": connectionID, "call_id": cid, "media": media, "sdp": sdp,
		"ek": ek, "ek_sig": esig})
	if err != nil {
		sk.Destroy()
		return nil, err
	}
	id, err := o.String("call_id")
	if err != nil || id != cid {
		sk.Destroy()
		return nil, ErrCall
	}
	ice, err := d.verifyICE(o, id)
	if err != nil {
		sk.Destroy()
		return nil, err
	}
	return &Call{ID: id, Conn: connectionID, ICE: ice, key: sk, Started: d.cfg.Now()}, nil
}

// IncomingCall checks a call.offer event from the vault (its ICE
// configuration signed by the vault).
func (d *Device) IncomingCall(ev *envelope.Inner) (*Call, error) {
	if ev.Type != "call.offer" {
		return nil, ErrCall
	}
	o, err := strictjson.ParseObject(ev.Body)
	if err != nil {
		return nil, ErrCall
	}
	id, err1 := o.String("call_id")
	conn, err2 := o.String("connection_id")
	if err1 != nil || err2 != nil {
		return nil, ErrCall
	}
	ice, err := d.verifyICE(o, id)
	if err != nil {
		return nil, err
	}
	media, _ := o.String("media")
	ek, err := o.Base64("ek", callwire.EKSize)
	if err != nil {
		return nil, ErrCall
	}
	if err := verifyPeerShare(o, callwire.ShareMessage(callwire.RoleOffer, id, media, ek)); err != nil {
		return nil, err
	}
	return &Call{ID: id, Conn: conn, ICE: ice, Offer: ev, Started: d.cfg.Now()}, nil
}

// CallAnswer answers an incoming call: it encapsulates to the caller's
// ek (the media key stays on this device) and sends call.answer.
func (d *Device) CallAnswer(ctx context.Context, c *Call, sdp string) error {
	o, err := strictjson.ParseObject(c.Offer.Body)
	if err != nil {
		return ErrCall
	}
	ek, err := o.Base64("ek", callwire.EKSize)
	if err != nil {
		return ErrCall
	}
	enc, k, err := callwire.Answer(ek, c.ID)
	if err != nil {
		return err
	}
	esig, err := callwire.SignShare(d.ik, callwire.ShareMessage(callwire.RoleAnswer, c.ID, "", enc))
	if err != nil {
		suite.Wipe(k)
		return err
	}
	body := strictjson.NewBuilder().String("call_id", c.ID).String("sdp", sdp).Base64("enc", enc).Base64("enc_sig", esig).Bytes()
	if _, err := d.Send(ctx, "call.answer", body); err != nil {
		suite.Wipe(k)
		return err
	}
	c.Key = k
	return nil
}

// CallAccept takes the callee's call.answer event and derives the media
// key on the calling device.
func (d *Device) CallAccept(c *Call, ev *envelope.Inner) (sdp string, err error) {
	o, err := strictjson.ParseObject(ev.Body)
	if err != nil {
		return "", ErrCall
	}
	if id, _ := o.String("call_id"); id != c.ID {
		return "", ErrCall
	}
	enc, err := o.Base64("enc", callwire.EncSize)
	if err != nil {
		return "", ErrCall
	}
	if err := verifyPeerShare(o, callwire.ShareMessage(callwire.RoleAnswer, c.ID, "", enc)); err != nil {
		return "", err
	}
	if c.Key, err = callwire.Accept(c.key, enc, c.ID); err != nil {
		return "", err
	}
	c.key.Destroy()
	c.key = nil
	sdp, _ = o.String("sdp")
	return sdp, nil
}

// CallICE trickles candidates (ephemeral, exp 30 s).
func (d *Device) CallICE(ctx context.Context, callID string, candidates []map[string]any) error {
	b, err := json.Marshal(map[string]any{"call_id": callID, "candidates": candidates})
	if err != nil {
		return err
	}
	_, err = d.SendExp(ctx, "call.ice", b, d.cfg.Now().Add(30*time.Second))
	return err
}

// CallRinging tells the caller this device is ringing (ephemeral).
func (d *Device) CallRinging(ctx context.Context, callID string) error {
	_, err := d.SendExp(ctx, "call.ringing", strictjson.NewBuilder().String("call_id", callID).Bytes(), d.cfg.Now().Add(30*time.Second))
	return err
}

// CallEnd hangs up, declines or reports busy or timeout.
func (d *Device) CallEnd(ctx context.Context, callID, reason string) error {
	_, err := d.Send(ctx, "call.end", strictjson.NewBuilder().String("call_id", callID).String("reason", reason).Bytes())
	return err
}

// SendExp is Send with an `exp` (ephemeral types, §8.5).
func (d *Device) SendExp(ctx context.Context, typ string, body json.RawMessage, exp time.Time) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sendFull(ctx, "", typ, body, "", "", exp)
}

// verifyPeerShare checks a share from the other side of a call: its
// device's signature and its vault's, under the connection's identity key
// (`peer_ik`, as this device's own vault has it on record, §10.10).
func verifyPeerShare(o strictjson.Object, m []byte) error {
	peer, e1 := o.Base64("peer_ik", ed25519.PublicKeySize)
	dev, e2 := o.Base64("device_ik", ed25519.PublicKeySize)
	ds, e3 := o.Base64("device_sig", ed25519.SignatureSize)
	vs, e4 := o.Base64("vault_sig", ed25519.SignatureSize)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil {
		return callwire.ErrShare
	}
	return callwire.VerifyShare(peer, dev, m, ds, vs)
}
