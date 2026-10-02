package enclave_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-relay/relayauth"
	"github.com/vettid/vettid-relay/relayclient"

	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/enclave"
	"github.com/vettid/vettid-vault/internal/enclavetest"
	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/suite"
)

const relayURL = "https://relay.test.vettid.org"

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

var (
	r3 = enclavetest.ReleaseSpec{Number: 3, PCR0: 0xa3, PCR1: 0x13, PCR2: 0x23, Status: "active"}
	r4 = enclavetest.ReleaseSpec{Number: 4, PCR0: 0xa4, PCR1: 0x14, PCR2: 0x24, Status: "active"}
	r5 = enclavetest.ReleaseSpec{Number: 5, PCR0: 0xa5, PCR1: 0x15, PCR2: 0x25, Status: "active"}
)

type fx struct {
	// served overrides the manifest the app sends (stale-manifest tests).
	served []byte
	t      *testing.T
	clk    *clock
	w      *enclavetest.World
	ctx    context.Context
	trust  client.Trust
}

func newFx(t *testing.T) *fx {
	t.Helper()
	clk := &clock{t: time.Now().UTC().Truncate(time.Millisecond)}
	w := enclavetest.NewWorld(clk.Now, relayURL)
	w.AddRelease(r3)
	if _, err := w.Start(3); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return &fx{t: t, clk: clk, w: w, ctx: context.Background(), trust: w.Trust()}
}

type app struct {
	dev  *client.Device
	att  client.Attester
	guid string
	vid  string
}

func (f *fx) newApp(guid string, att client.Attester) *app {
	f.t.Helper()
	d, err := client.Generate(client.Config{Role: "app", Name: "phone", RelayURL: relayURL, Now: f.clk.Now, Trust: &f.trust})
	if err != nil {
		f.t.Fatal(err)
	}
	return &app{dev: d, att: att, guid: guid}
}

// enclaveFor plays GET /api/vault/enclave and verifies the answer.
func (f *fx) enclaveFor(a *app, release string, enroll bool) (*client.Enclave, *enclave.Instance) {
	f.t.Helper()
	desc, att, in, err := f.w.Enclave(a.vid, release)
	if err != nil {
		f.t.Fatal(err)
	}
	_, m, err := a.dev.VerifyManifest(f.w.Served(), f.trust)
	if err != nil {
		f.t.Fatal(err)
	}
	e, err := client.VerifyEnclave(desc, att, m, enroll, f.trust, f.clk.Now())
	if err != nil {
		f.t.Fatalf("verify enclave: %v", err)
	}
	return e, in
}

func newVaultID() string {
	b, _ := suite.RandomBytes(16)
	const hx = "0123456789abcdef"
	out := make([]byte, 32)
	for i, c := range b {
		out[2*i], out[2*i+1] = hx[c>>4], hx[c&15]
	}
	return string(out)
}

// enroll runs §11.3 up to vault.enrolled (the first-app handshake needs a
// real relay and is covered end to end).
func (f *fx) enroll(a *app, pin string) *altchan.EnrollResult {
	f.t.Helper()
	e, in := f.enclaveFor(a, "", true)
	served, _, _ := a.dev.VerifyManifest(f.w.Served(), f.trust)
	req, err := a.dev.BuildEnroll(a.guid, pin, e, served, a.att)
	if err != nil {
		f.t.Fatal(err)
	}
	vid := newVaultID()
	resp, err := f.w.Post(f.ctx, in, enclave.OpEnroll, vid, a.guid, req)
	if err != nil {
		f.t.Fatal(err)
	}
	if len(resp.Envelope) != altchan.ResultEnvelopeSize {
		f.t.Fatalf("result size %d", len(resp.Envelope))
	}
	r, err := a.dev.OpenEnrollResult(resp.Envelope, req.RequestID)
	if err != nil {
		f.t.Fatal(err)
	}
	if r.OK {
		a.vid = vid
		f.deliver(a)
		if a.dev.VaultID() != vid {
			f.t.Fatal("vault.enrolled not accepted")
		}
	}
	return r
}

// deliver hands the app every deposit made into its mailbox.
func (f *fx) deliver(a *app) {
	ra := a.dev.RelayAddr()
	for i, d := range f.w.Relays.DepositsTo(ra.Mailbox) {
		a.dev.Deliver(f.ctx, relayclient.Message{MsgID: "d" + string(rune('a'+i)), Payload: d.Payload, Sender: f.senderOf(d)})
	}
}

// senderOf is the collect sender: the depositing vault's relay key.
func (f *fx) senderOf(d enclavetest.Deposit) string { return relayauth.EncodeKey(d.Sender) }

// unlock runs §11.4 against the vault's routed instance.
func (f *fx) unlock(a *app, pin string, o client.UnlockOptions, release string) (*altchan.UnlockResult, error) {
	f.t.Helper()
	e, in := f.enclaveFor(a, release, false)
	doc := f.w.Served()
	if f.served != nil {
		doc, f.served = f.served, nil
	}
	served, m, err := a.dev.VerifyManifest(doc, f.trust)
	if err != nil {
		return nil, err
	}
	req, err := a.dev.BuildUnlock(a.guid, pin, e, served, m, a.att, o)
	if err != nil {
		return nil, err
	}
	resp, err := f.w.Post(f.ctx, in, enclave.OpUnlock, a.vid, a.guid, req)
	if err != nil {
		f.t.Fatal(err)
	}
	if resp.Status != enclave.StatusDone || len(resp.Envelope) != altchan.ResultEnvelopeSize {
		f.t.Fatalf("response %s %d", resp.Status, len(resp.Envelope))
	}
	return a.dev.OpenUnlockResult(resp.Envelope)
}

func (f *fx) mustUnlock(a *app, pin string, o client.UnlockOptions, release string) *altchan.UnlockResult {
	f.t.Helper()
	r, err := f.unlock(a, pin, o, release)
	if err != nil {
		f.t.Fatal(err)
	}
	return r
}

func android(seed byte) client.Attester {
	return enclavetest.NewAndroidAttester(seed, enclavetest.AndroidOptions{})
}

func ios(seed byte) client.Attester {
	return enclavetest.NewIOSAttester(seed, enclavetest.IOSOptions{})
}
