package client

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/suite"
)

// approvalVault answers the device's requests in the fake vault's mailbox:
// device.transfer.approve with the next code of codes ("" for ok),
// credential.get with {}; it records every message's type in arrival
// order.
type approvalVault struct {
	*fakeVault
	mu    sync.Mutex
	codes []string
	types []string
}

func (v *approvalVault) run(ctx context.Context) {
	for ctx.Err() == nil {
		now := time.Now()
		for _, m := range v.r.take(v.mailbox()) {
			env, err := envelope.Parse(m.Payload)
			if err != nil {
				continue
			}
			in, _, err := v.kr.Open(env, now)
			if err != nil || in.Re != "" {
				continue
			}
			v.mu.Lock()
			v.types = append(v.types, in.Type)
			code := ""
			if in.Type == "device.transfer.approve" && len(v.codes) > 0 {
				code, v.codes = v.codes[0], v.codes[1:]
			}
			v.mu.Unlock()
			if in.Type == "relay.token.issued" {
				continue // a notice: no answer
			}
			id, _ := envelope.NewULID(now)
			out := &envelope.Inner{ID: id, Type: in.Type, TS: now, Re: in.ID, Status: envelope.StatusOK, Body: []byte(`{}`)}
			if code != "" {
				out.Status, out.Error, out.Body = envelope.StatusError, &envelope.Error{Code: code}, nil
			}
			raw, err := v.kr.Current().Seal(out)
			if err == nil {
				v.r.put(v.dev.Mailbox, v.relayPK(), raw)
			}
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (v *approvalVault) got() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	return append([]string(nil), v.types...)
}

// VAULT-MESSAGING 0.55.10 §11.14.10 (owner decision 2026-10-23): before
// each approval it sends, the old app deposits relay.token.issued and has
// it answered 201 first: also the approval sent again after
// stale_credential, and each call after busy or retry. A renewal the relay
// refuses does not stop the approval.
func TestTransferApproveRenewsTokenFirst(t *testing.T) {
	r, fv, d := pair(t)
	d.mu.Lock()
	d.st.Credential = &CredentialCopy{Blob: []byte("blob"), Version: 1}
	for i := 0; i < 6; i++ {
		k, err := suite.GeneratePrivateKey()
		if err != nil {
			d.mu.Unlock()
			t.Fatal(err)
		}
		d.st.UTKs = append(d.st.UTKs, UTK{ID: "u" + string(rune('a'+i)), EK: k.Public().Bytes(), Expires: time.Now().Add(time.Hour)})
	}
	d.mu.Unlock()
	v := &approvalVault{fakeVault: fv, codes: []string{"stale_credential", "busy", "retry", "", ""}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	go v.run(ctx)

	if err := d.TransferApprove(ctx, "t1", "123456", "pw"); Code(err) != "busy" {
		t.Fatalf("first call: %v", err) // stale_credential, fetched, sent again: busy
	}
	if err := d.TransferApprove(ctx, "t1", "123456", "pw"); Code(err) != "retry" {
		t.Fatalf("second call: %v", err)
	}
	if err := d.TransferApprove(ctx, "t1", "123456", "pw"); err != nil {
		t.Fatalf("third call: %v", err)
	}
	want := []string{
		"relay.token.issued", "device.transfer.approve", // stale_credential
		"credential.get",
		"relay.token.issued", "device.transfer.approve", // busy
		"relay.token.issued", "device.transfer.approve", // retry
		"relay.token.issued", "device.transfer.approve", // ok
	}
	if got := v.got(); len(got) != len(want) {
		t.Fatalf("order %v, want %v", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("order %v, want %v", got, want)
			}
		}
	}

	// The relay refuses the renewal: the approval is still sent.
	before := len(v.got())
	r.mu.Lock()
	r.failDeposit, r.depositStatus = 1, http.StatusForbidden
	r.mu.Unlock()
	if err := d.TransferApprove(ctx, "t1", "123456", "pw"); err != nil {
		t.Fatalf("after a refused renewal: %v", err)
	}
	if got := v.got()[before:]; len(got) != 1 || got[0] != "device.transfer.approve" {
		t.Fatalf("after a refused renewal: %v", got)
	}
}
