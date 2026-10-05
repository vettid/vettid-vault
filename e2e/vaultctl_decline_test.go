//go:build devenclave && e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/relaytest"
)

// VAULT-MESSAGING 0.10.5 through vaultctl, two vaults on the real relay:
// a declined connection request reaches the other member as peer_declined
// (the accepter also gets connection.event{failed, reason: declined}), in
// both directions; and a pairing rejected on the phone ends `vaultctl
// pair` on the new device with "rejected" instead of a 10-minute wait.
func TestVaultctlDecline(t *testing.T) {
	r := relaytest.Start(t, nil)
	dir := t.TempDir()
	bin := filepath.Join(dir, "vaultctl")
	if out, err := exec.Command("go", "build", "-tags", "devenclave", "-o", bin, "../cmd/vaultctl").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	runErr := func(state string, args ...string) (string, error) {
		var out bytes.Buffer
		cmd := exec.Command(bin, append([]string{"-state", state, "-timeout", "60s"}, args...)...)
		cmd.Stdout, cmd.Stderr = &out, &out
		err := cmd.Run()
		return out.String(), err
	}
	runAs := func(state string, args ...string) string {
		t.Helper()
		out, err := runErr(state, args...)
		if err != nil {
			t.Fatalf("vaultctl %v: %v\n%s", args, err, out)
		}
		return out
	}
	// poll collects events until marker appears and returns them.
	poll := func(state string, markers ...string) string {
		t.Helper()
		var all string
		for range 30 {
			all += runAs(state, "events", "-wait", "1s")
			ok := true
			for _, m := range markers {
				ok = ok && strings.Contains(all, m)
			}
			if ok {
				return all
			}
		}
		t.Fatalf("no %v in %s", markers, all)
		return ""
	}
	t.Setenv("VAULTCTL_PASSWORD", "correct horse battery staple")
	newVault := func(name string) string {
		t.Helper()
		app, store := filepath.Join(dir, name+".json"), filepath.Join(dir, name+"-store")
		runAs(app, "init", "-role", "app", "-name", name, "-relay", r.URL)
		vaultID := strings.TrimSpace(runAs(app, "vault-create", "-store", store, "-relay", r.URL, "-pin", "246802", "-app", app))
		ctx, cancel := context.WithCancel(context.Background())
		vr := exec.CommandContext(ctx, bin, "vault-run", "-store", store, "-vault-id", vaultID, "-pin", "246802")
		var vlog bytes.Buffer
		vr.Stdout, vr.Stderr = &vlog, &vlog
		if err := vr.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_ = vr.Process.Signal(os.Interrupt)
			done := make(chan struct{})
			go func() { _ = vr.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				cancel()
			}
			cancel()
			if t.Failed() {
				t.Logf("%s vault-run output:\n%s", name, vlog.String())
			}
		})
		runAs(app, "enroll-wait")
		runAs(app, "credential", "create")
		runAs(app, "request", "vault.enroll.confirm")
		return app
	}
	a, b := newVault("alice"), newVault("bob")

	// request runs an invitation from A to B until both see the SAS.
	request := func() (pid, cid string) {
		t.Helper()
		out := runAs(a, "request", "connection.invite.create", `{"ttl_seconds":600}`)
		link := between(out, `"link": "`, `"`)
		out = runAs(b, "request", "connection.invite.accept", `{"link":"`+link+`"}`)
		cid = between(out, `"connection_id": "`, `"`)
		poll(b, "connection.request.outgoing")
		out = poll(a, "connection.request.pending")
		return between(out, `"pending_id": "`, `"`), cid
	}

	// The inviter declines: the accepter sees peer_declined and failed.
	pid, cid := request()
	runAs(a, "request", "connection.decline", `{"pending_id":"`+pid+`"}`)
	out := poll(b, `"peer_declined"`, `"reason": "declined"`)
	if !strings.Contains(out, cid) {
		t.Fatalf("peer_declined for another request: %s", out)
	}

	// The accepter declines: the inviter sees peer_declined.
	pid, cid = request()
	runAs(b, "request", "connection.decline", `{"connection_id":"`+cid+`"}`)
	if out := poll(a, `"peer_declined"`); !strings.Contains(out, pid) {
		t.Fatalf("peer_declined for another request: %s", out)
	}
	if out := runAs(a, "request", "connection.request.list", `{}`); !strings.Contains(out, `"incoming": []`) {
		t.Fatalf("request list after peer_declined: %s", out)
	}

	// A pairing rejected on the phone ends `vaultctl pair` with "rejected".
	desk := filepath.Join(dir, "desk.json")
	runAs(desk, "init", "-role", "desktop", "-name", "laptop", "-relay", r.URL)
	out = runAs(a, "request", "device.pair.create", `{"role":"desktop"}`)
	link := between(out, `"link": "`, `"`)
	paired := make(chan string, 1)
	go func() {
		out, err := runErr(desk, "pair", "-link", link)
		paired <- fmt.Sprintf("%v: %s", err, out)
	}()
	out = poll(a, "device.pair.pending")
	runAs(a, "request", "device.pair.reject", `{"pairing_id":"`+between(out, `"pairing_id": "`, `"`)+`"}`)
	select {
	case res := <-paired:
		if strings.HasPrefix(res, "<nil>") || !strings.Contains(res, "rejected on your phone") {
			t.Fatalf("pair after a rejection: %s", res)
		}
	case <-time.After(45 * time.Second):
		t.Fatal("vaultctl pair kept waiting after the rejection")
	}
}
