package main

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/vsock"
	"github.com/vettid/vettid-vault/parent"
)

func TestCapacityRequestFlags(t *testing.T) {
	c, err := capacityRequest(200, 1024, 0, "1, 2,4", 8, 150*time.Second, time.Minute, 90*time.Minute)
	if err != nil || c.MaxVaults != 200 || len(c.UnlockConcurrency) != 3 || c.UnlockConcurrency[1] != 2 || c.SettleSeconds != 150 ||
		c.IdleSeconds != 60 || c.BudgetMinutes != 90 {
		t.Fatalf("%v %+v", err, c)
	}
	for name, f := range map[string]func() error{
		"too many": func() error {
			_, err := capacityRequest(5000, 1024, 0, "1", 8, time.Minute, time.Minute, time.Hour)
			return err
		},
		"bad unlocks": func() error {
			_, err := capacityRequest(5, 1024, 0, "1,x", 8, time.Minute, time.Minute, time.Hour)
			return err
		},
		"level 16": func() error {
			_, err := capacityRequest(5, 1024, 0, "16", 8, time.Minute, time.Minute, time.Hour)
			return err
		},
		"no settle": func() error { _, err := capacityRequest(5, 1024, 0, "1", 8, 0, time.Minute, time.Hour); return err },
		"budget": func() error {
			_, err := capacityRequest(5, 1024, 0, "1", 8, time.Minute, time.Minute, 5*time.Hour)
			return err
		},
	} {
		if f() == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// vsockListener is a vsock listener for a test: its connections come from
// the context ids the test names.
type vsockListener struct {
	port  uint32
	conns chan net.Conn
	done  chan struct{}
}

func (l *vsockListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}
func (l *vsockListener) Close() error   { close(l.done); return nil }
func (l *vsockListener) Addr() net.Addr { return vsock.Addr{CID: vsock.CIDAny, Port: l.port} }

type vsockConn struct {
	net.Conn
	cid uint32
}

func (c vsockConn) RemoteAddr() net.Addr { return vsock.Addr{CID: c.cid, Port: 40000} }

// accepting returns the connections l accepts.
func accepting(l net.Listener) chan net.Conn {
	got := make(chan net.Conn)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			got <- c
		}
	}()
	return got
}

// answered reports whether a connection from context id cid is handed on
// by the listener that listen returned (got) or closed unanswered.
func answered(t *testing.T, raw *vsockListener, got chan net.Conn, cid uint32) bool {
	t.Helper()
	mine, theirs := net.Pipe()
	defer mine.Close()
	raw.conns <- vsockConn{theirs, cid}
	closed := make(chan error, 1)
	go func() { _, err := mine.Read(make([]byte, 1)); closed <- err }()
	select {
	case c := <-got:
		c.Close()
		return true
	case err := <-closed:
		if err != io.EOF {
			t.Fatalf("a connection from context id %d: %v", cid, err)
		}
		return false
	case <-time.After(5 * time.Second):
		t.Fatalf("a connection from context id %d was neither accepted nor closed", cid)
		return false
	}
}

// Both of the parent's listeners answer only the context id given by
// -enclave-cid, on the port asked for; and a context id that is not an
// enclave's is refused as configuration.
func TestListenersAnswerOnlyTheEnclaveCID(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, channel := range []string{"control", "egress"} {
		for _, cid := range []uint{parent.DefaultEnclaveCID, 21} {
			var raw *vsockListener
			l, err := listen("", 5000, cid, channel, log, func(port uint32) (net.Listener, error) {
				raw = &vsockListener{port: port, conns: make(chan net.Conn), done: make(chan struct{})}
				return raw, nil
			})
			if err != nil || raw == nil || raw.port != 5000 {
				t.Fatalf("%s, -enclave-cid %d: %v", channel, cid, err)
			}
			acc := accepting(l)
			for _, peer := range []uint32{uint32(cid), 3, 1, 16, 21, 22} {
				if got, want := answered(t, raw, acc, peer), peer == uint32(cid); got != want {
					t.Errorf("%s, -enclave-cid %d: a peer with context id %d answered: %v", channel, cid, peer, got)
				}
			}
			l.Close()
		}
	}
	for _, cid := range []uint{0, 1, 2, 3, vsock.CIDAny, 1 << 33} {
		called := false
		if l, err := listen("", 5000, cid, "control", log, func(uint32) (net.Listener, error) { called = true; return nil, errors.New("x") }); err == nil || l != nil || called {
			t.Errorf("-enclave-cid %d accepted", cid)
		}
	}
	// Development: TCP, loopback.
	l, err := listen("127.0.0.1:0", 0, parent.DefaultEnclaveCID, "control", log, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if a, err := l.Accept(); err != nil {
		t.Fatalf("loopback TCP peer: %v", err)
	} else {
		a.Close()
	}
}

// The flag's default is the context id the host runs the enclave with.
func TestEnclaveCIDFlagDefault(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), `flag.Uint("enclave-cid", parent.DefaultEnclaveCID,`); n != 1 {
		t.Fatalf("-enclave-cid does not default to parent.DefaultEnclaveCID (%d)", n)
	}
	// Each listener is made by listen with the flag's value.
	for _, call := range []string{`listen(*controlTCP, *controlPort, *enclaveCID, "control", log, listenVsock)`, `listen(*egressTCP, *egressPort, *enclaveCID, "egress", log, listenVsock)`} {
		if !strings.Contains(string(src), call) {
			t.Errorf("main does not make a listener with %s", call)
		}
	}
	if strings.Contains(string(src), "vsock.Listen(") && strings.Count(string(src), "vsock.Listen(") != 1 {
		t.Error("a vsock listener is opened outside listenVsock")
	}
}
