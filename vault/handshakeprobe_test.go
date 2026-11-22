package vault

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// No caller asks whether a handshake ended by exporting it: Export marshals
// the hs.init body (an app's carries the app key and the unlock secret)
// and the copy would be dropped unwiped; Initiator.Done says it.
func TestNoExportAsDoneProbe(t *testing.T) {
	// Either form: errors.Is(xerr, …ErrDone) or xerr == …ErrDone.
	probe := regexp.MustCompile(`Export\(\);\s*(errors\.Is\([^)]*ErrDone|[A-Za-z_]\w*\s*==\s*[\w.]*ErrDone)`)
	for _, form := range []string{
		"if _, xerr := ini.Export(); errors.Is(xerr, handshake.ErrDone) {",
		"if _, err := ini.Export(); err == handshake.ErrDone {",
		"if _, err := d.ini.Export(); err == ErrDone {",
	} {
		if !probe.MatchString(form) {
			t.Fatalf("the probe misses %q", form)
		}
	}
	files, _ := filepath.Glob("*.go")
	more, _ := filepath.Glob("../client/*.go")
	n := 0
	for _, f := range append(files, more...) {
		if f == "handshakeprobe_test.go" { // its own samples, above
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		n++
		if probe.Match(src) {
			t.Errorf("%s asks Export whether a handshake is done", f)
		}
	}
	if n < 20 {
		t.Fatalf("only %d files read", n)
	}
}
