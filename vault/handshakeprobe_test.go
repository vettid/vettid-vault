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
	probe := regexp.MustCompile(`Export\(\);\s*errors\.Is\([^)]*ErrDone`)
	files, _ := filepath.Glob("*.go")
	more, _ := filepath.Glob("../client/*.go")
	n := 0
	for _, f := range append(files, more...) {
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
