package vectors

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ReleasesDir holds each published production release's frozen vectors,
// testdata/releases/<n>/ (VAULT-RELEASES §11.3, docs/RELEASING.md): a copy
// of testdata/vectors at the release's tag, committed when the release is
// published and kept while the release lives (until it is removed).
const ReleasesDir = "../../testdata/releases"

var releaseDirName = regexp.MustCompile(`^[1-9][0-9]*$`)

// frozenDirs lists the frozen vector directories: every
// testdata/releases/<n>/, plus any directories in
// VMS_FROZEN_VECTORS (colon-separated; scripts/compat-matrix.sh passes a
// previous ref's testdata/vectors this way).
func frozenDirs(t *testing.T) map[string]string {
	dirs := map[string]string{}
	ents, err := os.ReadDir(ReleasesDir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if !releaseDirName.MatchString(e.Name()) {
			t.Errorf("testdata/releases/%s: not a production release number", e.Name())
			continue
		}
		dirs[e.Name()] = filepath.Join(ReleasesDir, e.Name())
	}
	for _, d := range strings.Split(os.Getenv("VMS_FROZEN_VECTORS"), ":") {
		if d != "" {
			dirs["env:"+d] = d
		}
	}
	return dirs
}

// TestFrozenReleaseVectors checks every live release's frozen vectors
// with HEAD's code (the move-only contract, VAULT-RELEASES §3.4 C1-C2):
// the wire formats, keys, envelopes, handshake, invite, alternate-channel
// requests and the manifest of a published release must still be derived
// and accepted byte for byte. A frozen directory must hold every vector
// file of its release.
func TestFrozenReleaseVectors(t *testing.T) {
	dirs := frozenDirs(t)
	if len(dirs) == 0 {
		t.Skip("no frozen release vectors yet (testdata/releases is empty before release 1)")
	}
	for name, dir := range dirs {
		t.Run(name, func(t *testing.T) {
			for _, f := range Files {
				if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
					t.Fatalf("frozen vectors incomplete: %v", err)
				}
			}
			checkVectors(t, dir)
			checkReleaseVectors(t, dir)
		})
	}
}
