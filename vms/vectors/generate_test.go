//go:build vmsvectors

package vectors

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

var update = flag.Bool("update", false, "rewrite testdata/vectors")

// TestVectorsUpToDate regenerates every vector through the library's
// sending code with scripted randomness and requires the checked-in files
// to match byte for byte. With -update it rewrites them.
func TestVectorsUpToDate(t *testing.T) {
	got, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(Files) {
		t.Fatalf("generated %d files, want %d", len(got), len(Files))
	}
	// Generation is deterministic.
	again, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range Files {
		if !bytes.Equal(got[name], again[name]) {
			t.Fatalf("%s: generation is not deterministic", name)
		}
	}
	if *update {
		if err := os.MkdirAll(Dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, name := range Files {
			if err := os.WriteFile(filepath.Join(Dir, name), got[name], 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	for _, name := range Files {
		want, err := os.ReadFile(filepath.Join(Dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got[name], want) {
			t.Errorf("%s differs from the generated vectors (run go generate ./vms/vectors)", name)
		}
	}
}
