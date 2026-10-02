package vms

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// libraryFiles returns the non-test Go files of the packages that ship
// (everything under vms/ except the vector generator).
func libraryFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == "vectors" || d.Name() == "testdata") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) < 10 {
		t.Fatalf("found only %d files", len(files))
	}
	return files
}

// calls returns every pkg.Func call expression in the library sources.
func calls(t *testing.T) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	fset := token.NewFileSet()
	for _, f := range libraryFiles(t) {
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(af, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if s, ok := c.Fun.(*ast.SelectorExpr); ok {
					if id, ok := s.X.(*ast.Ident); ok {
						name := id.Name + "." + s.Sel.Name
						out[name] = append(out[name], fset.Position(c.Pos()).String())
					}
				}
			}
			return true
		})
	}
	return out
}

// §13.6: tag and key comparisons MUST be constant-time. The library
// compares secret or key material only through crypto/subtle (suite.Equal,
// Kid.Equal, suite.EqualPublic, the AEADs); variable-time comparisons are
// banned from library code outright.
func TestNoVariableTimeComparisons(t *testing.T) {
	c := calls(t)
	for _, banned := range []string{"bytes.Equal", "bytes.Compare", "reflect.DeepEqual", "strings.EqualFold"} {
		for _, at := range c[banned] {
			// The only allowed use: ordering two public th1 values (§6.5).
			if banned == "bytes.Compare" && strings.Contains(at, "policy.go") {
				continue
			}
			t.Errorf("%s at %s", banned, at)
		}
	}
	if len(c["subtle.ConstantTimeCompare"]) == 0 {
		t.Fatal("no constant-time comparisons found")
	}
}

// §13.6: keys, PINs, tokens, signatures and plaintext MUST NOT appear in
// errors. Library errors are fixed sentinels: no formatted errors and no
// wrapping of input data.
func TestErrorsAreSentinels(t *testing.T) {
	c := calls(t)
	for _, banned := range []string{"fmt.Errorf", "fmt.Sprintf", "fmt.Sprint", "fmt.Println", "fmt.Printf", "log.Printf", "log.Println", "log.Print", "slog.Info", "slog.Error", "slog.Debug", "slog.Warn"} {
		for _, at := range c[banned] {
			// keyschedule.go formats the SAS digits (a value meant to be shown).
			if banned == "fmt.Sprintf" && strings.Contains(at, "keyschedule.go") {
				continue
			}
			t.Errorf("%s at %s", banned, at)
		}
	}
}
