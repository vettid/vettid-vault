package vault

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// Every goroutine that runs vault code goes through Manager.Go (or
// Session.Go): a panic in a plain one would end the vault process with no
// log and no zeroize. The go statements left are counted per file, each
// one reviewed; a new one fails here until it is.
func TestNoPlainGoroutines(t *testing.T) {
	allowed := map[string]int{
		"vault/panic.go":        3, // Manager.Go itself, panicked's bounded zeroize, Session.Go without a manager (tests)
		"vault/attach_run.go":   1, // attWaitWrites' waiter: attWrites.Wait, no vault code
		"vault/relay.go":        1, // the stream reader of a relay not made through track (no goFn)
		"vault/push.go":         1, // newPusher without a goFn (tests)
		"features/calls/ice.go": 1, // Prime without a session (tests)
	}
	found := map[string]int{}
	for _, root := range []string{".", "../features"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			name := filepath.ToSlash(filepath.Join("vault", path))
			if root != "." {
				name = filepath.ToSlash(strings.TrimPrefix(path, "../"))
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if _, ok := n.(*ast.GoStmt); ok {
					found[name]++
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, n := range found {
		if n != allowed[name] {
			t.Errorf("%s: %d go statements, %d reviewed: run vault work through Manager.Go or Session.Go", name, n, allowed[name])
		}
	}
	for name, n := range allowed {
		if found[name] != n {
			t.Errorf("%s: %d go statements, %d listed: update the list", name, found[name], n)
		}
	}
}
