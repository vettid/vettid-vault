package client

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

// answer is how the stand-in vault answers one request type: a response
// (ok or an error code) and the events it sends after it.
type answer struct {
	body   func(req strictjson.Object) []byte
	code   string // an error response with this code instead of ok
	events func(req strictjson.Object) []struct {
		typ  string
		body []byte
	}
}

// answeringWith runs the stand-in vault in the background, answering each
// request type as answers says, until the test ends.
func answeringWith(t *testing.T, v *fakeVault, answers map[string]answer) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Add(1)
	t.Cleanup(func() { cancel(); wg.Wait() })
	go func() {
		defer wg.Done()
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
				a, ok := answers[in.Type]
				if !ok {
					continue
				}
				req, _ := strictjson.ParseObject(in.Body)
				id, _ := envelope.NewULID(now)
				resp := &envelope.Inner{ID: id, Type: in.Type, TS: now, Re: in.ID, Status: envelope.StatusOK, Body: []byte(`{}`)}
				if a.code != "" {
					resp.Status, resp.Error = envelope.StatusError, &envelope.Error{Code: a.code}
					resp.Body = []byte(`{"detail":"refused"}`)
				} else if a.body != nil {
					resp.Body = a.body(req)
				}
				if raw, err := v.kr.Current().Seal(resp); err == nil {
					v.r.put(v.dev.Mailbox, v.relayPK(), raw)
				}
				if a.events != nil {
					for _, e := range a.events(req) {
						v.send(e.typ, e.body)
					}
				}
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()
}

// watchDrops records the messages the client wipes as it drops them, and
// the parses it wipes, until the test ends.
func watchDrops(t *testing.T) (drops *[]*envelope.Inner, parses *[]strictjson.Object) {
	t.Helper()
	var mu sync.Mutex
	var ds []*envelope.Inner
	var ps []strictjson.Object
	testDropHook = func(in *envelope.Inner) { mu.Lock(); ds = append(ds, in); mu.Unlock() }
	testParsedHook = func(o strictjson.Object) { mu.Lock(); ps = append(ps, o); mu.Unlock() }
	t.Cleanup(func() { testDropHook, testParsedHook = nil, nil })
	return &ds, &ps
}

const respSecret = "s3cret-item-value"

// droppedWith reports how many dropped messages of typ were wiped, and fails
// if one was not.
func droppedWith(t *testing.T, drops []*envelope.Inner, typ string) int {
	t.Helper()
	n := 0
	for _, in := range drops {
		if in.Type != typ {
			continue
		}
		if !wiped(in.Body) {
			t.Fatalf("a dropped %s kept its body", typ)
		}
		n++
	}
	return n
}

func allWiped(t *testing.T, ps []strictjson.Object) {
	t.Helper()
	for _, o := range ps {
		for k, v := range o {
			if !wiped(v) {
				t.Fatalf("member %q of a parse kept its value", k)
			}
		}
	}
}

// Op returns the caller's own copy of the response body and wipes the
// response; a refusal's OpError keeps its own copy of the body.
func TestOpWipesTheResponse(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	answeringWith(t, v, map[string]answer{
		"item.get":    {body: func(strictjson.Object) []byte { return []byte(`{"value":"` + respSecret + `"}`) }},
		"item.delete": {code: "not_found"},
	})
	drops, _ := watchDrops(t)
	o, err := d.Op(ctx, "item.get", map[string]any{"id": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := o.String("value"); s != respSecret {
		t.Fatalf("the returned body was changed: %q", s)
	}
	if n := droppedWith(t, *drops, "item.get"); n != 1 {
		t.Fatalf("%d wiped item.get responses, want 1", n)
	}
	_, err = d.Op(ctx, "item.delete", map[string]any{"id": "x"})
	var oe *OpError
	if !errors.As(err, &oe) || oe.Code != "not_found" || string(oe.Body) != `{"detail":"refused"}` {
		t.Fatalf("err = %v (body %q)", err, func() []byte {
			if oe != nil {
				return oe.Body
			}
			return nil
		}())
	}
	if n := droppedWith(t, *drops, "item.delete"); n != 1 {
		t.Fatalf("%d wiped item.delete responses, want 1", n)
	}
}

// The waits for an event (ActionResult, a location wait, GrantCatalog,
// GrantFetch's error result) wipe the event they take and every parse
// their predicates make; what they return is the caller's and intact.
func TestEventWaitsWipe(t *testing.T) {
	ctx := context.Background()
	t.Run("ActionResult", func(t *testing.T) {
		_, v, d := pair(t)
		drops, parses := watchDrops(t)
		v.send("action.result", []byte(`{"invocation_id":"other","out":"`+respSecret+`"}`))
		v.send("action.result", []byte(`{"invocation_id":"inv-1","out":"`+respSecret+`"}`))
		o, err := d.ActionResult(ctx, "inv-1")
		if err != nil {
			t.Fatal(err)
		}
		if s, _ := o.String("out"); s != respSecret {
			t.Fatalf("the returned body was changed: %q", s)
		}
		if n := droppedWith(t, *drops, "action.result"); n != 1 {
			t.Fatalf("%d wiped action.result, want 1", n)
		}
		if len(*parses) < 2 {
			t.Fatalf("%d predicate parses wiped, want at least 2", len(*parses))
		}
		allWiped(t, *parses)
	})
	t.Run("LocationEvent", func(t *testing.T) {
		_, v, d := pair(t)
		drops, parses := watchDrops(t)
		v.send("location.event", []byte(`{"connection_id":"c1","event":"started","at":"`+respSecret+`"}`))
		o, err := d.LocationEvent(ctx, "c1", "started")
		if err != nil {
			t.Fatal(err)
		}
		if s, _ := o.String("at"); s != respSecret {
			t.Fatalf("the returned body was changed: %q", s)
		}
		if n := droppedWith(t, *drops, "location.event"); n != 1 {
			t.Fatalf("%d wiped location.event, want 1", n)
		}
		if len(*parses) == 0 {
			t.Fatal("the predicate's parse was not wiped")
		}
		allWiped(t, *parses)
	})
	t.Run("GrantCatalog", func(t *testing.T) {
		_, v, d := pair(t)
		answeringWith(t, v, map[string]answer{"grant.catalog": {
			body: func(strictjson.Object) []byte { return []byte(`{"request_id":"r1"}`) },
			events: func(strictjson.Object) []struct {
				typ  string
				body []byte
			} {
				return []struct {
					typ  string
					body []byte
				}{{"grant.catalog.result", []byte(`{"request_id":"r1","items":["` + respSecret + `"]}`)}}
			},
		}})
		drops, parses := watchDrops(t)
		items, err := d.GrantCatalog(ctx, "c1")
		if err != nil {
			t.Fatal(err)
		}
		if string(items) != `["`+respSecret+`"]` {
			t.Fatalf("the returned items were changed: %q", items)
		}
		if droppedWith(t, *drops, "grant.catalog") != 1 || droppedWith(t, *drops, "grant.catalog.result") != 1 {
			t.Fatal("the response and the event were not both wiped")
		}
		allWiped(t, *parses)
	})
	t.Run("GrantFetch error result", func(t *testing.T) {
		_, v, d := pair(t)
		answeringWith(t, v, map[string]answer{"grant.fetch": {
			body: func(strictjson.Object) []byte { return []byte(`{"fetch_id":"f1"}`) },
			events: func(strictjson.Object) []struct {
				typ  string
				body []byte
			} {
				return []struct {
					typ  string
					body []byte
				}{{"grant.value", []byte(`{"fetch_id":"f1","error":"denied","retry_after":5,"x":"` + respSecret + `"}`)}}
			},
		}})
		drops, parses := watchDrops(t)
		res, err := d.GrantFetch(ctx, "g1")
		if err != nil {
			t.Fatal(err)
		}
		if res.Error != "denied" || res.RetryAfter != 5 {
			t.Fatalf("result %+v", res)
		}
		if droppedWith(t, *drops, "grant.value") != 1 {
			t.Fatal("the grant.value event was not wiped")
		}
		n := 0
		for _, o := range *parses {
			if o.Has("fetch_id") && o.Has("x") {
				n++
			}
		}
		if n < 2 { // the predicate's and the result's parse
			t.Fatalf("%d wiped parses of the grant.value body, want 2", n)
		}
		allWiped(t, *parses)
	})
}

// stmtLists are the nodes that hold a statement list.
func stmtList(n ast.Node) []ast.Stmt {
	switch x := n.(type) {
	case *ast.BlockStmt:
		return x.List
	case *ast.CaseClause:
		return x.Body
	case *ast.CommClause:
		return x.Body
	}
	return nil
}

// No client function drops a parsed response or event body unwiped.
//
// A parsed body is the first result of any function in client or
// client/wallet whose first result is a strictjson.Object, of takeObject,
// or of a ParseObject of a message's body. Each assignment of one, on its
// own:
//   - is wiped (wipeParsed or Object.Wipe, deferred or not) after it in its
//     block or an enclosing one, or by a deferred closure in an enclosing
//     block (which wipes whatever the variable ends with); or
//   - is handed on (returned, or a slice of it returned), and then every
//     return after it hands it on too, or is the error check right after
//     it, or follows a wipe of it in its block.
//
// A plain (not deferred) wipe covers only if no return comes between the
// assignment and it, apart from the `if err != nil` right after it. A value
// handed on must not also be wiped (use after wipe), and in a function that
// wipes it, no slice of it (v[...], v.OptObjectRaw, a variable taken from
// one, a no-copy conversion) is returned, stored outside the function, sent,
// or captured by a closure. A parsed body is never discarded with _, nor
// passed straight to anything but dropOp.
//
// It matches variables by name, not by declaration (go/types), so it does
// not see a shadowed name, `var x = d.Op(...)`, a Device reached under
// another name than d, or the *Response and *envelope.Inner that Request,
// AwaitResponse and WaitEvent return. Nor does it see a slice of a wiped
// value that leaves inside a composite literal, or through a helper or
// append that does not copy it.
func TestNoUnwipedResponseParse(t *testing.T) {
	type file struct {
		name string
		src  []byte
		af   *ast.File
	}
	fset := token.NewFileSet()
	var files []file
	for _, pat := range []string{"*.go", "wallet/*.go"} {
		names, err := filepath.Glob(pat)
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range names {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			af, err := parser.ParseFile(fset, f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, file{f, src, af})
		}
	}
	if len(files) < 20 {
		t.Fatalf("found only %d files", len(files))
	}
	// The sources, by their first result's type.
	sources := map[string]bool{"takeObject": true}
	for _, f := range files {
		for _, d := range f.af.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Type.Results == nil || len(fd.Type.Results.List) == 0 {
				continue
			}
			if sel, ok := fd.Type.Results.List[0].Type.(*ast.SelectorExpr); ok && sel.Sel.Name == "Object" {
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == "strictjson" {
					sources[fd.Name.Name] = true
				}
			}
		}
	}
	for _, must := range []string{"Op", "credOp", "credOpWith", "credOpBefore", "sealedOp", "sealedWith", "criticalApprove", "LeashItemSet"} {
		if !sources[must] {
			t.Fatalf("%s is not found as a source: the type scan is broken", must)
		}
	}
	var bad []string
	for _, f := range files {
		text := func(e ast.Node) string {
			return string(f.src[fset.Position(e.Pos()).Offset:fset.Position(e.End()).Offset])
		}
		isSource := func(e ast.Expr) bool {
			call, ok := e.(*ast.CallExpr)
			if !ok {
				return false
			}
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				if fn.Sel.Name == "ParseObject" && len(call.Args) == 1 {
					a := text(call.Args[0])
					return a == "r.Body()" || strings.HasSuffix(a, ".Body")
				}
				// a Device method (every receiver is d) or a client function
				x, ok := fn.X.(*ast.Ident)
				return ok && (x.Name == "d" || x.Name == "client") && sources[fn.Sel.Name]
			case *ast.Ident:
				return sources[fn.Name]
			}
			return false
		}
		// wipeOf reports whether stmt wipes v: wipeParsed(v) or v.Wipe(),
		// deferred or not; closure reports a deferred closure that does.
		wipeOf := func(stmt ast.Stmt, v string) (direct, deferred, closure bool) {
			var call *ast.CallExpr
			switch x := stmt.(type) {
			case *ast.ExprStmt:
				call, _ = x.X.(*ast.CallExpr)
			case *ast.DeferStmt:
				call = x.Call
				if lit, ok := call.Fun.(*ast.FuncLit); ok {
					found := false
					ast.Inspect(lit.Body, func(n ast.Node) bool {
						if c, ok := n.(*ast.CallExpr); ok && isWipe(c, v) {
							found = true
						}
						return true
					})
					return false, false, found
				}
				return isWipe(call, v), true, false
			}
			return call != nil && isWipe(call, v), false, false
		}
		// escapes flags, in a function that wipes v, a slice of v (v[...],
		// v.OptObjectRaw, or a variable taken from one) that leaves the
		// function: returned, converted without a copy, stored outside it,
		// sent, or captured by a closure other than the wipe's own.
		escapes := func(body *ast.BlockStmt, v string, from token.Pos) {
			aliases := map[string]bool{v: true}
			isSlice := func(e ast.Expr) bool {
				switch x := e.(type) {
				case *ast.IndexExpr:
					id, ok := x.X.(*ast.Ident)
					return ok && id.Name == v
				case *ast.CallExpr:
					if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "OptObjectRaw" {
						id, ok := sel.X.(*ast.Ident)
						return ok && id.Name == v
					}
				}
				return false
			}
			ast.Inspect(body, func(n ast.Node) bool {
				if as, ok := n.(*ast.AssignStmt); ok && len(as.Rhs) == 1 && isSlice(as.Rhs[0]) {
					if id, ok := as.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
						aliases[id.Name] = true
					}
				}
				return true
			})
			// carries reports whether e hands out v's bytes: an alias, a
			// slice of v, or a no-copy conversion of one.
			var carries func(e ast.Expr) bool
			carries = func(e ast.Expr) bool {
				switch x := e.(type) {
				case *ast.Ident:
					return aliases[x.Name] && x.Name != v
				case *ast.ParenExpr:
					return carries(x.X)
				case *ast.CallExpr:
					if f := text(x.Fun); (f == "json.RawMessage" || f == "[]byte") && len(x.Args) == 1 {
						return carries(x.Args[0])
					}
				}
				return isSlice(e)
			}
			// locals are the names the function declares (:= or var);
			// assigning to any other name stores outside it.
			locals := map[string]bool{}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.AssignStmt:
					if x.Tok == token.DEFINE {
						for _, l := range x.Lhs {
							if id, ok := l.(*ast.Ident); ok {
								locals[id.Name] = true
							}
						}
					}
				case *ast.ValueSpec:
					for _, id := range x.Names {
						locals[id.Name] = true
					}
				}
				return true
			})
			flag := func(n ast.Node, how string) {
				bad = append(bad, fset.Position(n.Pos()).String()+": a slice of "+v+", which is wiped, "+how)
			}
			ast.Inspect(body, func(n ast.Node) bool {
				if n == nil || n.Pos() < from {
					return true
				}
				switch x := n.(type) {
				case *ast.ReturnStmt:
					for _, r := range x.Results {
						if carries(r) {
							flag(r, "is returned")
						}
					}
				case *ast.AssignStmt:
					for i, l := range x.Lhs {
						id, isID := l.(*ast.Ident)
						if (!isID || !locals[id.Name]) && i < len(x.Rhs) && carries(x.Rhs[i]) {
							flag(x, "is stored outside the function")
						}
					}
				case *ast.SendStmt:
					if carries(x.Value) {
						flag(x, "is sent")
					}
				case *ast.FuncLit:
					wipesV := false
					uses := false
					ast.Inspect(x.Body, func(m ast.Node) bool {
						if c, ok := m.(*ast.CallExpr); ok && isWipe(c, v) {
							wipesV = true
						}
						if id, ok := m.(*ast.Ident); ok && aliases[id.Name] {
							uses = true
						}
						return true
					})
					if uses && !wipesV {
						flag(x, "is captured by a closure")
					}
					return false
				}
				return true
			})
		}
		checkFunc := func(body *ast.BlockStmt, where string) {
			if body == nil {
				return
			}
			parent := map[ast.Node]ast.Node{}
			var stack []ast.Node
			ast.Inspect(body, func(n ast.Node) bool {
				if n == nil {
					stack = stack[:len(stack)-1]
					return false
				}
				if _, ok := n.(*ast.FuncLit); ok && len(stack) > 0 {
					return false // its own function
				}
				if len(stack) > 0 {
					parent[n] = stack[len(stack)-1]
				}
				stack = append(stack, n)
				return true
			})
			// holders returns the statement lists enclosing n, innermost
			// first, with the index of the statement that contains n.
			type at struct {
				list []ast.Stmt
				idx  int
			}
			holders := func(n ast.Node) []at {
				var out []at
				for c := n; c != nil; c = parent[c] {
					p := parent[c]
					if p == nil {
						break
					}
					for i, s := range stmtList(p) {
						if s == c {
							out = append(out, at{stmtList(p), i})
						}
					}
				}
				return out
			}
			var returns []*ast.ReturnStmt
			ast.Inspect(body, func(n ast.Node) bool {
				if _, ok := n.(*ast.FuncLit); ok {
					return false
				}
				if r, ok := n.(*ast.ReturnStmt); ok {
					returns = append(returns, r)
				}
				return true
			})
			handsOn := func(r *ast.ReturnStmt, v string) bool {
				for _, e := range r.Results {
					switch x := e.(type) {
					case *ast.Ident:
						if x.Name == v {
							return true
						}
					case *ast.IndexExpr:
						if id, ok := x.X.(*ast.Ident); ok && id.Name == v {
							return true
						}
					}
				}
				return false
			}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.FuncLit:
					return false
				case *ast.ExprStmt:
					if isSource(x.X) {
						bad = append(bad, fset.Position(x.Pos()).String()+": "+where+" discards a parsed body")
					}
				case *ast.CallExpr:
					for _, arg := range x.Args {
						if isSource(arg) {
							if fn, ok := x.Fun.(*ast.Ident); !ok || fn.Name != "dropOp" {
								bad = append(bad, fset.Position(x.Pos()).String()+": "+where+" passes a parsed body straight on")
							}
						}
					}
				case *ast.AssignStmt:
					if len(x.Rhs) != 1 || !isSource(x.Rhs[0]) {
						return true
					}
					id, ok := x.Lhs[0].(*ast.Ident)
					if !ok || id.Name == "_" {
						bad = append(bad, fset.Position(x.Pos()).String()+": "+where+" discards a parsed body")
						return true
					}
					v, pos := id.Name, x.Pos()
					wiped, closure := false, false
					hs := holders(x)
					// an if/switch initialiser: the statement's own body counts
					if ifs, ok := parent[x].(*ast.IfStmt); ok && ifs.Init == x {
						hs = append([]at{{ifs.Body.List, -1}}, holders(ifs)...)
					}
					// errCheck is the `if err != nil` right after x, whose
					// returns drop nothing (the source failed).
					var errCheck ast.Stmt
					if h := holders(x); len(h) > 0 && h[0].idx+1 < len(h[0].list) {
						if ifs, ok := h[0].list[h[0].idx+1].(*ast.IfStmt); ok && text(ifs.Cond) == "err != nil" {
							errCheck = ifs
						}
					}
					returnBetween := func(from, to token.Pos) bool {
						for _, r := range returns {
							if r.Pos() > from && r.Pos() < to && (errCheck == nil || r.Pos() < errCheck.Pos() || r.End() > errCheck.End()) {
								return true
							}
						}
						return false
					}
					for _, h := range hs {
						for k, s := range h.list {
							d, deferred, c := wipeOf(s, v)
							if c {
								closure = true
							}
							// a deferred wipe covers every later path; a plain
							// one only if no path returns before it
							if d && k > h.idx && (deferred || !returnBetween(x.End(), s.Pos())) {
								wiped = true
							}
						}
					}
					if wiped || closure {
						escapes(body, v, x.Pos())
					}
					handed := false
					for _, r := range returns {
						if r.Pos() > pos && handsOn(r, v) {
							handed = true
						}
					}
					switch {
					case handed && (wiped || closure):
						bad = append(bad, fset.Position(pos).String()+": "+where+" hands "+v+" on and wipes it (use after wipe)")
					case wiped || closure:
					case handed:
						// every later return hands it on, is the error check
						// right after it, or follows a wipe of it
						var next ast.Stmt
						if h := holders(x); len(h) > 0 && h[0].idx+1 < len(h[0].list) {
							next = h[0].list[h[0].idx+1]
						}
						for _, r := range returns {
							if r.Pos() < pos || handsOn(r, v) {
								continue
							}
							if next != nil && r.Pos() >= next.Pos() && r.End() <= next.End() {
								if ifs, ok := next.(*ast.IfStmt); ok && text(ifs.Cond) == "err != nil" {
									continue
								}
							}
							ok := false
							if h := holders(r); len(h) > 0 {
								for k := 0; k < h[0].idx; k++ {
									if d, _, _ := wipeOf(h[0].list[k], v); d && h[0].list[k].Pos() > pos {
										ok = true
									}
								}
							}
							if !ok {
								bad = append(bad, fset.Position(r.Pos()).String()+": "+where+" returns without handing on or wiping "+v)
							}
						}
					default:
						bad = append(bad, fset.Position(pos).String()+": "+where+" neither hands on nor wipes "+v)
					}
				}
				return true
			})
		}
		ast.Inspect(f.af, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				checkFunc(x.Body, x.Name.Name)
			case *ast.FuncLit:
				checkFunc(x.Body, "a func literal")
			case *ast.KeyValueExpr:
				if k, ok := x.Key.(*ast.Ident); ok && k.Name == "Body" && text(x.Value) == "r.Body()" {
					bad = append(bad, fset.Position(x.Pos()).String()+": Body: r.Body() keeps the response's bytes")
				}
			}
			return true
		})
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// isWipe reports whether call wipes v: wipeParsed(v) or v.Wipe().
func isWipe(call *ast.CallExpr, v string) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		if fn.Name == "wipeParsed" && len(call.Args) == 1 {
			id, ok := call.Args[0].(*ast.Ident)
			return ok && id.Name == v
		}
	case *ast.SelectorExpr:
		id, ok := fn.X.(*ast.Ident)
		return ok && id.Name == v && fn.Sel.Name == "Wipe"
	}
	return false
}

// dropOp wipes the parsed body, destroys the reply key, and passes the
// error on.
func TestDropOp(t *testing.T) {
	rk, err := suite.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	o, err := strictjson.ParseObject([]byte(`{"secret":"` + respSecret + `"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("op failed")
	if got := dropOp(o, rk, "id", want); got != want {
		t.Fatalf("err = %v", got)
	}
	if !wiped(o["secret"]) {
		t.Fatal("the parsed body was not wiped")
	}
	if _, err := rk.Seed(); !errors.Is(err, suite.ErrDestroyed) {
		t.Fatalf("the reply key was not destroyed: %v", err)
	}
	if err := dropOp(nil, nil, "", nil); err != nil {
		t.Fatal(err)
	}
}

// sealedWith destroys the reply key on every path that does not hand it
// to the caller: a refused response, a body keep refuses, a wait that
// ends; on success the caller gets it, intact.
func TestSealedWithDestroysTheReplyKey(t *testing.T) {
	ctx := context.Background()
	ek, err := suite.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	u := UTK{ID: "u1", EK: ek.Public().Bytes(), Expires: time.Now().Add(time.Hour)}
	for _, c := range []struct {
		name    string
		answer  *answer
		timeout time.Duration
		ok      bool
	}{
		{"refused", &answer{code: "forbidden"}, 0, false},
		{"keep refuses the body", &answer{body: func(strictjson.Object) []byte { return []byte(`{"utks":"not a list"}`) }}, 0, false},
		{"the wait ends", nil, 50 * time.Millisecond, false},
		{"success", &answer{body: func(strictjson.Object) []byte { return []byte(`{}`) }}, 0, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, v, d := pair(t)
			if c.answer != nil {
				answeringWith(t, v, map[string]answer{"x.sealed": *c.answer})
			}
			var destroyed []*suite.PrivateKey
			testReplyKeyHook = func(k *suite.PrivateKey) { destroyed = append(destroyed, k) }
			defer func() { testReplyKeyHook = nil }()
			cctx := ctx
			if c.timeout > 0 {
				var cancel context.CancelFunc
				cctx, cancel = context.WithTimeout(ctx, c.timeout)
				defer cancel()
			}
			o, rk, _, err := d.sealedWith(cctx, "x.sealed", u, nil, false, map[string]any{"pin": "1234"}, true, nil)
			if c.ok {
				if err != nil || rk == nil || len(destroyed) != 0 {
					t.Fatalf("err %v, key %v, %d destroyed", err, rk != nil, len(destroyed))
				}
				if _, err := rk.Seed(); err != nil {
					t.Fatal("the handed reply key was destroyed")
				}
				rk.Destroy()
				wipeParsed(o)
				return
			}
			if err == nil || rk != nil {
				t.Fatalf("err %v, key returned %v", err, rk != nil)
			}
			if len(destroyed) != 1 {
				t.Fatalf("%d reply keys destroyed, want 1", len(destroyed))
			}
			if _, err := destroyed[0].Seed(); !errors.Is(err, suite.ErrDestroyed) {
				t.Fatal("the reply key was not destroyed")
			}
		})
	}
}

// Op wipes the request body it marshalled once the request is sent; the
// vault received it intact.
func TestOpWipesTheRequest(t *testing.T) {
	ctx := context.Background()
	_, v, d := pair(t)
	answeringWith(t, v, map[string]answer{"item.put": {body: func(req strictjson.Object) []byte {
		s, _ := req.String("value")
		return strictjson.NewBuilder().String("got", s).Bytes()
	}}})
	var bodies [][]byte
	testRequestHook = func(b []byte) { bodies = append(bodies, b) }
	defer func() { testRequestHook = nil }()
	o, err := d.Op(ctx, "item.put", map[string]any{"value": respSecret})
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := o.String("got"); got != respSecret {
		t.Fatalf("the vault got %q", got)
	}
	if len(bodies) != 1 || !wiped(bodies[0]) {
		t.Fatalf("%d request bodies wiped", len(bodies))
	}
}
