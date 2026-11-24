package itemspec

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// foldersBody is a leash.item.set body binding git with folders fs (each
// already JSON).
func foldersBody(fs ...string) string {
	return `{"ways":["use","run"],"run":{"programs":[{"program":"git"}],"folders":[` + strings.Join(fs, ",") + `]}}`
}

func folder(path string, write bool) string {
	return fmt.Sprintf(`{"path":%s,"write":%v}`, js(path), write)
}

// §10.11 (0.93.0) "Member folders for runs": what leash.item.set accepts.
func TestParseFoldersAccepts(t *testing.T) {
	var fs []string
	for i := 0; i < MaxFolders; i++ {
		fs = append(fs, folder(fmt.Sprintf("/home/al/w%02d", i), i%2 == 0))
	}
	w, err := parseWays(t, foldersBody(fs...), nil)
	if err != nil || len(w.Run.Folders) != MaxFolders {
		t.Fatalf("16 folders: %v %+v", err, w)
	}
	w, err = parseWays(t, foldersBody(`{"path":"/home/al/work"}`, folder(win("C:", "Users", "al", "Docs"), true)), nil)
	if err != nil || w.Run.Folders[0].Write || !w.Run.Folders[1].Write {
		t.Fatalf("a missing write is false: %v %+v", err, w)
	}
	// Siblings and a longer name beside a shorter one are not nested.
	for _, pair := range [][2]string{{"/home/al/work", "/home/al/work2"}, {"/home/al/a", "/home/al/b"}, {"/a/b", "/b/a"},
		{win("C:", "x"), win("D:", "x")}, {"/x", win("C:", "x")}} {
		if _, err := parseWays(t, foldersBody(folder(pair[0], false), folder(pair[1], false)), nil); err != nil {
			t.Errorf("%q and %q: %v", pair[0], pair[1], err)
		}
	}
	// No folders member: none (the binding of 0.92.1).
	w, err = parseWays(t, `{"ways":["use","run"],"run":{"programs":[{"program":"git"}]}}`, nil)
	if err != nil || len(w.Run.Folders) != 0 {
		t.Fatalf("no folders: %v %+v", err, w)
	}
}

// §10.11 (0.93.0): what leash.item.set refuses.
func TestParseFoldersRefuses(t *testing.T) {
	var fs []string
	for i := 0; i <= MaxFolders; i++ {
		fs = append(fs, folder(fmt.Sprintf("/home/al/w%02d", i), false))
	}
	long := "/" + strings.Repeat("a", MaxProgram)
	cases := map[string]string{
		"17 folders":         foldersBody(fs...),
		"the root":           foldersBody(folder("/", false)),
		"a drive's root":     foldersBody(folder(win("C:", ""), false)),
		"a drive's / root":   foldersBody(folder("C:/", false)),
		"relative":           foldersBody(folder("home/al", false)),
		"trailing separator": foldersBody(folder("/home/al/", false)),
		"dot-dot":            foldersBody(folder("/home/al/../x", false)),
		"dot":                foldersBody(folder("/home/./al", false)),
		"a colon":            foldersBody(folder("/home/al:x", false)),
		"a control char":     foldersBody(folder("/home/a\x01l", false)),
		"a format char":      foldersBody(folder("/home/a\u200bl", false)),
		"over-long":          foldersBody(folder(long, false)),
		"no path":            foldersBody(`{"write":true}`),
		"a non-string path":  foldersBody(`{"path":7}`),
		"non-boolean write":  foldersBody(`{"path":"/home/al","write":"true"}`),
		"null write":         foldersBody(`{"path":"/home/al","write":null}`),
		"not an array":       `{"ways":["use","run"],"run":{"programs":[{"program":"git"}],"folders":{}}}`,
		"an entry not obj":   foldersBody(`"/home/al"`),
		"equal":              foldersBody(folder("/home/al/work", false), folder("/home/al/work", true)),
		"equal but case":     foldersBody(folder("/home/al/Work", false), folder("/home/al/work", false)),
		"equal but sep":      foldersBody(folder("/home/al/work", false), folder("/home"+win("", "al", "work"), false)),
		"equal but dot":      foldersBody(folder("/home/al/work", false), folder("/home/al/work.", false)),
		"equal but space":    foldersBody(folder("/home/al/work", false), folder("/home/al/work ", false)),
		"drive case":         foldersBody(folder(win("C:", "x"), false), folder(win("c:", "X"), false)),
		"drive sep":          foldersBody(folder(win("C:", "x", "y"), false), folder("C:/x/y", false)),
		"under":              foldersBody(folder("/home/al", false), folder("/home/al/work", false)),
		"above":              foldersBody(folder("/home/al/work", false), folder("/home/al", false)),
		"under, folded":      foldersBody(folder("/home/AL", false), folder("/home/al/work", false)),
		"under, long s":      foldersBody(folder("/home/ſ", false), folder("/home/s/work", false)),
		"equal, NFC":         foldersBody(folder("/home/é", false), folder("/home/é", false)),
		"under, NFC":         foldersBody(folder("/a/café", false), folder("/a/café/x", false)),
		"equal, J caron":     foldersBody(folder("/a/J̌", false), folder("/a/ǰ", false)),
		"dots-space element": foldersBody(folder("/home/al/.. /x", false)),
		"dot-space element":  foldersBody(folder("/home/al/. /x", false)),
		"three dots":         foldersBody(folder("/home/al/.../x", false)),
		"space element":      foldersBody(folder("/home/al/ /x", false)),
		"trailing dots-only": foldersBody(folder("/home/al/..  ", false)),
		"equal, Kelvin sign": foldersBody(folder("/home/K", false), folder("/home/k", false)),
		"folders, no run":    `{"ways":["use"],"run":{"programs":[],"folders":[` + folder("/home/al", false) + `]}}`,
	}
	for name, body := range cases {
		if _, err := parseWays(t, body, nil); err == nil {
			t.Errorf("%s accepted: %s", name, body)
		}
	}
}

// §10.11 (0.93.0): adding a folder, changing a path and turning write on
// widen; removing one, turning write off and emptying folders narrow.
func TestFoldersWiden(t *testing.T) {
	bind := func(fs ...string) *ItemWays {
		w, err := parseWays(t, foldersBody(fs...), nil)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	cur := bind(folder("/home/al/work", false), folder("/home/al/docs", true))
	for name, next := range map[string]*ItemWays{
		"added":    bind(folder("/home/al/work", false), folder("/home/al/docs", true), folder("/home/al/more", false)),
		"path":     bind(folder("/home/al/work2", false), folder("/home/al/docs", true)),
		"case":     bind(folder("/home/al/Work", false), folder("/home/al/docs", true)),
		"write on": bind(folder("/home/al/work", true), folder("/home/al/docs", true)),
	} {
		if !Widens(cur, next) {
			t.Errorf("%s does not widen", name)
		}
	}
	for name, next := range map[string]*ItemWays{
		"same":      bind(folder("/home/al/work", false), folder("/home/al/docs", true)),
		"removed":   bind(folder("/home/al/docs", true)),
		"write off": bind(folder("/home/al/work", false), folder("/home/al/docs", false)),
		"emptied":   bind(),
	} {
		if Widens(cur, next) {
			t.Errorf("%s widens", name)
		}
	}
	// From settings stored before 0.93.0 (no folders): adding one widens.
	old := bind()
	old.Run.Folders = nil
	if !Widens(old, bind(folder("/home/al/work", false))) {
		t.Error("a first folder does not widen")
	}
}

// bound returns settings binding /usr/bin/git, pinned, each false, with
// folders fs.
func bound(fs ...Folder) *ItemWays {
	return &ItemWays{Ways: []string{WayUse, WayRun}, Run: &RunWays{
		Programs: []Program{{Program: "/usr/bin/git", SHA256: hashA, Path: "/usr/bin/git", Env: []string{"GH_HOST"}}}, Folders: fs}}
}

func pinnedRun() *Run { return runOf("/usr/bin/git", hashA, []string{"git", "push"}) }

// §10.11 (0.93.0) "How the vault compares": a cwd equal to an entry or
// under it, element by element, exactly and case-sensitively.
func TestJudgeRunCwd(t *testing.T) {
	work := Folder{Path: "/home/al/work"}
	w := bound(work, Folder{Path: win("C:", "Users", "al"), Write: true})
	// No cwd: the run's work/, always allowed, with no folders at all.
	if j := JudgeRun(bound(), pinnedRun()); j.Refusal != "" || j.Refer || j.Folders || len(j.Flags) != 0 {
		t.Fatalf("no cwd: %+v", j)
	}
	for _, cwd := range []string{"/home/al/work", "/home/al/work/site", "/home/al/work/a/b/c", "/home/al" + win("", "work", "site"),
		win("C:", "Users", "al"), "C:/Users/al/x", win("C:", "Users", "al", "x")} {
		r := pinnedRun()
		r.Cwd = cwd
		j := JudgeRun(w, r)
		if j.Refusal != "" || !j.Refer || !j.Folders || j.CwdFolder == nil || j.OutputFolder != nil {
			t.Errorf("%s: %+v", cwd, j)
			continue
		}
		if strings.Join(j.Flags, ",") != FlagMemberFolder {
			t.Errorf("%s flags %v", cwd, j.Flags)
		}
	}
	r := pinnedRun()
	r.Cwd = "/home/al/work/site"
	if j := JudgeRun(w, r); *j.CwdFolder != work {
		t.Fatalf("matched %+v", j.CwdFolder)
	}
	for _, cwd := range []string{"/home/al/work2", "/home/al/Work", "/home/al/WORK/site", "/home/al/docs", "/home/al", "/", "/home",
		win("c:", "Users", "al"), win("C:", "users", "al"), win("C:", "Users"), "/home/al/work2/x"} {
		r := pinnedRun()
		r.Cwd = cwd
		j := JudgeRun(w, r)
		if j.Refusal != "cwd_not_allowed" || j.Where != "cwd" || j.Path != cwd || j.Refer {
			t.Errorf("%s: %+v", cwd, j)
		}
	}
	// With empty folders any cwd is refused.
	r = pinnedRun()
	r.Cwd = "/home/al/work"
	if j := JudgeRun(bound(), r); j.Refusal != "cwd_not_allowed" {
		t.Fatalf("empty folders: %+v", j)
	}
}

// §10.11 (0.93.0): the checks run in order: env_not_allowed before
// cwd_not_allowed, and the cwd, then each input, then the output.
func TestJudgeRunOrder(t *testing.T) {
	w := bound(Folder{Path: "/home/al/work"})
	r := pinnedRun()
	r.Cwd = "/elsewhere"
	r.Env = []EnvVar{{"OTHER", "v"}}
	if j := JudgeRun(w, r); j.Refusal != "env_not_allowed" {
		t.Fatalf("env first: %+v", j)
	}
	r = pinnedRun()
	r.Cwd = "/elsewhere"
	r.Inputs = []RunInput{{"/out/a.txt", 1}}
	r.Output = &RunOutput{Folder: "/out2", Names: []string{"b"}}
	if j := JudgeRun(w, r); j.Where != "cwd" || j.Path != "/elsewhere" {
		t.Fatalf("cwd first: %+v", j)
	}
	r.Cwd = ""
	r.Inputs = []RunInput{{"/home/al/work/ok.txt", 1}, {"/out/a.txt", 1}, {"/out/b.txt", 1}}
	if j := JudgeRun(w, r); j.Where != "input" || j.Path != "/out/a.txt" {
		t.Fatalf("the first input that fails: %+v", j)
	}
	r.Inputs = r.Inputs[:1]
	if j := JudgeRun(w, r); j.Where != "output" || j.Path != "/out2" {
		t.Fatalf("output last: %+v", j)
	}
}

// §10.11 (0.93.0) "Files handed in and out": an input under any entry; an
// output folder equal to or under an entry with write.
func TestJudgeRunFiles(t *testing.T) {
	ro, rw := Folder{Path: "/home/al/docs"}, Folder{Path: "/home/al/out", Write: true}
	w := bound(ro, rw)
	r := pinnedRun()
	r.Inputs = []RunInput{{"/home/al/docs/a.pdf", 10}, {"/home/al/out/b.pdf", 20}}
	j := JudgeRun(w, r)
	if j.Refusal != "" || !j.Refer || !j.Folders || j.CwdFolder != nil || j.OutputFolder != nil || strings.Join(j.Flags, ",") != FlagMemberFiles {
		t.Fatalf("inputs only: %+v", j)
	}
	for _, folder := range []string{"/home/al/out", "/home/al/out/sub"} {
		r := pinnedRun()
		r.Output = &RunOutput{Folder: folder, Names: []string{"x.pdf"}}
		j := JudgeRun(w, r)
		if j.Refusal != "" || j.OutputFolder == nil || *j.OutputFolder != rw || strings.Join(j.Flags, ",") != FlagMemberFiles {
			t.Errorf("output %s: %+v", folder, j)
		}
	}
	for _, folder := range []string{"/home/al/docs", "/home/al/docs/sub", "/home/al", "/elsewhere", "/home/al/Out"} {
		r := pinnedRun()
		r.Output = &RunOutput{Folder: folder, Names: []string{"x.pdf"}}
		if j := JudgeRun(w, r); j.Refusal != "cwd_not_allowed" || j.Where != "output" || j.Path != folder {
			t.Errorf("output %s: %+v", folder, j)
		}
	}
	r = pinnedRun()
	r.Inputs = []RunInput{{"/elsewhere/a.pdf", 1}}
	if j := JudgeRun(w, r); j.Refusal != "cwd_not_allowed" || j.Where != "input" {
		t.Fatalf("an input outside: %+v", j)
	}
	// A binding with no folders refuses any input or output.
	r = pinnedRun()
	r.Inputs = []RunInput{{"/home/al/docs/a.pdf", 1}}
	if j := JudgeRun(bound(), r); j.Where != "input" {
		t.Fatalf("no folders, input: %+v", j)
	}
	r = pinnedRun()
	r.Output = &RunOutput{Folder: "/home/al/out", Names: []string{"x"}}
	if j := JudgeRun(bound(), r); j.Where != "output" {
		t.Fatalf("no folders, output: %+v", j)
	}
	// Both flags, in order, after the program's.
	r = pinnedRun()
	r.Cwd = "/home/al/docs"
	r.Output = &RunOutput{Folder: "/home/al/out", Names: []string{"x"}}
	if j := JudgeRun(w, r); strings.Join(j.Flags, ",") != FlagMemberFolder+","+FlagMemberFiles || *j.CwdFolder != ro || *j.OutputFolder != rw {
		t.Fatalf("both: %+v", j)
	}
	sh := runOf("/bin/sh", hashA, []string{"sh"})
	sh.Cwd = "/home/al/docs"
	if j := JudgeRun(&ItemWays{Ways: []string{WayUse, WayRun}, Run: &RunWays{Programs: []Program{}, Each: true, Folders: []Folder{ro}}}, sh); strings.Join(j.Flags, ",") != "shell,unbound_program,member_folder" {
		t.Fatalf("flag order: %v", j.Flags)
	}
}

// filesBody is a valid item.run with inputs and output, changed by edit.
func filesBody(edit func(m map[string]any)) string {
	return runBody(func(m map[string]any) {
		m["inputs"] = []any{map[string]any{"path": "/home/al/docs/a.pdf", "size": 10}}
		m["output"] = map[string]any{"folder": "/home/al/out", "names": []any{"x.pdf"}}
		if edit != nil {
			edit(m)
		}
	})
}

func inputs(n int, size uint64) []any {
	var in []any
	for i := 0; i < n; i++ {
		in = append(in, map[string]any{"path": fmt.Sprintf("/home/al/docs/f%02d.pdf", i), "size": size})
	}
	return in
}

func outNames(n int) []any {
	var l []any
	for i := 0; i < n; i++ {
		l = append(l, fmt.Sprintf("n%02d", i))
	}
	return l
}

// §10.11 (0.93.0): the files' form.
func TestParseRunFiles(t *testing.T) {
	r, err := parseRunReq(t, filesBody(nil))
	if err != nil || len(r.Inputs) != 1 || r.Inputs[0] != (RunInput{"/home/al/docs/a.pdf", 10}) || r.Output == nil ||
		r.Output.Folder != "/home/al/out" || strings.Join(r.Output.Names, ",") != "x.pdf" {
		t.Fatalf("parsed %v %+v", err, r)
	}
	// The paths together: 16,384 bytes accepted, one more refused.
	pathsOf := func(total int) []any {
		var in []any
		left := total
		for i := 0; left > 0; i++ {
			n := min(left, 4000)
			dir, last := fmt.Sprintf("/d%02d/", i), fmt.Sprintf("/f%02d", i)
			p := dir + strings.Repeat("a", n-len(dir)-len(last)) + last
			in = append(in, map[string]any{"path": p, "size": 0})
			left -= n
		}
		return in
	}
	ok := map[string]func(m map[string]any){
		"16 inputs":          func(m map[string]any) { m["inputs"] = inputs(MaxRunInputs, 1) },
		"16 MiB":             func(m map[string]any) { m["inputs"] = inputs(1, MaxRunInputSize) },
		"64 MiB in all":      func(m map[string]any) { m["inputs"] = inputs(4, MaxRunInputSize) },
		"size 0":             func(m map[string]any) { m["inputs"] = inputs(1, 0) },
		"paths 16,384":       func(m map[string]any) { m["inputs"] = pathsOf(MaxRunInputPaths) },
		"no inputs":          func(m map[string]any) { delete(m, "inputs") },
		"empty inputs":       func(m map[string]any) { m["inputs"] = []any{} },
		"no output":          func(m map[string]any) { delete(m, "output") },
		"1 name":             func(m map[string]any) { m["output"].(map[string]any)["names"] = outNames(1) },
		"16 names":           func(m map[string]any) { m["output"].(map[string]any)["names"] = outNames(MaxRunOutputs) },
		"output at a root":   func(m map[string]any) { m["output"].(map[string]any)["folder"] = "/" }, // refused by the binding, not the form
		"a name with spaces": func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"my report.pdf"} },
		"a name with a dot":  func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{".hidden"} },
		"CONSOLE is not CON": func(m map[string]any) {
			m["output"].(map[string]any)["names"] = []any{"CONSOLE.txt", "COM10", "LPT10", "COMA", "CONIN"}
		},
		"a 255-byte name":      func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{strings.Repeat("é", 127) + "a"} },
		"names differ in case": func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a", "b"} },
	}
	for name, edit := range ok {
		if _, err := parseRunReq(t, filesBody(edit)); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	bad := map[string]func(m map[string]any){
		"17 inputs":             func(m map[string]any) { m["inputs"] = inputs(MaxRunInputs+1, 1) },
		"16 MiB + 1":            func(m map[string]any) { m["inputs"] = inputs(1, MaxRunInputSize+1) },
		"over 64 MiB":           func(m map[string]any) { m["inputs"] = append(inputs(4, MaxRunInputSize), inputs(5, 1)[4]) },
		"paths 16,385":          func(m map[string]any) { m["inputs"] = pathsOf(MaxRunInputPaths + 1) },
		"size -1":               func(m map[string]any) { m["inputs"] = []any{json.RawMessage(`{"path":"/a/b","size":-1}`)} },
		"size 1.5":              func(m map[string]any) { m["inputs"] = []any{json.RawMessage(`{"path":"/a/b","size":1.5}`)} },
		"size 1e3":              func(m map[string]any) { m["inputs"] = []any{json.RawMessage(`{"path":"/a/b","size":1e3}`)} },
		"size a string":         func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "/a/b", "size": "1"}} },
		"no size":               func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "/a/b"}} },
		"no path":               func(m map[string]any) { m["inputs"] = []any{map[string]any{"size": 1}} },
		"a relative input":      func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "a/b", "size": 1}} },
		"an input at the root":  func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "/", "size": 1}} },
		"an input dot-dot":      func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "/a/../b", "size": 1}} },
		"an input trailing sep": func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "/a/b/", "size": 1}} },
		"inputs not an array":   func(m map[string]any) { m["inputs"] = map[string]any{} },
		"an input reserved":     func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "/a/con.txt", "size": 1}} },
		"an input trailing dot": func(m map[string]any) { m["inputs"] = []any{map[string]any{"path": "/a/b.", "size": 1}} },
		"inputs, NFC": func(m map[string]any) {
			m["inputs"] = []any{map[string]any{"path": "/a/é.pdf", "size": 1}, map[string]any{"path": "/b/é.pdf", "size": 1}}
		},
		"input dots-only element": func(m map[string]any) {
			m["inputs"] = []any{map[string]any{"path": "/home/al/work/.. /.ssh/id", "size": 1}}
		},
		"output dots-only element": func(m map[string]any) { m["output"].(map[string]any)["folder"] = "/home/al/out/. /.. /.. /.ssh" },
		"cwd dots-only element":    func(m map[string]any) { m["cwd"] = "/home/al/work/.. " },
		"inputs, long s": func(m map[string]any) {
			m["inputs"] = []any{map[string]any{"path": "/a/ſ.pdf", "size": 1}, map[string]any{"path": "/b/s.pdf", "size": 1}}
		},
		"names, long s": func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"ſ.pdf", "S.pdf"} },
		"two inputs, one name": func(m map[string]any) {
			m["inputs"] = []any{map[string]any{"path": "/a/x.pdf", "size": 1}, map[string]any{"path": "/b/X.PDF", "size": 1}}
		},
		"0 names":               func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{} },
		"17 names":              func(m map[string]any) { m["output"].(map[string]any)["names"] = outNames(MaxRunOutputs + 1) },
		"no names":              func(m map[string]any) { delete(m["output"].(map[string]any), "names") },
		"no folder":             func(m map[string]any) { delete(m["output"].(map[string]any), "folder") },
		"a relative folder":     func(m map[string]any) { m["output"].(map[string]any)["folder"] = "out" },
		"output not an object":  func(m map[string]any) { m["output"] = []any{} },
		"names equal but case":  func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a.pdf", "A.PDF"} },
		"a name with /":         func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a/b"} },
		"a name with \\":        func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{win("a", "b")} },
		"a name with :":         func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a:b"} },
		"a name ..":             func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{".."} },
		"a name .":              func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"."} },
		"a name trailing dot":   func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a."} },
		"a name trailing space": func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a "} },
		"a name empty":          func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{""} },
		"a name 256 bytes":      func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{strings.Repeat("a", 256)} },
		"a name control":        func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a\x01"} },
		"a name format char":    func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"a\u202eb"} },
		"CON":                   func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"CON"} },
		"nul.txt":               func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"nul.txt"} },
		"Com1.tar.gz":           func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"Com1.tar.gz"} },
		"lpt9":                  func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"lpt9"} },
		"lpt0":                  func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"LPT0"} },
		"com0.txt":              func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"com0.txt"} },
		"COM superscript 1":     func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"COM¹"} },
		"lpt superscript 3 ext": func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"lpt³.log"} },
		"CONIN$":                func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"CONIN$"} },
		"conout$.txt":           func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"conout$.txt"} },
		"CONIN$.txt":            func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"CONIN$.txt"} },
		// 0.93.2: compared upper-cased with strings.ToUpper, the dotless i
		// reads as I.
		"CON dotless-i N$": func(m map[string]any) {
			m["output"].(map[string]any)["names"] = []any{"CON" + string(rune(0x131)) + "N$"}
		},
		"CON dotless-i N$.txt": func(m map[string]any) {
			m["output"].(map[string]any)["names"] = []any{"CON" + string(rune(0x131)) + "N$.txt"}
		},
		"CON .txt":               func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"CON .txt"} },
		"nul  .log":              func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"nul  .log"} },
		"COM superscript 2":      func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"COM²"} },
		"LPT superscript 3":      func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"LPT³"} },
		"prn .txt":               func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"prn .txt"} },
		"aux":                    func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{"aux"} },
		"a name not a string":    func(m map[string]any) { m["output"].(map[string]any)["names"] = []any{1} },
		"VETTID_IN as name":      func(m map[string]any) { m["name"] = "VETTID_IN" },
		"VETTID_OUT as name":     func(m map[string]any) { m["name"] = "VETTID_OUT" },
		"VETTID_IN in env":       func(m map[string]any) { m["env"] = map[string]any{"VETTID_IN": "/x"} },
		"VETTID_OUT in env":      func(m map[string]any) { m["env"] = map[string]any{"VETTID_OUT": "/x"} },
		"a cwd at an empty elem": func(m map[string]any) { m["cwd"] = "/a//b" },
	}
	for name, edit := range bad {
		if _, err := parseRunReq(t, filesBody(edit)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// §10.11 (0.93.0): VETTID_IN and VETTID_OUT are refused in a binding's env
// list too.
func TestVettidNamesRefusedInBinding(t *testing.T) {
	for _, n := range []string{"VETTID_IN", "VETTID_OUT"} {
		if _, err := parseWays(t, `{"ways":["use","run"],"run":{"programs":[{"program":"git","env":[`+js(n)+`]}]}}`, nil); err == nil {
			t.Errorf("%s accepted in env", n)
		}
	}
	if !ValidEnvName("VETTID_INX") || !ValidEnvName("VETTID") {
		t.Error("only the two names are refused")
	}
}

// §10.11 (0.93.0): folders on the wire, an empty list when none, in the
// settings and the catalog of an item with a run way; none without one.
func TestFoldersWire(t *testing.T) {
	w := bound(Folder{Path: "/home/al/work"}, Folder{Path: "/home/al/out", Write: true})
	want := `"folders":[{"path":"/home/al/work","write":false},{"path":"/home/al/out","write":true}]`
	if !strings.Contains(string(w.JSON("a", "i")), want) {
		t.Fatalf("item_ways: %s", w.JSON("a", "i"))
	}
	if string(w.CatalogFolders()) != want[len(`"folders":`):] {
		t.Fatalf("catalog: %s", w.CatalogFolders())
	}
	if e := bound(); string(e.CatalogFolders()) != "[]" || !strings.Contains(string(e.JSON("a", "i")), `"folders":[]`) {
		t.Fatalf("none: %s %s", e.CatalogFolders(), e.JSON("a", "i"))
	}
	stored := bound()
	stored.Run.Folders = nil // settings stored before 0.93.0
	if string(stored.CatalogFolders()) != "[]" {
		t.Fatalf("stored: %s", stored.CatalogFolders())
	}
	if (&ItemWays{Ways: []string{WayUse}}).CatalogFolders() != nil || (*ItemWays)(nil).CatalogFolders() != nil {
		t.Fatal("folders without a run way")
	}
	// A parsed binding round-trips through storage (encoding/json).
	p, err := parseWays(t, foldersBody(folder("/home/al/work", true)), nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(p)
	var back ItemWays
	if err := json.Unmarshal(raw, &back); err != nil || !back.Equal(p) {
		t.Fatalf("round trip: %v %s", err, raw)
	}
	c := p.Clone()
	c.Run.Folders[0].Write = false
	if !p.Run.Folders[0].Write {
		t.Fatal("Clone shares the folders")
	}
}

// 0.93.1: an input lies strictly under an entry, never equal to it.
func TestJudgeRunInputEqualToEntry(t *testing.T) {
	r := pinnedRun()
	r.Inputs = []RunInput{{"/home/al/docs", 1}}
	if j := JudgeRun(bound(Folder{Path: "/home/al/docs"}), r); j.Refusal != "cwd_not_allowed" || j.Where != "input" {
		t.Fatalf("an input equal to its entry: %+v", j)
	}
}

// 0.93.1: an empty inputs list is the same as none: no flag, no referral
// for it, and no folders on the approval.
func TestEmptyInputsAreNone(t *testing.T) {
	r, err := parseRunReq(t, runBody(func(m map[string]any) { m["inputs"] = []any{}; delete(m, "cwd") }))
	if err != nil {
		t.Fatal(err)
	}
	if j := JudgeRun(bound(), r); j.Refusal != "" || j.Refer || j.Folders || len(j.Flags) != 0 {
		t.Fatalf("empty inputs: %+v", j)
	}
}

// The limits as the spec writes them, not through the constants.
func TestFolderLimitsLiteral(t *testing.T) {
	if MaxFolders != 16 || MaxRunInputs != 16 || MaxProgram != 4096 || MaxRunInputSize != 16777216 || MaxRunInputTotal != 67108864 ||
		MaxRunInputPaths != 16384 || MaxRunOutputs != 16 || MaxFlatName != 255 {
		t.Fatal("a limit differs from VAULT-MESSAGING 0.93.0 §10.11")
	}
}

// 0.93.1: the spec's pairs through the real key (FolderKey, and the names'
// key): equal pairs are one key, distinct ones are not.
func TestFoldKeyPairs(t *testing.T) {
	same := [][2]string{
		{"/a/caf\u00e9", "/a/cafe\u0301"}, {"/a/J\u030c", "/a/\u01f0"}, {"/home/al/Work", "/home/al/work"},
		{"/a/aί", "/a/áͅ"}, {"/a/\u017f", "/a/S"}, {"/a/\u212a", "/a/k"}, {"/a/x.", "/a/x"}, {"/a/x ", "/a/x"},
		{"/a/b", "/a" + win("", "b")}, {win("C:", "x"), win("c:", "X")}, {win("C:", "x"), "C:/x"},
	}
	// 0.93.2: the dotless i keys as I (the upper step); the dotted capital
	// I stays I + U+0307, apart from i.
	dotless, dotted := string(rune(0x131)), string(rune(0x130))
	same = append(same, [2]string{"/a/" + dotless, "/a/I"}, [2]string{"/a/" + dotless, "/a/i"},
		[2]string{"/a/" + dotted, "/a/i" + string(rune(0x307))})
	for _, p := range same {
		if strings.Join(FolderKey(p[0]), "/") != strings.Join(FolderKey(p[1]), "/") {
			t.Errorf("%q and %q: two keys %q %q", p[0], p[1], FolderKey(p[0]), FolderKey(p[1]))
		}
	}
	for _, p := range [][2]string{{"/a/\u00df", "/a/ss"}, {"/a/work", "/a/work2"}, {"/a/e", "/a/\u00e9"}, {"/x", win("C:", "x")},
		{"/a/" + dotted, "/a/i"}} {
		if strings.Join(FolderKey(p[0]), "/") == strings.Join(FolderKey(p[1]), "/") {
			t.Errorf("%q and %q: one key", p[0], p[1])
		}
	}
	if foldCase("\u01f0.txt") != foldCase("J\u030c.TXT") || foldCase("a.txt") == foldCase("b.txt") {
		t.Error("the names' key")
	}
	if foldCase(dotless+".txt") != foldCase("I.TXT") || foldCase(dotted+".txt") == foldCase("i.txt") {
		t.Error("the names' key of the dotless and the dotted i")
	}
	// Through ParseWays: /a/ı against /a/I (and /a/i) refused, /a/İ against
	// /a/i two entries.
	for _, other := range []string{"/a/I", "/a/i"} {
		if _, err := parseWays(t, foldersBody(folder(other, false), folder("/a/"+dotless, false)), nil); err == nil {
			t.Errorf("/a/%s against %s accepted", dotless, other)
		}
	}
	if _, err := parseWays(t, foldersBody(folder("/a/"+dotted, false), folder("/a/i", false)), nil); err != nil {
		t.Errorf("/a/%s against /a/i: %v", dotted, err)
	}
}
