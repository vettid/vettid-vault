package itemspec

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// runBody is a valid item.run request's members (without op and item_id),
// changed by edit.
func runBody(edit func(m map[string]any)) string {
	m := map[string]any{"field_id": "password", "program": "/usr/bin/git", "sha256": hashA,
		"argv": []any{"git", "push"}, "cwd": "/home/a/repo", "how": "env", "name": "TOKEN"}
	if edit != nil {
		edit(m)
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func parseRunReq(t *testing.T, body string) (*Run, error) {
	t.Helper()
	o, err := strictjson.ParseObject([]byte(body))
	if err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return ParseRun(o)
}

func TestParseRunAccepts(t *testing.T) {
	r, err := parseRunReq(t, runBody(func(m map[string]any) { m["env"] = map[string]any{"GH_HOST": "x", "A_B": ""} }))
	if err != nil {
		t.Fatal(err)
	}
	want := &Run{FieldID: "password", Program: "/usr/bin/git", SHA256: hashA, Argv: []string{"git", "push"},
		Cwd: "/home/a/repo", How: HowEnv, Name: "TOKEN", Env: []EnvVar{{"A_B", ""}, {"GH_HOST", "x"}}}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("%+v", r)
	}
	for _, edit := range []func(m map[string]any){
		func(m map[string]any) { m["how"] = "stdin"; delete(m, "name") },
		func(m map[string]any) { m["how"] = "file"; m["argv"] = []any{"git", "{secret_file}"} },
		func(m map[string]any) {
			m["program"] = win("C:", "Program Files", "Git", "git.exe")
			m["cwd"] = win("C:", "")
		},
		func(m map[string]any) { m["cwd"] = "/" },
		func(m map[string]any) { m["argv"] = []any{strings.Repeat("a", MaxRunArg)} },
		func(m map[string]any) {
			a := make([]any, 8)
			for i := range a {
				a[i] = strings.Repeat("a", MaxRunArgTotal/8)
			}
			m["argv"] = a
		},
		func(m map[string]any) { m["argv"] = []any{"git", "-c", "a\nb\x01"} }, // shown escaped, not refused
		func(m map[string]any) {
			env := map[string]any{}
			for i := 0; i < MaxRunEnv; i++ {
				env["V"+strings.Repeat("_", i)] = strings.Repeat("v", MaxRunEnvValue)
			}
			m["env"] = env
		},
	} {
		if _, err := parseRunReq(t, runBody(edit)); err != nil {
			t.Errorf("%s: %v", runBody(edit), err)
		}
	}
}

func TestParseRunRefuses(t *testing.T) {
	long := make([]any, MaxRunArgs+1)
	for i := range long {
		long[i] = "a"
	}
	over := make([]any, 9)
	for i := range over {
		over[i] = strings.Repeat("a", MaxRunArgTotal/8)
	}
	envOver := map[string]any{}
	for i := 0; i <= MaxRunEnv; i++ {
		envOver["V"+strings.Repeat("_", i)] = "v"
	}
	cases := map[string]func(m map[string]any){
		"no field":            func(m map[string]any) { delete(m, "field_id") },
		"bad field":           func(m map[string]any) { m["field_id"] = "" },
		"bare program":        func(m map[string]any) { m["program"] = "git" },
		"relative program":    func(m map[string]any) { m["program"] = "bin/git" },
		"UNC program":         func(m map[string]any) { m["program"] = "//server/share/git" },
		"program control":     func(m map[string]any) { m["program"] = "/usr/bin/gi\x7ft" },
		"program bidi":        func(m map[string]any) { m["program"] = "/usr/bin/\u202egit" },
		"directory program":   func(m map[string]any) { m["program"] = "/usr/bin/" },
		"no sha256":           func(m map[string]any) { delete(m, "sha256") },
		"short sha256":        func(m map[string]any) { m["sha256"] = hashA[1:] },
		"upper sha256":        func(m map[string]any) { m["sha256"] = strings.ToUpper(hashA) },
		"non-hex sha256":      func(m map[string]any) { m["sha256"] = "g" + hashA[1:] },
		"no argv":             func(m map[string]any) { delete(m, "argv") },
		"empty argv":          func(m map[string]any) { m["argv"] = []any{} },
		"argv too many":       func(m map[string]any) { m["argv"] = long },
		"argv too long":       func(m map[string]any) { m["argv"] = []any{strings.Repeat("a", MaxRunArg+1)} },
		"argv over total":     func(m map[string]any) { m["argv"] = over },
		"argv not strings":    func(m map[string]any) { m["argv"] = []any{1} },
		"no cwd":              func(m map[string]any) { delete(m, "cwd") },
		"relative cwd":        func(m map[string]any) { m["cwd"] = "repo" },
		"cwd control":         func(m map[string]any) { m["cwd"] = "/home/a\nb" },
		"bad how":             func(m map[string]any) { m["how"] = "arg" },
		"env without name":    func(m map[string]any) { delete(m, "name") },
		"file without name":   func(m map[string]any) { m["how"] = "file"; delete(m, "name") },
		"stdin with name":     func(m map[string]any) { m["how"] = "stdin" },
		"name lower case":     func(m map[string]any) { m["name"] = "token" },
		"name PATH":           func(m map[string]any) { m["name"] = "PATH" },
		"name LD_":            func(m map[string]any) { m["name"] = "LD_PRELOAD" },
		"name GIT_":           func(m map[string]any) { m["name"] = "GIT_ASKPASS" },
		"name NODE_OPTIONS":   func(m map[string]any) { m["name"] = "NODE_OPTIONS" },
		"name SSLKEYLOGFILE":  func(m map[string]any) { m["name"] = "SSLKEYLOGFILE" },
		"env not an object":   func(m map[string]any) { m["env"] = []any{} },
		"env refused name":    func(m map[string]any) { m["env"] = map[string]any{"HTTPS_PROXY": "x"} },
		"env bad name":        func(m map[string]any) { m["env"] = map[string]any{"a": "x"} },
		"env value not str":   func(m map[string]any) { m["env"] = map[string]any{"A": 1} },
		"env value too long":  func(m map[string]any) { m["env"] = map[string]any{"A": strings.Repeat("v", MaxRunEnvValue+1)} },
		"env too many":        func(m map[string]any) { m["env"] = envOver },
		"env repeats name":    func(m map[string]any) { m["env"] = map[string]any{"TOKEN": "x"} },
		"env with stdin name": func(m map[string]any) { m["how"] = "stdin"; m["env"] = map[string]any{"TOKEN": "x"} },
	}
	for name, edit := range cases {
		if r, err := parseRunReq(t, runBody(edit)); err == nil && name != "env with stdin name" {
			t.Errorf("%s accepted: %+v", name, r)
		}
	}
	// With stdin there is no name, so an env TOKEN is not a repeat: refused
	// only because stdin carries a name here.
	if _, err := parseRunReq(t, runBody(func(m map[string]any) { m["how"] = "stdin"; delete(m, "name"); m["env"] = map[string]any{"TOKEN": "x"} })); err != nil {
		t.Errorf("stdin with env TOKEN: %v", err)
	}
}

func TestMatchProgram(t *testing.T) {
	ps := []Program{{Program: "/usr/bin/git"}, {Program: "gh"}, {Program: win("C:", "Tools", "op.exe")}, {Program: "node.exe"}}
	for prog, want := range map[string]string{
		"/usr/bin/git":                   "/usr/bin/git",
		"/opt/gh":                        "gh",
		"/usr/local/bin/gh":              "gh",
		win("C:", "Tools", "op.exe"):     win("C:", "Tools", "op.exe"),
		win("C:", "nodejs", "node.exe"):  "node.exe",
		"/usr/bin/GIT":                   "",
		"/usr/local/bin/git":             "",
		"/opt/GH":                        "",
		"/opt/gh.exe":                    "",
		win("C:", "tools", "op.exe"):     "",
		"C:/Tools/op.exe":                "",
		win("C:", "nodejs", "node"):      "",
		win("C:", "nodejs", "NODE.EXE"):  "",
		win("C:", "nodejs", "node.exe."): "",
	} {
		e, ok := MatchProgram(ps, prog)
		if ok != (want != "") || e.Program != want {
			t.Errorf("%s: %q %v, want %q", prog, e.Program, ok, want)
		}
	}
}

func TestShellsAndInterpreters(t *testing.T) {
	for _, p := range []string{"/bin/sh", "/bin/bash", "/usr/bin/env", "/bin/busybox", "/usr/bin/fish", win("C:", "Windows", "System32", "cmd.exe"),
		win("C:", "Windows", "System32", "CMD.EXE"), win("C:", "x", "PowerShell.exe"), "/usr/bin/pwsh", win("C:", "x", "bash.exe."), "/bin/ZSH"} {
		if !IsShell(p) {
			t.Errorf("%s is a shell", p)
		}
	}
	for _, p := range []string{"/usr/bin/git", "/bin/shx", "/usr/bin/bashful", "/usr/bin/python3"} {
		if IsShell(p) {
			t.Errorf("%s is not a shell", p)
		}
	}
	for _, p := range []string{"/usr/bin/python3", "/usr/bin/python3.12", "/usr/bin/node", "/usr/bin/nodejs", "/usr/bin/perl5.36", "/usr/bin/ruby",
		"/usr/bin/php8", "/usr/bin/osascript", win("C:", "Python313", "Python.exe"), win("C:", "x", "NODE.EXE")} {
		if !IsInterpreter(p) {
			t.Errorf("%s is an interpreter", p)
		}
	}
	for _, p := range []string{"/usr/bin/git", "/usr/bin/npython", "/usr/bin/gh"} {
		if IsInterpreter(p) {
			t.Errorf("%s is not an interpreter", p)
		}
	}
}

func runOf(program, sha string, argv []string, env ...string) *Run {
	r := &Run{FieldID: "password", Program: program, SHA256: sha, Argv: argv, Cwd: "/", How: HowEnv, Name: "TOKEN"}
	for _, n := range env {
		r.Env = append(r.Env, EnvVar{n, "v"})
	}
	return r
}

func TestJudgeRun(t *testing.T) {
	git := []string{"git", "push"}
	bound := func(each bool, ps ...Program) *ItemWays {
		return &ItemWays{Version: 3, Ways: []string{WayUse, WayRun}, Run: &RunWays{Programs: ps, Each: each}}
	}
	pinned := Program{Program: "/usr/bin/git", SHA256: hashA, Path: "/usr/bin/git", Env: []string{"GH_HOST"}}
	cases := []struct {
		name string
		w    *ItemWays
		r    *Run
		want RunJudgement
	}{
		{"absent settings", nil, runOf("/usr/bin/git", hashA, git), RunJudgement{Refusal: "way_not_allowed"}},
		{"no run way", &ItemWays{Ways: []string{WayUse, WayProxy, WayReveal}}, runOf("/usr/bin/git", hashA, git), RunJudgement{Refusal: "way_not_allowed"}},
		{"not bound to it", bound(false, pinned), runOf("/usr/local/bin/git", hashA, git), RunJudgement{Refusal: "program_not_allowed"}},
		{"env not listed", bound(false, pinned), runOf("/usr/bin/git", hashA, git, "GH_HOST", "GH_TOKEN", "A"),
			RunJudgement{Refusal: "env_not_allowed", Names: []string{"A", "GH_TOKEN"}}},
		{"env when unbound", bound(true), runOf("/usr/bin/git", hashA, git, "GH_HOST"),
			RunJudgement{Refusal: "env_not_allowed", Names: []string{"GH_HOST"}}},
		{"pinned, each false", bound(false, pinned), runOf("/usr/bin/git", hashA, git, "GH_HOST"),
			RunJudgement{Entry: pinned, Bound: true, PinMatch: true}},
		{"pinned, each true", bound(true, pinned), runOf("/usr/bin/git", hashA, git),
			RunJudgement{Entry: pinned, Bound: true, PinMatch: true, Refer: true}},
		{"unbound", bound(false), runOf("/usr/bin/git", hashA, git),
			RunJudgement{Refer: true, Flags: []string{FlagUnboundProgram}}},
		{"unrecorded", bound(false, Program{Program: "git"}), runOf("/usr/bin/git", hashA, git),
			RunJudgement{Entry: Program{Program: "git"}, Bound: true, Refer: true, Flags: []string{FlagProgramUnrecorded}}},
		{"changed file", bound(false, pinned), runOf("/usr/bin/git", hashB, git),
			RunJudgement{Entry: pinned, Bound: true, Refer: true, Flags: []string{FlagProgramChanged}, PreviousSHA256: hashA, PreviousPath: "/usr/bin/git"}},
		{"moved file", bound(false, Program{Program: "git", SHA256: hashA, Path: "/usr/bin/git"}), runOf("/tmp/x/git", hashA, git),
			RunJudgement{Entry: Program{Program: "git", SHA256: hashA, Path: "/usr/bin/git"}, Bound: true, Refer: true,
				Flags: []string{FlagProgramChanged}, PreviousSHA256: hashA, PreviousPath: "/usr/bin/git"}},
		{"pinned shell", bound(false, Program{Program: "/bin/bash", SHA256: hashA, Path: "/bin/bash"}), runOf("/bin/bash", hashA, []string{"bash", "-c", "x"}),
			RunJudgement{Entry: Program{Program: "/bin/bash", SHA256: hashA, Path: "/bin/bash"}, Bound: true, PinMatch: true, Refer: true, Flags: []string{FlagShell}}},
		{"pinned interpreter, no inline code", bound(false, Program{Program: "python3", SHA256: hashA, Path: "/usr/bin/python3"}),
			runOf("/usr/bin/python3", hashA, []string{"python3", "x.py"}),
			RunJudgement{Entry: Program{Program: "python3", SHA256: hashA, Path: "/usr/bin/python3"}, Bound: true, PinMatch: true, Refer: true}},
		{"inline code, unbound", bound(false), runOf("/usr/bin/node", hashA, []string{"node", "--eval", "x"}),
			RunJudgement{Refer: true, Flags: []string{FlagInlineCode, FlagUnboundProgram}}},
		{"inline flag as argv[0] only", bound(false), runOf("/usr/bin/perl", hashA, []string{"-e"}),
			RunJudgement{Refer: true, Flags: []string{FlagUnboundProgram}}},
		{"a shell's -c is not inline_code", bound(false), runOf("/bin/sh", hashA, []string{"sh", "-c", "x"}),
			RunJudgement{Refer: true, Flags: []string{FlagShell, FlagUnboundProgram}}},
	}
	for _, c := range cases {
		got := JudgeRun(c.w, c.r)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.name, got, c.want)
		}
		wantPin := false
		for _, f := range c.want.Flags {
			wantPin = wantPin || f == FlagProgramUnrecorded || f == FlagProgramChanged
		}
		if got.RecordsPin() != wantPin {
			t.Errorf("%s: RecordsPin %v", c.name, got.RecordsPin())
		}
	}
}

func TestWithPin(t *testing.T) {
	w := &ItemWays{Version: 4, Ways: []string{WayUse, WayRun}, Run: &RunWays{Programs: []Program{{Program: "git", Env: []string{"A"}}, {Program: "/usr/bin/gh"}}}}
	n, ok := WithPin(w, "git", hashA, "/usr/bin/git")
	if !ok || n.Run.Programs[0].SHA256 != hashA || n.Run.Programs[0].Path != "/usr/bin/git" || n.Run.Programs[0].Env[0] != "A" ||
		n.Run.Programs[1].SHA256 != "" || n.Version != 4 {
		t.Fatalf("%+v", n)
	}
	if w.Run.Programs[0].SHA256 != "" {
		t.Fatal("the original changed")
	}
	if _, ok := WithPin(w, "/usr/bin/git", hashA, "/usr/bin/git"); ok {
		t.Fatal("pinned an entry that is not there")
	}
	if _, ok := WithPin(nil, "git", hashA, "/usr/bin/git"); ok {
		t.Fatal("pinned absent settings")
	}
	if _, ok := WithPin(&ItemWays{Ways: []string{WayUse}}, "git", hashA, "/x"); ok {
		t.Fatal("pinned settings without run")
	}
}
