package itemspec

import (
	"strings"
	"testing"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

// win joins a Windows path with backslashes (kept out of string literals).
func win(parts ...string) string { return strings.Join(parts, string(rune(backslash))) }

func parseWays(t *testing.T, body string, cur *ItemWays) (*ItemWays, error) {
	t.Helper()
	o, err := strictjson.ParseObject([]byte(body))
	if err != nil {
		t.Fatalf("%s: %v", body, err)
	}
	return ParseWays(o, cur)
}

func js(s string) string { return string(strictjson.MarshalString(s)) }

// §10.11: what leash.item.set accepts.
func TestParseWaysAccepts(t *testing.T) {
	w, err := parseWays(t, `{"ways":["reveal","use","proxy","run"],"run":{"programs":[{"program":"/usr/bin/git","env":["GH_HOST"]},{"program":"gh"}],"each":false},
		"proxy":{"hosts":["api.example.com","x.example.org:8443"],"header":"Authorization","prefix":"Bearer "}}`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(w.Ways, ",") != "use,run,proxy,reveal" {
		t.Fatalf("ways not in wire order: %v", w.Ways)
	}
	if w.Run.Each || len(w.Run.Programs) != 2 || w.Run.Programs[1].Env == nil || len(w.Run.Programs[1].Env) != 0 {
		t.Fatalf("run: %+v", w.Run)
	}
	if w.Proxy.Prefix != "Bearer " || len(w.Proxy.Hosts) != 2 {
		t.Fatalf("proxy: %+v", w.Proxy)
	}
	// each defaults to true; prefix to "".
	w, err = parseWays(t, `{"ways":["use","run","proxy"],"run":{"programs":[]},"proxy":{"hosts":["a.example"],"header":"X-Api-Key"}}`, nil)
	if err != nil || !w.Run.Each || w.Proxy.Prefix != "" {
		t.Fatalf("defaults: %+v %v", w, err)
	}
	// Windows paths.
	for _, p := range []string{win("C:", "Program Files", "Git", "bin", "git.exe"), "D:/tools/x.exe", "git.exe"} {
		if _, err := parseWays(t, `{"ways":["use","run"],"run":{"programs":[{"program":`+js(p)+`}]}}`, nil); err != nil {
			t.Errorf("%q refused", p)
		}
	}
	// Just use.
	if w, err := parseWays(t, `{"ways":["use"]}`, nil); err != nil || w.Run != nil || w.Proxy != nil {
		t.Fatalf("use only: %+v %v", w, err)
	}
}

// §10.11, 0.85.3: what leash.item.set refuses (bad_request), one case per
// rule.
func TestParseWaysRefuses(t *testing.T) {
	long := strings.Repeat("a", MaxProgram)
	cases := map[string]string{
		"no ways":                `{}`,
		"ways not an array":      `{"ways":"use"}`,
		"without use":            `{"ways":["reveal"]}`,
		"empty ways":             `{"ways":[]}`,
		"unknown way":            `{"ways":["use","http"]}`,
		"duplicate way":          `{"ways":["use","use"]}`,
		"run without way":        `{"ways":["use"],"run":{"programs":[]}}`,
		"way without run":        `{"ways":["use","run"]}`,
		"proxy without way":      `{"ways":["use"],"proxy":{"hosts":["a.example"],"header":"X"}}`,
		"way without proxy":      `{"ways":["use","proxy"]}`,
		"run not an object":      `{"ways":["use","run"],"run":[]}`,
		"no programs":            `{"ways":["use","run"],"run":{}}`,
		"each false unbound":     `{"ways":["use","run"],"run":{"programs":[],"each":false}}`,
		"each not a bool":        `{"ways":["use","run"],"run":{"programs":[{"program":"git"}],"each":"no"}}`,
		"17 programs":            `{"ways":["use","run"],"run":{"programs":[` + strings.TrimSuffix(strings.Repeat(`{"program":"p"},`, 17), ",") + `]}}`,
		"relative path":          `{"ways":["use","run"],"run":{"programs":[{"program":"bin/git"}]}}`,
		"dot relative":           `{"ways":["use","run"],"run":{"programs":[{"program":"./git"}]}}`,
		"volume relative":        `{"ways":["use","run"],"run":{"programs":[{"program":"C:git.exe"}]}}`,
		"UNC":                    `{"ways":["use","run"],"run":{"programs":[{"program":` + js(win("", "", "srv", "share", "x.exe")) + `}]}}`,
		"double slash":           `{"ways":["use","run"],"run":{"programs":[{"program":"//srv/x"}]}}`,
		"backslash name":         `{"ways":["use","run"],"run":{"programs":[{"program":` + js(win("bin", "git")) + `}]}}`,
		"empty program":          `{"ways":["use","run"],"run":{"programs":[{"program":""}]}}`,
		"trailing slash":         `{"ways":["use","run"],"run":{"programs":[{"program":"/usr/bin/"}]}}`,
		"control character":      `{"ways":["use","run"],"run":{"programs":[{"program":"/usr/bin/gi\tt"}]}}`,
		"too long":               `{"ways":["use","run"],"run":{"programs":[{"program":"/` + long + `"}]}}`,
		"same program":           `{"ways":["use","run"],"run":{"programs":[{"program":"git"},{"program":"git"}]}}`,
		"same without case":      `{"ways":["use","run"],"run":{"programs":[{"program":"/usr/bin/git"},{"program":"/USR/BIN/GIT"}]}}`,
		"same without .exe":      `{"ways":["use","run"],"run":{"programs":[{"program":"git"},{"program":"GIT.EXE"}]}}`,
		"bare is abs's last":     `{"ways":["use","run"],"run":{"programs":[{"program":"/usr/bin/git"},{"program":"git"}]}}`,
		"bare is win abs's last": `{"ways":["use","run"],"run":{"programs":[{"program":"git"},{"program":` + js(win("C:", "Git", "git.exe")) + `}]}}`,
		"new pin":                `{"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` + strings.Repeat("a", 64) + `","path":"/usr/bin/git"}]}}`,
		"sha256 without path":    `{"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` + strings.Repeat("a", 64) + `"}]}}`,
		"env not an array":       `{"ways":["use","run"],"run":{"programs":[{"program":"git","env":"GH_HOST"}]}}`,
		"env refused name":       `{"ways":["use","run"],"run":{"programs":[{"program":"git","env":["NODE_OPTIONS"]}]}}`,
		"env lowercase":          `{"ways":["use","run"],"run":{"programs":[{"program":"git","env":["gh_host"]}]}}`,
		"env duplicate":          `{"ways":["use","run"],"run":{"programs":[{"program":"git","env":["A","A"]}]}}`,
		"33 env names":           `{"ways":["use","run"],"run":{"programs":[{"program":"git","env":[` + names(33) + `]}]}}`,
		"no hosts":               `{"ways":["use","proxy"],"proxy":{"hosts":[],"header":"X"}}`,
		"9 hosts":                `{"ways":["use","proxy"],"proxy":{"hosts":[` + hosts(9) + `],"header":"X"}}`,
		"wildcard host":          `{"ways":["use","proxy"],"proxy":{"hosts":["*.example.com"],"header":"X"}}`,
		"IPv4 host":              `{"ways":["use","proxy"],"proxy":{"hosts":["10.0.0.1"],"header":"X"}}`,
		"IPv4 short host":        `{"ways":["use","proxy"],"proxy":{"hosts":["127.1"],"header":"X"}}`,
		"hex host":               `{"ways":["use","proxy"],"proxy":{"hosts":["0x7f000001"],"header":"X"}}`,
		"IPv6 host":              `{"ways":["use","proxy"],"proxy":{"hosts":["[::1]:443"],"header":"X"}}`,
		"uppercase host":         `{"ways":["use","proxy"],"proxy":{"hosts":["API.example.com"],"header":"X"}}`,
		"port 0":                 `{"ways":["use","proxy"],"proxy":{"hosts":["a.example:0"],"header":"X"}}`,
		"port 65536":             `{"ways":["use","proxy"],"proxy":{"hosts":["a.example:65536"],"header":"X"}}`,
		"port leading zero":      `{"ways":["use","proxy"],"proxy":{"hosts":["a.example:0443"],"header":"X"}}`,
		"empty port":             `{"ways":["use","proxy"],"proxy":{"hosts":["a.example:"],"header":"X"}}`,
		"same host default port": `{"ways":["use","proxy"],"proxy":{"hosts":["a.example","a.example:443"],"header":"X"}}`,
		"label dash":             `{"ways":["use","proxy"],"proxy":{"hosts":["-a.example"],"header":"X"}}`,
		"empty label":            `{"ways":["use","proxy"],"proxy":{"hosts":["a..example"],"header":"X"}}`,
		"no header":              `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"]}}`,
		"empty header":           `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":""}}`,
		"header not a token":     `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"X Key"}}`,
		"header too long":        `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"` + strings.Repeat("x", 65) + `"}}`,
		"header Host":            `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"host"}}`,
		"header Cookie":          `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"Cookie"}}`,
		"header Content-Length":  `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"Content-Length"}}`,
		"header TE (hop)":        `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"TE"}}`,
		"header Proxy-Auth":      `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"Proxy-Authorization"}}`,
		"header Connection":      `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"Connection"}}`,
		"prefix too long":        `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"X","prefix":"` + strings.Repeat("p", 33) + `"}}`,
		"prefix control":         `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"X","prefix":"a\nb"}}`,
		"prefix non-ASCII":       `{"ways":["use","proxy"],"proxy":{"hosts":["a.example"],"header":"X","prefix":"` + "\xc3\xa9" + `"}}`,
	}
	// Characters that could make the program shown read as another: DEL, C1,
	// format (Cf: bidirectional overrides and isolates, zero width) and
	// line or paragraph separators (Zl, Zp).
	for name, r := range map[string]rune{"DEL": 0x7f, "C1 NEL": 0x85, "RLO": 0x202e, "LRI": 0x2066, "ZWSP": 0x200b,
		"ZWJ": 0x200d, "BOM": 0xfeff, "LS": 0x2028, "PS": 0x2029} {
		cases["program with "+name] = `{"ways":["use","run"],"run":{"programs":[{"program":` + js("/usr/bin/g"+string(r)+"it") + `}]}}`
	}
	// Bindings Windows reads as the same file (folded / and trailing dots).
	cases["drive / and \\ alike"] = `{"ways":["use","run"],"run":{"programs":[{"program":"C:/x/git.exe"},{"program":` + js(win("c:", "x", "git")) + `}]}}`
	cases["trailing dot"] = `{"ways":["use","run"],"run":{"programs":[{"program":"git.exe."},{"program":"git"}]}}`
	cases["trailing space on abs"] = `{"ways":["use","run"],"run":{"programs":[{"program":"git"},{"program":` + js(win("C:", "x", "git.exe ")) + `}]}}`
	// Hosts that name this computer or its network.
	for _, h := range []string{"localhost", "api", "a.localhost", "x.y.localhost", "localhost:8443"} {
		cases["host "+h] = `{"ways":["use","proxy"],"proxy":{"hosts":[` + js(h) + `],"header":"X"}}`
	}
	for name, body := range cases {
		if _, err := parseWays(t, body, nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Still accepted: a name like localhost inside a longer one, non-ASCII
	// letters in a path.
	for _, body := range []string{
		`{"ways":["use","proxy"],"proxy":{"hosts":["localhost.example.com","mylocalhost.org"],"header":"X"}}`,
		`{"ways":["use","run"],"run":{"programs":[{"program":` + js("/home/j"+string(rune(0xf8))+"rn/bin/tool") + `}]}}`,
	} {
		if _, err := parseWays(t, body, nil); err != nil {
			t.Errorf("%s refused", body)
		}
	}
}

func names(n int) string {
	var l []string
	for i := 0; i < n; i++ {
		l = append(l, `"N`+strings.Repeat("A", i)+`"`)
	}
	return strings.Join(l, ",")
}

func hosts(n int) string {
	var l []string
	for i := 0; i < n; i++ {
		l = append(l, `"h`+strings.Repeat("a", i)+`.example"`)
	}
	return strings.Join(l, ",")
}

// 0.85.3: a pin may be kept (same program, same values) or left out, never
// set or changed; changing an entry's program drops it.
func TestParseWaysPins(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	cur := &ItemWays{Version: 1, Ways: []string{WayUse, WayRun}, Run: &RunWays{Each: true,
		Programs: []Program{{Program: "git", SHA256: sha, Path: "/usr/bin/git", Env: []string{}}}}}
	keep := `{"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` + sha + `","path":"/usr/bin/git"}]}}`
	if w, err := parseWays(t, keep, cur); err != nil || w.Run.Programs[0].SHA256 != sha || w.Run.Programs[0].Path != "/usr/bin/git" {
		t.Fatalf("keep: %+v %v", w, err)
	}
	if w, err := parseWays(t, `{"ways":["use","run"],"run":{"programs":[{"program":"git"}]}}`, cur); err != nil || w.Run.Programs[0].SHA256 != "" {
		t.Fatalf("drop: %+v %v", w, err)
	}
	for name, body := range map[string]string{
		"other sha":       `{"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` + strings.Repeat("cd", 32) + `","path":"/usr/bin/git"}]}}`,
		"other path":      `{"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` + sha + `","path":"/bin/git"}]}}`,
		"other program":   `{"ways":["use","run"],"run":{"programs":[{"program":"git2","sha256":"` + sha + `","path":"/usr/bin/git"}]}}`,
		"path only":       `{"ways":["use","run"],"run":{"programs":[{"program":"git","path":"/usr/bin/git"}]}}`,
		"upper case hash": `{"ways":["use","run"],"run":{"programs":[{"program":"git","sha256":"` + strings.ToUpper(sha) + `","path":"/usr/bin/git"}]}}`,
	} {
		if _, err := parseWays(t, body, cur); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Against absent settings no pin can be kept.
	if _, err := parseWays(t, keep, nil); err == nil {
		t.Fatal("pin kept from nothing")
	}
}

// §10.11 "Widening needs the member": each widening, and narrowings that
// are not.
func TestWidens(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	cur := &ItemWays{Version: 1, Ways: []string{WayUse, WayRun, WayProxy}, Run: &RunWays{Each: true,
		Programs: []Program{{Program: "git", SHA256: sha, Path: "/usr/bin/git", Env: []string{"GH_HOST"}}, {Program: "/usr/bin/gh", Env: []string{}}}},
		Proxy: &ProxyWays{Hosts: []string{"api.example.com"}, Header: "Authorization", Prefix: "Bearer "}}
	w := func(body string) *ItemWays {
		t.Helper()
		v, err := parseWays(t, body, cur)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		return v
	}
	same := `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","sha256":"` + sha + `","path":"/usr/bin/git","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Bearer "}}`
	if Widens(cur, w(same)) {
		t.Fatal("the same settings widen")
	}
	widen := map[string]string{
		"reveal added":    `{"ways":["use","run","proxy","reveal"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"program added":   `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"},{"program":"curl"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"program changed": `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/local/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"programs empty":  `{"ways":["use","run","proxy"],"run":{"programs":[]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"env name added":  `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST","GH_REPO"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"env on other":    `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh","env":["GH_HOST"]}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"each false":      `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}],"each":false},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"host added":      `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com","up.example.com"],"header":"Authorization"}}`,
		"host port":       `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com:8443"],"header":"Authorization"}}`,
	}
	for name, body := range widen {
		if !Widens(cur, w(body)) {
			t.Errorf("%s: not a widening", name)
		}
	}
	narrow := map[string]string{
		"pin dropped":     `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Bearer "}}`,
		"program dropped": `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Bearer "}}`,
		"env dropped":     `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Bearer "}}`,
		"proxy dropped":   `{"ways":["use","run"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]}}`,
		"all dropped":     `{"ways":["use"]}`,
		"host default":    `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com:443"],"header":"Authorization","prefix":"Bearer "}}`,
		// The prefix is not a widening (printable ASCII, bound hosts), nor
		// the header's case.
		"prefix changed": `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Token "}}`,
		"header case":    `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"authorization","prefix":"Bearer "}}`,
		// An absolute entry for the bare name's file narrows.
		"bare made absolute": `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"/usr/bin/git","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Bearer "}}`,
	}
	for name, body := range narrow {
		if Widens(cur, w(body)) {
			t.Errorf("%s: a widening", name)
		}
	}
	// Changes that widen besides the spec's list (erratum): a header of
	// another name; an absolute entry made bare; a bare entry made absolute
	// with an env name the bare one did not list.
	for name, body := range map[string]string{
		"header changed":   `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"X-Api-Key"}}`,
		"absolute to bare": `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git"},{"program":"gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"absolute + env":   `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"/usr/bin/git","env":["GH_HOST","GH_REPO"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		// The bare git replaced by a name that matches it only loosely: a
		// narrowing needs the exact last element.
		"bare to /opt/x/GIT":       `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"/opt/x/GIT","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"bare to /usr/bin/git.exe": `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"/usr/bin/git.exe","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"bare to git.":             `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git.","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"bare to git with a space": `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git ","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
		"bare to GIT":              `{"ways":["use","run","proxy"],"run":{"programs":[{"program":"GIT","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`,
	} {
		if !Widens(cur, w(body)) {
			t.Errorf("%s: not a widening", name)
		}
	}
	// Binding an unbound item narrows, unless an entry lists env names (an
	// unbound item allows none).
	unbound := &ItemWays{Version: 1, Ways: []string{WayUse, WayRun}, Run: &RunWays{Each: true, Programs: []Program{}}}
	bind := func(body string) *ItemWays {
		t.Helper()
		v, err := parseWays(t, body, unbound)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		return v
	}
	if Widens(unbound, bind(`{"ways":["use","run"],"run":{"programs":[{"program":"git"},{"program":"/usr/bin/gh"}]}}`)) {
		t.Fatal("binding widens")
	}
	if !Widens(unbound, bind(`{"ways":["use","run"],"run":{"programs":[{"program":"git","env":["GH_HOST"]}]}}`)) {
		t.Fatal("binding with env does not widen")
	}
	if !Widens(unbound, bind(`{"ways":["use","run"],"run":{"programs":[{"program":"git"}],"each":false}}`)) {
		t.Fatal("binding with each false does not widen")
	}
	// From absent settings (["use"]): any other way widens, use alone not.
	if Widens(nil, w(`{"ways":["use"]}`)) || !Widens(nil, w(`{"ways":["use","reveal"]}`)) {
		t.Fatal("from absent settings")
	}
	// each true from false narrows.
	cur.Run.Each = false
	if Widens(cur, w(`{"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","env":["GH_HOST"]},{"program":"/usr/bin/gh"}]},"proxy":{"hosts":["api.example.com"],"header":"Authorization"}}`)) {
		t.Fatal("each true widens")
	}
}

// ProgramKey folds / only in a drive path (a letter, then a colon).
func TestProgramKey(t *testing.T) {
	if ProgramKey("C:/x/Git.EXE. ") != ProgramKey(win("c:", "x", "git")) {
		t.Fatal("drive path not folded")
	}
	if ProgramKey("/:/a/b") == ProgramKey(win("/:", "a", "b")) {
		t.Fatal("a POSIX path folded as a drive path")
	}
	if ProgramKey("/usr/bin/git") == ProgramKey(win("", "usr", "bin", "git")) {
		t.Fatal("a POSIX path's / folded")
	}
}

// §10.11 (0.85.3, 0.86.4): the name rule of item.run and of each entry's
// env.
func TestValidEnvName(t *testing.T) {
	for _, n := range []string{"GH_HOST", "A", "_X", "AWS_REGION", "X1", strings.Repeat("A", 64)} {
		if !ValidEnvName(n) {
			t.Errorf("%s refused", n)
		}
	}
	for _, n := range []string{"", "1A", "a", "GH-HOST", strings.Repeat("A", 65), "HOME", "USERPROFILE", "SYSTEMROOT", "PATHEXT",
		"PATH", "TMPDIR", "TEMP", "TMP", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "GIT_SSH_COMMAND", "COR_PROFILER", "COR_PROFILER_PATH",
		"CORECLR_PROFILER", "DOTNET_STARTUP_HOOKS", "NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV", "SHELL", "COMSPEC", "PSMODULEPATH",
		"PERL5OPT", "PYTHONPATH", "PYTHONSTARTUP", "RUBYOPT", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "GCONV_PATH", "XDG_CONFIG_HOME",
		"AWS_CONFIG_FILE", "KUBECONFIG", "LESSOPEN", "PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SUDO_ASKPASS", "GOFLAGS",
		"RUSTC_WRAPPER", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE", "OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES", "SSLKEYLOGFILE",
		"XDG_CONFIG_DIRS", "XDG_DATA_HOME", "XDG_DATA_DIRS", "ELECTRON_RUN_AS_NODE", "PYTHONWARNINGS", "LUA_INIT", "LUA_INIT_5_4",
		"VIMINIT", "EXINIT", "CLASSPATH", "NPM_CONFIG_REGISTRY", "PIP_INDEX_URL", "__COMPAT_LAYER", "PROGRAMFILES",
		"COMMONPROGRAMFILES", "PROGRAMDATA"} {
		if ValidEnvName(n) {
			t.Errorf("%s accepted", n)
		}
	}
}

// The wire forms: item_ways, and the catalog's programs and hosts (the
// pinned path, never the hash; never header or prefix).
func TestWaysJSON(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	w := &ItemWays{Version: 3, Ways: []string{WayUse, WayRun, WayProxy}, Run: &RunWays{Each: true,
		Programs: []Program{{Program: "git", SHA256: sha, Path: "/usr/bin/git", Env: []string{"GH_HOST"}}, {Program: "/usr/bin/gh"}}},
		Proxy: &ProxyWays{Hosts: []string{"api.example.com"}, Header: "Authorization", Prefix: "Bearer "}}
	want := `{"agent_id":"a","item_id":"i","version":3,"ways":["use","run","proxy"],"run":{"programs":[{"program":"git","sha256":"` + sha +
		`","path":"/usr/bin/git","env":["GH_HOST"]},{"program":"/usr/bin/gh","env":[]}],"each":true},"proxy":{"hosts":["api.example.com"],"header":"Authorization","prefix":"Bearer "}}`
	if got := string(w.JSON("a", "i")); got != want {
		t.Fatalf("item_ways:\n%s\n%s", got, want)
	}
	if got := string(w.CatalogPrograms()); got != `[{"program":"git","path":"/usr/bin/git","env":["GH_HOST"]},{"program":"/usr/bin/gh","env":[]}]` {
		t.Fatalf("catalog programs: %s", got)
	}
	if got := string(w.CatalogHosts()); got != `["api.example.com"]` {
		t.Fatalf("catalog hosts: %s", got)
	}
	var absent *ItemWays
	if got := string(absent.JSON("a", "i")); got != `{"agent_id":"a","item_id":"i","ways":["use"]}` {
		t.Fatalf("absent: %s", got)
	}
	if absent.CatalogPrograms() != nil || absent.CatalogHosts() != nil || !absent.Has(WayUse) || absent.Has(WayReveal) {
		t.Fatal("absent settings")
	}
	// Clone is deep; Equal compares content.
	c := w.Clone()
	c.Run.Programs[0].Env[0] = "X"
	c.Proxy.Hosts[0] = "y.example"
	c.Ways[0] = "z"
	if w.Run.Programs[0].Env[0] != "GH_HOST" || w.Proxy.Hosts[0] != "api.example.com" || w.Ways[0] != WayUse || w.Equal(c) {
		t.Fatal("clone shares")
	}
	if !w.Equal(w.Clone()) || absent.Equal(w) || w.Equal(nil) || !absent.Equal(nil) {
		t.Fatal("equal")
	}
}
