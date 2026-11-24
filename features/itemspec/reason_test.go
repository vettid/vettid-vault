package itemspec

import (
	"encoding/json"
	"errors"
	"math/rand/v2"
	"strings"
	"testing"
)

// run is a run binding body with programs (JSON) and more members.
func run(programs string, more ...string) string {
	return `{"ways":["use","run"],"run":{"programs":[` + programs + `]` + strings.Join(more, "") + `}}`
}

func prog(p string, more ...string) string {
	return `{"program":` + js(p) + strings.Join(more, "") + `}`
}

func proxy(hosts, header, more string) string {
	return `{"ways":["use","proxy"],"proxy":{"hosts":[` + hosts + `],"header":` + header + more + `}}`
}

// reasonCases are refused leash.item.set bodies and the reason each gets
// (§10.11 "Why a setting is refused", 0.93.2): one or more per rule
// family, and the order of the members and of the entries.
var reasonCases = []struct{ name, body, want string }{
	{"ways missing", `{}`, "ways: missing"},
	{"ways not a list", `{"ways":"use"}`, "ways: not a list"},
	{"a way not a string", `{"ways":["use",1]}`, "ways: not a string"},
	{"an unknown way", `{"ways":["use","fly"]}`, "ways: not a known way"},
	{"a way twice", `{"ways":["use","use"]}`, "ways: repeated"},
	{"no use", `{"ways":["reveal"]}`, "ways: without use"},
	{"run without its way", `{"ways":["use"],"run":{"programs":[]}}`, "run: present without the run way"},
	{"the run way without run", `{"ways":["use","run"]}`, "run: missing for the run way"},
	{"run not an object", `{"ways":["use","run"],"run":[]}`, "run: not an object"},
	{"programs missing", `{"ways":["use","run"],"run":{}}`, "run.programs: missing"},
	{"too many programs", run(strings.TrimSuffix(strings.Repeat(prog("git")+",", MaxPrograms+1), ",")), "run.programs: too many"},
	{"an entry not an object", run(`"git"`), "run.programs[0]: not an object"},
	{"no program", run(`{"env":[]}`), "run.programs[0].program: missing"},
	{"an empty program", run(prog("")), "run.programs[0].program: empty"},
	{"a long program", run(prog("/" + strings.Repeat("a", MaxProgram))), "run.programs[0].program: too long"},
	{"a control character", run(prog("gi" + string(rune(1)) + "t")), "run.programs[0].program: holds a control or format character"},
	{"a format character", run(prog("/usr/bin/g" + string(rune(0x202e)) + "it")), "run.programs[0].program: holds a control or format character"},
	{"a tilde", run(prog("C:/Git/BASH~1.EXE")), "run.programs[0].program: holds a ~ in the last element"},
	{"not clean", run(prog("/usr//bin/git")), "run.programs[0].program: not a clean path"},
	{"a separator in a bare name", run(prog("git:x")), "run.programs[0].program: holds a separator or a colon"},
	{"no file", run(prog("/usr/bin/..  ")), "run.programs[0].program: names no file"},
	{"a bare name of dots", run(prog(". .")), "run.programs[0].program: names no file"},
	{"a pin without path", run(prog("git", `,"sha256":"`+strings.Repeat("a", 64)+`"`)), "run.programs[0].path: missing with sha256"},
	{"a path without pin", run(prog("git", `,"path":"/usr/bin/git"`)), "run.programs[0].sha256: missing with path"},
	{"a pin not recorded", run(prog("git", `,"sha256":"`+strings.Repeat("a", 64)+`","path":"/usr/bin/git"`)), "run.programs[0].sha256: not the recorded fingerprint"},
	{"env not a list", run(prog("git", `,"env":"X"`)), "run.programs[0].env: not a list"},
	{"a name of another form", run(prog("git", `,"env":["OK","bad-name"]`)), "run.programs[0].env[1]: not a valid name"},
	{"a reserved name", run(prog("git", `,"env":["OK","VETTID_IN"]`)), "run.programs[0].env[1]: VETTID_IN is reserved"},
	{"a name that loads code", run(prog("git", `,"env":["LD_PRELOAD"]`)), "run.programs[0].env[0]: LD_PRELOAD loads code"},
	{"a refused prefix, another form", run(prog("git", `,"env":["LD_pre-load"]`)), "run.programs[0].env[0]: not a valid name"},
	{"a listed name", run(prog("git", `,"env":["HTTP_PROXY"]`)), "run.programs[0].env[0]: HTTP_PROXY is not allowed"},
	{"a name twice", run(prog("git", `,"env":["OK","OK"]`)), "run.programs[0].env[1]: repeated"},
	{"two equal entries", run(prog("gh") + "," + prog("git") + "," + prog("GIT.exe")), "run.programs[2].program: matches another entry"},
	{"an absolute entry and its bare name", run(prog("/usr/bin/git") + "," + prog("git")), "run.programs[1].program: matches another entry"},
	{"each not a boolean", run(prog("git"), `,"each":"no"`), "run.each: not a boolean"},
	{"each false, no program", run("", `,"each":false`), "run.each: false without a program"},
	{"folders not a list", run(prog("git"), `,"folders":{}`), "run.folders: not a list"},
	{"a folder not absolute", run(prog("git"), `,"folders":[`+folder("home/al", false)+`]`), "run.folders[0].path: not absolute"},
	{"the root", run(prog("git"), `,"folders":[`+folder("/", false)+`]`), "run.folders[0].path: the root"},
	{"a dots-only element", run(prog("git"), `,"folders":[`+folder("/home/al/. /x", false)+`]`), "run.folders[0].path: holds an element of only dots and spaces"},
	{"write not a boolean", run(prog("git"), `,"folders":[{"path":"/home/al","write":1}]`), "run.folders[0].write: not a boolean"},
	{"two equal folders", run(prog("git"), `,"folders":[`+folder("/home/al/Work", false)+","+folder("/home/al/work", true)+`]`), "run.folders[1].path: matches another entry"},
	{"a folder inside another", run(prog("git"), `,"folders":[`+folder("/home/al/work", false)+","+folder("/home", false)+`]`), "run.folders[1].path: inside or above another entry"},
	{"a dotless i", run(prog("git"), `,"folders":[`+folder("/a/I", false)+","+folder("/a/"+string(rune(0x131)), false)+`]`), "run.folders[1].path: matches another entry"},
	{"proxy without its way", `{"ways":["use"],"proxy":{}}`, "proxy: present without the proxy way"},
	{"no hosts", proxy("", `"Authorization"`, ""), "proxy.hosts: empty"},
	{"hosts missing", `{"ways":["use","proxy"],"proxy":{"header":"Authorization"}}`, "proxy.hosts: missing"},
	{"an IP literal", proxy(`"127.0.0.1"`, `"Authorization"`, ""), "proxy.hosts[0]: not allowed for the proxy"},
	{"localhost", proxy(`"api.example.com","db.localhost"`, `"Authorization"`, ""), "proxy.hosts[1]: not allowed for the proxy"},
	{"not a host name", proxy(`"api_x.example.com"`, `"Authorization"`, ""), "proxy.hosts[0]: not a host name"},
	{"a bad port", proxy(`"api.example.com:0"`, `"Authorization"`, ""), "proxy.hosts[0]: not a valid port"},
	{"a host twice", proxy(`"api.example.com","api.example.com:443"`, `"Authorization"`, ""), "proxy.hosts[1]: matches another entry"},
	{"no header", `{"ways":["use","proxy"],"proxy":{"hosts":["api.example.com"]}}`, "proxy.header: missing"},
	{"a header not a token", proxy(`"api.example.com"`, `"X Key"`, ""), "proxy.header: not a valid header name"},
	{"a refused header", proxy(`"api.example.com"`, `"Cookie"`, ""), "proxy.header: not allowed for the proxy"},
	{"a long prefix", proxy(`"api.example.com"`, `"Authorization"`, `,"prefix":`+js(strings.Repeat("B", MaxPrefix+1))), "proxy.prefix: too long"},
	{"a prefix not ASCII", proxy(`"api.example.com"`, `"Authorization"`, `,"prefix":`+js("Bearer"+string(rune(0xe9)))), "proxy.prefix: holds a character outside printable ASCII"},
	// The first rule broken in the spec's order of members: programs
	// before each and folders, run before proxy.
	{"a program before a folder", run(prog(""), `,"folders":[`+folder("/", false)+`]`), "run.programs[0].program: empty"},
	{"two programs before each", run(prog("git")+","+prog("git"), `,"each":"no"`), "run.programs[1].program: matches another entry"},
	{"each before folders", run(prog("git"), `,"each":"no","folders":[`+folder("/", false)+`]`), "run.each: not a boolean"},
	{"run before proxy", `{"ways":["use","run","proxy"],"run":{"programs":[` + prog("") + `]},"proxy":{"hosts":[]}}`, "run.programs[0].program: empty"},
	// Within a member, the rules in "Program strings" order: the shape and
	// the clean path before the ~, the length before the shape.
	{"not clean before a tilde", run(prog("/usr//bin/BASH~1")), "run.programs[0].program: not a clean path"},
	{"a long relative folder", run(prog("git"), `,"folders":[`+folder(strings.Repeat("a", MaxProgram+1), false)+`]`), "run.folders[0].path: too long"},
	// A rule between entries is judged as each entry is read: the first
	// entry that breaks any rule is named.
	{"a clash before a later bad entry", run(prog("git") + "," + prog("git") + "," + prog("")), "run.programs[1].program: matches another entry"},
	{"nesting before a later bad folder", run(prog("git"), `,"folders":[`+folder("/a", false)+","+folder("/a/b", false)+","+folder("rel", false)+`]`), "run.folders[1].path: inside or above another entry"},
	{"a last element of dots", run(prog("/usr/bin/..")), "run.programs[0].program: names no file"},
	{"too many env names", run(prog("git", `,"env":[`+strings.TrimSuffix(strings.Repeat(`"A",`, MaxEnvNames+1), ",")+`]`)), "run.programs[0].env: too many"},
	{"too many folders", run(prog("git"), `,"folders":[`+strings.TrimSuffix(strings.Repeat(folder("/x", false)+",", MaxFolders+1), ",")+`]`), "run.folders: too many"},
	{"too many hosts", proxy(strings.TrimSuffix(strings.Repeat(`"a.example.com",`, MaxHosts+1), ","), `"Authorization"`, ""), "proxy.hosts: too many"},
	{"a folder not an object", run(prog("git"), `,"folders":["/home/al"]`), "run.folders[0]: not an object"},
	{"a folder without path", run(prog("git"), `,"folders":[{"write":true}]`), "run.folders[0].path: missing"},
	{"a non-string path", run(prog("git"), `,"folders":[{"path":7}]`), "run.folders[0].path: not a string"},
	{"a non-string sha256", run(prog("git", `,"sha256":1,"path":"/usr/bin/git"`)), "run.programs[0].sha256: not a string"},
	{"a non-string pin path", run(prog("git", `,"sha256":"`+strings.Repeat("a", 64)+`","path":1`)), "run.programs[0].path: not a string"},
	{"a non-string host", proxy(`7`, `"Authorization"`, ""), "proxy.hosts[0]: not a string"},
	{"a non-string header", proxy(`"api.example.com"`, `7`, ""), "proxy.header: not a string"},
	{"a non-string prefix", proxy(`"api.example.com"`, `"Authorization"`, `,"prefix":7`), "proxy.prefix: not a string"},
	{"an empty header", proxy(`"api.example.com"`, `""`, ""), "proxy.header: empty"},
	{"a long header", proxy(`"api.example.com"`, js(strings.Repeat("X", MaxHeader+1)), ""), "proxy.header: too long"},
	{"an empty host", proxy(`""`, `"Authorization"`, ""), "proxy.hosts[0]: empty"},
	{"a long host", proxy(js(strings.Repeat(strings.Repeat("a", 60)+".", 5)+"com"), `"Authorization"`, ""), "proxy.hosts[0]: too long"},
	{"the first bad entry", run(prog("git") + "," + prog("") + "," + prog("/a//b")), "run.programs[1].program: empty"},
}

// Each refused body gets its reason: the member and the rule broken.
func TestRefusalReasons(t *testing.T) {
	for _, c := range reasonCases {
		_, err := parseWays(t, c.body, nil)
		var r *Refusal
		if !errors.As(err, &r) || !errors.Is(err, ErrWays) {
			t.Errorf("%s: %v, want a refusal", c.name, err)
			continue
		}
		if r.Message() != c.want {
			t.Errorf("%s: %q, want %q", c.name, r.Message(), c.want)
		}
	}
}

// typedValues are the strings of a body a member typed: programs, paths,
// fingerprints, hosts, the header and the prefix, and env names of
// another form than the name rule's.
func typedValues(t *testing.T, body string) []string {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(key string, v any)
	walk = func(key string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				walk(k, e)
			}
		case []any:
			for _, e := range x {
				walk(key, e)
			}
		case string:
			switch key {
			case "program", "path", "sha256", "hosts", "header", "prefix":
				out = append(out, x)
			case "env":
				if !envNameForm(x) {
					out = append(out, x)
				}
			}
		}
	}
	walk("", v)
	return out
}

// A reason is printable ASCII, at most 200 bytes, and never holds a value
// the member typed (a variable name of the name's form, which the vault
// refuses by its own list, excepted).
func TestRefusalNeverEchoes(t *testing.T) {
	for _, c := range reasonCases {
		_, err := parseWays(t, c.body, nil)
		var r *Refusal
		if !errors.As(err, &r) {
			continue // reported by TestRefusalReasons
		}
		m := r.Message()
		if len(m) == 0 || len(m) > 200 {
			t.Errorf("%s: %d bytes", c.name, len(m))
		}
		for i := 0; i < len(m); i++ {
			if m[i] < 0x20 || m[i] > 0x7e {
				t.Errorf("%s: byte %#x in %q", c.name, m[i], m)
			}
		}
		for _, v := range typedValues(t, c.body) {
			if len(v) >= 3 && strings.Contains(m, v) {
				t.Errorf("%s: %q echoes %q", c.name, m, v)
			}
		}
	}
}

// Over generated bodies, a reason never holds a typed value. Every value
// the generator types starts with the marker "Qq": no rule holds it, and
// no variable name of the name's form can (lower case), so a "Qq" in a
// message is a value echoed.
func TestRefusalNeverEchoesGenerated(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	chars := []rune("aZ09/\\:~. -_*" + string(rune(0xe9)) + string(rune(0x131)) + string(rune(1)) + string(rune(0x202e)))
	val := func() string {
		b := []rune("Qq")
		for range rng.IntN(12) {
			b = append(b, chars[rng.IntN(len(chars))])
		}
		s := string(b)
		switch rng.IntN(4) {
		case 0:
			return "/" + s // absolute, of a kind
		case 1:
			return "C:/" + s
		}
		return s
	}
	refused := 0
	for range 20000 {
		var progs []string
		for range rng.IntN(4) {
			env := ""
			if rng.IntN(2) == 0 {
				env = `,"env":[` + js(val()) + `]`
			}
			progs = append(progs, prog(val(), env))
		}
		more := ""
		if rng.IntN(2) == 0 {
			more = `,"folders":[` + folder(val(), false) + "," + folder(val(), true) + `]`
		}
		body := run(strings.Join(progs, ","), more)
		if rng.IntN(3) == 0 {
			body = proxy(js(val())+","+js(val()), js(val()), `,"prefix":`+js(val()))
		}
		_, err := parseWays(t, body, nil)
		var r *Refusal
		if !errors.As(err, &r) {
			continue
		}
		refused++
		if m := r.Message(); strings.Contains(m, "Qq") || len(m) > 200 {
			t.Fatalf("%q from %s", m, body)
		}
	}
	if refused < 1000 {
		t.Fatalf("only %d of the generated bodies refused", refused)
	}
}
