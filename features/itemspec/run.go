package itemspec

import (
	"errors"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Limits of an item.run request (VAULT-MESSAGING §10.11).
const (
	MaxRunArgs     = 64
	MaxRunArg      = 4096
	MaxRunArgTotal = 32768
	MaxRunEnv      = 32
	MaxRunEnvValue = 4096
)

// How a run is given the secret (§10.11).
const (
	HowEnv   = "env"
	HowStdin = "stdin"
	HowFile  = "file"
)

// The approval flags of an item.run (§10.11, 0.42.0 and 0.85.3), in the
// order the approval lists them.
const (
	FlagShell             = "shell"
	FlagInlineCode        = "inline_code"
	FlagUnboundProgram    = "unbound_program"
	FlagProgramUnrecorded = "program_unrecorded"
	FlagProgramChanged    = "program_changed"
)

// Run is a parsed item.run request, without its item_id.
type Run struct {
	FieldID string
	Program string
	SHA256  string
	Argv    []string
	Cwd     string
	How     string
	Name    string
	// Env is the further variables, sorted by name.
	Env []EnvVar
}

// EnvVar is one of a run's further variables.
type EnvVar struct{ Name, Value string }

// ErrRun is a malformed item.run (bad_request).
var ErrRun = errors.New("itemspec: bad item.run")

// ParseRun parses an item.run request's members other than op and
// item_id (§10.11): field_id; program, an absolute path (the one the
// connector resolved); sha256, 64 lowercase hex digits; argv, 1–64
// strings of at most 4,096 bytes each and 32,768 in all, none holding NUL
// (no process could receive it, so what runs would differ from what the
// approval shows; other characters the app shows escaped); cwd, a clean
// absolute path; how, env, stdin or file; name, required for env and file, and
// absent for stdin (the spec is silent; a name with stdin would be shown
// for nothing); env, 0–32 further variables whose names follow the name
// rule and differ from name, with values of at most 4,096 bytes and no
// NUL. The name
// rule is checked here (bad_request); whether a name is allowed is the
// caller's (env_not_allowed).
func ParseRun(o strictjson.Object) (*Run, error) {
	r := &Run{}
	var err error
	if r.FieldID, err = o.String("field_id"); err != nil || !ValidFieldID(r.FieldID) {
		return nil, ErrRun
	}
	if r.Program, err = o.String("program"); err != nil || !IsAbsProgram(r.Program) || !ValidProgram(r.Program) {
		return nil, ErrRun
	}
	if r.SHA256, err = o.String("sha256"); err != nil || !validSHA256(r.SHA256) {
		return nil, ErrRun
	}
	args, err := o.Array("argv")
	if err != nil || len(args) == 0 || len(args) > MaxRunArgs {
		return nil, ErrRun
	}
	total := 0
	for _, raw := range args {
		a, err := strictjson.AsString(raw)
		if err != nil || len(a) > MaxRunArg || strings.IndexByte(a, 0) >= 0 {
			return nil, ErrRun
		}
		total += len(a)
		r.Argv = append(r.Argv, a)
	}
	if total > MaxRunArgTotal {
		return nil, ErrRun
	}
	if r.Cwd, err = o.String("cwd"); err != nil || !validCwd(r.Cwd) {
		return nil, ErrRun
	}
	if r.How, err = o.String("how"); err != nil || r.How != HowEnv && r.How != HowStdin && r.How != HowFile {
		return nil, ErrRun
	}
	name, hasName, err := o.OptString("name")
	if err != nil || hasName != (r.How != HowStdin) || hasName && !ValidEnvName(name) {
		return nil, ErrRun
	}
	r.Name = name
	if raw, present, err := o.OptObjectRaw("env"); err != nil {
		return nil, ErrRun
	} else if present {
		env, err := strictjson.AsObject(raw)
		if err != nil || len(env) > MaxRunEnv {
			return nil, ErrRun
		}
		for n, rv := range env {
			v, err := strictjson.AsString(rv)
			if err != nil || !ValidEnvName(n) || n == r.Name || len(v) > MaxRunEnvValue || strings.IndexByte(v, 0) >= 0 {
				return nil, ErrRun
			}
			r.Env = append(r.Env, EnvVar{n, v})
		}
		sort.Slice(r.Env, func(i, j int) bool { return r.Env[i].Name < r.Env[j].Name })
	}
	return r, nil
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// validCwd: a clean absolute path (cleanPath; the root itself included),
// at most MaxProgram bytes of UTF-8, with no character ValidProgram
// refuses (the bounds are not in the spec).
func validCwd(p string) bool {
	return IsAbsProgram(p) && len(p) <= MaxProgram && utf8.ValidString(p) && showable(p) && cleanPath(p, true)
}

// MatchProgram returns the entry of programs a run's program matches
// (§10.11): an absolute entry when it equals program exactly, a bare entry
// when it equals program's last path element exactly (on Windows the
// member writes git.exe, not git). The settings' duplicate rule (0.85.3)
// leaves at most one match; the first is returned.
func MatchProgram(programs []Program, program string) (Program, bool) {
	last := LastElement(program)
	for _, p := range programs {
		if IsAbsProgram(p.Program) && p.Program == program || !IsAbsProgram(p.Program) && p.Program == last {
			return p, true
		}
	}
	return Program{}, false
}

// shells are the programs flagged shell and always referred (§10.11): the
// shells, and (owner decision a, #14596) the launchers, which run another
// program named in their argv, and the evaluators, which run code given in
// it, so that a pinned one cannot run whatever argv an agent picks.
var shells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "fish": true, "csh": true,
	"tcsh": true, "busybox": true, "env": true, "cmd": true, "powershell": true, "pwsh": true,
	// Shells of the same kind, added with #14596.
	"toybox": true, "ash": true, "rbash": true, "ksh93": true, "yash": true, "posh": true, "nu": true, "xonsh": true,
	"elvish": true, "osh": true, "ysh": true,
	// Launchers (#14596).
	"sudo": true, "doas": true, "xargs": true, "nohup": true, "timeout": true, "nice": true, "ssh": true, "wsl": true,
	// Launchers of the same kind, added with #14596.
	"su": true, "runuser": true, "pkexec": true, "runas": true, "setsid": true, "stdbuf": true, "time": true,
	"chroot": true, "nsenter": true, "unshare": true, "ionice": true, "taskset": true, "chrt": true, "prlimit": true,
	"flock": true, "script": true, "watch": true, "systemd-run": true, "strace": true, "ltrace": true, "gdb": true,
	"npx": true, "bunx": true, "uvx": true, "pnpx": true, "pipx": true, "rundll32": true, "regsvr32": true,
	"msiexec": true, "conhost": true, "sg": true, "newgrp": true, "setpriv": true, "capsh": true, "setarch": true,
	"linux32": true, "linux64": true, "arch": true, "numactl": true, "cgexec": true, "firejail": true, "bwrap": true,
	"fakeroot": true, "faketime": true, "proxychains": true, "proxychains4": true, "torsocks": true, "sshpass": true,
	"unbuffer": true, "xvfb-run": true, "dbus-run-session": true, "dbus-launch": true, "chpst": true,
	"valgrind": true, "perf": true, "lldb": true, "start-stop-daemon": true, "daemonize": true,
	"systemd-nspawn": true, "machinectl": true, "flatpak-spawn": true, "parallel": true, "tmux": true,
	"screen": true, "caffeinate": true, "sandbox-exec": true, "open": true, "launchctl": true, "forfiles": true,
	"pcalua": true, "wt": true, "explorer": true, "schtasks": true, "wmic": true,
	"run0": true, "sudo-rs": true, "gsudo": true, "psexec": true, "psexec64": true, "socat": true, "nc": true,
	"ncat": true, "netcat": true, "wine": true, "mono": true, "mintty": true,
	// Evaluators (#14596).
	"awk": true, "gawk": true, "mawk": true, "deno": true, "bun": true, "py": true, "cscript": true, "wscript": true,
	"mshta": true,
	// Evaluators of the same kind, added with #14596.
	"pyw": true, "expect": true, "rscript": true, "r": true, "julia": true, "jshell": true, "groovy": true,
	"jrunscript": true, "jjs": true, "csi": true, "fsi": true, "msbuild": true, "installutil": true, "hh": true,
	"swift": true, "scala": true, "kotlin": true, "clojure": true, "guile": true, "racket": true, "sbcl": true,
	"runghc": true, "ghci": true, "escript": true, "erl": true, "elixir": true, "iex": true, "qjs": true, "jsc": true,
	"ipython": true, "bpython": true, "jython": true, "micropython": true, "ts-node": true, "tsx": true, "irb": true,
	"jruby": true,
	// Added in the second round (#14676): loaders, multicall binaries,
	// Homebrew's g-prefixed coreutils, WSL and Git for Windows launchers,
	// remote shells, Windows debuggers and script hosts, process wrappers,
	// terminals and schedulers, and more shells and evaluators.
	"ld.so": true, "wine64": true, "coreutils": true, "genv": true, "gtimeout": true, "gxargs": true, "gnice": true,
	"gnohup": true, "gstdbuf": true, "gchroot": true, "gtime": true, "wslg": true, "git-bash": true, "git-cmd": true,
	"debian": true, "kali": true, "plink": true, "winrs": true, "mosh": true, "autossh": true, "rsh": true,
	"ssh-agent": true, "cdb": true, "ntsd": true, "windbg": true, "cmstp": true, "regasm": true, "regsvcs": true,
	"odbcconf": true, "msxsl": true, "bitsadmin": true, "scriptrunner": true, "tini": true, "dumb-init": true,
	"gosu": true, "su-exec": true, "runcon": true, "rlwrap": true, "eatmydata": true, "proot": true, "ccache": true,
	"xcrun": true, "dtrace": true, "dtruss": true, "systemd-cat": true, "systemd-inhibit": true, "xterm": true,
	"gnome-terminal": true, "konsole": true, "alacritty": true, "kitty": true, "at": true, "crontab": true,
	"oksh": true, "pdksh": true, "lksh": true, "hush": true, "sash": true, "rc": true, "es": true,
	"bb": true, "ghc": true, "ocaml": true, "raku": true, "gjs": true, "d8": true, "tcc": true, "emacs": true,
	"sqlite3": true, "dc": true, "truffleruby": true, "graalpy": true,
}

// versionedShells are the shells whose names also come with a version
// number appended (bash5, zsh5, pwsh7, py3, ksh93): flagged with any
// trailing digits and dots removed, and only these, so the rule stays
// tight.
var versionedShells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "mksh": true, "oksh": true, "pdksh": true,
	"lksh": true, "fish": true, "csh": true, "tcsh": true, "ash": true, "yash": true, "pwsh": true,
	"powershell": true, "py": true, "pyw": true,
}

// shellPrefixes are shells (flag shell, always referred) whose names carry
// versions or variants (§10.11, #14596): lua5.4 and luajit, pypy3.10,
// tclsh8.6, wish8.6, javaw, busybox.static, gawk-5.3.0, bash-static,
// zsh-5.9, pwsh-preview, powershell_ise, ld-linux-x86-64.so.2,
// ld-musl-x86_64.so.1, qemu-x86_64, ubuntu2204. By prefix, as the
// interpreters: looser only adds flags.
var shellPrefixes = []string{"lua", "pypy", "tclsh", "wish", "java", "busybox", "gawk-", "bash-", "mksh-", "zsh-", "ksh-",
	"dash-", "pwsh-", "powershell_", "powershell-", "ld-linux", "ld-musl", "qemu-", "ubuntu"}

// scriptExts are the endings of Windows scripts, which run in cmd.exe or
// PowerShell by nature (npx.cmd, groovy.bat, x.ps1): flagged shell
// whatever their name (#14676).
var scriptExts = []string{".cmd", ".bat", ".ps1"}

// shellSuffixes: any awk (nawk, goawk, original-awk, busybox-awk).
var shellSuffixes = []string{"awk"}

// The list is best-effort: a program not on it that runs what its argv
// names (git -c core.sshCommand=..., rsync -e, find -exec) is judged by
// its binding like any other.

var interpreters = []string{"python", "node", "perl", "ruby", "php", "osascript"}

var inlineArgs = map[string]bool{"-c": true, "-e": true, "-E": true, "-r": true, "--eval": true}

// programBase is a program's last path element as the flags compare it:
// in any case and without .exe (§10.11), and, more loosely still, without
// the trailing dots and spaces Windows drops (ProgramKey): looser here only
// adds flags.
func programBase(program string) string { return ProgramKey(LastElement(program)) }

// flagBase is programBase also without a final .com (Windows runs x.com
// for x as it runs x.exe); for the flags only, never a binding's key.
func flagBase(program string) string {
	b := programBase(program)
	return strings.TrimRight(strings.TrimSuffix(b, ".com"), " .")
}

// IsShell reports whether program is one of the shells, launchers or
// evaluators (§10.11: flag shell).
func IsShell(program string) bool {
	for _, e := range scriptExts {
		if strings.HasSuffix(programBase(program), e) {
			return true
		}
	}
	b := flagBase(program)
	if shells[b] || versionedShells[strings.TrimRight(b, "0123456789.")] {
		return true
	}
	for _, p := range shellPrefixes {
		if strings.HasPrefix(b, p) {
			return true
		}
	}
	for _, p := range shellSuffixes {
		if strings.HasSuffix(b, p) {
			return true
		}
	}
	return false
}

// IsInterpreter reports whether program's base starts with one of the
// interpreters' names (§10.11).
func IsInterpreter(program string) bool {
	b := flagBase(program)
	for _, i := range interpreters {
		if strings.HasPrefix(b, i) {
			return true
		}
	}
	return false
}

// RunJudgement is how an item's settings judge a run (§10.11).
type RunJudgement struct {
	// Refusal is way_not_allowed, program_not_allowed or env_not_allowed,
	// or "" when the run is not refused; Names are env_not_allowed's
	// refused names, sorted.
	Refusal string
	Names   []string
	// Entry is the matched program entry, Bound whether programs is not
	// empty (so Entry is set).
	Entry Program
	Bound bool
	// PinMatch: the run matches the entry's recorded pin.
	PinMatch bool
	// Refer: the run goes to an app; Flags are its approval's, and
	// PreviousSHA256 and PreviousPath the recorded pin, with
	// program_changed.
	Refer          bool
	Flags          []string
	PreviousSHA256 string
	PreviousPath   string
}

// RecordsPin reports whether approving the run records its pin: it is
// flagged program_unrecorded or program_changed (§10.11, 0.85.3).
func (j RunJudgement) RecordsPin() bool {
	for _, f := range j.Flags {
		if f == FlagProgramUnrecorded || f == FlagProgramChanged {
			return true
		}
	}
	return false
}

// JudgeRun judges r under the settings w (nil: ["use"]) (§10.11):
//   - refused way_not_allowed without the run way;
//   - refused program_not_allowed when programs is not empty and r's
//     program matches none of it;
//   - refused env_not_allowed when r sets a variable the matched entry's
//     env does not list, or any variable when programs is empty;
//   - otherwise referred when each is true, programs is empty, the run
//     does not match the entry's pin, or the program is a shell or an
//     interpreter, with its flags.
func JudgeRun(w *ItemWays, r *Run) RunJudgement {
	var j RunJudgement
	if !w.Has(WayRun) || w.Run == nil {
		j.Refusal = "way_not_allowed"
		return j
	}
	j.Bound = len(w.Run.Programs) > 0
	if j.Bound {
		e, ok := MatchProgram(w.Run.Programs, r.Program)
		if !ok {
			return RunJudgement{Refusal: "program_not_allowed"}
		}
		j.Entry = e
	}
	var names []string
	for _, v := range r.Env {
		if !j.Bound || !contains(j.Entry.Env, v.Name) {
			names = append(names, v.Name)
		}
	}
	if len(names) > 0 {
		sort.Strings(names)
		return RunJudgement{Refusal: "env_not_allowed", Names: names}
	}
	shell, interp := IsShell(r.Program), IsInterpreter(r.Program)
	if shell {
		j.Flags = append(j.Flags, FlagShell)
	}
	if interp {
		for _, a := range r.Argv[1:] {
			if inlineArgs[a] {
				j.Flags = append(j.Flags, FlagInlineCode)
				break
			}
		}
	}
	if !j.Bound {
		j.Flags = append(j.Flags, FlagUnboundProgram)
	} else if j.Entry.SHA256 == "" {
		j.Flags = append(j.Flags, FlagProgramUnrecorded)
	} else if r.SHA256 != j.Entry.SHA256 || r.Program != j.Entry.Path {
		j.Flags = append(j.Flags, FlagProgramChanged)
		j.PreviousSHA256, j.PreviousPath = j.Entry.SHA256, j.Entry.Path
	} else {
		j.PinMatch = true
	}
	j.Refer = w.Run.Each || !j.Bound || !j.PinMatch || shell || interp
	return j
}

// WithPin returns a copy of w whose entry for program (an entry's own
// program, as JudgeRun matched it) has the pin sha256 and path (§10.11,
// 0.85.3: what the member approved), and false if w has no such entry.
// The version and time are the caller's.
func WithPin(w *ItemWays, entry, sha256, path string) (*ItemWays, bool) {
	if w == nil || w.Run == nil {
		return nil, false
	}
	n := w.Clone()
	for i := range n.Run.Programs {
		if n.Run.Programs[i].Program == entry {
			n.Run.Programs[i].SHA256, n.Run.Programs[i].Path = sha256, path
			return n, true
		}
	}
	return nil, false
}
