package itemspec

import (
	"reflect"
	"testing"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Owner decision a, #14596: launchers and evaluators are flagged shell and
// always referred, even pinned with each false; the card's names and the
// ones added with it.
var launchers = []string{
	"sudo", "doas", "xargs", "nohup", "timeout", "nice", "ssh", "wsl", "awk", "gawk", "mawk", "lua", "deno", "bun",
	"java", "py", "pypy", "pypy3", "tclsh", "cscript", "wscript", "mshta",
	"toybox", "ash", "rbash", "ksh93", "yash", "posh", "nu", "xonsh", "elvish", "osh", "ysh",
	"su", "runuser", "pkexec", "runas", "setsid", "stdbuf", "time", "chroot", "nsenter", "unshare", "ionice",
	"taskset", "chrt", "prlimit", "flock", "script", "watch", "systemd-run", "strace", "ltrace", "gdb", "npx", "bunx",
	"uvx", "pnpx", "pipx", "rundll32", "regsvr32", "msiexec", "conhost", "sg", "newgrp", "setpriv", "capsh",
	"setarch", "linux32", "linux64", "arch", "numactl", "cgexec", "firejail", "bwrap", "fakeroot", "faketime",
	"proxychains", "proxychains4", "torsocks", "sshpass", "unbuffer", "xvfb-run", "dbus-run-session", "dbus-launch",
	"chpst", "valgrind", "perf", "lldb", "start-stop-daemon", "daemonize", "systemd-nspawn", "machinectl",
	"flatpak-spawn", "parallel", "tmux", "screen", "caffeinate", "sandbox-exec", "open", "launchctl", "forfiles",
	"pcalua", "wt", "explorer", "schtasks", "wmic",
	"pyw", "expect", "rscript", "r", "julia", "jshell", "groovy", "jrunscript", "jjs", "csi", "fsi", "msbuild",
	"installutil", "hh", "swift", "scala", "kotlin", "clojure", "guile", "racket", "sbcl", "runghc", "ghci",
	"escript", "erl", "elixir", "iex", "qjs", "jsc",
	"run0", "sudo-rs", "gsudo", "psexec", "psexec64", "socat", "nc", "ncat", "netcat", "wine", "mono", "mintty",
	"ipython", "bpython", "jython", "micropython", "ts-node", "tsx", "irb", "jruby",
	"ld.so", "wine64", "coreutils", "genv", "gtimeout", "gxargs", "gnice", "gnohup", "gstdbuf", "gchroot", "gtime",
	"wslg", "git-bash", "git-cmd", "debian", "kali", "plink", "winrs", "mosh", "autossh", "rsh", "ssh-agent", "cdb",
	"ntsd", "windbg", "cmstp", "regasm", "regsvcs", "odbcconf", "msxsl", "bitsadmin", "scriptrunner", "tini",
	"dumb-init", "gosu", "su-exec", "runcon", "rlwrap", "eatmydata", "proot", "ccache", "xcrun", "dtrace", "dtruss",
	"systemd-cat", "systemd-inhibit", "xterm", "gnome-terminal", "konsole", "alacritty", "kitty", "at", "crontab",
	"oksh", "pdksh", "lksh", "hush", "sash", "rc", "es", "bb", "ghc", "ocaml", "raku", "gjs", "d8", "tcc", "emacs",
	"sqlite3", "dc", "truffleruby", "graalpy",
}

func TestLaunchersAreShells(t *testing.T) {
	for _, n := range launchers {
		for _, p := range []string{"/usr/bin/" + n, win("C:", "Windows", "System32", n+".exe"), win("C:", "x", n+".EXE. ")} {
			if !IsShell(p) {
				t.Errorf("%s is not flagged shell", p)
			}
		}
	}
	// Versions and variants, by prefix or suffix; and case.
	for _, p := range []string{"/usr/bin/lua5.4", "/usr/bin/luajit", "/usr/bin/pypy3.10", "/usr/bin/tclsh8.6",
		"/usr/bin/wish8.6", win("C:", "Java", "bin", "javaw.exe"), "/usr/bin/gawk-5.3.0", "/bin/bash-static",
		"/bin/mksh-static", "/usr/bin/pwsh-preview", win("C:", "x", "powershell_ise.exe"), "/usr/bin/nawk",
		"/usr/bin/goawk", "/usr/bin/original-awk", "/bin/busybox-awk", "/bin/busybox.static", "/usr/bin/zsh-5.9",
		"/bin/ksh-93", "/bin/dash-0.5", "/usr/bin/Rscript", "/usr/bin/powershell-preview",
		"/lib64/ld-linux-x86-64.so.2", "/lib/ld-musl-x86_64.so.1", "/usr/bin/qemu-x86_64",
		win("C:", "x", "ubuntu2204.exe"),
		// Versions appended to a shell's name.
		"/usr/local/bin/bash5", "/usr/bin/zsh5", "/opt/pwsh7", "/usr/bin/py3", "/usr/bin/py3.12", "/bin/sh2",
		// Windows scripts and .com by name, as .exe (owner decision b, #14880).
		win("C:", "npm", "npx.cmd"), win("C:", "npm", "PNPX.CMD"), win("C:", "npm", "tsx.cmd. "),
		win("C:", "x", "groovy.bat"), win("C:", "x", "scala.BAT"), win("C:", "x", "wsl.ps1"), win("C:", "x", "bash5.cmd"), win("C:", "x", "cmd.COM"),
		win("C:", "x", "bash5.com"),
		// Stacked endings, and the trim after each (#14925 L1, L2).
		win("C:", "x", "bash.exe.cmd"), win("C:", "x", "bash.cmd.bat"), win("C:", "x", "npx.cmd.cmd"),
		win("C:", "x", "bash.exe.com"), win("C:", "x", "npx.cmd.ps1"), win("C:", "x", "cmd.com.bat"),
		win("C:", "x", "bash .cmd"), win("C:", "x", "npx..cmd"),
		// Versions and prefixes as scripts.
		win("C:", "x", "py3.12.cmd"), win("C:", "x", "d8.cmd"), win("C:", "x", "ksh93.bat"),
		win("C:", "x", "powershell-preview.cmd")} {
		if !IsShell(p) {
			t.Errorf("%s is not flagged shell", p)
		}
	}
	for _, p := range []string{"/usr/bin/git", "/usr/bin/gh", "/usr/bin/pydoc", "/usr/bin/rsync", "/usr/bin/sshd-x", "/usr/bin/sudoers",
		win("C:", "x", "git.com"), "/usr/bin/bashful", "/usr/bin/py-spy", "/usr/bin/cmdline", "/usr/bin/x.cmdx",
		// Ordinary programs stay ordinary as scripts (owner decision b, #14779, #14880).
		win("C:", "nodejs", "npm.cmd"), win("C:", "nodejs", "npm.ps1"), win("C:", "x", "yarn.cmd"),
		win("C:", "x", "pnpm.cmd"), win("C:", "x", "tsc.cmd"), win("C:", "x", "build.bat")} {
		if IsShell(p) {
			t.Errorf("%s is flagged shell", p)
		}
	}
}

// A launcher pinned with each false, run as pinned, is still referred,
// flagged shell.
func TestPinnedLauncherReferred(t *testing.T) {
	for _, n := range launchers {
		path := "/usr/bin/" + n
		e := Program{Program: path, SHA256: hashA, Path: path}
		got := JudgeRun(&ItemWays{Version: 3, Ways: []string{WayUse, WayRun}, Run: &RunWays{Programs: []Program{e}}}, runOf(path, hashA, []string{n, "git", "push"}))
		want := RunJudgement{Entry: e, Bound: true, PinMatch: true, Refer: true, Flags: []string{FlagShell}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %+v\nwant %+v", n, got, want)
		}
	}
}

// On Windows a pinned npx.cmd with each false is referred; a pinned
// npm.cmd is not (owner decision b, #14880).
func TestPinnedScriptsByName(t *testing.T) {
	for _, c := range []struct {
		program string
		refer   bool
	}{{win("C:", "npm", "npx.cmd"), true}, {win("C:", "npm", "npm.cmd"), false}} {
		e := Program{Program: c.program, SHA256: hashA, Path: c.program}
		got := JudgeRun(&ItemWays{Version: 3, Ways: []string{WayUse, WayRun}, Run: &RunWays{Programs: []Program{e}}},
			runOf(c.program, hashA, []string{"x", "publish"}))
		want := RunJudgement{Entry: e, Bound: true, PinMatch: true, Refer: c.refer}
		if c.refer {
			want.Flags = []string{FlagShell}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %+v, want %+v", c.program, got, want)
		}
	}
}

// A "~" in the last element is refused, in an entry's program and a run's
// (Windows 8.3 short names); elsewhere in the path it is not.
func TestShortNamesRefused(t *testing.T) {
	for _, p := range []string{"GIT~1.EXE", "git~", "/usr/bin/git~1", win("C:", "PROGRA~1", "Git", "bin", "GIT~1.EXE"), "C:/x/BASH~1.EXE", "~"} {
		if ValidProgram(p) {
			t.Errorf("%s is valid", p)
		}
	}
	for _, p := range []string{"/home/a~b/bin/git", win("C:", "PROGRA~1", "Git", "bin", "git.exe"), "git"} {
		if !ValidProgram(p) {
			t.Errorf("%s is not valid", p)
		}
	}
	// A run's program.
	body := `{"op":"item.run","item_id":"i","field_id":"password","program":"C:\\PROGRA~1\\Git\\bin\\GIT~1.EXE",` +
		`"sha256":"` + hashA + `","argv":["git"],"cwd":"/","how":"env","name":"TOKEN"}`
	if _, err := parseRunBody(t, body); err == nil {
		t.Error("a run's short name parsed")
	}
	ok := `{"op":"item.run","item_id":"i","field_id":"password","program":"C:\\PROGRA~1\\Git\\bin\\git.exe",` +
		`"sha256":"` + hashA + `","argv":["git"],"cwd":"/","how":"env","name":"TOKEN"}`
	if _, err := parseRunBody(t, ok); err != nil {
		t.Errorf("a short name before the last element: %v", err)
	}
}

func parseRunBody(t *testing.T, body string) (*Run, error) {
	t.Helper()
	o, err := strictjson.ParseObject([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return ParseRun(o)
}
