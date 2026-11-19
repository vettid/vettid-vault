package itemspec

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Ways to use a secret (VAULT-MESSAGING §10.11, 0.42.0; 0.85.3): for each
// agent and each item that agent's rules include, the ways it allows. The
// items feature keeps them with the agent's inclusions of the item; the
// leash feature parses, checks and enforces them.

// The ways, in their wire order.
const (
	WayUse    = "use"
	WayRun    = "run"
	WayProxy  = "proxy"
	WayReveal = "reveal"
)

var wayOrder = []string{WayUse, WayRun, WayProxy, WayReveal}

// Limits of the settings (§10.11). MaxProgram is not in the spec (it is
// silent): item.run's bound on one argument, 4,096 bytes.
const (
	MaxPrograms = 16
	MaxEnvNames = 32
	MaxHosts    = 8
	MaxProgram  = 4096
	MaxHeader   = 64
	MaxPrefix   = 32
	MaxDNSName  = 253
)

// Program is one entry of an item's run binding. SHA256 and Path are the
// pin the vault records when the member approves a run flagged
// program_unrecorded or program_changed (0.85.3): both or neither.
type Program struct {
	Program string   `json:"program"`
	SHA256  string   `json:"sha256,omitempty"`
	Path    string   `json:"path,omitempty"`
	Env     []string `json:"env"`
}

// RunWays are the settings of the run way.
type RunWays struct {
	Programs []Program `json:"programs"`
	Each     bool      `json:"each"`
}

// ProxyWays are the settings of the proxy way.
type ProxyWays struct {
	Hosts  []string `json:"hosts"`
	Header string   `json:"header"`
	Prefix string   `json:"prefix"`
}

// ItemWays are one agent's settings for one item. Absent settings (a nil
// *ItemWays) mean ["use"].
type ItemWays struct {
	Version uint64     `json:"version"`
	Ways    []string   `json:"ways"`
	Run     *RunWays   `json:"run,omitempty"`
	Proxy   *ProxyWays `json:"proxy,omitempty"`
	Updated time.Time  `json:"updated"`
}

// AgentItemWays is one included item's settings (nil: absent).
type AgentItemWays struct {
	ItemID string
	Ways   *ItemWays
}

// AgentEntry is one item of an agent's catalog: its metadata and its
// settings (nil: absent).
type AgentEntry struct {
	Meta Meta
	Ways *ItemWays
}

// Has reports whether w allows way; absent settings allow only use.
func (w *ItemWays) Has(way string) bool {
	if w == nil {
		return way == WayUse
	}
	return contains(w.Ways, way)
}

// WayList is the ways w allows, in wire order (["use"] for absent
// settings).
func (w *ItemWays) WayList() []string {
	if w == nil {
		return []string{WayUse}
	}
	return append([]string(nil), w.Ways...)
}

// Clone returns a deep copy (nil for nil).
func (w *ItemWays) Clone() *ItemWays {
	if w == nil {
		return nil
	}
	c := *w
	c.Ways = append([]string(nil), w.Ways...)
	if w.Run != nil {
		r := *w.Run
		r.Programs = make([]Program, len(w.Run.Programs))
		for i, p := range w.Run.Programs {
			p.Env = append([]string{}, p.Env...)
			r.Programs[i] = p
		}
		c.Run = &r
	}
	if w.Proxy != nil {
		p := *w.Proxy
		p.Hosts = append([]string(nil), w.Proxy.Hosts...)
		c.Proxy = &p
	}
	return &c
}

// Equal reports whether two settings are the same (nil equals nil only).
func (w *ItemWays) Equal(o *ItemWays) bool {
	if w == nil || o == nil {
		return w == nil && o == nil
	}
	return string(w.JSON("", "")) == string(o.JSON("", ""))
}

// JSON is the item_ways wire form (§10.11) for agent and item: version and
// updated_at only for stored settings.
func (w *ItemWays) JSON(agent, item string) []byte {
	b := strictjson.NewBuilder().String("agent_id", agent).String("item_id", item)
	if w != nil {
		b.Uint("version", w.Version)
	}
	b.Raw("ways", StrList(w.WayList()))
	if w != nil && w.Run != nil {
		b.Raw("run", strictjson.NewBuilder().Raw("programs", programsJSON(w.Run.Programs, true)).Bool("each", w.Run.Each).Bytes())
	}
	if w != nil && w.Proxy != nil {
		b.Raw("proxy", strictjson.NewBuilder().Raw("hosts", StrList(w.Proxy.Hosts)).String("header", w.Proxy.Header).
			String("prefix", w.Proxy.Prefix).Bytes())
	}
	if w != nil && !w.Updated.IsZero() {
		b.String("updated_at", envelope.FormatTS(w.Updated))
	}
	return b.Bytes()
}

// CatalogPrograms is the catalog's programs (§10.11, 0.85.3): {program,
// env, path?}, the pinned path when there is a pin, never the hash.
func (w *ItemWays) CatalogPrograms() []byte {
	if w == nil || w.Run == nil {
		return nil
	}
	return programsJSON(w.Run.Programs, false)
}

// CatalogHosts is the catalog's hosts (never header or prefix).
func (w *ItemWays) CatalogHosts() []byte {
	if w == nil || w.Proxy == nil {
		return nil
	}
	return StrList(w.Proxy.Hosts)
}

func programsJSON(ps []Program, withHash bool) []byte {
	arr := []byte{'['}
	for i, p := range ps {
		if i > 0 {
			arr = append(arr, ',')
		}
		b := strictjson.NewBuilder().String("program", p.Program)
		if withHash && p.SHA256 != "" {
			b.String("sha256", p.SHA256)
		}
		if p.Path != "" {
			b.String("path", p.Path)
		}
		arr = append(arr, b.Raw("env", StrList(nonNilStrs(p.Env))).Bytes()...)
	}
	return append(arr, ']')
}

func nonNilStrs(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

// --- parsing (leash.item.set) ---

// ParseWays parses the ways, run and proxy members of a leash.item.set
// body strictly (§10.11), against cur, the item's current settings (nil:
// absent). A pin (sha256 and path) may only be kept from cur's entry with
// the same program, or left out; the vault records new pins itself
// (0.85.3). Errors are ErrWays.
func ParseWays(o strictjson.Object, cur *ItemWays) (*ItemWays, error) {
	raw, err := o.Array("ways")
	if err != nil {
		return nil, ErrWays
	}
	seen := map[string]bool{}
	for _, r := range raw {
		s, err := strictjson.AsString(r)
		if err != nil || !contains(wayOrder, s) || seen[s] {
			return nil, ErrWays
		}
		seen[s] = true
	}
	if !seen[WayUse] {
		return nil, ErrWays // ways always holds use
	}
	w := &ItemWays{}
	for _, way := range wayOrder {
		if seen[way] {
			w.Ways = append(w.Ways, way) // a set: kept in wire order
		}
	}
	runRaw, hasRun, err := o.OptObjectRaw("run")
	if err != nil || hasRun != seen[WayRun] {
		return nil, ErrWays // present exactly when ways holds run
	}
	if hasRun {
		if w.Run, err = parseRun(runRaw, cur); err != nil {
			return nil, err
		}
	}
	proxyRaw, hasProxy, err := o.OptObjectRaw("proxy")
	if err != nil || hasProxy != seen[WayProxy] {
		return nil, ErrWays
	}
	if hasProxy {
		if w.Proxy, err = parseProxy(proxyRaw); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// ErrWays is a leash.item.set body that breaks a rule of §10.11
// (bad_request).
var ErrWays = errors.New("itemspec: bad item_ways")

func parseRun(raw []byte, cur *ItemWays) (*RunWays, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, ErrWays
	}
	arr, err := o.Array("programs")
	if err != nil || len(arr) > MaxPrograms {
		return nil, ErrWays
	}
	r := &RunWays{Programs: []Program{}, Each: true}
	if _, present := o["each"]; present {
		if r.Each, err = o.Bool("each"); err != nil {
			return nil, ErrWays
		}
	}
	var old []Program
	if cur != nil && cur.Run != nil {
		old = cur.Run.Programs
	}
	for _, pr := range arr {
		p, err := parseProgram(pr, old)
		if err != nil {
			return nil, err
		}
		r.Programs = append(r.Programs, p)
	}
	if !r.Each && len(r.Programs) == 0 {
		return nil, ErrWays // each: false only for a bound item
	}
	// (0.85.3) No two entries match the same path: compared without case
	// and without a final .exe, no two entries are equal, and no bare name
	// equals an absolute entry's last path element.
	keys := map[string]bool{}
	for _, p := range r.Programs {
		k := ProgramKey(p.Program)
		if keys[k] {
			return nil, ErrWays
		}
		keys[k] = true
	}
	for _, p := range r.Programs {
		if IsAbsProgram(p.Program) && hasBare(r.Programs, ProgramKey(LastElement(p.Program))) {
			return nil, ErrWays
		}
	}
	return r, nil
}

func hasBare(ps []Program, key string) bool {
	for _, p := range ps {
		if !IsAbsProgram(p.Program) && ProgramKey(p.Program) == key {
			return true
		}
	}
	return false
}

func parseProgram(raw []byte, old []Program) (Program, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return Program{}, ErrWays
	}
	p := Program{Env: []string{}}
	if p.Program, err = o.String("program"); err != nil || !ValidProgram(p.Program) {
		return Program{}, ErrWays
	}
	sha, hasSHA, err1 := o.OptString("sha256")
	path, hasPath, err2 := o.OptString("path")
	if err1 != nil || err2 != nil || hasSHA != hasPath {
		return Program{}, ErrWays
	}
	if hasSHA {
		// Kept only: the same program, the same recorded values (0.85.3).
		kept := false
		for _, q := range old {
			if q.Program == p.Program && q.SHA256 != "" && q.SHA256 == sha && q.Path == path {
				kept = true
			}
		}
		if !kept {
			return Program{}, ErrWays
		}
		p.SHA256, p.Path = sha, path
	}
	if envRaw, present, err := o.OptArray("env"); err != nil || len(envRaw) > MaxEnvNames {
		return Program{}, ErrWays
	} else if present {
		seen := map[string]bool{}
		for _, r := range envRaw {
			n, err := strictjson.AsString(r)
			if err != nil || !ValidEnvName(n) || seen[n] {
				return Program{}, ErrWays
			}
			seen[n] = true
			p.Env = append(p.Env, n)
		}
	}
	return p, nil
}

func parseProxy(raw []byte) (*ProxyWays, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, ErrWays
	}
	arr, err := o.Array("hosts")
	if err != nil || len(arr) == 0 || len(arr) > MaxHosts {
		return nil, ErrWays
	}
	p := &ProxyWays{}
	seen := map[string]bool{}
	for _, r := range arr {
		h, err := strictjson.AsString(r)
		if err != nil || !ValidProxyHost(h) || seen[HostKey(h)] {
			return nil, ErrWays
		}
		seen[HostKey(h)] = true
		p.Hosts = append(p.Hosts, h)
	}
	if p.Header, err = o.String("header"); err != nil || !ValidProxyHeader(p.Header) {
		return nil, ErrWays
	}
	if pre, present, err := o.OptString("prefix"); err != nil || present && !validPrefix(pre) {
		return nil, ErrWays
	} else if present {
		p.Prefix = pre
	}
	return p, nil
}

// --- widening (§10.11 "Widening needs the member") ---

// Widens reports whether next allows more than cur (nil: ["use"]): a way,
// a program or a host added, programs emptied, a name added to an entry's
// env (0.85.3), or each set to false. Such a change needs the credential's
// unlock window. Dropping a pin, a program, a host, a name or a way, and
// each set to true, only narrow.
//
// Binding an unbound item (programs from empty to a list) narrows, unless
// an entry lists env names: an unbound item allows no env at all. An
// absolute entry whose last element is exactly a bare entry's program
// narrows too (the bare name matched it and more), unless it lists a name
// the bare entry did not. Only an exact last element counts: a bare name
// matches "its last path element" (§10.11), and the looser comparison of
// the no-two-match rule (case, .exe, trailing dots) must not decide a
// narrowing.
//
// A change of the proxy's header is a widening (not in the spec's list;
// an erratum): some hosts echo or log a header, so a new header name can
// send the value somewhere the member did not approve. Only its case is
// free (header names compare without case). A change of the prefix is
// not: it is printable ASCII only, and the value still goes only to the
// bound hosts.
func Widens(cur, next *ItemWays) bool {
	for _, way := range next.WayList() {
		if !cur.Has(way) {
			return true
		}
	}
	if next.Run != nil && cur != nil && cur.Run != nil {
		if len(next.Run.Programs) == 0 && len(cur.Run.Programs) > 0 {
			return true // unbound: any program
		}
		unbound := len(cur.Run.Programs) == 0
		for _, p := range next.Run.Programs {
			q, ok := findProgram(cur.Run.Programs, p.Program)
			switch {
			case ok:
			case unbound:
				q = Program{} // bound now: narrower, with no env allowed before
			case IsAbsProgram(p.Program):
				// A bare entry this absolute one narrows, if there is one.
				if q, ok = findBare(cur.Run.Programs, LastElement(p.Program)); !ok {
					return true
				}
			default:
				return true // a program added (a changed program is one added)
			}
			for _, n := range p.Env {
				if !contains(q.Env, n) {
					return true
				}
			}
		}
		if !next.Run.Each && cur.Run.Each {
			return true
		}
	}
	if next.Proxy != nil && cur != nil && cur.Proxy != nil && !strings.EqualFold(next.Proxy.Header, cur.Proxy.Header) {
		return true
	}
	if next.Proxy != nil && cur != nil && cur.Proxy != nil {
		have := map[string]bool{}
		for _, h := range cur.Proxy.Hosts {
			have[HostKey(h)] = true
		}
		for _, h := range next.Proxy.Hosts {
			if !have[HostKey(h)] {
				return true
			}
		}
	}
	return false
}

// findBare finds the bare entry whose program is exactly name.
func findBare(ps []Program, name string) (Program, bool) {
	for _, p := range ps {
		if !IsAbsProgram(p.Program) && p.Program == name {
			return p, true
		}
	}
	return Program{}, false
}

func findProgram(ps []Program, program string) (Program, bool) {
	for _, p := range ps {
		if p.Program == program {
			return p, true
		}
	}
	return Program{}, false
}

// --- the name rule and the bindings' values ---

const backslash = byte(92)

// IsAbsProgram reports whether p is an absolute path: POSIX "/…" or a
// Windows drive path "X:\…" or "X:/…". (The spec is silent on the forms;
// a UNC path is neither, and the connector refuses it, AGENT-PLAN §4.9.)
func IsAbsProgram(p string) bool {
	if strings.HasPrefix(p, "/") {
		return !strings.HasPrefix(p, "//")
	}
	return len(p) >= 3 && (p[0] >= 'A' && p[0] <= 'Z' || p[0] >= 'a' && p[0] <= 'z') && p[1] == ':' &&
		(p[2] == '/' || p[2] == backslash) && !(len(p) > 3 && (p[3] == '/' || p[3] == backslash))
}

// ValidProgram reports whether p is a binding's program: an absolute path
// or a bare name (no separator and no volume), at most MaxProgram bytes of
// UTF-8 without control characters, nor format characters (Unicode Cf:
// bidirectional overrides and isolates, zero-width characters) or line
// and paragraph separators (Zl, Zp), which could make the program shown
// on the phone read as another (the bounds are not in the spec). An
// absolute path is also a clean one (cleanPath).
func ValidProgram(p string) bool {
	if p == "" || len(p) > MaxProgram || !utf8.ValidString(p) || !showable(p) {
		return false
	}
	if IsAbsProgram(p) {
		return cleanPath(p, false) && strings.TrimRight(LastElement(p), " .") != ""
	}
	return !strings.ContainsAny(p, "/:"+string(rune(backslash))) && strings.Trim(p, " .") != ""
}

// cleanPath reports whether an absolute path p (IsAbsProgram) names its
// file the one way (the spec is silent): after its root ("/", or "X:\" or
// "X:/"), no empty element (a doubled or trailing separator), no "." or
// ".." element, and no ":" (on Windows a ":" after the drive names a
// stream of a file, "cmd.exe::$DATA"; refused on every system, so the
// vault needs no knowledge of the connector's). root allows the root
// itself ("/", "C:\"), as a cwd may be.
func cleanPath(p string, root bool) bool {
	rest := p[1:]
	if p[0] != '/' {
		rest = p[3:] // "X:\" or "X:/"
	}
	if rest == "" {
		return root
	}
	start := 0
	for i := 0; i <= len(rest); i++ {
		if i < len(rest) && rest[i] != '/' && rest[i] != backslash {
			continue
		}
		e := rest[start:i]
		if e == "" || e == "." || e == ".." || strings.Contains(e, ":") {
			return false
		}
		start = i + 1
	}
	return true
}

// showable reports whether p has none of the characters a path shown on
// the phone may not hold: control characters (C0, DEL, C1), format
// characters (Unicode Cf) and line and paragraph separators (Zl, Zp).
func showable(p string) bool {
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r >= 0x80 && r < 0xa0 || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return false
		}
	}
	return true
}

// LastElement is a path's last element (after the last / or \).
func LastElement(p string) string {
	if i := strings.LastIndexAny(p, "/"+string(rune(backslash))); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ProgramKey is how bindings are compared (0.85.3): without case and
// without a final .exe. As Windows reads them, a drive path's / is \, and
// trailing dots and spaces of the last element are dropped (C:/x/git.exe.
// and c:\x\GIT name one file).
func ProgramKey(p string) string {
	k := strings.ToLower(p)
	dir, last := "", k
	if i := strings.LastIndexAny(k, "/"+string(rune(backslash))); i >= 0 {
		dir, last = k[:i+1], k[i+1:]
	}
	if len(dir) >= 3 && dir[0] >= 'a' && dir[0] <= 'z' && dir[1] == ':' { // a drive path (IsAbsProgram; k is lower case)
		dir = strings.ReplaceAll(dir, "/", string(rune(backslash)))
	}
	last = strings.TrimRight(last, " .")
	last = strings.TrimRight(strings.TrimSuffix(last, ".exe"), " .")
	return dir + last
}

var (
	envExact = map[string]bool{}
	// envPrefixes are names refused by their start (§10.11).
	envPrefixes = []string{"LD_", "DYLD_", "GIT_", "COR_PROFILER", "CORECLR_", "DOTNET_", "LUA_INIT_", "NPM_CONFIG_", "PIP_"}
)

func init() {
	for _, n := range []string{
		// The connector's minimal environment (AGENT-PLAN §4.9), on every
		// system; Windows names compared upper-case, as the name rule's
		// pattern only admits them.
		"HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
		"USERPROFILE", "USERNAME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
		"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATHEXT",
		"PATH", "TMPDIR", "TEMP", "TMP",
		// Names that make a program load or run other code (0.85.3).
		"NODE_OPTIONS", "NODE_PATH", "BASH_ENV", "ENV", "SHELL", "COMSPEC", "PSMODULEPATH",
		"PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME",
		"PYTHONUSERBASE", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
		"GCONV_PATH", "XDG_CONFIG_HOME", "AWS_CONFIG_FILE", "KUBECONFIG",
		// Owner decisions of 2026-11-05.
		"LESSOPEN", "PAGER", "EDITOR", "VISUAL", "SSH_ASKPASS", "SUDO_ASKPASS", "GOFLAGS", "RUSTC_WRAPPER",
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
		"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
		// 0.86.4.
		"OPENSSL_CONF", "OPENSSL_ENGINES", "OPENSSL_MODULES", "SSLKEYLOGFILE",
		"XDG_CONFIG_DIRS", "XDG_DATA_HOME", "XDG_DATA_DIRS", "ELECTRON_RUN_AS_NODE", "PYTHONWARNINGS",
		"LUA_INIT", "VIMINIT", "EXINIT", "CLASSPATH",
		"__COMPAT_LAYER", "PROGRAMFILES", "COMMONPROGRAMFILES", "PROGRAMDATA",
	} {
		envExact[n] = true
	}
}

// ValidEnvName is item.run's name rule (§10.11; 0.85.3, 0.86.4): it
// matches ^[A-Z_][A-Z0-9_]{0,63}$ and is none of the refused names. It is
// a backstop under each entry's env allowlist and holds even for a listed
// name.
func ValidEnvName(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	if envExact[n] {
		return false
	}
	for _, p := range envPrefixes {
		if strings.HasPrefix(n, p) {
			return false
		}
	}
	return true
}

// ValidProxyHost reports whether h is a proxy binding's host: a lowercase
// DNS name of at least two labels with an optional :port (1–65535, default
// 443), no wildcard, no IP literal, and not localhost or under it.
func ValidProxyHost(h string) bool {
	name := h
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		name = h[:i]
		port := h[i+1:]
		if port == "" || len(port) > 5 || port[0] == '0' {
			return false
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return false
		}
	}
	if name == "" || len(name) > MaxDNSName || net.ParseIP(name) != nil {
		return false
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 || labels[len(labels)-1] == "localhost" {
		// A single-label name or localhost (RFC 6761) names this computer or
		// its local network, never an API's host.
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	// A numeric last label is an IP literal in another notation (1.2.3,
	// 0x7f.1, 2130706433), never a DNS name.
	last := labels[len(labels)-1]
	allDigits := true
	for i := 0; i < len(last); i++ {
		if last[i] < '0' || last[i] > '9' {
			allDigits = false
		}
	}
	return !allDigits && !strings.HasPrefix(last, "0x")
}

// HostKey is a proxy host with its default port made explicit, to compare
// hosts.
func HostKey(h string) string {
	if strings.LastIndexByte(h, ':') < 0 {
		return h + ":443"
	}
	return h
}

var refusedHeaders = map[string]bool{
	// Hop-by-hop fields (RFC 9110 §7.6.1, and the older proxy ones), and
	// those the spec names.
	"connection": true, "keep-alive": true, "proxy-authenticate": true, "proxy-authorization": true,
	"proxy-connection": true, "te": true, "trailer": true, "transfer-encoding": true, "upgrade": true,
	"host": true, "content-length": true, "cookie": true,
}

// ValidProxyHeader reports whether h is a proxy binding's header: an HTTP
// token of 1–MaxHeader characters, not a hop-by-hop field, Host,
// Content-Length, Transfer-Encoding or Cookie.
func ValidProxyHeader(h string) bool {
	if h == "" || len(h) > MaxHeader {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return !refusedHeaders[strings.ToLower(h)]
}

// validPrefix: 0–MaxPrefix printable ASCII characters.
func validPrefix(p string) bool {
	if len(p) > MaxPrefix {
		return false
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return false
		}
	}
	return true
}
