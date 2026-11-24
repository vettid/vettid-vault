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
	// Folders are the member folders a run may use (0.93.0); nil, as in
	// settings stored before it, is none.
	Folders []Folder `json:"folders,omitempty"`
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
		r.Folders = append([]Folder(nil), w.Run.Folders...)
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
		// (0.93.0) folders always, an empty list when none: how an app learns
		// the vault is 0.93.0 or later (§10.11).
		b.Raw("run", strictjson.NewBuilder().Raw("programs", programsJSON(w.Run.Programs, true)).Bool("each", w.Run.Each).
			Raw("folders", foldersJSON(w.Run.Folders)).Bytes())
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

// CatalogFolders is the catalog's folders (§10.11, 0.93.0): [{path,
// write}], an empty list when none, for every item with a run way (how a
// connector learns the vault is 0.93.0 or later); nil without one.
func (w *ItemWays) CatalogFolders() []byte {
	if w == nil || w.Run == nil {
		return nil
	}
	return foldersJSON(w.Run.Folders)
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
// (0.85.3). Errors are a *Refusal (errors.Is ErrWays): the first rule
// broken, taking the members in the specification's order (ways, then
// run's programs, each and folders, then proxy's hosts, header and
// prefix; entries by index), and for a rule between entries the later
// entry (0.93.2 "Why a setting is refused").
func ParseWays(o strictjson.Object, cur *ItemWays) (*ItemWays, error) {
	raw, err := o.Array("ways")
	if err != nil {
		return nil, refuseType(o, "ways", ruleNotList)
	}
	seen := map[string]bool{}
	for _, r := range raw {
		s, err := strictjson.AsString(r)
		if err != nil {
			return nil, refuse("ways", ruleNotString)
		}
		if !contains(wayOrder, s) {
			return nil, refuse("ways", "not a known way")
		}
		if seen[s] {
			return nil, refuse("ways", ruleRepeated)
		}
		seen[s] = true
	}
	if !seen[WayUse] {
		return nil, refuse("ways", "without use") // ways always holds use
	}
	w := &ItemWays{}
	for _, way := range wayOrder {
		if seen[way] {
			w.Ways = append(w.Ways, way) // a set: kept in wire order
		}
	}
	runRaw, hasRun, err := o.OptObjectRaw("run")
	if err != nil {
		return nil, refuse("run", ruleNotObject)
	}
	if hasRun != seen[WayRun] {
		return nil, refuse("run", presence(hasRun, "the run way")) // present exactly when ways holds run
	}
	if hasRun {
		if w.Run, err = parseRun(runRaw, cur); err != nil {
			return nil, err
		}
	}
	proxyRaw, hasProxy, err := o.OptObjectRaw("proxy")
	if err != nil {
		return nil, refuse("proxy", ruleNotObject)
	}
	if hasProxy != seen[WayProxy] {
		return nil, refuse("proxy", presence(hasProxy, "the proxy way"))
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

// Refusal is why a leash.item.set body is refused (§10.11 "Why a setting
// is refused", 0.93.2): the member's path in the body and the rule it
// breaks. It is ErrWays. Message is error.message: printable ASCII, at
// most 200 bytes, never a value the member typed (a variable name the
// vault refuses by its own list excepted, once it has the name's form).
type Refusal struct{ Member, Rule string }

func (r *Refusal) Error() string { return "itemspec: " + r.Message() }
func (r *Refusal) Unwrap() error { return ErrWays }

// Message is "<member>: <rule>".
func (r *Refusal) Message() string { return r.Member + ": " + r.Rule }

func refuse(member, rule string) error { return &Refusal{Member: member, Rule: rule} }

// refuseType is the refusal of o's member name that is missing or of the
// wrong type (rule).
func refuseType(o strictjson.Object, name, rule string) error {
	if _, present := o[name]; !present {
		return refuse(name, ruleMissing)
	}
	return refuse(name, rule)
}

// presence is the rule for a member present without its way, or missing
// with it.
func presence(present bool, way string) string {
	if present {
		return "present without " + way
	}
	return ruleMissing + " for " + way
}

// at is a member path with an index: run.programs[2].
func at(member string, i int) string { return member + "[" + strconv.Itoa(i) + "]" }

func parseRun(raw []byte, cur *ItemWays) (*RunWays, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, refuse("run", ruleNotObject)
	}
	arr, err := o.Array("programs")
	if err != nil {
		if _, present := o["programs"]; !present {
			return nil, refuse("run.programs", ruleMissing)
		}
		return nil, refuse("run.programs", ruleNotList)
	}
	if len(arr) > MaxPrograms {
		return nil, refuse("run.programs", ruleTooMany)
	}
	r := &RunWays{Programs: []Program{}, Each: true}
	var old []Program
	if cur != nil && cur.Run != nil {
		old = cur.Run.Programs
	}
	for i, pr := range arr {
		p, err := parseProgram(at("run.programs", i), pr, old, r.Programs)
		if err != nil {
			return nil, err
		}
		r.Programs = append(r.Programs, p)
	}
	if _, present := o["each"]; present {
		if r.Each, err = o.Bool("each"); err != nil {
			return nil, refuse("run.each", ruleNotBool)
		}
	}
	if !r.Each && len(r.Programs) == 0 {
		return nil, refuse("run.each", "false without a program") // each: false only for a bound item
	}
	if fr, present := o["folders"]; present {
		if r.Folders, err = parseFolders(fr); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// programsClash reports whether two entries match the same path: equal on
// ProgramKey, or a bare name equal to an absolute entry's last element.
func programsClash(a, b string) bool {
	if ProgramKey(a) == ProgramKey(b) {
		return true
	}
	return IsAbsProgram(a) && !IsAbsProgram(b) && ProgramKey(LastElement(a)) == ProgramKey(b) ||
		IsAbsProgram(b) && !IsAbsProgram(a) && ProgramKey(LastElement(b)) == ProgramKey(a)
}

// parseProgram parses one entry of run.programs; before are the entries
// read before it.
func parseProgram(member string, raw []byte, old, before []Program) (Program, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return Program{}, refuse(member, ruleNotObject)
	}
	p := Program{Env: []string{}}
	if p.Program, err = o.String("program"); err != nil {
		return Program{}, refuseType(o, "program", ruleNotString).(*Refusal).in(member)
	}
	if rule := programProblem(p.Program); rule != "" {
		return Program{}, refuse(member+".program", rule)
	}
	// (0.85.3) No two entries match the same path: compared without case
	// and without a final .exe, no two entries are equal, and no bare name
	// equals an absolute entry's last path element. Judged as each entry
	// is read, so the first entry that breaks a rule, its own or this one,
	// is named (the later of the two), and on its program before its other
	// members.
	for _, q := range before {
		if programsClash(p.Program, q.Program) {
			return Program{}, refuse(member+".program", ruleMatches)
		}
	}
	sha, hasSHA, err1 := o.OptString("sha256")
	path, hasPath, err2 := o.OptString("path")
	switch {
	case err1 != nil:
		return Program{}, refuse(member+".sha256", ruleNotString)
	case err2 != nil:
		return Program{}, refuse(member+".path", ruleNotString)
	case hasSHA && !hasPath:
		return Program{}, refuse(member+".path", ruleMissing+" with sha256")
	case hasPath && !hasSHA:
		return Program{}, refuse(member+".sha256", ruleMissing+" with path")
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
			return Program{}, refuse(member+".sha256", "not the recorded fingerprint")
		}
		p.SHA256, p.Path = sha, path
	}
	envRaw, present, err := o.OptArray("env")
	if err != nil {
		return Program{}, refuse(member+".env", ruleNotList)
	}
	if len(envRaw) > MaxEnvNames {
		return Program{}, refuse(member+".env", ruleTooMany)
	}
	if present {
		seen := map[string]bool{}
		for i, r := range envRaw {
			n, err := strictjson.AsString(r)
			if err != nil {
				return Program{}, refuse(at(member+".env", i), ruleNotString)
			}
			if rule := envNameProblem(n); rule != "" {
				return Program{}, refuse(at(member+".env", i), rule)
			}
			if seen[n] {
				return Program{}, refuse(at(member+".env", i), ruleRepeated)
			}
			seen[n] = true
			p.Env = append(p.Env, n)
		}
	}
	return p, nil
}

// in prefixes the member path with parent's.
func (r *Refusal) in(parent string) error {
	r.Member = parent + "." + r.Member
	return r
}

func parseProxy(raw []byte) (*ProxyWays, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, refuse("proxy", ruleNotObject)
	}
	arr, err := o.Array("hosts")
	if err != nil {
		return nil, refuseType(o, "hosts", ruleNotList).(*Refusal).in("proxy")
	}
	if len(arr) == 0 {
		return nil, refuse("proxy.hosts", ruleEmpty)
	}
	if len(arr) > MaxHosts {
		return nil, refuse("proxy.hosts", ruleTooMany)
	}
	p := &ProxyWays{}
	seen := map[string]bool{}
	for i, r := range arr {
		h, err := strictjson.AsString(r)
		if err != nil {
			return nil, refuse(at("proxy.hosts", i), ruleNotString)
		}
		if rule := proxyHostProblem(h); rule != "" {
			return nil, refuse(at("proxy.hosts", i), rule)
		}
		if seen[HostKey(h)] {
			return nil, refuse(at("proxy.hosts", i), ruleMatches)
		}
		seen[HostKey(h)] = true
		p.Hosts = append(p.Hosts, h)
	}
	if p.Header, err = o.String("header"); err != nil {
		return nil, refuseType(o, "header", ruleNotString).(*Refusal).in("proxy")
	}
	if rule := proxyHeaderProblem(p.Header); rule != "" {
		return nil, refuse("proxy.header", rule)
	}
	pre, present, err := o.OptString("prefix")
	if err != nil {
		return nil, refuse("proxy.prefix", ruleNotString)
	}
	if present {
		if rule := prefixProblem(pre); rule != "" {
			return nil, refuse("proxy.prefix", rule)
		}
		p.Prefix = pre
	}
	return p, nil
}

// --- widening (§10.11 "Widening needs the member") ---

// Widens reports whether next allows more than cur (nil: ["use"]): a way,
// a program or a host added, programs emptied, a name added to an entry's
// env (0.85.3), each set to false, or (0.93.0) a folders entry added (a
// changed path is one added) or its write turned on. Such a change needs
// the credential's unlock window. Dropping a pin, a program, a host, a
// name, a folder or a way, write turned off, and each set to true, only
// narrow.
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
		// (0.93.0) A folder added (a changed path is one added) or write
		// turned on; removing one, write turned off and emptying folders
		// narrow.
		for _, f := range next.Run.Folders {
			if g, ok := findFolder(cur.Run.Folders, f.Path); !ok || f.Write && !g.Write {
				return true
			}
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

// findFolder finds the folders entry whose path is exactly p.
func findFolder(fs []Folder, p string) (Folder, bool) {
	for _, f := range fs {
		if f.Path == p {
			return f, true
		}
	}
	return Folder{}, false
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
func ValidProgram(p string) bool { return programProblem(p) == "" }

// Rules a refused setting names (§10.11 "Why a setting is refused", 0.93.2):
// fixed English phrases, printable ASCII, never a value the member typed.
const (
	ruleMissing     = "missing"
	ruleNotString   = "not a string"
	ruleNotBool     = "not a boolean"
	ruleNotList     = "not a list"
	ruleNotObject   = "not an object"
	ruleEmpty       = "empty"
	ruleTooLong     = "too long"
	ruleTooMany     = "too many"
	ruleRepeated    = "repeated"
	ruleNotUTF8     = "not valid UTF-8"
	ruleControl     = "holds a control or format character"
	ruleTilde       = "holds a ~ in the last element"
	ruleNotClean    = "not a clean path"
	ruleNoFile      = "names no file"
	ruleSeparator   = "holds a separator or a colon"
	ruleNotAbsolute = "not absolute"
	ruleRoot        = "the root"
	ruleDotsOnly    = "holds an element of only dots and spaces"
	ruleMatches     = "matches another entry"
	ruleNested      = "inside or above another entry"
	ruleBadName     = "not a valid name"
	ruleNotHost     = "not a host name"
	ruleBadPort     = "not a valid port"
	ruleNotForProxy = "not allowed for the proxy"
	ruleNotHeader   = "not a valid header name"
	ruleNotASCII    = "holds a character outside printable ASCII"
)

// programProblem is the rule a binding's program breaks (ValidProgram), or
// "" when it is valid.
func programProblem(p string) string {
	switch {
	case p == "":
		return ruleEmpty
	case len(p) > MaxProgram:
		return ruleTooLong
	case !utf8.ValidString(p):
		return ruleNotUTF8
	case !showable(p):
		return ruleControl
	}
	// The rules in the order "Program strings" gives them: the shape and
	// the clean path, then the ~.
	if IsAbsProgram(p) {
		// A last element of dots and spaces first, as "Program strings"
		// lists it ("/usr/bin/.." names no file).
		// An empty last element (/usr/bin/) is the clean-path rule's.
		if last := LastElement(p); last != "" && strings.TrimRight(last, " .") == "" {
			return ruleNoFile
		}
		if !cleanPath(p, false) {
			return ruleNotClean
		}
	} else {
		if strings.ContainsAny(p, "/:"+string(rune(backslash))) {
			return ruleSeparator
		}
		if strings.Trim(p, " .") == "" {
			return ruleNoFile
		}
	}
	// No "~" in the last element (owner decision a, #14596): on Windows an
	// 8.3 short name (BASH~1.EXE) is another name for a file, which the
	// member would read on the phone as another program, and which the
	// shell list and the bindings would not know. Refused on every system,
	// as the ":" rule.
	if strings.Contains(LastElement(p), "~") {
		return ruleTilde
	}
	return ""
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
		// 0.93.0: the connector's own, the run's work/in/ and work/out/.
		"VETTID_IN", "VETTID_OUT",
	} {
		envExact[n] = true
	}
	// The names a run's environment already holds, set by the connector
	// (its minimal environment, VETTID_IN and VETTID_OUT): "reserved" in a
	// refusal's reason; the other listed names are "not allowed".
	for _, n := range []string{"HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
		"USERPROFILE", "USERNAME", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
		"SYSTEMROOT", "WINDIR", "SYSTEMDRIVE", "PATHEXT", "PATH", "TMPDIR", "TEMP", "TMP",
		"VETTID_IN", "VETTID_OUT"} {
		envReserved[n] = true
	}
}

// envReserved are the refused names the connector sets itself.
var envReserved = map[string]bool{}

// ValidEnvName is item.run's name rule (§10.11; 0.85.3, 0.86.4): it
// matches ^[A-Z_][A-Z0-9_]{0,63}$ and is none of the refused names. It is
// a backstop under each entry's env allowlist and holds even for a listed
// name.
func ValidEnvName(n string) bool { return envNameProblem(n) == "" }

// envNameForm reports whether n has the name rule's form,
// ^[A-Z_][A-Z0-9_]{0,63}$.
func envNameForm(n string) bool {
	if n == "" || len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'A' && c <= 'Z' || c == '_' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}

// envNameProblem is the rule a variable name breaks (ValidEnvName), or "".
// A name the vault refuses by its list is named in the rule (it has the
// name rule's form, checked first: §10.11 "Why a setting is refused"); a
// name of another form is not.
func envNameProblem(n string) string {
	if !envNameForm(n) {
		return ruleBadName
	}
	if envReserved[n] {
		return n + " is reserved"
	}
	if envExact[n] {
		return n + " is not allowed"
	}
	for _, p := range envPrefixes {
		if strings.HasPrefix(n, p) {
			return n + " loads code"
		}
	}
	return ""
}

// ValidProxyHost reports whether h is a proxy binding's host: a lowercase
// DNS name of at least two labels with an optional :port (1–65535, default
// 443), no wildcard, no IP literal, and not localhost or under it.
func ValidProxyHost(h string) bool { return proxyHostProblem(h) == "" }

// proxyHostProblem is the rule a proxy host breaks (ValidProxyHost), or "".
func proxyHostProblem(h string) string {
	name := h
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		name = h[:i]
		port := h[i+1:]
		if port == "" || len(port) > 5 || port[0] == '0' {
			return ruleBadPort
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return ruleBadPort
		}
	}
	if name == "" {
		return ruleEmpty
	}
	if len(name) > MaxDNSName {
		return ruleTooLong
	}
	if net.ParseIP(name) != nil {
		return ruleNotForProxy // an IP literal
	}
	labels := strings.Split(name, ".")
	if len(labels) < 2 || labels[len(labels)-1] == "localhost" {
		// A single-label name or localhost (RFC 6761) names this computer or
		// its local network, never an API's host.
		return ruleNotForProxy
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return ruleNotHost
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ruleNotHost
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
	if allDigits || strings.HasPrefix(last, "0x") {
		return ruleNotForProxy
	}
	return ""
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
func ValidProxyHeader(h string) bool { return proxyHeaderProblem(h) == "" }

// proxyHeaderProblem is the rule a proxy header breaks, or "".
func proxyHeaderProblem(h string) string {
	if h == "" {
		return ruleEmpty
	}
	if len(h) > MaxHeader {
		return ruleTooLong
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return ruleNotHeader
		}
	}
	if refusedHeaders[strings.ToLower(h)] {
		return ruleNotForProxy
	}
	return ""
}

// prefixProblem is the rule a proxy prefix breaks (0–MaxPrefix printable
// ASCII characters), or "".
func prefixProblem(p string) string {
	if len(p) > MaxPrefix {
		return ruleTooLong
	}
	for i := 0; i < len(p); i++ {
		if p[i] < 0x20 || p[i] > 0x7e {
			return ruleNotASCII
		}
	}
	return ""
}
