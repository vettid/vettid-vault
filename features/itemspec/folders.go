package itemspec

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"github.com/vettid/vettid-vault/vms/strictjson"
)

// Limits of a run binding's folders and of an item.run's files (§10.11,
// 0.93.0).
const (
	MaxFolders       = 16
	MaxRunInputs     = 16
	MaxRunInputSize  = 16 << 20 // 16 MiB a file
	MaxRunInputTotal = 64 << 20 // 64 MiB in all
	MaxRunInputPaths = 16384    // bytes of the inputs' paths together
	MaxRunOutputs    = 16
	MaxFlatName      = 255
)

// Folder is one entry of a run binding's folders (§10.11 "Member folders
// for runs", 0.93.0): a member folder a run may use as cwd, and, with
// Write, where files may be copied back.
type Folder struct {
	Path  string `json:"path"`
	Write bool   `json:"write"`
}

// RunInput is one of an item.run's inputs: a file copied read-only into
// the run's work/in/, with the size the member approves.
type RunInput struct {
	Path string
	Size uint64
}

// RunOutput is an item.run's output: the folder the named files of the
// run's work/out/ are copied back to.
type RunOutput struct {
	Folder string
	Names  []string
}

// parseFolders parses a run binding's folders (0–16 entries {path,
// write}): each path a clean absolute path as a run's cwd, not the root;
// write a boolean, false when absent; no entry equal to, under or above
// another, compared folded (FolderKey).
func parseFolders(raw []byte) ([]Folder, error) {
	arr, err := strictjson.AsArray(raw)
	if err != nil {
		return nil, refuse("run.folders", ruleNotList)
	}
	if len(arr) > MaxFolders {
		return nil, refuse("run.folders", ruleTooMany)
	}
	fs := make([]Folder, 0, len(arr))
	for i, r := range arr {
		member := at("run.folders", i)
		o, err := strictjson.AsObject(r)
		if err != nil {
			return nil, refuse(member, ruleNotObject)
		}
		var f Folder
		if f.Path, err = o.String("path"); err != nil {
			return nil, refuseType(o, "path", ruleNotString).(*Refusal).in(member)
		}
		if rule := folderPathProblem(f.Path); rule != "" {
			return nil, refuse(member+".path", rule)
		}
		// No entry equal to, under or above another, judged as each entry
		// is read (the first entry that breaks a rule is named), and on
		// its path before its other members.
		ki := FolderKey(f.Path)
		for _, g := range fs {
			kk := FolderKey(g.Path)
			if folderWithin(ki, kk) && folderWithin(kk, ki) {
				return nil, refuse(member+".path", ruleMatches)
			}
			if folderWithin(ki, kk) || folderWithin(kk, ki) {
				return nil, refuse(member+".path", ruleNested)
			}
		}
		if _, present := o["write"]; present {
			if f.Write, err = o.Bool("write"); err != nil {
				return nil, refuse(member+".write", ruleNotBool)
			}
		}
		fs = append(fs, f)
	}
	return fs, nil
}

// ValidFolderPath is a folders entry's path: a run's cwd (validCwd), but
// not the root itself, which would put every file in reach.
func ValidFolderPath(p string) bool { return folderPathProblem(p) == "" }

// folderPathProblem is the rule a folders entry's path breaks
// (ValidFolderPath), or "".
func folderPathProblem(p string) string {
	switch {
	case p == "":
		return ruleEmpty
	case len(p) > MaxProgram: // "Program strings" order: the bytes, then the shape
		return ruleTooLong
	case !utf8.ValidString(p):
		return ruleNotUTF8
	case !showable(p):
		return ruleControl
	case !IsAbsProgram(p):
		return ruleNotAbsolute
	case !cleanPath(p, true):
		return ruleNotClean
	case !cleanPath(p, false):
		return ruleRoot
	case dotsOnlyElement(p):
		return ruleDotsOnly
	}
	return ""
}

// pathElements splits an absolute path (IsAbsProgram) into its root ("/",
// or a drive "X:") and its elements, / and \ both separating (the spec's
// element by element comparison). A path that is not absolute is its own
// root with no elements, which no entry matches.
func pathElements(p string) (string, []string) {
	if !IsAbsProgram(p) {
		return p, nil
	}
	root, rest := "/", p[1:]
	if p[0] != '/' {
		root, rest = p[:2], p[3:]
	}
	if rest == "" {
		return root, nil
	}
	return root, strings.FieldsFunc(rest, func(r rune) bool { return r == '/' || r == rune(backslash) })
}

// FolderKey is how folders entries are compared with each other (§10.11
// "No entry may be equal to, under or above another"): folded, on every
// system, as a program for the no-two-match rule: without case, a drive
// path's / as \ (so / and \ separate alike), and trailing dots and spaces
// dropped from each element. The root and the elements, in order.
func FolderKey(p string) []string {
	root, els := pathElements(p)
	key := []string{foldCase(root)}
	for _, e := range els {
		key = append(key, strings.TrimRight(foldCase(e), " ."))
	}
	return key
}

// foldCase is the key "without case" for a path element or a name
// (0.93.1, 0.93.2): NFD(fold(upper(NFD(s)))), canonical caseless matching
// (Unicode D145) with simple folding, each rune upper-cased by its simple
// mapping (unicode.ToUpper) and then mapped to the smallest rune of its
// unicode.SimpleFold orbit. Decomposing first lets a letter with marks
// fold like the letter alone: "ǰ" and J followed by a combining caron are
// one key, as are both forms of "café" (one name to macOS), and the long s
// and S, the Kelvin sign and K. The upper step (0.93.2) makes the dotless
// i key as I, as it is alone in its orbit; for every other rune of Go's
// tables it changes nothing. Looser only refuses more.
func foldCase(s string) string {
	return norm.NFD.String(strings.Map(func(r rune) rune { return foldRune(unicode.ToUpper(r)) }, norm.NFD.String(s)))
}

// foldRune is the smallest rune of r's simple case folding orbit.
func foldRune(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		least = min(least, f)
	}
	return least
}

// folderWithin reports whether the path a is equal to the path b or lies
// under it, element by element (each a root and elements).
func folderWithin(a, b []string) bool {
	if len(a) < len(b) {
		return false
	}
	for i := range b {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// exactKey is a path as the vault matches it against an entry (§10.11 "How
// the vault compares"): its root and elements, / and \ both separating,
// compared exactly and case-sensitively, never as a text prefix.
func exactKey(p string) []string {
	root, els := pathElements(p)
	return append([]string{root}, els...)
}

// MatchFolder returns the entry of folders that p equals or lies under
// (§10.11), compared exactly (exactKey); with write, only an entry that
// has write. The no-nesting rule leaves at most one; the first is
// returned.
func MatchFolder(folders []Folder, p string, write bool) (Folder, bool) {
	return matchFolder(folders, p, write, false)
}

// MatchFolderUnder is MatchFolder for a file: p must lie strictly under the
// entry, never equal it (an input, 0.93.1).
func MatchFolderUnder(folders []Folder, p string) (Folder, bool) {
	return matchFolder(folders, p, false, true)
}

func matchFolder(folders []Folder, p string, write, strict bool) (Folder, bool) {
	k := exactKey(p)
	for _, f := range folders {
		fk := exactKey(f.Path)
		if (!write || f.Write) && folderWithin(k, fk) && (!strict || len(k) > len(fk)) {
			return f, true
		}
	}
	return Folder{}, false
}

// ValidFlatName is an input's last path element or an output name
// (§10.11, 0.93.0): 1–255 bytes of UTF-8, no control, Cf, Zl or Zp
// character, no /, \ or :, not . or .., no trailing dot or space, and no
// reserved Windows name (CON, PRN, AUX, NUL, COM1–COM9, LPT1–LPT9), with
// or without an extension, in any case.
func ValidFlatName(n string) bool {
	if n == "" || len(n) > MaxFlatName || !utf8.ValidString(n) || !showable(n) {
		return false
	}
	if strings.ContainsAny(n, "/:"+string(rune(backslash))) || n == "." || n == ".." {
		return false
	}
	if last := n[len(n)-1]; last == '.' || last == ' ' {
		return false
	}
	return !reservedName(n)
}

// reservedName reports whether n is a Windows device name, with or without
// an extension (CON, con.txt, Com1.tar.gz), any case: CON, PRN, AUX, NUL,
// CONIN$, CONOUT$, and COM or LPT followed by a digit 0-9 or a superscript
// one, two or three (0.93.1). Windows also drops spaces before the
// extension (CON .txt), so they are trimmed.
func reservedName(n string) bool {
	base := n
	if i := strings.IndexByte(n, '.'); i >= 0 {
		base = n[:i]
	}
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if !strings.HasPrefix(base, "COM") && !strings.HasPrefix(base, "LPT") {
		return false
	}
	switch base[3:] {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "\u00b9", "\u00b2", "\u00b3":
		return true
	}
	return false
}

// parseInputs parses an item.run's inputs (0–16 {path, size}): each path a
// clean absolute path as a cwd, not the root, whose last element is a flat
// name; size a non-negative integer of at most 16 MiB; all sizes together
// at most 64 MiB; the paths together at most 16,384 bytes; no two names
// equal without case.
func parseInputs(raw []byte) ([]RunInput, error) {
	arr, err := strictjson.AsArray(raw)
	if err != nil || len(arr) > MaxRunInputs {
		return nil, ErrRun
	}
	var ins []RunInput
	var total uint64
	paths := 0
	seen := map[string]bool{}
	for _, r := range arr {
		o, err := strictjson.AsObject(r)
		if err != nil {
			return nil, ErrRun
		}
		var in RunInput
		if in.Path, err = o.String("path"); err != nil || !ValidFolderPath(in.Path) || !ValidFlatName(LastElement(in.Path)) {
			return nil, ErrRun
		}
		if in.Size, err = o.Uint("size", 0, MaxRunInputSize); err != nil {
			return nil, ErrRun
		}
		total += in.Size
		paths += len(in.Path)
		k := foldCase(LastElement(in.Path))
		if total > MaxRunInputTotal || paths > MaxRunInputPaths || seen[k] {
			return nil, ErrRun
		}
		seen[k] = true
		ins = append(ins, in)
	}
	return ins, nil
}

// parseOutput parses an item.run's output {folder, names}: folder a clean
// absolute path as a cwd; names 1–16 flat names, no two equal without
// case.
func parseOutput(raw []byte) (*RunOutput, error) {
	o, err := strictjson.AsObject(raw)
	if err != nil {
		return nil, ErrRun
	}
	out := &RunOutput{}
	if out.Folder, err = o.String("folder"); err != nil || !validCwd(out.Folder) {
		return nil, ErrRun
	}
	arr, err := o.Array("names")
	if err != nil || len(arr) == 0 || len(arr) > MaxRunOutputs {
		return nil, ErrRun
	}
	seen := map[string]bool{}
	for _, r := range arr {
		n, err := strictjson.AsString(r)
		if err != nil || !ValidFlatName(n) || seen[foldCase(n)] {
			return nil, ErrRun
		}
		seen[foldCase(n)] = true
		out.Names = append(out.Names, n)
	}
	return out, nil
}

// foldersJSON is a binding's folders on the wire: [{path, write}], an
// empty list when there are none.
func foldersJSON(fs []Folder) []byte {
	arr := []byte{'['}
	for i, f := range fs {
		if i > 0 {
			arr = append(arr, ',')
		}
		arr = append(arr, folderJSON(f)...)
	}
	return append(arr, ']')
}

func folderJSON(f Folder) []byte {
	return strictjson.NewBuilder().String("path", f.Path).Bool("write", f.Write).Bytes()
}
