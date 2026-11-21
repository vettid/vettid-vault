package strictjson

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// jsonGen builds random JSON aimed at what checkTree must get right:
// member names that are equal once decoded but spelled differently
// (plain, \u escapes, surrogate pairs, \/ and the short escapes), nesting
// around MaxDepth, strings full of escapes, quotes and backslashes, and
// numbers and literals of every form.
type jsonGen struct {
	r     *rand.Rand
	bs, u string // a backslash, and the start of a \u escape
}

func newJSONGen(seed uint64) *jsonGen {
	return &jsonGen{r: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), bs: "\\", u: "\\" + "u"}
}

// A small alphabet, so that names collide often.
var genRunes = []rune{'a', 'b', '/', '"', '\\', 'é', '😀', '\n', 0x7f, 0xfffd}

func (g *jsonGen) ws() string {
	if g.r.IntN(4) != 0 {
		return ""
	}
	return []string{" ", "\t", "\n", "\r", "  \n "}[g.r.IntN(5)]
}

// spell writes s as a JSON string literal, each rune in a random legal
// spelling.
func (g *jsonGen) spell(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, c := range s {
		hex := func(v rune) string { return g.u + fmt.Sprintf([]string{"%04x", "%04X"}[g.r.IntN(2)], v) }
		switch {
		case c == '"':
			b.WriteString([]string{g.bs + `"`, hex(c)}[g.r.IntN(2)])
		case c == '\\':
			b.WriteString([]string{g.bs + g.bs, hex(c)}[g.r.IntN(2)])
		case c == '\n':
			b.WriteString([]string{g.bs + "n", hex(c)}[g.r.IntN(2)])
		case c == '/':
			b.WriteString([]string{"/", g.bs + "/", hex(c)}[g.r.IntN(3)])
		case c > 0xffff:
			if g.r.IntN(2) == 0 {
				b.WriteRune(c)
			} else {
				v := c - 0x10000
				b.WriteString(hex(0xd800+(v>>10)) + hex(0xdc00+(v&0x3ff)))
			}
		default:
			if g.r.IntN(3) == 0 {
				b.WriteString(hex(c))
			} else {
				b.WriteRune(c)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (g *jsonGen) name() string {
	n := g.r.IntN(3)
	rs := make([]rune, n)
	for i := range rs {
		rs[i] = genRunes[g.r.IntN(len(genRunes))]
	}
	return string(rs)
}

func (g *jsonGen) number() string {
	forms := []string{"0", "-0", "1", "-12", "3.25", "1e5", "-2E-3", "0.0", "123456789012345678901234567890", "1.5e+300"}
	return forms[g.r.IntN(len(forms))]
}

func (g *jsonGen) value(depth, maxDepth int) string {
	k := g.r.IntN(8)
	if depth >= maxDepth {
		k = 3 + g.r.IntN(5) // a scalar
	}
	switch k {
	case 0, 1:
		return g.object(depth+1, maxDepth)
	case 2:
		n := g.r.IntN(4)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = g.ws() + g.value(depth+1, maxDepth) + g.ws()
		}
		return "[" + strings.Join(parts, ",") + "]"
	case 3, 4:
		return g.spell(g.name() + g.name())
	case 5:
		return g.number()
	default:
		return []string{"true", "false", "null"}[g.r.IntN(3)]
	}
}

func (g *jsonGen) object(depth, maxDepth int) string {
	n := g.r.IntN(5)
	parts := make([]string, n)
	for i := range parts {
		parts[i] = g.ws() + g.spell(g.name()) + g.ws() + ":" + g.ws() + g.value(depth, maxDepth) + g.ws()
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// deep nests objects and arrays to a depth around MaxDepth.
func (g *jsonGen) deep() string {
	d := MaxDepth - 3 + g.r.IntN(7)
	var open, close strings.Builder
	open.WriteString("{" + g.spell("a") + ":")
	close.WriteString("}")
	for i := 1; i < d; i++ {
		if g.r.IntN(2) == 0 {
			open.WriteString("{" + g.spell(g.name()) + ":")
			close.WriteString("}")
		} else {
			open.WriteString("[")
			close.WriteString("]")
		}
	}
	cs := []rune(close.String())
	for i, j := 0, len(cs)-1; i < j; i, j = i+1, j-1 {
		cs[i], cs[j] = cs[j], cs[i]
	}
	return open.String() + g.value(0, 0) + string(cs)
}

// mutate damages b at a few random points, with bytes that matter to
// the walk.
func (g *jsonGen) mutate(b string) string {
	bytes := []byte(b)
	for range 1 + g.r.IntN(3) {
		if len(bytes) == 0 {
			break
		}
		i := g.r.IntN(len(bytes))
		switch g.r.IntN(4) {
		case 0:
			bytes = append(bytes[:i], bytes[i+1:]...)
		case 1:
			ins := `{}[]:,"\ ` + "\t"
			bytes = append(bytes[:i], append([]byte{ins[g.r.IntN(len(ins))]}, bytes[i:]...)...)
		case 2:
			j := i + g.r.IntN(len(bytes)-i)
			bytes = append(bytes[:j], append(append([]byte(nil), bytes[i:j]...), bytes[j:]...)...)
		default:
			bytes = bytes[:i]
		}
	}
	return string(bytes)
}

func (g *jsonGen) input() string {
	var s string
	switch g.r.IntN(10) {
	case 0:
		s = g.deep()
	case 1:
		s = g.value(0, 6) // any top level
	default:
		s = g.ws() + g.object(1, 3+g.r.IntN(5)) + g.ws()
	}
	if g.r.IntN(3) == 0 {
		s = g.mutate(s)
	}
	return s
}

// TestCheckTreeGenerated compares the walk with the decoder it replaced
// on generated inputs. VETTID_CHECKTREE_N sets how many (default 20000)
// and VETTID_CHECKTREE_SEED the seed (default: the clock, logged).
func TestCheckTreeGenerated(t *testing.T) {
	n := 20000
	if v, err := strconv.Atoi(os.Getenv("VETTID_CHECKTREE_N")); err == nil && v > 0 {
		n = v
	}
	seed := uint64(time.Now().UnixNano())
	if v, err := strconv.ParseUint(os.Getenv("VETTID_CHECKTREE_SEED"), 10, 64); err == nil {
		seed = v
	}
	t.Logf("seed %d, %d inputs", seed, n)
	g := newJSONGen(seed)
	counts := map[string]int{}
	for range n {
		b := []byte(g.input())
		sameAsDecoder(t, b)
		if !utf8.Valid(b) {
			counts["invalid utf-8"]++
			continue
		}
		switch err := checkTree(b); {
		case err == nil:
			counts["accepted"]++
		case json.Valid(b):
			counts["well-formed, refused: "+err.Error()]++
		default:
			counts["malformed"]++
		}
	}
	for k, v := range counts {
		t.Logf("%8d %s", v, k)
	}
	// The generator must reach each outcome, or it is not testing them.
	for _, want := range []string{"accepted", "well-formed, refused: " + ErrDuplicate.Error(), "well-formed, refused: " + ErrDepth.Error(), "well-formed, refused: " + ErrNotObject.Error(), "malformed"} {
		if n >= 20000 && counts[want] == 0 {
			t.Errorf("no input reached %q", want)
		}
	}
}
