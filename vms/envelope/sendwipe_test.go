package envelope

import (
	"math/rand/v2"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/strictjson"
	"github.com/vettid/vettid-vault/vms/suite"
)

const sendSecret = `{"token":"s3cret-token","n":{"k":[1,"two"]}}`

func sendInner() *Inner {
	return &Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZZ", Type: "test.ping", TS: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), Body: []byte(sendSecret)}
}

// watchSent records each buffer the send path wipes, until the test ends.
func watchSent(t *testing.T) map[string][][]byte {
	t.Helper()
	seen := map[string][][]byte{}
	testSentHook = func(what string, b []byte) { seen[what] = append(seen[what], b) }
	t.Cleanup(func() { testSentHook = nil })
	return seen
}

func checkWiped(t *testing.T, seen map[string][][]byte, what string, want int) {
	t.Helper()
	if len(seen[what]) != want {
		t.Fatalf("%d %s buffers wiped, want %d", len(seen[what]), what, want)
	}
	for _, b := range seen[what] {
		if len(b) == 0 || !allZero(b) {
			t.Fatalf("a %s buffer kept its bytes", what)
		}
	}
}

// EncodeInner wipes the compacted body and the unpadded JSON it makes, and
// returns a padded plaintext that decodes to the same message.
func TestEncodeInnerWipes(t *testing.T) {
	seen := watchSent(t)
	in := sendInner()
	padded, err := EncodeInner(in, ModeSealed)
	if err != nil {
		t.Fatal(err)
	}
	checkWiped(t, seen, "compacted body", 1)
	checkWiped(t, seen, "unpadded JSON", 1)
	got, err := DecodeInner(padded, ModeSealed)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Body) != sendSecret || got.ID != in.ID {
		t.Fatalf("decoded %+v", got)
	}
	if string(in.Body) != sendSecret {
		t.Fatal("EncodeInner changed the caller's body")
	}
}

// SealInner and SealInnerFixed wipe every plaintext buffer, and what they
// seal opens to the same message.
func TestSealInnerWipes(t *testing.T) {
	sk, err := suite.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	const fixed = 4096
	for _, c := range []struct {
		name string
		seal func(*Inner) ([]byte, error)
		size int
	}{
		{"SealInner", func(in *Inner) ([]byte, error) {
			env, _, err := SealInner(in, sk.Public(), suite.Anonymous)
			return env, err
		}, 0},
		{"SealInnerFixed", func(in *Inner) ([]byte, error) {
			env, _, err := SealInnerFixed(in, fixed, sk.Public(), suite.Anonymous)
			return env, err
		}, fixed},
	} {
		t.Run(c.name, func(t *testing.T) {
			seen := watchSent(t)
			raw, err := c.seal(sendInner())
			if err != nil {
				t.Fatal(err)
			}
			checkWiped(t, seen, "compacted body", 1)
			checkWiped(t, seen, "unpadded JSON", 1)
			checkWiped(t, seen, "padded plaintext", 1)
			env, err := Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			padded, _, err := OpenSealed(env, sk)
			if err != nil {
				t.Fatal(err)
			}
			if c.size != 0 && len(padded) != c.size {
				t.Fatalf("padded to %d, want %d", len(padded), c.size)
			}
			j, err := Unpad(padded)
			if c.size != 0 {
				j, err = UnpadFixed(padded, c.size)
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := ParseInner(j, ModeSealed)
			if err != nil || string(got.Body) != sendSecret {
				t.Fatalf("opened %v %v", got, err)
			}
		})
	}
}

// Marshal sizes its builder up front (marshalSize), so the builder never
// outgrows its buffer, which would leave a copy of the body in the old one:
// the JSON is never longer than the size. Error messages full of control
// characters and invalid UTF-8, the longest to escape, included.
func TestMarshalNeverOutgrowsItsSize(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	str := func(n int) string {
		b := make([]byte, r.IntN(n+1))
		for i := range b {
			switch r.IntN(4) {
			case 0:
				b[i] = byte(r.IntN(0x20)) // control: escaped as 6 bytes
			case 1:
				b[i] = 0x80 + byte(r.IntN(0x80)) // invalid UTF-8 on its own
			default:
				const set = "ab\\\"<>&"
				b[i] = set[r.IntN(len(set))]
			}
		}
		return string(b)
	}
	grew := 0
	testMarshalHook = func(g bool) {
		if g {
			grew++
		}
	}
	t.Cleanup(func() { testMarshalHook = nil })
	for range 5000 {
		ts := time.Unix(int64(r.IntN(2_000_000_000)), int64(r.IntN(1000))*int64(time.Millisecond)).UTC()
		in := &Inner{ID: "01HZZZZZZZZZZZZZZZZZZZZZZZ", Type: "test.ping", TS: ts}
		body := strictjson.NewBuilder().String("v", str(300)).Bytes()
		in.Body = body
		if r.IntN(2) == 0 {
			in.Re, in.Status = "01HZZZZZZZZZZZZZZZZZZZZZZY", StatusError
			in.Error = &Error{Code: "not_found", Message: str(MaxErrorMsgLen)}
		}
		if r.IntN(3) == 0 {
			in.Exp = ts.Add(time.Minute)
		}
		if r.IntN(3) == 0 {
			in.Features = []string{"a_b_c", "hs_confirm"}
		}
		mode := ModeSealed
		if r.IntN(2) == 0 {
			mode, in.Seq = ModeSession, uint64(1+r.IntN(1<<40))
		}
		j, err := in.Marshal(mode)
		if err != nil {
			t.Fatal(err)
		}
		cb, _ := strictjson.CompactObject(in.Body)
		var errObj int
		if in.Error != nil {
			eb := strictjson.NewBuilder().String("code", in.Error.Code)
			if in.Error.Message != "" {
				eb.String("message", in.Error.Message)
			}
			errObj = len(eb.Bytes())
		}
		if n := marshalSize(in, len(cb), errObj); len(j) > n {
			t.Fatalf("Marshal wrote %d bytes, more than its size %d: the builder grew", len(j), n)
		}
	}
	if grew != 0 {
		t.Fatalf("the builder outgrew its buffer %d times", grew)
	}
}
