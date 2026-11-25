//go:build vmsvectors

package vectors

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/vettid/vettid-vault/vms/handshake"
	"github.com/vettid/vettid-vault/vms/invite"
	"github.com/vettid/vettid-vault/vms/paircode"
)

// The short pairing code (pair-code.json, 0.94.1 §6.7.2).
const (
	PairCode        = "K7QM4XPZ"
	PairCodeClaimID = "q4f7m2xk5n3p6r7t2v4w6y7z3a" // canonical: 128 bits, the last character's low bits zero
	PairCodePairing = "01JB2Z6V9K3M4N5P6Q7R8S9TA0"
	PairCodeToken   = "v4.public.VEVTVC1QQUlSQ09ERS1vcGVu"
	PairCodeEpoch   = 493044     // 2026-03-31T12:00:00Z
	PairCodeOther   = "K7QM4XP2" // another code, for a blob that must not open
)

// genPairCode builds pair-code.json (VAULT-MESSAGING 0.94.1 §6.7.2,
// RELAY-PROTOCOL 0.14.0 §6.9.1): for a fixed code, relay, epoch, relay
// nonce, s_c and bundle nonce, the lookup salt and its id, pw with its
// 0x00 bytes, tag, x, k_w, the associated data and the blob of an agent
// bundle (the vault of keys.json), the desktop purpose's tag for the same
// code, the input normalization, the relay forms, the salt list checks,
// and the changes that must not open.
func genPairCode(vault *principal) (obj, error) {
	r, err := paircode.CanonicalRelay(RelayURL)
	if err != nil || r != RelayURL {
		return nil, errors.New("vectors: the relay is not canonical")
	}
	nonce, sc, bnonce := rep(NoncePairRelay, 16), rep(SaltPairClaim, 16), rep(NoncePairBundle, 24)
	sr := paircode.SaltR(r, PairCodeEpoch, nonce)
	tag, err := paircode.Tag(paircode.PurposeAgent, r, []byte(PairCode), sr)
	if err != nil {
		return nil, err
	}
	tagD, err := paircode.Tag(paircode.PurposeDesktop, r, []byte(PairCode), sr)
	if err != nil {
		return nil, err
	}
	x, err := paircode.X(paircode.PurposeAgent, r, []byte(PairCode), sc)
	if err != nil {
		return nil, err
	}
	kw, err := paircode.KW(x)
	if err != nil {
		return nil, err
	}
	t0 := time.Unix(PairCodeEpoch*paircode.Hour+17*60, 0).UTC() // 12:17
	b := &invite.Bundle{Kind: "agent", InviteID: PairCodePairing, Remote: false,
		Vault: handshake.Principal{IK: vault.ikPub(), KEM: vault.kem.Public(), Relay: vault.addr},
		Token: PairCodeToken, Exp: t0.Add(paircode.TTL)}
	bj, err := b.Marshal()
	if err != nil {
		return nil, err
	}
	blob, err := paircode.SealWithNonce(kw, bnonce, paircode.PurposeAgent, r, PairCodeClaimID, sc, bj)
	if err != nil {
		return nil, err
	}
	entry := func(epoch int64, nb byte) obj {
		n := rep(nb, 16)
		return obj{{"salt_id", paircode.SaltID(paircode.SaltR(r, epoch, n))}, {"epoch", int(epoch)},
			{"nonce", base64.StdEncoding.EncodeToString(n)}}
	}
	at := func(sec int64) string {
		return time.Unix(PairCodeEpoch*paircode.Hour+sec, 0).UTC().Format(time.RFC3339)
	}
	// Each refused list fails one check only: a wrong-size nonce's salt_id
	// is computed over that nonce.
	odd := func(n int) obj {
		nn := rep(NoncePairRelay, n)
		return obj{{"salt_id", paircode.SaltID(paircode.SaltR(r, PairCodeEpoch, nn))}, {"epoch", PairCodeEpoch},
			{"nonce", base64.StdEncoding.EncodeToString(nn)}}
	}
	badID := obj{{"salt_id", "00000000"}, {"epoch", PairCodeEpoch}, {"nonce", base64.StdEncoding.EncodeToString(nonce)}}
	one := []obj{entry(PairCodeEpoch, NoncePairRelay)}
	two := []obj{entry(PairCodeEpoch, NoncePairRelay), entry(PairCodeEpoch+1, NoncePairRelay2)}
	type sc_ = struct {
		name  string
		list  []obj
		now   string
		seen  []obj
		valid bool
		why   string
	}
	salts := []sc_{
		{"one entry, mid-hour", one, at(30 * 60), nil, true, ""},
		{"two entries near the hour", two, at(59 * 60), nil, true, ""},
		{"the window's first second", one, at(-240), nil, true, ""},
		{"the window's last second", one, at(3600 + 720), nil, true, ""},
		{"before the window", one, at(-241), nil, false, paircode.ReasonClock},
		{"after the window", one, at(3600 + 721), nil, false, paircode.ReasonClock},
		{"no entries", []obj{}, at(30 * 60), nil, false, paircode.ReasonCount},
		{"three entries", []obj{entry(PairCodeEpoch-1, 0xa5), entry(PairCodeEpoch, NoncePairRelay), entry(PairCodeEpoch+1, NoncePairRelay2)},
			at(30 * 60), nil, false, paircode.ReasonCount},
		{"a 15-byte nonce", []obj{odd(15)}, at(30 * 60), nil, false, paircode.ReasonNonce},
		{"a 17-byte nonce", []obj{odd(17)}, at(30 * 60), nil, false, paircode.ReasonNonce},
		{"one epoch twice", []obj{entry(PairCodeEpoch, NoncePairRelay), entry(PairCodeEpoch, NoncePairRelay2)}, at(30 * 60), nil, false, paircode.ReasonEpochDup},
		{"a salt_id that does not recompute", []obj{badID}, at(30 * 60), nil, false, paircode.ReasonSaltID},
		{"a seen epoch with the same nonce", one, at(30 * 60), []obj{{{"epoch", PairCodeEpoch}, {"nonce", base64.StdEncoding.EncodeToString(nonce)}}},
			true, ""},
		{"one of two entries outside its window", []obj{entry(PairCodeEpoch, NoncePairRelay), entry(PairCodeEpoch+5, NoncePairRelay2)},
			at(30 * 60), nil, false, paircode.ReasonClock},
		{"a seen epoch with another nonce", one, at(30 * 60), []obj{{{"epoch", PairCodeEpoch}, {"nonce", base64.StdEncoding.EncodeToString(rep(0xa6, 16))}}},
			false, paircode.ReasonChanged},
	}
	var saltCases []obj
	for _, c := range salts {
		o := obj{{"name", c.name}, {"salts", c.list}, {"now", c.now}}
		if c.seen != nil {
			o = append(o, member{"seen", c.seen})
		}
		o = append(o, member{"valid", c.valid})
		if !c.valid {
			o = append(o, member{"reason", c.why})
		}
		saltCases = append(saltCases, o)
	}
	// Which entry a vault PUTs under, then the other once (§6.7.2).
	type fp = struct {
		name  string
		list  []obj
		at    int64
		order []int64
	}
	prev := []obj{entry(PairCodeEpoch-1, 0xa5), entry(PairCodeEpoch, NoncePairRelay)}
	var forPut []obj
	for _, c := range []fp{
		{"mid-hour, one entry", one, 30 * 60, []int64{PairCodeEpoch}},
		{"hh:58:00, the next listed", two, 3600 - 120, []int64{PairCodeEpoch, PairCodeEpoch + 1}},
		{"hh:57:59, the next listed", two, 3600 - 121, []int64{PairCodeEpoch}},
		{"hh:01:59, the previous listed", prev, 119, []int64{PairCodeEpoch, PairCodeEpoch - 1}},
		{"hh:02:00, the previous listed", prev, 120, []int64{PairCodeEpoch}},
		{"hh:01:00, the clock ahead of the list", []obj{entry(PairCodeEpoch-1, 0xa5)}, 60, []int64{PairCodeEpoch - 1}},
		{"hh:03:00, no entry current", []obj{entry(PairCodeEpoch-1, 0xa5)}, 180, nil},
	} {
		var in []paircode.Salt
		for _, o := range c.list {
			n, _ := base64.StdEncoding.DecodeString(o[2].v.(string))
			in = append(in, paircode.Salt{SaltID: o[0].v.(string), Epoch: int64(o[1].v.(int)), Nonce: n})
		}
		checked, err := paircode.CheckSalts(r, in, time.Unix(PairCodeEpoch*paircode.Hour+c.at, 0), nil)
		if err != nil {
			return nil, err
		}
		var got []int64
		for _, e := range paircode.ForPut(checked, time.Unix(PairCodeEpoch*paircode.Hour+c.at, 0)) {
			got = append(got, e.Epoch)
		}
		if len(got) != len(c.order) || len(got) > 0 && (got[0] != c.order[0] || len(got) == 2 && got[1] != c.order[1]) {
			return nil, errors.New("vectors: for_put " + c.name)
		}
		order := []int{}
		for _, e := range c.order {
			order = append(order, int(e))
		}
		forPut = append(forPut, obj{{"name", c.name}, {"salts", c.list}, {"now", at(c.at)}, {"epochs", order}})
	}
	var norm []obj
	for _, c := range []struct{ in, out, err string }{
		{"K7QM-4XPZ", PairCode, ""}, {"k7qm 4xpz", PairCode, ""}, {" K7QM4XPZ ", PairCode, ""}, {"k-7-q-m-4-x-p-z", PairCode, ""},
		{"K7QM-4XP0", "", "bad_symbol"}, {"K7QM-4XP1", "", "bad_symbol"}, {"k7qm-4xpi", "", "bad_symbol"},
		{"k7qm-4xpl", "", "bad_symbol"}, {"k7qm-4xpo", "", "bad_symbol"}, {"K7QM-4XPÉ", "", "bad_symbol"},
		{"K7QM-4XP\u017f", "", "bad_symbol"}, {"K7QM-4XP\u00df", "", "bad_symbol"}, {"K7QM-4XP\u212a", "", "bad_symbol"},
		{"K7QM-4XP", "", "not_a_code"}, {"K7QM-4XPZ2", "", "not_a_code"}, {"https://relay.vettid.org", "", "not_a_code"},
		// (0.94.1) The removed set, one case per class, and each invisible.
		{"K7QM\t4XPZ", PairCode, ""}, {"K7QM\r\n4XPZ\n", PairCode, ""}, {"K7QM\u00a04XPZ", PairCode, ""},
		{"K7QM\u30004XPZ", PairCode, ""}, {"K7QM\u20104XPZ", PairCode, ""}, {"K7QM\u20144XPZ", PairCode, ""},
		{"K7QM\U00010ead4XPZ", PairCode, ""}, {"K7QM\u22124XPZ", PairCode, ""}, {"K7QM\u00ad4XPZ", PairCode, ""},
		{"K7QM\u200b4XPZ", PairCode, ""}, {"K7QM\u200e4XPZ", PairCode, ""}, {"K7QM\u200f4XPZ", PairCode, ""},
		{"K7QM\u20604XPZ", PairCode, ""}, {"\ufeffK7QM-4XPZ", PairCode, ""},
		// Not removed: a non-ASCII character outside the set.
		{"K7QM\u00b74XP", "", "bad_symbol"}, {"K7QM\u00b74XPZ", "", "not_a_code"}, {"K7QM_4XPZ", "", "not_a_code"},
	} {
		got, err := paircode.Normalize(c.in)
		want := map[string]error{"": nil, "bad_symbol": paircode.ErrSymbol, "not_a_code": paircode.ErrCode}[c.err]
		if string(got) != c.out || !errors.Is(err, want) {
			return nil, errors.New("vectors: normalization " + c.in)
		}
		o := obj{{"input", asciiJSON(c.in)}}
		if c.err == "" {
			o = append(o, member{"code", c.out})
		} else {
			o = append(o, member{"error", c.err})
		}
		norm = append(norm, o)
	}
	var relays []obj
	for _, c := range []struct{ in, out string }{
		{"https://relay.vettid.org", "https://relay.vettid.org"}, {"relay.vettid.org", "https://relay.vettid.org"},
		{"HTTPS://Relay.VettID.org/", "https://relay.vettid.org"}, {"https://relay.vettid.org:443", "https://relay.vettid.org"},
		{"relay.example.org:8443", "https://relay.example.org:8443"}, {"xn--bcher-kva.example", "https://xn--bcher-kva.example"},
		{"http://relay.vettid.org", ""}, {"https://relay.vettid.org/v1", ""}, {"https://relay.vettid.org?x=1", ""},
		{"https://relay.vettid.org#x", ""}, {"https://user@relay.vettid.org", ""}, {"https://192.0.2.1", ""},
		{"https://[2001:db8::1]:8443", ""}, {"https://bücher.example", ""}, {"https://relay.vettid.org:0443", ""},
		{"XN--BCHER-KVA.example", "https://xn--bcher-kva.example"}, {"https://relay.vettid.org:443/", "https://relay.vettid.org"},
		{"localhost:8443", "https://localhost:8443"},
		{"relay.vettid.org.", ""}, {"https://relay.vettid.org:", ""}, {"https://1.2.3.4.", ""}, {"https://0177.0.0.1", ""},
		{"https://[fe80::1%25eth0]", ""}, {"https://relay.vettid.org/?", ""}, {"https://relay.vettid.org#", ""},
		{"https://rel%61y.org", ""}, {"https://0x", ""}, {"https://1.0x", ""}, {"https://0x.0x", ""},
		{"https://relay.99999999999999999999999", ""}, {"https://relay.vettid.org:65536", ""}, {"https://relay.vettid.org//", ""},
	} {
		got, err := paircode.CanonicalRelay(c.in)
		if c.out == "" && err == nil || c.out != "" && got != c.out {
			return nil, errors.New("vectors: relay form " + c.in)
		}
		o := obj{{"input", c.in}}
		if c.out != "" {
			o = append(o, member{"r", c.out})
		} else {
			o = append(o, member{"refused", true})
		}
		relays = append(relays, o)
	}
	mod := func(s string) string { return s[:len(s)-1] + "e" } // another canonical id
	sc2 := append([]byte(nil), sc...)
	sc2[15] ^= 1
	changed := append([]byte(nil), blob...)
	changed[len(changed)-1] ^= 1
	notOpen := []obj{
		{{"name", "another claim id"}, {"claim_id", mod(PairCodeClaimID)}},
		{{"name", "another s_c"}, {"salt_b64", base64.StdEncoding.EncodeToString(sc2)}},
		{{"name", "another relay"}, {"r", "https://relay.vettid.org:8443"}},
		{{"name", "the desktop purpose"}, {"purpose", paircode.PurposeDesktop}},
		{{"name", "another code"}, {"code", PairCodeOther}},
		{{"name", "a changed blob"}, {"blob_b64", base64.StdEncoding.EncodeToString(changed)}},
	}
	for _, n := range notOpen {
		p, rr, cid, s, k, bl := paircode.PurposeAgent, r, PairCodeClaimID, sc, kw, blob
		for _, m := range n[1:] {
			switch m.k {
			case "claim_id":
				cid = m.v.(string)
			case "salt_b64":
				s = sc2
			case "r":
				rr = m.v.(string)
			case "purpose":
				p = m.v.(string)
			case "code":
				x2, err := paircode.X(p, rr, []byte(m.v.(string)), s)
				if err != nil {
					return nil, err
				}
				if k, err = paircode.KW(x2); err != nil {
					return nil, err
				}
			case "blob_b64":
				bl = changed
			}
		}
		if _, err := paircode.Open(k, p, rr, cid, s, bl); err == nil {
			return nil, errors.New("vectors: a changed input opened")
		}
	}
	// The desktop purpose's own bundle and blob, and a relay with a port.
	xD, err := paircode.X(paircode.PurposeDesktop, r, []byte(PairCode), sc)
	if err != nil {
		return nil, err
	}
	kwD, err := paircode.KW(xD)
	if err != nil {
		return nil, err
	}
	bd := *b
	bd.Kind = "desktop"
	bdj, err := bd.Marshal()
	if err != nil {
		return nil, err
	}
	blobD, err := paircode.SealWithNonce(kwD, bnonce, paircode.PurposeDesktop, r, PairCodeClaimID, sc, bdj)
	if err != nil {
		return nil, err
	}
	const rPort = "https://relay.example.org:8443"
	srP := paircode.SaltR(rPort, PairCodeEpoch, nonce)
	tagP, err := paircode.Tag(paircode.PurposeAgent, rPort, []byte(PairCode), srP)
	if err != nil {
		return nil, err
	}
	return obj{
		{"description", "VAULT-MESSAGING 0.94.1 §6.7.2 short pairing codes, RELAY-PROTOCOL 0.14.1 §6.9.1. " +
			"Argon2id v0x13 t=3 m=262144 KiB p=1 32 bytes; pw is passed as bytes with its length (it holds 0x00 bytes). " +
			"The blob seals the agent bundle of the vault of keys.json under k_w with aad; each not_open case changes one input, and the blob must not open. " +
			"removed is every code point the input rule removes, U+XXXX, ascending."},
		{"argon2id", obj{{"version", 19}, {"t", paircode.ArgonTime}, {"m_kib", paircode.ArgonMemoryKiB}, {"p", paircode.ArgonThreads}, {"len", paircode.KeySize}}},
		{"code", PairCode},
		{"display", paircode.Display([]byte(PairCode))},
		{"purpose", paircode.PurposeAgent},
		{"r", r},
		{"epoch", PairCodeEpoch},
		{"nonce_b64", base64.StdEncoding.EncodeToString(nonce)},
		{"s_r_hex", hx(sr)},
		{"salt_id", paircode.SaltID(sr)},
		{"pw_lookup_hex", hx(paircode.PW("lookup", paircode.PurposeAgent, r, []byte(PairCode)))},
		{"tag_b64", base64.StdEncoding.EncodeToString(tag)},
		{"tag_desktop_b64", base64.StdEncoding.EncodeToString(tagD)},
		{"s_c_b64", base64.StdEncoding.EncodeToString(sc)},
		{"pw_key_hex", hx(paircode.PW("key", paircode.PurposeAgent, r, []byte(PairCode)))},
		{"x_hex", hx(x)},
		{"k_w_hex", hx(kw)},
		{"claim_id", PairCodeClaimID},
		{"aad_hex", hx(paircode.AAD(paircode.PurposeAgent, r, PairCodeClaimID, sc))},
		{"created", t0.Format(time.RFC3339)},
		{"bundle_json", string(bj)},
		{"blob_nonce_b64", base64.StdEncoding.EncodeToString(bnonce)},
		{"blob_b64", base64.StdEncoding.EncodeToString(blob)},
		{"put_body", obj{{"salt_id", paircode.SaltID(sr)}, {"tag", base64.StdEncoding.EncodeToString(tag)},
			{"salt", base64.StdEncoding.EncodeToString(sc)}, {"blob", base64.StdEncoding.EncodeToString(blob)}}},
		{"not_open", notOpen},
		{"desktop", obj{{"purpose", paircode.PurposeDesktop}, {"x_hex", hx(xD)}, {"k_w_hex", hx(kwD)},
			{"aad_hex", hx(paircode.AAD(paircode.PurposeDesktop, r, PairCodeClaimID, sc))}, {"bundle_json", string(bdj)},
			{"blob_b64", base64.StdEncoding.EncodeToString(blobD)}}},
		{"with_port", obj{{"r", rPort}, {"s_r_hex", hx(srP)}, {"salt_id", paircode.SaltID(srP)},
			{"pw_lookup_hex", hx(paircode.PW("lookup", paircode.PurposeAgent, rPort, []byte(PairCode)))},
			{"tag_b64", base64.StdEncoding.EncodeToString(tagP)}}},
		{"for_put", forPut},
		{"normalize", norm},
		{"removed", removedList()},
		{"relay_forms", relays},
		{"salt_lists", saltCases},
	}, nil
}

// asciiJSON is s as a JSON string with every non-ASCII character as a \\u
// escape (UTF-16), so a look-alike input reads as what it is.
func asciiJSON(s string) json.RawMessage {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r >= 0x7f:
			for _, u := range utf16.Encode([]rune{r}) {
				fmt.Fprintf(&b, "\\u%04x", u)
			}
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return json.RawMessage(b.String())
}

// removedList is every code point the input rule removes (0.94.1 §6.7.2),
// as U+XXXX, in order.
func removedList() []string {
	var cps []rune
	for c := range paircode.Removed {
		cps = append(cps, c)
	}
	slices.Sort(cps)
	out := make([]string, len(cps))
	for i, c := range cps {
		out[i] = fmt.Sprintf("U+%04X", c)
	}
	return out
}
