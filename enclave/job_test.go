package enclave

import (
	"bytes"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/vms/altchan"
	"github.com/vettid/vettid-vault/vms/envelope"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/suite"
)

func testJob() *Job {
	kid, _ := suite.ParseKidHex("0011223344556677")
	return &Job{Op: OpUnlock, VaultID: "0123456789abcdef0123456789abcdef", UserGUID: "u-1", RequestID: "01JZZZZZZZZZZZZZZZZZZZZZZZ", ETKKid: kid,
		Inner: &envelope.Inner{Type: altchan.TypeUnlock, ID: "01JZZZZZZZZZZZZZZZZZZZZZZZ", TS: time.Date(2026, 10, 2, 12, 0, 0, 123e6, time.UTC), Body: []byte(`{"a":1}`)}}
}

func TestJobRoundTrip(t *testing.T) {
	j := testJob()
	g, err := ParseJob(j.Fields())
	if err != nil || g.Op != j.Op || g.VaultID != j.VaultID || !g.ETKKid.Equal(j.ETKKid) || !g.Inner.TS.Equal(j.Inner.TS) || !bytes.Equal(g.Inner.Body, j.Inner.Body) {
		t.Fatalf("%+v %v", g, err)
	}
	if g.Manifest != nil {
		t.Fatal("manifest from an empty field")
	}
	// 0.10.0: the manifest document travels with the job.
	j.Manifest = []byte(`{"manifest":"e30="}`)
	if g2, err := ParseJob(j.Fields()); err != nil || !bytes.Equal(g2.Manifest, j.Manifest) {
		t.Fatalf("manifest field: %v", err)
	}
	// 0.15.0: the app key and the account snapshot travel with the job.
	j.AppKey, j.Account = []byte{1, 2, 3}, []byte(`{"v":1}`)
	if g3, err := ParseJob(j.Fields()); err != nil || !bytes.Equal(g3.AppKey, j.AppKey) || !bytes.Equal(g3.Account, j.Account) {
		t.Fatalf("app key / account fields: %v", err)
	}
	g.Wipe()
	if !bytes.Equal(g.Inner.Body, make([]byte, len(g.Inner.Body))) {
		t.Fatal("wipe")
	}
	bad := func(i int, v string) [][]byte { f := testJob().Fields(); f[i] = []byte(v); return f }
	for name, f := range map[string][][]byte{
		"op": bad(0, "lock"), "vault": bad(1, "A/B"), "guid": bad(2, "a b"), "ulid": bad(3, "x"), "kid": bad(4, "00112233445566"),
		"type": bad(5, altchan.TypeEnroll), "id": bad(6, "01JYYYYYYYYYYYYYYYYYYYYYYY"), "ts": bad(7, "2026-10-02T12:00:00Z"), "body": bad(8, ""),
		"count":              testJob().Fields()[:9],
		"manifest too large": bad(9, string(make([]byte, manifest.MaxServed+1))),
	} {
		if _, err := ParseJob(f); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseJob(f *testing.F) {
	f.Add([]byte("unlock"), []byte(`{"a":1}`), []byte("2026-10-02T12:00:00.123Z"), []byte(`{"manifest":"e30="}`))
	f.Fuzz(func(t *testing.T, op, body, ts, doc []byte) {
		fs := testJob().Fields()
		fs[0], fs[7], fs[8], fs[9] = op, ts, body, doc
		j, err := ParseJob(fs)
		if err != nil {
			return
		}
		if _, err := ParseJob(j.Fields()); err != nil {
			t.Fatal("re-encoding refused")
		}
	})
}
