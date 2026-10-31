package vote

import (
	"encoding/json"
	"testing"
)

// FuzzSyncBody feeds vote.site.sync's body parser (sync.go) arbitrary
// bytes: it must neither panic nor answer anything but a JSON object or an
// error response.
func FuzzSyncBody(f *testing.F) {
	id := lid(1)
	for _, s := range []string{
		`{}`,
		`{"services_confirm":{"version":1,"sha256":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}`,
		`{"entries":[{"proposal_id":"` + id + `","document":{"status":"absent"}}]}`,
		`{"entries":[{"proposal_id":"` + id + `","index":{"service_id":"x"},"document":{"status":"unreachable"}}]}`,
		`{"entries":[{"proposal_id":"` + id + `","document":{"status":"found","at":1}}]}`,
		`{"lists":[{"doc":"AAAA","sig":"AAAA"}]}`,
		`{"lists":[],"entries":[{}]}`,
		`{"blob":{"id":"x","key":"AAAA","sha256":"AAAA","size":1}}`,
		`[`, `null`, `{"entries":{}}`, `{"entries":[1]}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > 1<<16 {
			return
		}
		c := newCastEnv(t)
		r := c.app("vote.site.sync", string(body))
		if r.OK() && !json.Valid(r.Body) {
			t.Fatalf("answer is not JSON: %q", r.Body)
		}
	})
}
