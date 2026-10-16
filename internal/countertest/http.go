package countertest

import (
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/vault/counter"
)

// Handler serves the S3 calls of the counter (VAULT-HOST-PROTOCOL §8.1)
// over HTTP from the bucket, for the enclave's real client: path-style
// keys on a virtual-hosted host, Date headers from the counter's clock,
// and a refusal of any request without the expected owner or a SigV4
// Authorization header. Pages hold at most PageSize entries, so the
// client's pagination is exercised.
func (b *Bucket) Handler(account string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Amz-Expected-Bucket-Owner") != account || !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") ||
			!strings.Contains(r.Header.Get("Authorization"), "x-amz-expected-bucket-owner") {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Date", b.Now().Format(http.TimeFormat))
		key := strings.TrimPrefix(r.URL.Path, "/")
		q := r.URL.Query()
		ctx := context.Background()
		fail := func(err error) {
			if err == counter.ErrUnknown || err == errDown {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		}
		switch {
		case r.Method == http.MethodGet && key == "" && q.Has("versions"):
			b.serveList(w, q.Get("prefix"), q.Get("key-marker"), q.Get("version-id-marker"))
		case r.Method == http.MethodPut:
			body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<16))
			until, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-Amz-Object-Lock-Retain-Until-Date"))
			if err != nil || r.Header.Get("X-Amz-Object-Lock-Mode") != counter.ModeCompliance || r.Header.Get("Content-Md5") == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if r.Header.Get("If-None-Match") == "*" {
				st, v, err := b.PutCreate(ctx, key, body, until)
				if err != nil {
					fail(err)
					return
				}
				if st == counter.PutPrecondition {
					w.WriteHeader(http.StatusPreconditionFailed)
					return
				}
				w.Header().Set("X-Amz-Version-Id", v)
				return
			}
			v, err := b.Put(ctx, key, body, until)
			if err != nil {
				fail(err)
				return
			}
			w.Header().Set("X-Amz-Version-Id", v)
		case r.Method == http.MethodGet && q.Has("retention"):
			ret, err := b.GetRetention(ctx, key, q.Get("versionId"))
			if err != nil {
				fail(err)
				return
			}
			out, _ := xml.Marshal(struct {
				XMLName xml.Name `xml:"Retention"`
				Mode    string   `xml:"Mode"`
				Until   string   `xml:"RetainUntilDate"`
			}{Mode: ret.Mode, Until: ret.Until.Format("2006-01-02T15:04:05.000Z")})
			_, _ = w.Write(out)
		case r.Method == http.MethodGet && q.Has("versionId"):
			body, err := b.GetVersion(ctx, key, q.Get("versionId"))
			if err != nil {
				fail(err)
				return
			}
			_, _ = w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

// PageSize bounds one listing page.
const PageSize = 7

type xmlEntry struct {
	Key          string `xml:"Key"`
	VersionID    string `xml:"VersionId"`
	LastModified string `xml:"LastModified"`
}

func (b *Bucket) serveList(w http.ResponseWriter, prefix, km, vm string) {
	l, err := b.List(context.Background(), prefix)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	sort.SliceStable(l.Entries, func(i, j int) bool { return l.Entries[i].Key < l.Entries[j].Key })
	start := 0
	if km != "" {
		for i, e := range l.Entries {
			if e.Key == km && e.VersionID == vm {
				start = i + 1
			}
		}
	}
	type res struct {
		XMLName       xml.Name   `xml:"ListVersionsResult"`
		IsTruncated   bool       `xml:"IsTruncated"`
		NextKey       string     `xml:"NextKeyMarker,omitempty"`
		NextVersion   string     `xml:"NextVersionIdMarker,omitempty"`
		Versions      []xmlEntry `xml:"Version"`
		DeleteMarkers []xmlEntry `xml:"DeleteMarker"`
	}
	out := res{}
	end := min(start+PageSize, len(l.Entries))
	for _, e := range l.Entries[start:end] {
		x := xmlEntry{Key: e.Key, VersionID: e.VersionID, LastModified: e.LastModified.Format("2006-01-02T15:04:05.000Z")}
		if e.DeleteMarker {
			out.DeleteMarkers = append(out.DeleteMarkers, x)
		} else {
			out.Versions = append(out.Versions, x)
		}
	}
	if end < len(l.Entries) {
		out.IsTruncated = true
		out.NextKey, out.NextVersion = l.Entries[end-1].Key, l.Entries[end-1].VersionID
	}
	b2, _ := xml.Marshal(out)
	_, _ = w.Write(b2)
}
