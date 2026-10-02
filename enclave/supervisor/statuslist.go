package supervisor

import (
	"context"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vettid/vettid-vault/vms/devattest"
)

// StatusListURL is Google's attestation status list (§11.7).
const StatusListURL = "https://android.googleapis.com/attestation/status"

// statusFetcher keeps the Google attestation status list, fetched over
// TLS the enclave terminates (pinned Google Trust Services roots). The
// list's age is the enclave's own fetch time.
type statusFetcher struct {
	url  string
	http *http.Client
	now  func() time.Time

	mu   sync.Mutex
	list *devattest.StatusList
	raw  []byte // the list as fetched, for vault processes
}

// rawList returns the fetched bytes and the fetch time.
func (s *statusFetcher) rawList() ([]byte, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.list == nil {
		return nil, time.Time{}, false
	}
	return s.raw, s.list.FetchedAt, true
}

func (s *statusFetcher) get() *devattest.StatusList {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.list
}

func (s *statusFetcher) fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return devattest.ErrRevocationList
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, devattest.MaxStatusList+1))
	if err != nil {
		return err
	}
	l, err := devattest.ParseStatusList(b, s.now())
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.list, s.raw = l, b
	s.mu.Unlock()
	return nil
}

// run refreshes the list every interval (retry after retry on failure).
func (s *statusFetcher) run(ctx context.Context, interval, retry time.Duration, logf func(string, ...any)) {
	for {
		wait := interval
		if err := s.fetch(ctx); err != nil {
			logf("status list fetch failed", "error", errText(err))
			wait = retry
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}
