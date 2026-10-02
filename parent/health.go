package parent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"
)

// Health is the parent's status (no secrets, no vault ids).
type Health struct {
	OK             bool   `json:"ok"`
	InstanceID     string `json:"instance_id"`
	Enclave        bool   `json:"enclave_connected"`
	Release        string `json:"release,omitempty"`
	Vaults         int    `json:"vaults"`
	LastHeartbeat  int64  `json:"last_heartbeat,omitempty"`
	Processed      int    `json:"processed"`
	SplitBrain     int    `json:"split_brain"`
	LeasesLost     int    `json:"leases_lost"`
	EgressOpen     int    `json:"egress_open"`
	EgressTotal    int    `json:"egress_total"`
	HeartbeatError bool   `json:"heartbeat_error,omitempty"`
}

// Health returns the current status.
func (p *Parent) Health() Health {
	open, total := p.fwd.stats()
	p.mu.Lock()
	defer p.mu.Unlock()
	h := Health{InstanceID: p.cfg.InstanceID, Enclave: p.sess != nil, Vaults: len(p.running), Processed: p.stats.processed,
		SplitBrain: p.stats.splitBrain, LeasesLost: p.stats.leasesLost, EgressOpen: open, EgressTotal: total, HeartbeatError: p.stats.heartbeatErr}
	if p.desc != nil {
		h.Release = p.desc.release
	}
	if !p.stats.lastHeartbeat.IsZero() {
		h.LastHeartbeat = p.stats.lastHeartbeat.Unix()
	}
	h.OK = h.Enclave && p.desc != nil && !p.stats.lastHeartbeat.IsZero() && p.now().Sub(p.stats.lastHeartbeat) < 3*p.cfg.Heartbeat
	return h
}

// RunningVaults returns the ids of the vaults the enclave reported open
// (tests).
func (p *Parent) RunningVaults() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, 0, len(p.running))
	for id := range p.running {
		out = append(out, id)
	}
	return out
}

func (p *Parent) serveHealth(ctx context.Context) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		h := p.Health()
		w.Header().Set("Content-Type", "application/json")
		if !h.OK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		_ = json.NewEncoder(w).Encode(h)
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	l, err := net.Listen("tcp", p.cfg.HealthAddr)
	if err != nil {
		p.log.Error("health endpoint failed", "error", err.Error())
		return
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	_ = srv.Serve(l)
}
