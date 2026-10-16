package parent

import (
	"context"
	"strconv"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
)

// MetricsNamespace is the CloudWatch namespace of the parent's metrics
// (VAULT-RELEASES §8.7).
const MetricsNamespace = "VettID/Vault"

// The metrics (VAULT-RELAY-SCALING §6). The egress metrics are
// EgressOpen<Class> and EgressOpened<Class>, the class one of Relay, KMS,
// Push and Other. The only dimension is the instance: nothing identifies
// a member, a vault, a mailbox or an address.
const (
	MetricUnlockedVaults = "UnlockedVaults"        // vaults unlocked on this instance
	MetricEgressOpen     = "EgressOpen"            // egress connections open, by class
	MetricEgressOpened   = "EgressOpened"          // egress connections opened since the last record, by class
	MetricRelayInFlight  = "RelayRequestsInFlight" // relay requests on a stream or waiting for one
	MetricRelayWaitMax   = "RelayStreamWaitMax"    // longest wait for a stream in this minute and the one before
	MetricRelayErrors    = "RelayRequestErrors"    // relay requests without an answer since the last record
	MetricRelayRefused   = "RelayGrowthRefused"    // requests that waited at a connection bound since the last record
)

var egressMetricClass = map[string]string{egressRelay: "Relay", egressKMS: "KMS", egressPush: "Push", egressOther: "Other"}

// metrics writes one record every MetricsInterval.
func (p *Parent) metrics(ctx context.Context) {
	t := time.NewTicker(p.cfg.MetricsInterval)
	defer t.Stop()
	last := map[string]uint64{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.writeMetrics(ctx, last)
		}
	}
}

// writeMetrics logs one record in CloudWatch's embedded metric format:
// the log group's agent ships it with the other log lines, and CloudWatch
// takes the metrics the _aws member lists from it. last holds the
// counters of the previous record; a counter's metric is its increase.
func (p *Parent) writeMetrics(ctx context.Context, last map[string]uint64) {
	type def struct{ Name, Unit string }
	var defs []def
	kv := []any{"InstanceId", p.cfg.InstanceID}
	gauge := func(name, unit string, v uint64) {
		defs = append(defs, def{name, unit})
		kv = append(kv, name, v)
	}
	counter := func(name string, v uint64) {
		d := v
		if prev, ok := last[name]; ok && v >= prev {
			d = v - prev // else the counter started again (a new enclave)
		}
		last[name] = v
		gauge(name, "Count", d)
	}
	p.mu.Lock()
	s, vaults := p.sess, len(p.running)
	p.mu.Unlock()
	gauge(MetricUnlockedVaults, "Count", uint64(vaults))
	for _, cl := range egressClasses {
		open, total := p.fwd.classStats(cl)
		gauge(MetricEgressOpen+egressMetricClass[cl], "Count", uint64(open))
		counter(MetricEgressOpened+egressMetricClass[cl], uint64(total))
	}
	if st := enclaveStats(ctx, s); st != nil {
		gauge(MetricRelayInFlight, "Count", st[hostproto.StatRelayInFlight])
		gauge(MetricRelayWaitMax, "Milliseconds", st[hostproto.StatRelayWaitMaxMS])
		counter(MetricRelayErrors, st[hostproto.StatRelayErrors])
		// Which bound it was is in the record, not in a metric.
		counter(MetricRelayRefused, st[hostproto.StatRelayRefusedMax]+st[hostproto.StatRelayRefusedMin])
		for _, k := range []string{hostproto.StatRelayConns, hostproto.StatRelayDialed, hostproto.StatRelayStreams, hostproto.StatRelayWaiting,
			hostproto.StatRelayRefusedMax, hostproto.StatRelayRefusedMin, hostproto.StatRelayVaultLimit} {
			kv = append(kv, k, st[k])
		}
	}
	kv = append(kv, "_aws", map[string]any{
		"Timestamp": p.now().UnixMilli(),
		"CloudWatchMetrics": []map[string]any{{
			"Namespace": MetricsNamespace, "Dimensions": [][]string{{"InstanceId"}}, "Metrics": defs,
		}},
	})
	p.log.Info("metrics", kv...)
}

// enclaveStats asks the enclave for its counts (nil without an enclave or
// an answer). The enclave's answer is numbers under known names; anything
// else in it is dropped.
func enclaveStats(ctx context.Context, s *session) map[string]uint64 {
	if s == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := s.conn.Call(cctx, hostproto.KindStats)
	if err != nil || len(r) == 0 || string(r[0]) != hostproto.StatusOK {
		return nil
	}
	out := map[string]uint64{}
	for i := 1; i+1 < len(r); i += 2 {
		switch k := string(r[i]); k {
		case hostproto.StatRelayConns, hostproto.StatRelayDialed, hostproto.StatRelayStreams, hostproto.StatRelayInFlight, hostproto.StatRelayWaiting,
			hostproto.StatRelayWaitMaxMS, hostproto.StatRelayErrors, hostproto.StatRelayRefusedMax, hostproto.StatRelayRefusedMin,
			hostproto.StatRelayVaultLimit, hostproto.StatHeavyKDFFree:
			if v, err := strconv.ParseUint(string(r[i+1]), 10, 63); err == nil {
				out[k] = v
			}
		}
	}
	return out
}
