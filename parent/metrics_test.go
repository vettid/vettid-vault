package parent_test

import (
	"bytes"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/parent"
)

// metricRecords returns the metrics records logged so far.
func (h *harness) metricRecords() []map[string]any {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	var out []map[string]any
	for _, line := range bytes.Split(h.logs.Bytes(), []byte("\n")) {
		var m map[string]any
		if json.Unmarshal(line, &m) == nil && m["msg"] == "metrics" {
			out = append(out, m)
		}
	}
	return out
}

// VAULT-RELAY-SCALING §6: the parent writes its counts and the enclave's
// as CloudWatch embedded-metric records, by instance only; counters as
// their increase since the record before.
func TestMetrics(t *testing.T) {
	h := newHarness(t, func(c *parent.Config) { c.MetricsInterval = 50 * time.Millisecond; c.RelayHost = "relay.example.org" })
	waitFor(t, "a record without an enclave", func() bool { return len(h.metricRecords()) > 0 })
	first := h.metricRecords()[0]
	if _, ok := first[parent.MetricRelayInFlight]; ok || first[parent.MetricUnlockedVaults] != 0.0 || first["InstanceId"] != "i-test" {
		t.Fatalf("record without an enclave: %v", first)
	}

	e := h.connect("boot-1", nil)
	e.mu.Lock()
	e.stats = []string{hostproto.StatusOK, hostproto.StatRelayConns, "8", hostproto.StatRelayDialed, "11", hostproto.StatRelayStreams, "128",
		hostproto.StatRelayInFlight, "900", hostproto.StatRelayWaiting, "2", hostproto.StatRelayWaitMaxMS, "37", hostproto.StatRelayErrors, "5",
		hostproto.StatRelayRefusedMax, "3", hostproto.StatRelayRefusedMin, "1", "vault_id", "7", hostproto.StatRelayConns + "x", "9"}
	e.mu.Unlock()
	c, err := net.Dial("tcp", h.egress)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := hostproto.OpenEgress(c, "relay.example.org", 443); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	waitFor(t, "a record with the enclave's counts and the relay connection", func() bool {
		for _, m := range h.metricRecords() {
			if m[parent.MetricRelayErrors] == 5.0 && m[parent.MetricEgressOpen+"Relay"] == 1.0 {
				rec = m
				return true
			}
		}
		return false
	})
	for k, want := range map[string]float64{parent.MetricRelayInFlight: 900, parent.MetricRelayWaitMax: 37, parent.MetricRelayRefused: 4,
		parent.MetricEgressOpen + "KMS": 0, parent.MetricEgressOpen + "Push": 0, parent.MetricEgressOpen + "Other": 0,
		hostproto.StatRelayConns: 8, hostproto.StatRelayStreams: 128, hostproto.StatRelayWaiting: 2, hostproto.StatRelayRefusedMin: 1} {
		if rec[k] != want {
			t.Errorf("%s = %v, want %v", k, rec[k], want)
		}
	}
	if _, ok := rec["vault_id"]; ok {
		t.Error("a name the parent does not know reached the record")
	}
	// The record is in the embedded metric format: every metric it
	// declares is a number at the top level, the one dimension a string.
	aws, _ := rec["_aws"].(map[string]any)
	dirs, _ := aws["CloudWatchMetrics"].([]any)
	if ts, _ := aws["Timestamp"].(float64); ts < 1e12 || len(dirs) != 1 {
		t.Fatalf("_aws: %v", aws)
	}
	dir := dirs[0].(map[string]any)
	if dims, _ := json.Marshal(dir["Dimensions"]); dir["Namespace"] != parent.MetricsNamespace || string(dims) != `[["InstanceId"]]` {
		t.Errorf("directive: %v", dir)
	}
	declared := map[string]string{}
	for _, d := range dir["Metrics"].([]any) {
		m := d.(map[string]any)
		name, _ := m["Name"].(string)
		if _, ok := rec[name].(float64); !ok {
			t.Errorf("metric %q is not a number in the record", name)
		}
		declared[name], _ = m["Unit"].(string)
	}
	if len(declared) != 13 || declared[parent.MetricRelayWaitMax] != "Milliseconds" || declared[parent.MetricUnlockedVaults] != "Count" ||
		declared[parent.MetricEgressOpened+"Relay"] != "Count" {
		t.Errorf("declared metrics: %v", declared)
	}
	// Counters: the next record carries the increase, not the total.
	n := len(h.metricRecords())
	waitFor(t, "a later record", func() bool { return len(h.metricRecords()) > n+1 })
	later := h.metricRecords()[n+1]
	if later[parent.MetricRelayErrors] != 0.0 || later[parent.MetricRelayRefused] != 0.0 || later[parent.MetricEgressOpened+"Relay"] != 0.0 ||
		later[parent.MetricEgressOpen+"Relay"] != 1.0 || later[parent.MetricRelayInFlight] != 900.0 {
		t.Errorf("later record: %v", later)
	}
}
