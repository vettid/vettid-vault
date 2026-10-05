package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/vettid/vettid-vault/enclave/awskms"
	"github.com/vettid/vettid-vault/enclave/keypolicy"
	"github.com/vettid/vettid-vault/internal/hostproto"
	"github.com/vettid/vettid-vault/internal/selftest"
	"github.com/vettid/vettid-vault/internal/vaultipc"
	"github.com/vettid/vettid-vault/vault/store"
	"github.com/vettid/vettid-vault/vms/manifest"
	"github.com/vettid/vettid-vault/vms/nitro"
)

// selftestLabel domain-separates the self-test's attestation user_data,
// so the parent can never obtain an attestation that looks like an ETK
// descriptor's or a vault bundle's.
const selftestLabel = "vettid/vms/2/selftest"

// handleSelftest runs the hardware smoke test once (docs/SMOKE.md). It
// is only available when the parent's hello asked for it, before any
// instance exists, and it reports no secret.
func (s *Supervisor) handleSelftest(ctx context.Context, f *hostproto.Frame) [][]byte {
	// The request can overtake the end of the hello exchange.
	select {
	case <-s.selftestReady:
	case <-time.After(10 * time.Second):
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	if !s.selftestMode || s.cfg.SelftestEgress == nil || len(f.Fields) != 1 {
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	req, err := selftest.ParseRequest(f.Fields[0])
	if err != nil {
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	var rep *selftest.Report
	ran := false
	s.selftestOnce.Do(func() {
		ran = true
		rep = s.runSelftest(ctx, req)
	})
	if !ran {
		return hostproto.Strings(hostproto.StatusInvalid)
	}
	defer close(s.selftestDone)
	b, _ := json.Marshal(rep)
	return [][]byte{[]byte(hostproto.StatusOK), b}
}

func errStr(err error) string {
	if err == nil {
		return ""
	}
	return errText(err)
}

func (s *Supervisor) runSelftest(ctx context.Context, req *selftest.Request) *selftest.Report {
	r := &selftest.Report{Version: 1}
	s.selftestNSM(r)
	s.selftestProcess(r)

	// c. Egress: enclave TLS with pinned roots through the parent.
	tr, err := s.cfg.SelftestEgress(req.Region)
	if err != nil {
		r.Add("egress.config", false, true, errStr(err))
		return r
	}
	hc := tr.Client(60 * time.Second)
	s.selftestRelay(ctx, r, hc)
	st := &statusFetcher{url: s.cfg.StatusListURL, http: hc, now: s.now}
	if err := st.fetch(ctx); err != nil {
		r.Add("egress.google_status_list", false, true, errStr(err))
	} else {
		r.Add("egress.google_status_list", true, true, fmt.Sprintf("%d entries", st.get().Len()))
	}

	// d. KMS with the parent's role credentials.
	creds := &awskms.CachedCredentials{Source: s.link.credentials, Skew: 5 * time.Minute, Now: s.now}
	kms := awskms.NewClient(hc, req.Region, creds)
	if s.cfg.KMSEndpoint != "" {
		kms.Endpoint = s.cfg.KMSEndpoint
	}
	s.selftestKeyPolicy(ctx, r, kms, req)
	s.selftestVaultProcess(ctx, r, kms, req)

	// e. Storage through the parent.
	s.selftestStore(ctx, r, req)

	// f. Memory.
	r.MemTotal, r.MemAvailable = meminfo("MemTotal"), meminfo("MemAvailable")
	r.SupervisorRSS = selfStatus("VmRSS")
	r.Add("memory.reported", r.MemTotal > 0, true, fmt.Sprintf("total=%d available=%d supervisor_rss=%d vault_peak_rss=%d",
		r.MemTotal, r.MemAvailable, r.SupervisorRSS, r.VaultPeakRSS))

	// g. Capacity (W9), when asked: synthetic vault processes only.
	if req.Capacity != nil {
		s.selftestCapacity(ctx, r, *req.Capacity)
	}
	return r
}

// a. NSM: an attestation with a nonce and domain-separated user_data,
// verified against the pinned Nitro root.
func (s *Supervisor) selftestNSM(r *selftest.Report) {
	m, err := s.cfg.NSM.Measurements()
	if err != nil {
		r.Add("nsm.measurements", false, true, errStr(err))
		return
	}
	r.PCR0, r.PCR1, r.PCR2 = m.PCR0, m.PCR1, m.PCR2
	r.Add("nsm.measurements", !m.IsDebug(), true, "debug="+fmt.Sprint(m.IsDebug()))
	nonce := make([]byte, 32)
	_, _ = rand.Read(nonce)
	ud := sha256.Sum256(append([]byte(selftestLabel), nonce...))
	doc, err := s.cfg.NSM.Attest(ud[:], nonce, nil)
	if err != nil {
		r.Add("nsm.attestation", false, true, errStr(err))
		return
	}
	if s.cfg.NitroRoots == nil {
		r.Add("nsm.attestation_verifies", false, true, "no roots")
		return
	}
	d, err := nitro.Verify(doc, s.cfg.NitroRoots)
	ok := err == nil && d.CheckUserData(ud[:]) == nil && d.CheckNonce(nonce) == nil && d.CheckFresh(s.now(), 5*time.Minute, time.Minute) == nil &&
		d.Measurements().Equal(m)
	r.Add("nsm.attestation_verifies", ok, true, fmt.Sprintf("document %d bytes %s", len(doc), errStr(err)))
	if !ok {
		r.AttestationDocument = doc
	}
}

// b. The process environment the vault processes depend on.
func (s *Supervisor) selftestProcess(r *selftest.Report) {
	_, err := os.Stat("/proc/self/exe")
	r.Add("proc.mounted", err == nil, true, errStr(err))
	exe, err := os.Executable()
	r.Add("proc.self_exe", err == nil && exe != "", true, exe)
	y, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope")
	r.Add("kernel.yama_ptrace_scope", err == nil && strings.TrimSpace(string(y)) == "3", false, strings.TrimSpace(string(y))+errStr(err))
	d, err := supervisorDumpable()
	r.Add("supervisor.not_dumpable", err == nil && d == 0, true, fmt.Sprintf("dumpable=%d", d))
	for _, n := range s.hardenNotes {
		r.Add("supervisor.hardening_note", false, false, n)
	}
}

func (s *Supervisor) selftestRelay(ctx context.Context, r *selftest.Report, hc *http.Client) {
	host := "relay.vettid.org"
	if len(s.cfg.RelayHosts) > 0 {
		host = s.cfg.RelayHosts[0]
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+host+"/healthz", nil)
	resp, err := hc.Do(req)
	if err != nil {
		r.Add("egress.relay_healthz", false, true, errStr(err))
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var h struct{ Status, Protocol string }
	_ = json.Unmarshal(b, &h)
	r.Add("egress.relay_healthz", resp.StatusCode == 200 && h.Status == "ok" && RelayProtocolOK(h.Protocol), true,
		fmt.Sprintf("%s %d protocol=%s", resp.Proto, resp.StatusCode, h.Protocol))
	r.Add("egress.relay_http2", resp.ProtoMajor == 2, true, resp.Proto)
}

// MinRelayMinor is the oldest RELAY-PROTOCOL minor version (0.x) the vault
// works with: 0.4.0 (collect jti, §1.2). Later minors are additive (spec
// §7.3); 0.5.0 adds the mailbox deletion that §12.5 uses when available.
const MinRelayMinor = 4

// RelayProtocolOK reports whether a relay's /healthz protocol version
// ("0.<minor>.<patch>") is one the vault works with.
func RelayProtocolOK(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) != 3 || parts[0] != "0" {
		return false
	}
	minor, err1 := strconv.Atoi(parts[1])
	_, err2 := strconv.Atoi(parts[2])
	return err1 == nil && err2 == nil && minor >= MinRelayMinor && parts[1] == strconv.Itoa(minor)
}

// selftestManifest is an unsigned, in-memory manifest naming this
// enclave's measurements as release 1 sealed to the test key; it exists
// only to run the §11.10.7 check (never to verify a served manifest).
func selftestManifest(m nitro.Measurements, keyARN string) *manifest.Manifest {
	return &manifest.Manifest{Serial: 1, IssuedAt: time.Now(), Releases: []manifest.Release{{Number: 1, PCR0: m.PCR0, PCR1: m.PCR1,
		PCR2: m.PCR2, SealKey: keyARN, Status: manifest.StatusActive}}}
}

// d. The §11.10.7 check on the deletable test key: it has an admin
// statement, so it must be refused, and without that statement it should
// pass (showing the refusal is for the right reason).
func (s *Supervisor) selftestKeyPolicy(ctx context.Context, r *selftest.Report, kms *awskms.Client, req *selftest.Request) {
	desc, err1 := kms.DescribeKey(ctx, req.KeyARN)
	pol, err2 := kms.GetKeyPolicy(ctx, req.KeyARN)
	gr, err3 := kms.ListGrants(ctx, req.KeyARN)
	if err := errors.Join(err1, err2, err3); err != nil {
		r.Add("kms.read_key", false, true, errStr(err))
		return
	}
	r.Add("kms.read_key", true, true, "DescribeKey, GetKeyPolicy, ListGrants over enclave TLS (HTTP/1.1)")
	m, _ := s.cfg.NSM.Measurements()
	in := keypolicy.Input{KeyARN: req.KeyARN, Account: req.Account, Region: req.Region, Manifest: selftestManifest(m, req.KeyARN),
		Target: 1, DescribeKey: desc, GetKeyPolicy: pol, ListGrants: gr}
	// The image's pinned retirement role and window (0.10.0), if it pins
	// them for the test key's account.
	if s.cfg.Enclave != nil {
		if c := s.cfg.Enclave("selftest"); c.RetirementPrincipal != "" && c.SealAccount == req.Account {
			in.RetirementPrincipal, in.RetirementWindowDays = c.RetirementPrincipal, c.RetirementWindowDays
		}
	}
	_, err := keypolicy.Check(in)
	var ce *keypolicy.CheckError
	if errors.As(err, &ce) {
		r.KeyPolicyCheck = ce.Check
	}
	r.Add("kms.policy_check_rejects_test_key", err != nil, true, errStr(err))
	if stripped, n := withoutAdmin(pol); n > 0 {
		in.GetKeyPolicy = stripped
		_, err := keypolicy.Check(in)
		r.Add("kms.policy_check_passes_without_admin", err == nil, false, fmt.Sprintf("%d admin statement(s) removed %s", n, errStr(err)))
	}
}

// withoutAdmin removes Allow statements whose Action has a wildcard (the
// key administrator statement) from a GetKeyPolicy response.
func withoutAdmin(resp []byte) ([]byte, int) {
	var outer struct {
		Policy     string `json:"Policy"`
		PolicyName string `json:"PolicyName"`
	}
	if json.Unmarshal(resp, &outer) != nil {
		return nil, 0
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(outer.Policy), &doc) != nil {
		return nil, 0
	}
	var stmts []map[string]json.RawMessage
	if json.Unmarshal(doc["Statement"], &stmts) != nil {
		return nil, 0
	}
	keep := stmts[:0]
	removed := 0
	for _, st := range stmts {
		if strings.Contains(string(st["Action"]), "*") && strings.Contains(string(st["Effect"]), "Allow") {
			removed++
			continue
		}
		keep = append(keep, st)
	}
	doc["Statement"], _ = json.Marshal(keep)
	b, _ := json.Marshal(doc)
	out, _ := json.Marshal(map[string]string{"Policy": string(b), "PolicyName": outer.PolicyName})
	return out, removed
}

// b, d, f: a vault process (re-executed, own uid, seccomp, rlimits)
// round-trips a data key with its own Recipient key and runs the default
// Argon2id once.
func (s *Supervisor) selftestVaultProcess(ctx context.Context, r *selftest.Report, kms *awskms.Client, req *selftest.Request) {
	s.kms = kms
	s.encCfg.SealAccount, s.encCfg.SealRegion = req.Account, req.Region
	h := newProcHost(s, s.cfg.Proc)
	p, err := h.spawn("selftest", "selftest", false, "-selftest")
	if err != nil {
		r.Add("vault_process.spawn", false, true, errStr(err))
		return
	}
	defer h.stop(p)
	r.Add("vault_process.spawn", true, true, fmt.Sprintf("re-executed %s", h.cfg.Exec[0]))
	cctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	rep, err := p.conn.Call(cctx, vaultipc.KindSelftest, []byte(req.KeyARN))
	if err != nil || len(rep) != 2 || string(rep[0]) != hostproto.StatusOK {
		r.Add("vault_process.answered", false, true, errStr(err))
		return
	}
	var vr selftest.VaultResult
	if err := json.Unmarshal(rep[1], &vr); err != nil {
		r.Add("vault_process.answered", false, true, "malformed result")
		return
	}
	r.Checks = append(r.Checks, vr.Checks...)
	r.VaultPeakRSS = vr.PeakRSS
	want := s.cfg.Proc.UIDBase
	if want > 0 {
		r.Add("vault_process.own_uid_gid", vr.UID == want+p.slot && vr.GID == want+p.slot, true, fmt.Sprintf("uid=%d gid=%d", vr.UID, vr.GID))
	} else {
		r.Add("vault_process.own_uid_gid", false, false, fmt.Sprintf("uid switching off (uid=%d)", vr.UID))
	}
}

// e. Create-only, version-matched and stale writes through the parent.
func (s *Supervisor) selftestStore(ctx context.Context, r *selftest.Report, req *selftest.Request) {
	st := &hostStore{l: s.link}
	key := "smoke/" + req.RunID + "/object"
	v1, err := st.Put(ctx, key, []byte("one"), "")
	r.Add("s3.create_only_put", err == nil, true, errStr(err))
	if err != nil {
		return
	}
	_, err = st.Put(ctx, key, []byte("again"), "")
	r.Add("s3.create_only_refuses_existing", errors.Is(err, store.ErrConflict), true, errStr(err))
	v2, err := st.Put(ctx, key, []byte("two"), v1)
	r.Add("s3.if_match_put", err == nil, true, errStr(err))
	_, err = st.Put(ctx, key, []byte("stale"), v1)
	r.Add("s3.stale_if_match_refused", errors.Is(err, store.ErrConflict), true, errStr(err))
	b, v, err := st.Get(ctx, key)
	r.Add("s3.read_back", err == nil && string(b) == "two" && v == v2, true, errStr(err))
	err = st.Delete(ctx, key, v2)
	r.Add("s3.conditional_delete", err == nil, false, errStr(err))
}

func meminfo(field string) uint64 { return procField("/proc/meminfo", field) }

func selfStatus(field string) uint64 { return procField("/proc/self/status", field) }

func procField(path, field string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(line, field+":"); ok {
			var kb uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(rest), "%d", &kb); err == nil {
				return kb * 1024
			}
		}
	}
	return 0
}
