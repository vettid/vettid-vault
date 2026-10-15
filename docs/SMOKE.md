# V5 hardware smoke test

A one-off run of the **release** enclave image on a real Nitro host,
before V4, to check what CI cannot: the NSM, the vault processes' isolation
under the enclave kernel, the enclave's TLS egress through the parent, KMS
with Recipient attestation, and S3 conditional writes. It uses a temporary
stack (Graviton m7g.large, AL2023 arm64, enclaves enabled, public subnet,
no NAT, SSM only) and a **deletable** test KMS key, both destroyed
afterwards (vettid.org).

## How the self-test is triggered

The EIF is the normal release image (`Dockerfile.enclave`,
`CMD ["/vault-enclave"]`), so its PCR0 is the one a release built from the
same commit has. Nothing in the image is smoke-specific.

`vault-parent -selftest` answers the enclave's hello with mode
`selftest`. Before any instance exists, the supervisor then accepts a
single `Selftest` request with public parameters: run id, key ARN, account
and region. It runs the checks below, returns a report and exits. The
report holds booleans, check names, measurements, sizes and ids. It never
holds a key, a data key or a credential.

- **Attestation.** The self-test's attestation binds
  `SHA-256("vettid/vms/2/selftest" ‖ nonce)`. The domain separation means
  the parent can never obtain a document that passes for an ETK descriptor
  or a vault bundle.
- **Egress.** The self-test's egress is the release allowlist and roots
  plus `kms.<region>.amazonaws.com` for the requested region. The release
  KMS region is still empty until V5 proper.

## What is checked (expected result)

Required checks (any FAIL fails the run):

| Check | Expected |
|---|---|
| `nsm.measurements` | PCR0–2 read; not debug (all-zero) |
| `nsm.attestation_verifies` | document with nonce and the self-test user_data verifies against the pinned AWS Nitro root, is fresh, PCRs match |
| `proc.mounted`, `proc.self_exe` | `/proc` mounted; `/proc/self/exe` resolves (vault processes are re-executions of it) |
| `supervisor.not_dumpable` | `PR_SET_DUMPABLE` 0 |
| `kernel.user_namespaces_off` | `/proc/sys/user/max_user_namespaces` reads `0`: the supervisor wrote it before it reached the parent (release builds only; it needs root in the enclave). No process can then create a user namespace, and a release build starts no vault process while it is not 0 |
| `kernel.unprivileged_bpf_off` | `/proc/sys/kernel/unprivileged_bpf_disabled` is not `0` (the supervisor wrote `1`) |
| `kernel.io_uring_off` | `/proc/sys/kernel/io_uring_disabled` reads `2` **and** `io_uring_setup` in the supervisor (no filter, root) answers EPERM. Detail `kernel/io_uring_disabled = 2; io_uring_setup in the supervisor: operation not permitted`. On a kernel without the setting (4.14) the check holds only where `io_uring_setup` answers ENOSYS (the kernel has no io_uring): detail `absent: no io_uring in this kernel (io_uring_setup: ENOSYS)` |
| `kernel.kptr_restrict`, `kernel.dmesg_restrict`, `kernel.randomize_va_space`, `kernel.protected_symlinks`, `kernel.protected_hardlinks` | read back as written: `2`, `1`, `2`, `1`, `1` (every supported kernel has these) |
| `kernel.perf_event_paranoid`, `kernel.sysrq_off`, `kernel.kexec_load_disabled`, `kernel.modules_disabled`, `kernel.unprivileged_userfaultfd_off`, `kernel.legacy_tiocsti_off`, `kernel.protected_fifos`, `kernel.protected_regular` | read back as written: `3`, `0`, `1`, `1`, `0`, `0`, `2`, `2`. Required where the kernel has the setting. Where it does not (a feature not built in, or a setting newer than the kernel: on 4.14 `unprivileged_userfaultfd` (5.2), `legacy_tiocsti` (6.2), `protected_fifos` and `protected_regular` (4.19)) the check is informational, OK, with detail `absent: <why>` |
| `supervisor.nsm_closed` | `/dev/nsm` is a device owned by root with no access for group or others (the supervisor set it to 0600 and read it back; release builds only). A release supervisor that cannot do so serves no vault: outside the self-test it stops, and it starts no vault process |
| `egress.relay_healthz` | `GET https://relay.vettid.org/healthz` through the parent's forwarder, TLS against the pinned Amazon roots: 200, `status ok`, protocol `0.4.0` or a later `0.x` (0.5.0 adds mailbox deletion) |
| `egress.relay_http2` | the relay connection is HTTP/2 |
| `egress.google_status_list` | the attestation status list from `android.googleapis.com` (GTS roots) parses |
| `kms.read_key` | DescribeKey, GetKeyPolicy, ListGrants on the test key over enclave TLS to `kms.<region>.amazonaws.com` (HTTP/1.1), SigV4 with the instance role's credentials passed by the parent |
| `kms.policy_check_rejects_test_key` | the §11.10.7 check **refuses** the deletable key; `key_policy_check` = **6** (actions: the administrator statement's `kms:*`) unless `-expect-key-check` says otherwise |
| `vault_process.spawn` | a vault process is started by re-executing the enclave binary |
| `vault_process.own_uid_gid` | it runs as uid = gid = the id the supervisor assigned: 200000 plus a counter that only grows, so no id is given to a second process |
| `vault_process.not_dumpable` | `PR_SET_DUMPABLE` 0 in the child |
| `vault_process.user_namespace_refused` | the vault process tries, before it installs its filter (which refuses every clone without `CLONE_THREAD` and would hide the kernel's answer), to start a process in a new user namespace (`clone` with `CLONE_NEWUSER`, of a program that does not exist): the kernel answers ENOSPC and creates nothing. Detail `refused: no user namespace may be created (ENOSPC)`; `a user namespace was created` is the failure |
| `vault_process.seccomp_installed` | the filter installs (needs `CONFIG_SECCOMP_FILTER`) |
| `vault_process.seccomp_refuses_<call>`, one for each probe of `internal/seccomp`: the 13 calls the filter refused as a deny list, `socket_vsock`, `socket_inet`, `socketpair`, `io_uring_setup`, `io_uring_enter`, `io_uring_register`, `ptrace`, `process_vm_readv`, `process_vm_writev`, `pidfd_getfd`, `bpf`, `userfaultfd`, `perf_event_open`; calls added after Linux 4.14, `pidfd_open`, `pidfd_send_signal`, `process_madvise`, `process_mrelease`, `open_tree`, `fsconfig`, `mount_setattr`, `memfd_secret`, `landlock_create_ruleset`, `quotactl_fd`, `cachestat`, `set_mempolicy_home_node`, `io_pgetevents`, `futex_waitv`, `clone3`; older calls a vault process never makes, `execve`, `execveat`, `clone_process` (a clone without `CLONE_THREAD`), `unshare`, `setns`, `mount`, `umount2`, `chroot`, `keyctl`, `memfd_create`, `ioctl`, `connect`, `sendmsg`, `recvmsg`; and the calls the filter allows only with certain arguments, made with others: `kill_other` (signal 0 to the process group), `prctl_other`, `prlimit_set`, `mprotect_exec` (46 in the arm64 release image; an amd64 build adds `x32_socket`, `x32_only_ptrace`, `x32_only_process_vm_readv` and `x32_only_process_vm_writev`) | The filter's answer: EPERM, and ENOSYS ("no such call") for `clone3` and `io_uring_setup`. The filter is an allow list (`internal/seccomp`: 49 calls, 7 of them only with certain arguments); every call not on it gets EPERM, `clone3`, `io_uring_setup` and every number above Linux 6.6's last call ENOSYS. Each probe is made with arguments that do nothing (`Probe`: process 0, a descriptor that is not open, flags that do not exist, no address), so that without the filter the kernel answers something else (listed by `vault_process.seccomp_unfiltered_<call>`): on the pinned Linux 6.6.79, the three socket calls succeed (the probe closes what they create); `io_uring_setup` EPERM, from `kernel.io_uring_disabled` = 2 (which is why the filter answers it ENOSYS: EFAULT where io_uring is open); `io_uring_enter` and `io_uring_register` (descriptor not open) EBADF (from Linux 6.13 `io_uring_register` answers EINVAL instead); `ptrace` (`PTRACE_ATTACH` to process 0) ESRCH; `process_vm_readv` and `process_vm_writev` (no vectors) succeed with 0 bytes; `pidfd_getfd` EBADF; `bpf` (`BPF_MAP_LOOKUP_ELEM`, no attributes) EINVAL, because since Linux 5.19 `unprivileged_bpf_disabled` refuses only creating maps and loading programs; `userfaultfd` (every flag bit) EINVAL; `perf_event_open` (no attributes) EFAULT; the descriptor calls EBADF; the flag calls EINVAL; `execve`, `execveat`, `mount`, `chroot` (no path) and `prlimit_set` (new limit at an unmapped address) EFAULT; `clone_process` and `unshare` (`CLONE_NEWUSER` in a process with threads) EINVAL; `keyctl` EOPNOTSUPP; `kill_other` succeeds (signal 0 sends nothing); `memfd_secret` and `landlock_create_ruleset` EINVAL, or ENOSYS/EOPNOTSUPP where the kernel is built without them. On Linux 4.14 every call added since answers ENOSYS. The filter's answer therefore shows the filter, not the kernel's own checks |
| `vault_process.rlimit_as`, `…_nofile`, `…_core`, `…_fsize` | 4 GiB, 64, 0, 0 |
| `vault_process.minimal_environment` | ≤ 3 variables |
| `vault_process.kms_recipient_round_trip` | `GenerateDataKey` with `Recipient` (the child's own RSA key, attested by the supervisor) → unwrapped in the child → `Decrypt` with `Recipient` → unwrapped → **equal** (only equal/not-equal is reported) |
| `vault_process.argon2id_default` | one Argon2id with the production parameters (t=3, 64 MiB); the child's peak RSS is reported |
| `s3.create_only_put`, `s3.create_only_refuses_existing`, `s3.if_match_put`, `s3.stale_if_match_refused`, `s3.read_back` | under `smoke/<run-id>/` in the test bucket: `If-None-Match: *` put, a second create-only put refused, `If-Match` put, a stale `If-Match` refused, read back |
| `memory.reported` | enclave total and available memory, supervisor RSS, vault-process peak RSS |
| (script) attested PCR0 equals the built EIF's | `run-on-host.sh` compares the report's PCR0 with `nitro-cli build-enclave`'s |

Informational checks (reported, never fail the run):

- `kernel.release`: the enclave kernel's version (`/proc/sys/kernel/osrelease`). With the pinned blob set it is `6.6.79`.
- `vault_process.seccomp_unfiltered_<call>`, one for each probe: the vault process makes the same probes before it installs the filter and reports each answer. OK when that answer differs from the filter's (the answers listed above for the pinned kernel), which shows that the matching `seccomp_refuses_<call>` is the filter's refusal. On 6.6.79 every one is OK. On 4.14 `io_uring_setup` and `clone3` are not (the kernel has neither and answers ENOSYS, as the filter does).
- `vault_process.seccomp_allow_list`: the size of the allow list and the architecture (`49 system calls allowed (arm64); every other call EPERM, ENOSYS for clone3, io_uring_setup and calls after Linux 6.6`).
- `kernel.yama_ptrace_scope`: whether the enclave kernel has Yama.
- `supervisor.hardening_note`: one line for each setting the supervisor could not make. A line that begins "user namespaces are not closed", "bpf is not closed" or "kernel.<setting> is not set" goes with the failed check of that name and a failed `vault_process.spawn`: a release supervisor starts no vault process while any of them is not made.
- `kms.policy_check_passes_without_admin`: the same check with the administrator statement removed. It passes when the rest of the test key's policy has the §11.10.7 shape, which shows the refusal is for the right reason.
- `vault_process.open_fds`
- `supervisor.pid1`: the supervisor's pid and parent, and PID 1's name (expected: the EIF's init is PID 1 and the supervisor's parent).
- `supervisor.zombies`: zombies in the enclave after the vault process ended, and how many are the supervisor's (expected 0: orphans go to PID 1, which reaps them).
- `vault_process.threads`: the vault process's threads after the KMS round trip and the Argon2id (evidence for the process limit).
- `vault_process.rlimit_nproc`: `RLIMIT_NPROC` (256), set only where the process runs under a uid of its own.
- `s3.conditional_delete`

## Capacity measurement (W9)

`vault-parent -selftest -capacity N` runs the self-test above and then
measures how many vaults the enclave holds (VAULT-RELEASES §8.8, O6). It
is part of the self-test: the supervisor accepts it only in an enclave
whose parent's hello asked for the self-test, before any instance exists,
and only a vault process started in self-test mode answers its requests.
The release image is unchanged; the same EIF and PCR0 run it.

**What runs.** Synthetic vault processes, spawned exactly like real ones
(re-executed enclave binary, own uid never used before, rlimits including
`RLIMIT_AS` 4 GiB, seccomp, minimal environment, `GOMEMLIMIT` 512 MiB).
Each one does what an unlocking vault does to its memory, one Argon2id at
the release's parameters (t=3, 64 MiB) from a fixed test PIN and a fresh
salt, then decrypts random state of `-capacity-state-kib` (default
1024 KiB) with AES-256-GCM. At rest it holds the state and makes one
channel round trip (a status-list request) every long-poll period (25 s),
as an idle vault's long poll does. No member data, no KMS or S3 traffic,
no key leaves a process; the report holds sizes, times and counts only.

**Phases.**

1. Unlock latency, on an otherwise empty enclave: for each level of
   `-capacity-unlocks` (default `1,2,4`), `-capacity-unlock-samples`
   (default 8) unlocks, that many at a time. Each sample is process
   start + hardening + Argon2id as the supervisor sees it (no KMS or S3
   round trip), reported as p50/p95/max, with the KDF alone.
2. Fill: one synthetic vault after another, up to N. Before each, the
   available memory (`MemAvailable`) must exceed the floor by one
   unlock's peak; if not, the run waits up to `-capacity-settle`
   (default 180 s) for the runtime to return the KDF memory (an idle Go
   process collects every 2 minutes) and stops (`memory_floor`) if it
   does not come back.
3. Steady state: after `-capacity-settle`, every vault's RSS, PSS and
   private memory, the enclave's available memory and the supervisor's
   RSS; then idle CPU time per vault and of the supervisor over
   `-capacity-idle` (default 60 s).
4. Teardown: every synthetic process ends; the available memory after
   it is reported.

**Safety limits.**

- The floor is 15% of the enclave's memory (the release's lock
  threshold, §12.3), at least 256 MiB; `-capacity-floor-mib` can raise
  it, never lower it. No process is started, and no concurrent-unlock
  level is run, unless the available memory stays above the floor by the
  measured unlock peak (+10%; 96 MiB until measured). The enclave is
  never driven out of memory.
- N is at most 1000; state at most 64 MiB; at most 4 unlock levels of
  1–8, 64 samples each.
- `-capacity-budget` (default 90 min) bounds the run: the fill stops
  (`time_budget`) early enough for the steady-state windows and the
  teardown. The parent's timeout is then the budget plus 20 minutes.
- Whatever ends the run (N reached, floor, budget, a failed spawn, the
  parent's timeout), every synthetic process is ended; the vault
  processes also die with the supervisor (`PDEATHSIG`).
- `-capacity` without `-selftest` is refused.

**Report.** The JSON report gains a `capacity` section (all sizes in
bytes, times in ms): `params`, `mem_total_bytes`, `floor_bytes`,
`baseline_available_bytes`, `baseline_supervisor_rss_bytes`, `unlock`
(per level: `p50_ms`, `p95_ms`, `max_ms`, `kdf_p50_ms`, `kdf_p95_ms`),
`steps` (available memory and supervisor RSS by number of vaults),
`held`, `stop_reason` (`max_vaults`, `memory_floor`, `time_budget`, or
`spawn_failed`, `timeout`, `error`), `vault_rss_bytes`,
`vault_pss_bytes`, `vault_private_bytes` (min/mean/max at steady state),
`vault_rss_after_unlock_bytes`, `vault_peak_rss_bytes`,
`steady_available_bytes`, `marginal_bytes_per_vault` ((baseline −
steady available) / held), `projected_max_vaults` ((baseline − floor −
one unlock's peak) / marginal), `idle_cpu_ms_per_vault_minute`,
`supervisor_cpu_ms_per_minute_idle`, `torn_down`,
`available_after_bytes`. The parent also prints `CAPACITY …` lines.
Checks: `capacity.measured` and `capacity.torn_down` (required),
`capacity.unlock_latency` (informational).

The answer to O6 is `held` when the run stopped at `memory_floor` (the
vaults the enclave held with room for one more unlock), and
`projected_max_vaults` otherwise (N or the budget reached first). RSS
counts the shared binary pages in every process; PSS and the marginal
available memory do not.

**On a staging host** (as root through SSM, executionTimeout at least
7200 s; the same steps as the RUNBOOK's canary self-test):

```sh
systemctl stop vault-parent      # also stops the enclave
systemctl start vault-enclave    # a fresh enclave, which dials the self-test parent
/opt/vettid/bin/vault-parent -selftest -smoke-key-arn <vault/smoke-key-arn> -smoke-account <account> \
  -bucket <data bucket> -region us-east-1 -capacity 400 \
  >/root/capacity-report.json 2>/root/capacity.log
grep -E '^(PASS|FAIL|INFO|CAPACITY) ' /root/capacity.log
systemctl stop vault-enclave
sleep 60                         # SQS refuses to recreate the instance queue within 60 s of its deletion
systemctl start vault-enclave vault-parent
```

With the smoke script: `SMOKE_CAPACITY=400 run-on-host.sh run` (and
`SMOKE_MEMORY_MIB=5120` at `prepare` for the O6 allocation).
Off hardware, `TestSelftestCapacity` (e2e, dev enclave) runs it with
N = 3.

## The test key and the instance role

**Test key** (owner decision: a normal, deletable key). The key policy
has:

- the default administrator statement (`arn:aws:iam::<account>:root`,
  `kms:*`), which keeps the key deletable and is why §11.10.7 must refuse
  it;
- `kms:Decrypt` and `kms:GenerateDataKey` for the instance role, each
  with `StringEqualsIgnoreCase` `kms:RecipientAttestation:ImageSha384` =
  the EIF's PCR0, and `StringEquals` `kms:CallerAccount` = the account;
- `kms:DescribeKey`, `kms:GetKeyPolicy` and `kms:ListGrants` for the
  instance role.

With exactly that, the check refuses with check 6 and passes without the
administrator statement. PCR0 is known only after `build`, so the policy
is updated between the two steps.

**Instance role**, besides SSM (`AmazonSSMManagedInstanceCore`):

- `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject` on
  `arn:aws:s3:::<bucket>/smoke/*`;
- `kms:DescribeKey`, `kms:GetKeyPolicy`, `kms:ListGrants`,
  `kms:GenerateDataKey`, `kms:Decrypt` on the test key's ARN;
- nothing else. The self-test touches no DynamoDB table or SQS queue,
  and the parent reads the role's credentials through IMDSv2 (hop limit 1
  is enough: the parent runs on the host).

The host also needs outbound HTTPS for the build: GitHub, go.dev,
proxy.golang.org, sum.golang.org, Docker Hub, the AL2023 repositories.

## Commands (as root on the host, e.g. through SSM `AWS-RunShellScript`)

```sh
COMMIT=<40-hex commit of vettid-vault>
curl -fsSLo /root/run-on-host.sh https://raw.githubusercontent.com/vettid/vettid-vault/$COMMIT/scripts/smoke/run-on-host.sh
chmod +x /root/run-on-host.sh
/root/run-on-host.sh prepare           # nitro-cli, docker, allocator (1 vCPU, 3072 MiB), Go 1.26.9 by checksum
/root/run-on-host.sh build $COMMIT     # vault-parent + EIF; prints commit, binary_sha256, pcr0, pcr1, pcr2
```

Put `pcr0` into the test key's Decrypt and GenerateDataKey conditions,
then:

```sh
SMOKE_REGION=us-east-1 SMOKE_BUCKET=<bucket> SMOKE_ACCOUNT=<account> \
SMOKE_KEY_ARN=arn:aws:kms:us-east-1:<account>:key/<id> \
/root/run-on-host.sh run               # non-debug enclave, vault-parent -selftest, terminate
/root/run-on-host.sh clean             # optional: terminate enclaves, remove /opt/vettid-smoke
```

How a run works:

- `run` prints one PASS, FAIL or INFO line per check, and ends with
  `PASS selftest` or `FAIL selftest`.
- The full JSON report and the parent's log stay in
  `/opt/vettid-smoke/runs/<run-id>/`.
- Every step can be repeated. `prepare` re-applies its configuration;
  `build` re-checks out the commit and rebuilds; `run` terminates any
  enclave first.
- `binary_sha256` should equal the arm64 hash that the CI job
  `enclave-image` prints for the same commit. That job builds twice and
  requires byte-identical binaries.

## First hardware run (2026-10-02, commit d11cb32)

Results: 33 of 34 checks passed on Nitro. The run used nitro-cli 1.5.0,
and the binary's sha256 matched CI.

**The one failure was `nsm.attestation_verifies` ("malformed attestation
document"), and it is fixed.**
- The cause: the real NSM encodes the attestation payload as an
  indefinite-length CBOR map (`0xbf … 0xff`), and `internal/cbor`
  rejected indefinite lengths. KMS accepted the same documents.
- The fix: the decoder now accepts indefinite-length arrays and maps,
  still rejecting duplicate keys, nesting beyond MaxDepth, misplaced
  breaks and indefinite strings.
- Unchanged: the signature still covers the exact received bytes, and
  the chain to the pinned root at the document's timestamp and the
  PCR, digest and field checks are as strict as before.
- The fake NSM now encodes its documents the same way.
- `vms/nitro.TestRealDocument` verifies a real NSM document (fixture in
  `vms/nitro/testdata/`) against the pinned AWS Nitro root.
- If the check ever fails again, the report carries the document
  (`attestation_document`, base64). It is public: the test nonce and the
  self-test user_data only.

**The Yama check's "network error" text was wrong.** A missing file's
`syscall.Errno` satisfied `net.Error`. Errors are now reported as
`open <path>: <errno>`.

## Notes and uncertainties

- **CPUs.** An m7g.large has 2 vCPUs, and the parent keeps at least one,
  so the enclave gets 1 vCPU (`SMOKE_CPUS=1`). Two vCPUs need an
  m7g.xlarge.
- **PCR0 and the toolchain.** PCR0 also depends on the kernel, command
  line, init and NSM module blobs. `build` builds the EIF with the pinned
  toolchain image (`release/eif-toolchain.lock`), not with the host's
  nitro-cli package, whose blobs are a different kernel; the
  measurements name the lock's SHA-256.
- **To confirm on this hardware:**
  - `CONFIG_SECCOMP_FILTER` in the Nitro enclave kernel. Release vault
    processes refuse to run without the filter.
  - Yama (optional).
  - `/proc` mounted by the enclave's init.
  - setuid/setgid to 200000+ from the root supervisor.
  - `RLIMIT_NPROC` and `RLIMIT_FSIZE` on a vault process.
  - `RLIMIT_AS` 4 GiB with Go's arenas.
  - `/dev/nsm` chmod (devtmpfs).
  - The NSM ioctl on arm64 (same `_IOWR(0x0A, 0, 32)`).
  - The enclave clock, which TLS validation and the attestation's
    freshness check use.
  - Early-boot entropy for `getrandom`.
  - The vault processes' allow list on the Nitro kernel: the self-test
    vault process, the KMS round trip, the Argon2id and the capacity run
    all work under it (a call missing from the list fails with EPERM and
    shows as a failed check or a vault process that ends with an error),
    and the vDSO clock (where the arm64 clock cannot be read in user
    space the vDSO falls back to `clock_gettime`, which is allowed).
  - The kernel settings: every `kernel.*` check OK, `modules_disabled`
    written before the supervisor reaches the parent without breaking
    the vsock connection (the driver is loaded by init or built in).
- **Timing.** The first `build` downloads the base image, Go, the modules
  and the AL2023 packages, which takes a few minutes. Use an SSM timeout
  of at least 30 minutes.
- **Destroy everything afterwards:** the stack, the bucket prefix and the
  test key (schedule deletion).
