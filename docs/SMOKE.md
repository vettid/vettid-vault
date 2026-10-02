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
| `egress.relay_healthz` | `GET https://relay.vettid.org/healthz` through the parent's forwarder, TLS against the pinned Amazon roots: 200, `status ok`, protocol `0.4.0` |
| `egress.relay_http2` | the relay connection is HTTP/2 |
| `egress.google_status_list` | the attestation status list from `android.googleapis.com` (GTS roots) parses |
| `kms.read_key` | DescribeKey, GetKeyPolicy, ListGrants on the test key over enclave TLS to `kms.<region>.amazonaws.com` (HTTP/1.1), SigV4 with the instance role's credentials passed by the parent |
| `kms.policy_check_rejects_test_key` | the §11.10.7 check **refuses** the deletable key; `key_policy_check` = **6** (actions: the administrator statement's `kms:*`) unless `-expect-key-check` says otherwise |
| `vault_process.spawn` | a vault process is started by re-executing the enclave binary |
| `vault_process.own_uid_gid` | it runs as uid = gid = 200000 + slot |
| `vault_process.not_dumpable` | `PR_SET_DUMPABLE` 0 in the child |
| `vault_process.seccomp_installed` | the filter installs (needs `CONFIG_SECCOMP_FILTER`) |
| `vault_process.seccomp_refuses_socket_vsock`, `…_socket_inet`, `…_ptrace` | EPERM |
| `vault_process.rlimit_as`, `…_nofile`, `…_core` | 4 GiB, 64, 0 |
| `vault_process.minimal_environment` | ≤ 3 variables |
| `vault_process.kms_recipient_round_trip` | `GenerateDataKey` with `Recipient` (the child's own RSA key, attested by the supervisor) → unwrapped in the child → `Decrypt` with `Recipient` → unwrapped → **equal** (only equal/not-equal is reported) |
| `vault_process.argon2id_default` | one Argon2id with the production parameters (t=3, 64 MiB); the child's peak RSS is reported |
| `s3.create_only_put`, `s3.create_only_refuses_existing`, `s3.if_match_put`, `s3.stale_if_match_refused`, `s3.read_back` | under `smoke/<run-id>/` in the test bucket: `If-None-Match: *` put, a second create-only put refused, `If-Match` put, a stale `If-Match` refused, read back |
| `memory.reported` | enclave total and available memory, supervisor RSS, vault-process peak RSS |
| (script) attested PCR0 equals the built EIF's | `run-on-host.sh` compares the report's PCR0 with `nitro-cli build-enclave`'s |

Informational checks (reported, never fail the run):

- `kernel.yama_ptrace_scope`: whether the enclave kernel has Yama.
- `kms.policy_check_passes_without_admin`: the same check with the administrator statement removed. It passes when the rest of the test key's policy has the §11.10.7 shape, which shows the refusal is for the right reason.
- `vault_process.open_fds`
- `s3.conditional_delete`

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
/root/run-on-host.sh prepare           # nitro-cli, docker, allocator (1 vCPU, 3072 MiB), Go 1.26.8 by checksum
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

## Notes and uncertainties

- **CPUs.** An m7g.large has 2 vCPUs, and the parent keeps at least one,
  so the enclave gets 1 vCPU (`SMOKE_CPUS=1`). Two vCPUs need an
  m7g.xlarge.
- **PCR0 and nitro-cli.** PCR0 also depends on the nitro-cli package's
  kernel and init blobs. `build` prints the nitro-cli version; record it
  with the PCRs.
- **To confirm on this hardware:**
  - `CONFIG_SECCOMP_FILTER` in the Nitro enclave kernel. Release vault
    processes refuse to run without the filter.
  - Yama (optional).
  - `/proc` mounted by the enclave's init.
  - setuid/setgid to 200000+ from the root supervisor.
  - `RLIMIT_AS` 4 GiB with Go's arenas.
  - `/dev/nsm` chmod (devtmpfs).
  - The NSM ioctl on arm64 (same `_IOWR(0x0A, 0, 32)`).
  - The enclave clock, which TLS validation and the attestation's
    freshness check use.
  - Early-boot entropy for `getrandom`.
- **Timing.** The first `build` downloads the base image, Go, the modules
  and the AL2023 packages, which takes a few minutes. Use an SSM timeout
  of at least 30 minutes.
- **Destroy everything afterwards:** the stack, the bucket prefix and the
  test key (schedule deletion).
