# Vault host files

The systemd units and scripts a vault host runs, installed into each
release's AMI by vettid.org's `VettidOrgVaultRelease<N>Stack` (EC2 Image
Builder component, VAULT-RELEASES §8.3). Each release's AMI carries its own
tag's parent and these files at its own source commit, so every release
runs its own parent with its own units.

## How the AMI build uses them

For release tag T at source commit C the component:

1. installs `aws-nitro-enclaves-cli` (pinned) and `amazon-cloudwatch-agent`;
2. downloads the release assets, checks them against vettid.org's pins and
   `nitro-cli describe-eif` (PCR0), and installs
   `/opt/vettid/vault-enclave.eif` and `/opt/vettid/bin/vault-parent`;
3. downloads `deploy/host/SHA256SUMS` at C from
   `raw.githubusercontent.com/vettid/vettid-vault/C/`, checks **its**
   SHA-256 against the pin in vettid.org's release entry, downloads every
   file it lists from the same directory, runs `sha256sum -c` and then
   `bash install.sh` as root in that directory.

`install.sh` is idempotent and starts nothing: it installs the units to
`/etc/systemd/system`, the scripts to `/opt/vettid/bin`, the CloudWatch
template to `/opt/vettid/etc`, `allocator.yaml` to
`/etc/nitro_enclaves/allocator.yaml` (1 vCPU, 5120 MiB: O6), a logrotate
rule for `/var/log/vettid/*.log` (daily, 3 rotations, copytruncate),
enables `nitro-enclaves-allocator`, `vault-host-config`, `vault-enclave`,
`vault-parent` and `vault-lifecycle`, and masks the dnf timers (the host's
DNS firewall blocks the repositories).

After changing a file here, regenerate the sums with `make host-sums`
(`go test ./scripts/` fails on a stale `SHA256SUMS`). The release's
vettid.org entry pins `sha256sum deploy/host/SHA256SUMS` at C
(docs/RELEASING.md).

## Inputs

`/etc/vettid/host.env`, written by the launch template's user data
(cloud-init `write_files`), `KEY=value` lines:

| key | example |
|---|---|
| `VETTID_SSM_PREFIX` | `/vettid-org/prod/vault` |
| `VETTID_REGION` | `us-east-1` |
| `VETTID_RELEASE` | `3` |
| `VETTID_ASG_NAME` | the release's Auto Scaling group (`[A-Za-z0-9_.-]`) |
| `VETTID_LIFECYCLE_HOOK` | its termination lifecycle hook |

SSM `String` parameters under `VETTID_SSM_PREFIX`, read by
`vault-host-config` with one `ssm get-parameters` call (retried for about
5 minutes, then the unit fails): `data-bucket-name`, `vaults-table-name`,
`vault-instances-table-name`, `vault-requests-table-name`,
`control-queue-prefix`, `dlq-arn` (an SQS ARN in this account and region),
`relay-host`, `host-log-group`. The parent itself reads
`<prefix>/control-queue-policy` (`-queue-policy-param`) and creates no
queue without a valid policy.

IMDSv2 (hop limit 1) gives the instance id, the account and the region
(the identity document). The scripts call only IMDS, SSM, Auto Scaling
(`complete-lifecycle-action`) and, through the agent, CloudWatch Logs.
There are no secrets on the host.

## Outputs and boot order

1. `nitro-enclaves-allocator` reserves the enclave's CPU and memory.
2. `vault-host-config` (oneshot, after `cloud-init` and
   `network-online.target`) validates every input with strict patterns and
   writes `/run/vettid/parent.env` (0600: `VAULT_INSTANCE_ID` = the EC2
   instance id, `VAULT_REGION`, `VAULT_BUCKET`, `VAULT_TABLE_VAULTS`,
   `VAULT_TABLE_INSTANCES`, `VAULT_TABLE_REQUESTS`, `VAULT_QUEUE_PREFIX`,
   `VAULT_DLQ_ARN`, `VAULT_RELAY_HOST`, `VAULT_QUEUE_POLICY_PARAM`) and
   `/run/vettid/lifecycle.env`, renders
   `/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json`
   (log group `host-log-group`, streams `{instance_id}/<log>`) and starts
   the agent. A missing `host.env` or parameter fails the unit, and the
   units below do not start.
3. `vault-enclave` (oneshot) runs the EIF in production mode with 1 vCPU,
   5120 MiB, CID 16. It dials the parent's vsock ports 5000/5001 with
   backoff.
4. `vault-parent` (after the enclave, so systemd stops it first) creates
   the instance queue with the policy, serves the enclave and registers
   the instance. Health: `127.0.0.1:8081/healthz`. On SIGTERM it locks
   every vault through the enclave, flushes lifecycle events, deletes the
   instance row and the queue (≤ 60 s; `TimeoutStopSec=90`). The enclave
   is `PartOf` the parent: stopping the parent then stops the enclave.
5. `vault-lifecycle` polls IMDS `autoscaling/target-lifecycle-state`
   every 5 s; on `Terminated` it stops the parent and the enclave and
   completes the lifecycle action with `CONTINUE` (the hook's 300 s
   heartbeat timeout, default `CONTINUE`, covers a failure).

Logs: `/var/log/vettid/{vault-host-config,vault-enclave,vault-parent,vault-lifecycle}.log`,
shipped to CloudWatch Logs.
