# Releasing the vault

How a vault release is built, checked, signed and published, and how
anyone can rebuild one and check that it matches. The plan behind it is
[VAULT-RELEASES](https://github.com/vettid/vettid.org/blob/master/docs/VAULT-RELEASES.md)
(§5 build, §6 keys, §7 manifest, §10 release process, §11 testing); the
formats are VAULT-MESSAGING 0.10.0 §11.10.

| Piece | Where |
|---|---|
| Release workflow (two clean arm64 builds, comparison, attestations, draft release) | [`.github/workflows/release.yml`](../.github/workflows/release.yml) |
| Pinned EIF toolchain (Amazon Linux 2023 by digest, `aws-nitro-enclaves-cli` RPMs by SHA-256, the enclave kernel blob set that vettid-vault builds from kernel.org source and publishes as a `kernel/<version>-<n>` release, by SHA-256 of the archive and of each blob) | [`release/Dockerfile.eif-builder`](../release/Dockerfile.eif-builder), [`release/eif-toolchain.lock`](../release/eif-toolchain.lock) |
| One clean build with that toolchain (CI and independent rebuilds) | [`release/rebuild.sh`](../release/rebuild.sh) → [`scripts/build-eif.sh`](../scripts/build-eif.sh) |
| EIF inspection: PCRs recomputed from the file, build comparison, measurement matching | [`cmd/eifinfo`](../cmd/eifinfo), [`internal/eif`](../internal/eif) |
| Per-channel release constants, the placeholder gate and the only-grow check of the feature list | [`enclave/releasecfg/`](../enclave/releasecfg), `go run ./cmd/releasecfg check [-previous <file>] <channel>` |
| Release-key check against a live KMS key | `vaultctl keycheck` ([`internal/keycheck`](../internal/keycheck)) |
| Manifest rendering, checking and signing | `vaultctl manifest` ([`internal/manifesttool`](../internal/manifesttool)) |
| Compatibility matrix and frozen vectors | [`.github/workflows/compat.yml`](../.github/workflows/compat.yml), [`scripts/compat-matrix.sh`](../scripts/compat-matrix.sh), [`compat/live-releases.txt`](../compat/live-releases.txt), [`testdata/releases/`](../testdata/releases) |

## Status: staging releases, production not yet

**Staging** is complete: `go run ./cmd/releasecfg check staging` passes,
and staging releases 1 and 2 were built, compared and published for
real (`release/staging/1` and `release/staging/2`; release 1 has since
been removed in the retirement drill). **Production** has no release
yet: `enclave/releasecfg/prod.json` still has `"release": 0`, the only
value the gate reports missing (the `TODO-O8` placeholder for the Play
certificate was removed on 2026-10-11, below), so the release gate
refuses every `prod` build, in the workflow, in `Dockerfile.enclave` and
in `scripts/build-eif.sh`, until the release commit sets the number.

The **dry run** with channel `none` (the constant-free image of the
hardware smoke test, which refuses every enrollment and unlock) still
exercises everything else: the pinned toolchain, two clean builds on two
runners, the byte comparison, the PCR recomputation, the attestations.
A dry run starts on every pull request that touches the build, and by
hand from the Actions tab (`release` → *Run workflow*, channel `none`).

### Unblocking production release 1

| Value | State |
|---|---|
| `seal_account`, `retirement_principal` | done: vettid-vault-prod 369484479783 and its `vettid-org-vault-key-retirement` role (fixed name, VAULT-RELEASES §6.3) |
| `manifest_keys` | done: key A (KMS `ECC_NIST_P256`) and key B (offline token), both SubjectPublicKeyInfo, base64 DER |
| `android_signers` | done (O8 as amended 2026-10-11, VAULT-RELEASES 0.1.12 §5.2): one entry, VettID's own release certificate `31a19613…8e65`, class `vettid`. It signs the F-Droid and direct builds and is never given to Google. The Play app-signing certificate is **not** pinned by release 1: a later production release adds it, class `google_play`, before the Play listing goes live |
| `android_package` | done: `com.vettid.app` (VAULT-MESSAGING 0.26.0; the file's value now, no longer a constant in code) |
| `ios_app_id` | done: `3X25CJ86MV.com.vettid.app` (VAULT-MESSAGING 0.35.0; team ID confirmed by the owner 2026-10-17; the file's value now, no longer a constant in code) |
| `features` | done: `[]`, no optional feature in release 1 (VAULT-MESSAGING 0.26.0, STAGING-DEVELOPMENT-PLAN D4) |
| `release` | the release commit sets it to 1 |

The owner's tag-signing key is on their GitHub account (the staging tags
show as *Verified*; the workflow refuses an unsigned, lightweight or
unverified tag), and the retirement and manifest-signer roles exist in the
vettid.org stacks. No workflow change is needed: the gate passes once
the file is complete.

### Android signers and the signer binding

(VAULT-MESSAGING 0.27.0 §11.7.1, §11.10.8; VAULT-RELEASES 0.1.12 §5.2.)
`android_signers` is a list of 1 to 4 entries, each a certificate and
its class:

```json
"android_signers": [
  {"digest": "<SHA-256 of the signing certificate, 64 lowercase hex>", "class": "vettid"}
]
```

| Class | Meaning | Where |
|---|---|---|
| `vettid` | a key only VettID holds: the F-Droid and direct builds | production and staging |
| `google_play` | the Play app-signing key, which Google generates and holds | production, from the release that precedes the Play listing |
| `development` | a development or automation key | staging only: the gate refuses it in `prod.json` |

The gate (`releasecfg check`) refuses an entry without a class, an
unknown class, a member besides the two, a repeated digest, the bare
list of digest strings used before 0.27.0, and `development` in the
production file. The classes are in the embedded file, so they are
measured with the digests; the vault labels a member's app from them and
never from anything the app says.

| File | Signers |
|---|---|
| `prod.json` | `31a19613…8e65` `vettid` (VettID's release certificate) |
| `staging.json` | `bd83a075…b2c4` `vettid` (the staging signing certificate, pinned by #20) and `2fed27b7…14f2` `development` (the automation certificate, pinned by #28) |

**Each vault is bound to the signer of its app.** The digest is recorded
with the attested device key at enrollment, at a transfer and at a
recovery's register. An unlock and a release approval need the recorded
signer to be pinned by the running release, or answer `signer_refused`
(sealed like every result, before the PIN, no backoff, no alarm, audited
as `device.signer_refused` at the next unlock that succeeds). So:

- **Adding a signer** changes nothing for existing vaults.
- **Removing a signer strands the vaults bound to it** at that release,
  from the confirming unlock of the move into it, until the member
  transfers or recovers to an app with a pinned signer. It is a decision
  of the same weight as retiring a release, with the same notice
  (VAULT-RELEASES §3.4 C6). A release that still pins the signer keeps
  unlocking such a vault as long as it lives.
- **The Play certificate.** An app installed from Google Play cannot
  enroll, receive a transfer or register for a recovery on a release
  that does not pin the Play app-signing certificate, so the Play
  listing does not go live, on any track members can install from,
  before a release that pins it is `active`. The Play *upload*
  certificate is never pinned.

**Vaults enrolled before 0.27.0** (staging only; production release 1
has the rule, so no production vault is ever unbound) have no recorded
signer. An app of 0.27.0 or later re-sends its key's certificate chain
with each unlock (`device_assertion.chain`) until `device.list` shows
its `signer`, and the vault binds from it. Without a chain such a vault
is answered `signer_refused`, **except on staging up to release 10
(S10)**, where it unlocks unbound: `releasecfg.StagingUnboundThrough`,
a constant in code that the channel file cannot change, read with the
measured channel and release number (`Config.AcceptsUnbound`). The
staging release after S10 refuses a vault that is still unbound, so move
each staging vault to the `com.vettid.app.staging` build (a transfer, a
recovery or a new enrollment, each of which binds) while S10 is live.
`releasecfg check staging` says so while it applies:
"vaults enrolled before 0.27.0 unlock unbound".

### The staging time scale

(VAULT-MESSAGING 0.43.0 §11.10.8, §11.14.14; VAULT-RELEASES 0.1.32 §5.2;
STAGING-TIME-SCALE.) `time_scale` divides the vault's waits of 1 hour or
more on staging, so that a day becomes an hour:

| Member | Staging | Production | Rule |
|---|---|---|---|
| `time_scale` | `24` (or `1` for a real-time run) | `1` | production exactly 1; staging 1 or 24; missing, a placeholder or any other value is malformed |
| `recovery_quiet_seconds` | `10800` (= 259,200 / `time_scale`) | at least `259200` | on staging exactly 259,200 / `time_scale`; the 72-hour lower bound is production's only |

The image uses the file's value only when its measured channel is
staging (`Config.TimeScale`, like `CounterLock`), and the enclave
returns 1 again in a production image whatever its configuration says
(`enclave.TimeScaleOf`), so no production vault scales whatever its
file says. The value is in the embedded file (so in `releasecfg_sha256`
and PCR0), in the ETK descriptor (`time_scale`, bound by the
attestation), in a transfer bundle and in `vault.status`.

What the vault divides, when each timer starts (`vault.Scale`, rounded
up to a whole second; the absolute time is stored, so a timer started
before a vault moved into the release keeps its time): the owner check's
interval (S1; the setting stays in real units), the recovery code's
delay and validity (S5, S6), the counter's 24-hour unavailable notice
(S8) and the provisional enrollment window (S13). The old phone's held
notice after a transfer (S11) is no longer scaled: since VAULT-MESSAGING
0.55.10 it is kept while its deposit token lives, at most 30 days after
the approval, in real time. The quiet period (S7) is the
channel file's own number. Nothing else changes: rate limits, the
backoff ladders, cryptographic freshness, token lifetimes, the recovery
wait unit (600 s on staging, not divided again), timers between vaults,
durations the member chooses, retention, and the counter's S3 locks.

`releasecfg check` prints the release log's words for the scale; each
release log entry from the release that ships it carries them: "Time
scale: 1 day = 1 hour (staging)", or "Time scale: real time".

### Features and the Android package

(VAULT-MESSAGING 0.26.0 §11.10.8; VAULT-RELEASES 0.1.11 §5.2.) Two
constants of the channel file decide what an image does beyond its keys:

| Member | Staging | Production | Rule |
|---|---|---|---|
| `android_package` | `com.vettid.app.staging` | `com.vettid.app` | exactly the channel's value; any other is malformed. Checked where an attestation is verified (enrollment, a transfer, a recovery's register); an unlock and a release approval do not check it again |
| `ios_app_id` (0.35.0) | `3X25CJ86MV.com.vettid.app.staging` | `3X25CJ86MV.com.vettid.app` | exactly the channel's value; any other is malformed. Checked at an App Attest attestation (enrollment, a transfer, a recovery's register) and at every assertion (unlock, recovery open, release approval), whose authenticator data names the App ID. The first release of a channel that pins it, and any release that changes it, says so in its release log entry (VAULT-RELEASES §3.4, C6) |
| `features` | all seven | `[]` | zero or more of `actions`, `calls`, `intro`, `leash`, `location`, `presence`, `wallet`, each once, in ascending byte order; anything else is malformed (an always-registered feature's name included) |

Both are in the embedded file, so they are in `releasecfg_sha256` and in
PCR0. An image registers exactly the listed optional features: a type of
a feature that is not listed is answered `unsupported_type`, the feature
keeps no state, and a `features.<name>` entry a vault already holds for
it is carried unchanged.

**A channel's list only grows.** `releasecfg check` runs two rules:

1. the file alone (every build: the workflow's gate, `Dockerfile.enclave`,
   `scripts/build-eif.sh`, and a rebuild from the tag);
2. with `-previous <file>`, against the channel file of the channel's
   previous release: a name that file lists and this one lacks is
   refused. A previous file from before 0.26.0 (staging 1 to 9) has no
   list and counts as listing all seven. The release workflow runs this
   on a release tag, reading the previous file from the highest
   `release/<channel>/<m>` tag below the new number; release 1 has no
   previous release.

By hand, before tagging release N:

```sh
git show release/staging/<N-1>:enclave/releasecfg/staging.json > /tmp/previous.json
go run ./cmd/releasecfg check -previous /tmp/previous.json staging
```

**Turning a feature on** is a release whose file adds the name (and whose
log entry names it). **Production's list is tested** in the development
enclave: `vault-enclave -dev-features none` (devenclave builds), or
`devstack -features none`; `e2e.TestNoOptionalFeatures` and
`e2e.TestHostStackProductionFeatures` run it in CI.

**Moving a staging vault to the new package** (S10): the old build keeps
unlocking on S10 and approves the move to it, but can no longer enroll,
receive a transfer or register for a recovery there; attach the vault to
the `com.vettid.app.staging` build by a transfer, a recovery, or a new
enrollment (VAULT-MESSAGING §11.10.8, "Moving the existing staging
vaults"; `e2e.TestAndroidPackagePerChannel`).

### Staging automation attestation

(VAULT-RELEASES §3.1, "Device attestation" on staging: "test CA **and**
the real vendor roots"; owner decision 2026-10-27; STAGING-DEVELOPMENT-PLAN
§2.5.5 and §4.) Until now every staging image accepted Google's roots
only, so nothing could enroll on staging without a phone. The staging
channel file may now name an **automation attestation CA** that staging
images accept beside the vendor roots, so that an automated test can
enroll a member's app device on staging and act as the app
(`vaultctl staging-enroll`, below). Production never accepts it.

```json
"automation_attestation": {
  "android_roots": ["<base64 DER of the CA certificate>"],
  "until": "2027-06-30"
}
```

| Rule | Where it is enforced |
|---|---|
| The member is **optional** and **staging only**: in `prod.json` it is malformed, whatever it holds | `releasecfg.Parse` (and `releasecfg check prod`), as for a `development` signer |
| 1 or 2 roots (a rotation), each a self-signed CA certificate (`cA`, `keyCertSign`) with an ECDSA P-256 or P-384 key, distinct keys; a `TODO-…` root is missing, so the gate refuses the file | `releasecfg.Parse` |
| `until` is the switch's **end date** (STAGING-DEVELOPMENT-PLAN §2.5.5), `YYYY-MM-DD`, UTC, at most 400 days after the newest root's `notBefore`; **no root is valid after that day** | `releasecfg.Parse` |
| `releasecfg check` refuses the file from the day after `until` | `cmd/releasecfg`: judged at `SOURCE_DATE_EPOCH` when set (an image build: `Dockerfile.enclave` and `scripts/build-eif.sh` set it to the commit time, so a rebuild of a tagged release gives the same answer on any day), at the current time otherwise (the release workflow's gate and CI). So no new staging release can be cut with an expired switch, and CI fails on `main` until the member is renewed or removed |
| A running image stops accepting the CA at the end date without a new release | the roots' validity ends with the switch, and §11.7 chain rule 7 refuses an expired certificate at every attestation |
| The roots reach the device policy **only in the staging channel** | `Config.AutomationRoots` is empty for any other channel or no configuration (like `TimeScale` and `CounterLock`); `enclave.releaseConfigFor` appends them to `pins.GoogleAttestationRoots()` only when non-empty |

**Only the root differs.** A chain from the CA passes every other check
of VAULT-MESSAGING §11.7 that a phone's chain does: the chain rules, the
package (`com.vettid.app.staging`), exactly one signer digest pinned by
the release (the automation uses the `development` signer, so the vault
reports "Development build" for it, §11.7.1), the minimum version code
(`android_min_version_code`, 101 on staging), the attestation and
KeyMint security levels (TEE), `deviceLocked` with `verifiedBootState`
Verified, and a generated, hardware-enforced EC P-256 signing key. The
security levels and the root of trust are what the CA **asserts**: no
hardware stands behind them. That is the point and the risk: **whoever
can sign with the CA key can act as a staging device** (enroll with a
member's setup code, receive a transfer, register for a recovery).
That is acceptable on staging only, where vaults are disposable
(STAGING-DEVELOPMENT-PLAN §2.1 rule 5), and it is why production cannot
carry the member.

**`check-tcb` is unaffected.** The CA certificate is a public
certificate in the committed channel file, not test code; the enclave
links no new package. The attester (`internal/autoattest`) is linked
only by `vaultctl`, which has no test or vector-only dependency
(`make check-tcb`); its tests use a local key.

**Who holds the CA key.** Nobody: it is an AWS KMS key in the staging
account (347272280361, us-east-1), `ECC_NIST_P256`, `SIGN_VERIFY`, so
the private key never leaves KMS. The repository holds only the CA
certificate. The key policy lets the account administer the key and
lets one role sign with it; the automation (and the owner, to make the
certificate) assume that role.

The owner's one-time steps, with credentials for the staging account
(the role name is a proposal):

```sh
export AWS_PROFILE=<staging admin profile> AWS_REGION=us-east-1
# 1. The signer role. It needs no IAM policy: the key policy below
#    grants it kms:Sign, kms:GetPublicKey and kms:DescribeKey on this key
#    only. Its trust policy names whoever runs the automation (here the
#    account's own principals; narrow it to the automation's identity).
aws iam create-role --role-name vettid-org-staging-automation-attest --max-session-duration 3600 \
  --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::347272280361:root"},"Action":"sts:AssumeRole"}]}'
# 2. The key (deletable: a staging key) and its alias.
cat > automation-ca-policy.json <<'JSON'
{"Version": "2012-10-17", "Statement": [
  {"Sid": "Administer", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::347272280361:root"},
   "Action": "kms:*", "Resource": "*"},
  {"Sid": "SignAsTheStagingAutomationCA", "Effect": "Allow",
   "Principal": {"AWS": "arn:aws:iam::347272280361:role/vettid-org-staging-automation-attest"},
   "Action": ["kms:Sign", "kms:GetPublicKey", "kms:DescribeKey"], "Resource": "*",
   "Condition": {"StringEquals": {"kms:SigningAlgorithm": "ECDSA_SHA_256"}}}
]}
JSON
KEY=$(aws kms create-key --key-spec ECC_NIST_P256 --key-usage SIGN_VERIFY \
  --description "VettID staging automation attestation CA (staging only, VAULT-RELEASES 3.1)" \
  --policy file://automation-ca-policy.json \
  --tags TagKey=vettid:purpose,TagValue=staging-automation-attestation \
  --query KeyMetadata.KeyId --output text)
aws kms create-alias --alias-name alias/vettid-org-staging-automation-attestation-ca --target-key-id "$KEY"
# 3. The CA certificate, self-signed by the key, valid to the end date;
#    run as the signer role. It prints the PEM on stderr and the member
#    on stdout.
go run ./cmd/vaultctl staging-ca-cert -kms-key alias/vettid-org-staging-automation-attestation-ca -until 2027-06-30
# 4. Add the printed member to enclave/releasecfg/staging.json, then
go run ./cmd/releasecfg check staging
#    and cut the next staging release from that commit (it changes PCR0).
```

The policy's administration statement is the account's usual one; the
staging account's administrators can therefore also grant `kms:Sign`.
That is the same trust as every other staging key.

**The automation as an app** (`vaultctl`, release build: no
`devenclave` tag). The commands refuse anything but the staging channel:
the channel file must be staging's (`-config`, default the checkout's
`enclave/releasecfg/staging.json`), complete, with an automation CA
whose end date has not passed and whose key is the KMS key given; every
URL must be `https` on `staging.vettid.org` or a host under it; the trust
is the AWS Nitro root (`enclave.NitroRoots`) and the staging manifest
keys only, so a production manifest or enclave never verifies.

```sh
go build -o vaultctl ./cmd/vaultctl
export AWS_PROFILE=<a profile that assumes vettid-org-staging-automation-attest>
export VAULTCTL_ATTEST_KMS_KEY=alias/vettid-org-staging-automation-attestation-ca
./vaultctl -state app.json init -role app -name automation -relay https://relay.vettid.org
# a member session on account.staging.vettid.org (the browser's Cookie
# header after the email sign-in: vid_id=...; vid_rt=...), the vault PIN
# and the credential password:
export VAULTCTL_PORTAL_COOKIE='vid_id=...; vid_rt=...' VAULTCTL_PIN=... VAULTCTL_PASSWORD=...
./vaultctl -state app.json -timeout 5m staging-enroll    # prints the vault id
./vaultctl -state app.json request vault.status
./vaultctl -state app.json staging-unlock               # a later session (VAULTCTL_PIN)
```

`staging-enroll` issues a setup code with the member session (`POST
/api/vault/enroll-code` with `X-VettID-CSRF: 1`), redeems it with the
app key, enrolls with an attestation chain the KMS key issues for
`com.vettid.app.staging`, the staging file's `development` signer and
its `android_min_version_code` (`-version-code` to report a higher one),
waits for `vault.enrolled`, runs the first handshake, creates the
credential and confirms the enrollment, as `api-enroll` does on the dev
stack. The device attestation key is a software P-256 key in
`<state>.attest-key` (mode 0600) beside the state file; an unlock signs
with it and needs no KMS call. Both files are the device: whoever holds
them unlocks the vault with the PIN.

**When the switch ends** (or the key is lost or leaked): remove the
member from `staging.json` in the next staging release, schedule the
key's deletion (`aws kms schedule-key-deletion --key-id "$KEY"
--pending-window-in-days 7`) once no live staging release pins the
certificate, and remove the signer role. To renew instead, make a new
certificate (the same key, or a new key as a second root while the two
overlap) with a later `until`, at most 400 days ahead.

## A release, step by step

The numbers are VAULT-RELEASES §10.1's. Production is shown; staging is
the same with `staging` and its own number sequence.

**1. Release commit and tag.** On a release branch, set
`enclave/releasecfg/prod.json` `"release": N` (and any pin changes),
review, merge. Then tag the merged commit, signed and annotated:

```sh
git tag -s release/prod/N -m "Vault production release N"
git push origin release/prod/N
```

(The plan's working name for the tag was `vault-rN`; the workflow uses
`release/<channel>/<n>` so that one pattern covers both channels.)

**2. The release workflow** runs on the tag:

1. `gate`: the tag is `release/<prod|staging>/<n>`, GitHub verifies its
   signature, the channel file passes the release gate and says
   `"release": n`, and (n > 1) its feature list lacks no name of the
   previous release's file (*Features and the Android package*).
2. `build` ×2: two `ubuntu-26.04-arm` runners, two checkout paths, each
   runs `release/rebuild.sh` (the pinned toolchain image, then
   `scripts/build-eif.sh` with no docker build cache).
3. `compare`: the enclave and parent binaries are byte-identical, the
   EIFs' measured sections are byte-identical (`eifinfo compare`), the
   measurements match (`eifinfo match`), and in each build the PCRs
   nitro-cli reported equal the ones recomputed from the EIF
   (`eifinfo pcrs`). The run summary shows `measurements.json`.
4. `attest`: GitHub artifact attestations (SLSA build provenance) for
   `vault-enclave.eif`, `vault-parent` and `measurements.json`.
5. `publish`: a **draft** GitHub release on the tag with
   `vault-enclave.eif`, `vault-parent-arm64` and `measurements.json`.

`measurements.json`:

| Field | Meaning |
|---|---|
| `channel`, `release` | the build's channel and release number |
| `source_commit`, `source_date_epoch` | the commit and its time (file times in the image) |
| `releasecfg_sha256` | SHA-256 of the embedded channel file |
| `binary_sha256`, `parent_sha256` | the enclave binary inside the EIF; the host's `vault-parent` (arm64) |
| `eif_sha256` | this EIF file (differs between builds, see below) |
| `eif_measured_sha256` | every EIF section except the metadata, with their headers: equal between builds |
| `pcr0`, `pcr1`, `pcr2` | recomputed from the EIF and checked against nitro-cli's |
| `nitro_cli_version`, `toolchain_lock_sha256` | the toolchain |
| `blobs_version` | the enclave kernel blob set's release from the lock (`vettid-6.6.159-1` once adopted; `vettid-6.6.158-1` from staging release 13; `v6.6.79`, AWS's, before; pinned already by `toolchain_lock_sha256`; empty for a build without the pinned toolchain). Added after staging release 12: earlier releases' files do not have it and keep their own hashes; `eifinfo match` prints it when it differs but does not require it to match |

**Why the EIF file hash differs between builds.** nitro-cli 1.5.0 writes a
metadata section into every EIF: the build time (to the nanosecond) and
the docker daemon's description of the image (storage paths, tag time).
In the workflow's two builds exactly `BuildMetadata.BuildTime`,
`DockerInfo.GraphDriver` and `DockerInfo.Metadata` differ; the image id
and creation time are equal. No PCR covers that section; the kernel, command line and ramdisks, which the PCRs
cover, are byte-identical. So the comparison is over the measured
sections (`eif_measured_sha256`) and the PCRs, and the published
`eif_sha256` identifies the one EIF that was published (the AMI build
checks it).

**3. Independent rebuild (two-builder rule).** Before anything is signed,
the owner rebuilds the tag on a separate arm64 machine (below) and the
measurements must match. Then publish the draft GitHub release.

**The vettid.org release entry and the AMI.** vettid.org's entry for the
release pins the release tag, its source commit C, PCR0, the SHA-256 of
`measurements.json` and the SHA-256 of `deploy/host/SHA256SUMS` at C:

```sh
git checkout <C> && sha256sum deploy/host/SHA256SUMS
gh release download release/prod/N -p measurements.json -O - | sha256sum
```

The host AMI is built by vettid.org's `VettidOrgVaultRelease<N>Stack`
(EC2 Image Builder, VAULT-RELEASES §8.3): it installs the release's EIF
and `vault-parent-arm64` (checked against those pins and
`nitro-cli describe-eif`), then the files listed in `deploy/host/SHA256SUMS`
at C, checked with `sha256sum -c`, and runs their `install.sh`
([`deploy/host/README.md`](../deploy/host/README.md)). Each release thus
runs its own parent with its own units. After changing anything in
`deploy/host/`, run `make host-sums` (a test fails on a stale
`SHA256SUMS`).

**4. Staging**, hardware self-test and the compatibility run on staging
hardware (VAULT-RELEASES §10.1 step 4, §11).

**5–6. The key, then keycheck.** After `VettidOrgVaultStack` creates the
release key (vettid.org W5), render the draft manifest that will list
release N and check the live key against it, as the retirement role (a
reader in every release key's policy):

```sh
vaultctl manifest render -releases releases.json -previous published.json -out draft.json
AWS_PROFILE=vault-prod-key-retirement vaultctl keycheck -channel prod \
  -key-arn arn:aws:kms:us-east-1:<account>:key/<id> -manifest draft.json -record keycheck/N
```

`keycheck` reads the key's `DescribeKey`, `GetKeyPolicy` and `ListGrants`
with the enclave's own KMS client (`enclave/awskms`, SigV4) and runs the
enclave's own §11.10.7 check (`enclave/keypolicy`) with the channel's
pinned constants from `enclave/releasecfg/prod.json` at the release
commit. Exit status: **0** pass; **1–8** the failing check (2 metadata,
3 grants, 4 policy shape, 6 actions, 7 conditions, 8 principals, 1 key
identity); **9** anything else (usage, an incomplete channel file, AWS
errors). `-record DIR` keeps the three responses for the release record;
`-fixtures DIR` re-checks recorded responses offline. The release stops
if the check fails.

**9–10. Sign and publish the manifest.** See *How the owner signs*. Then,
in vettid.org, commit the served document and the release log entry and
deploy the site (W7); the publish step also copies the document to the
vault data bucket as `manifests/<sha256>.json`.

**After publishing.** In this repository:

- freeze the release's vectors:
  `git archive release/prod/N testdata/vectors | tar -x --strip-components=2 -C testdata/releases/N`
  (create `testdata/releases/N/` first);
- add `release/prod/N` to `compat/live-releases.txt`;
- when a release becomes `removed` and leaves the manifest, delete both.

## How the owner signs

The manifest is signed over exactly its bytes:
`ECDSA-P256-SHA256("vettid/pcr-manifest/1" || 0x00 || manifest_bytes)`,
served as `{"manifest", "sig" (r || s), "key_id"}` (§11.10.1).
`vaultctl manifest` renders canonical bytes (the §11.10.1 member order,
entries sorted, `candidate` releases left out), checks them, signs them
and refuses a signature that does not verify under a **pinned** key.

```sh
# render: serial = the published one + 1, successor rules checked
vaultctl manifest render -releases releases.json -previous published.json -out m.json
vaultctl manifest check -in m.json -previous published.json
```

**Key A (KMS, the normal case).** As the manifest-signer role (owner
only, MFA):

```sh
AWS_PROFILE=vault-prod-manifest-signer vaultctl manifest sign -in m.json \
  -kms-key arn:aws:kms:us-east-1:<account>:key/<key A> -channel prod -out pcr-manifest.json
vaultctl manifest check -in pcr-manifest.json -channel prod
```

The signer asks KMS for the key's public key (it must be
`ECC_NIST_P256` / `SIGN_VERIFY` and pinned in the channel file), signs
the digest (`MessageType DIGEST`, `ECDSA_SHA_256`), converts KMS's DER
signature to r || s and verifies the result before writing it.

**Key B (offline token, only if A is lost or compromised).** The digest
leaves the machine; the key never enters it:

```sh
vaultctl manifest digest -in m.json          # prints digest_sha256 (hex)
# on the offline machine, sign the 32-byte digest with the token's P-256
# key as a raw ECDSA signature (no further hashing), e.g. with PKCS #11:
#   pkcs11-tool --sign --mechanism ECDSA --id <key B> -i digest.bin -o sig.bin
vaultctl manifest import-sig -in m.json -sig sig.bin -signer-pub keyB.pub -channel prod -out pcr-manifest.json
```

`-sig` takes r || s or DER, as binary, hex, base64 or PEM.

**Test and development keys.** `-key FILE` signs with a PEM private key;
it is for tests and local development, and the pinned-key check still
applies. The tests generate their own keys; no real key is in this
repository.

## Rebuild and match (anyone)

Anyone can check that a published release EIF was built from its tag.
You need an arm64 Linux machine (a Graviton instance, an arm64 laptop or
CI runner) with docker, Go 1.26 and python3; no Nitro hardware.

```sh
git clone https://github.com/vettid/vettid-vault && cd vettid-vault
git checkout release/prod/N
gh release download release/prod/N -p measurements.json -p vault-enclave.eif -D published
CHANNEL=prod release/rebuild.sh out published/measurements.json
go run ./cmd/eifinfo compare published/vault-enclave.eif out/vault-enclave.eif
gh attestation verify published/vault-enclave.eif --repo vettid/vettid-vault
```

`rebuild.sh` builds the pinned toolchain image (Amazon Linux 2023 by
digest; the nitro-cli RPMs and every blob checked by SHA-256), builds the
enclave image and the parent from clean, turns the image into an EIF
with nitro-cli and recomputes the PCRs from the file. `eifinfo match`
then requires the same commit, channel, release, channel file, enclave
and parent binaries, measured EIF sections and PCR0/1/2. Finally compare
PCR0 with the release's entry in the signed manifest at
`https://vettid.org/.well-known/vettid/pcr-manifest.json`: that PCR0, not
the attestation or the GitHub release, is what members' apps and the
release keys rely on.

**Where the base images come from.** `release/eif-toolchain.lock`
(`base_image`), `release/kernel/kernel.lock` (`nix_image`) and
`Dockerfile.enclave` name their base images upstream (Amazon ECR Public,
Docker Hub) by digest, and a rebuild like the one above pulls them from
there. The project's CI (the release, enclave-kernel and ci workflows)
sets `VETTID_IMAGE_MIRROR=ghcr.io/vettid/mirror` instead, and
`scripts/image-mirror.sh` pulls the same digests from VettID's copy
(vettid.org `.github/mirror`), because the upstream registries' anonymous
limits fail shared CI runners. A digest names the content, so the images,
and with them every binary hash and PCR, are the same either way; the
lock files and Dockerfiles are not changed by it.

`scripts/smoke/run-on-host.sh build` on a Graviton host builds the same
toolchain image and so gives the same PCRs; VAULT-RELEASES §5.1 asks for
that comparison once on real hardware. A nitro-cli installed from the
Amazon Linux repository does not: its blobs are a different enclave
kernel (Linux 4.14) from the lock's (Linux 6.6.159, built by
vettid-vault from source; docs/KERNEL.md).

The kernel blob set itself can be rebuilt from source as well, on the
same kind of machine (arm64 Linux with docker), and compared with the
hashes the lock pins: `release/kernel/build.sh out "$PWD/release/kernel/SHA256SUMS"`
(an absolute path: `build.sh` at `a344277` checks it from inside `out`),
or `release/kernel/rebuild-check.sh`, which also compares with the lock
and the published set
(docs/KERNEL.md, "How an auditor rebuilds and compares"). The independent
rebuild of a release that changes the kernel does this too.

## The compatibility matrix

VAULT-RELEASES §3.4 promises that a release keeps working for unlock,
an approved move, lock, recovery and the host's delete until it is
removed. The `compat` workflow (nightly and on pull requests touching
wire, storage or host code) checks every tag in
`compat/live-releases.txt` with `scripts/compat-matrix.sh`:

- **Frozen vectors**: the tag's `testdata/vectors` (and every
  `testdata/releases/<n>/`, in `go test ./vms/vectors`) must still be
  derived byte for byte by this tree (`TestFrozenReleaseVectors`).
- **Old host and enclave against new everything else**
  (`integration.TestCompatMoveOnly`, LocalStack): the tag's
  `vault-parent` and dev `vault-enclave` run release 3; this tree's
  vaultctl and client, member API stand-in, queue messages and relay,
  and release 4's parent and enclave. Enroll, status, lock, unlock; the
  release becomes `deprecated`, then `retired`, and still unlocks; the
  member approves a move to release 4; release 4 unlocks the vault.

| Contract | Checked in CI | Not (yet) |
|---|---|---|
| C1 manifest | format, signature label and statuses via frozen vectors; deprecated and retired entries still unlock | rotation through a key every live release pins |
| C2 alternate channel | envelopes, descriptor, signing strings via vectors; the member API stand-in's routes and queue messages against the old parent and enclave | the real member API (vettid.org's own tests) |
| C3 storage | the old parent's vault rows (state, sealed release, lease) and `vaults/<id>/state` read by this tree | schema evolution of real tables |
| C4 host | each release runs its own parent (the old one here) | AMI rebuilds |
| C5 AWS | — (LocalStack, a fake KMS) | real KMS, SigV4 endpoints, Amazon roots (hardware smoke) |
| C6 device attestation | test CA only | vendor roots and signing digests |
| C7 relay | messages flow through this tree's relay with an old vault | — |
| C8 member API features | lock and status | recovery (the stand-in has its routes; the compat row does not exercise them yet) and host delete (no stand-in route yet) |

Until production release 1 the list is empty, and the workflow runs one
**synthetic** row against the pull request's base commit (nightly: the
previous commit). That row is advisory: before release 1 nothing is
frozen and a deliberate wire change may break it. A row for a commit
before VAULT-MESSAGING 0.10.0's manifest-by-hash change fails, as it
should.

Locally, with LocalStack running (`docker compose -f
integration/docker-compose.yml up -d`):

```sh
VAULT_IT_LOCALSTACK=http://127.0.0.1:4566 scripts/compat-matrix.sh --synthetic main
```

Rows run one at a time (`-p 1`). The harness passes this tree's parent
flags to the old parent; if a flag is ever renamed, the matrix needs the
old flag set for older tags.

## Changing the toolchain

Everything in `release/eif-toolchain.lock` goes into PCR0, so changing
any of it is a release like any other. The lock has two parts:

- **nitro-cli.** `base_image` (digest), `releasever` and
  `nitro_cli_version` select the `aws-nitro-enclaves-cli` and `-devel`
  RPMs, pinned by their two SHA-256 lines. Update them from
  `dnf download` in the new base image, and
  `release/Dockerfile.eif-builder`'s `FROM` to the same digest
  (`scripts/lint_test.go` checks they agree). The blobs inside the devel
  RPM are not used: the builder removes them.
- **The enclave kernel blobs.** `blobs_version` names the blob set's
  release: `vettid-<version>-<n>` for vettid-vault's own build
  (`kernel/<version>-<n>` releases of this repository, built by
  `release/kernel` from kernel.org source; docs/KERNEL.md), or `v<version>`
  for an [aws-nitro-enclaves-sdk-bootstrap](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap)
  release. `blobs_url` is that release's archive and `blobs_dir` the
  directory of the arm64 set inside it. `kernel_lock_sha256` is the
  SHA-256 of the `release/kernel/kernel.lock` the set was built from.
  The builder downloads the archive, checks its SHA-256, and installs
  `Image`, `Image.config`, `cmdline`, `init`, `linuxkit` and `nsm.ko`
  from `blobs_dir` in place of the RPM's, then checks each one's
  SHA-256. A new kernel is a new blob set release, then a new
  `blobs_version`, `blobs_url`, `kernel_lock_sha256` and those seven hash
  lines, and `release/enclave-kernel` (`kernel_release`,
  `kernel_hardened`), which the enclave binary embeds and its self-test
  requires (`scripts/lint_test.go` checks they agree).

To check the seven hashes by hand (the same check the builder makes):

```sh
lock=release/eif-toolchain.lock
d="$(mktemp -d)"; dir="$(sed -n 's/^blobs_dir=//p' "$lock")"
curl -fsSL -o "$d/enclaves-blobs.txz" "$(sed -n 's/^blobs_url=//p' "$lock")"
tar -C "$d" --no-same-owner -xJf "$d/enclaves-blobs.txz" "$dir"
sha256sum "$d/enclaves-blobs.txz"
(cd "$d/$dir" && sha256sum Image Image.config cmdline init linuxkit nsm.ko)
grep -E '/(enclaves-blobs\.txz|blobs/)' "$lock"
```

The archive's hash must equal the `/toolchain/enclaves-blobs.txz` line
and each blob's the `/usr/share/nitro_enclaves/blobs/<name>` line.
`grep '^CONFIG_' "$d/$dir/Image.config"` shows the kernel's
configuration. The workflow's dry run on the pull request shows whether
the new toolchain still builds and reproduces.

**Copies of the blobs.** Every release carries its own copy of the blob
archive its EIF was built from: the release workflow's `publish` job
downloads `blobs_url`, checks the lock's SHA-256 and attaches it to the
draft release as `enclave-kernel-blobs-<blobs_version>.txz`. If the
archive's own release ever disappears, a rebuild takes the copy instead
(the hash is the same):

```sh
gh release download release/staging/N --repo vettid/vettid-vault --pattern 'enclave-kernel-blobs-*.txz' --dir /tmp/blobs
# then serve it at blobs_url's place, or point blobs_url at the copy for the rebuild
```

**Corresponding source.** A release with the source-built kernel
distributes Linux (GPL-2.0) in its EIF and in that copy, so the same job
also attaches the recipe's source archive
(`vettid-vault-release-kernel-<version>-<n>-source.tar.gz`, taken from
the blob set's release and checked against the lock's
`kernel_source_sha256` and the release's `SHA256SUMS`) and the
release notes name the blob set's release and the kernel.org tarball
(from `release/kernel/kernel.lock`). The blob set's own
`kernel/<version>-<n>` release carries the kernel.org tarball and its
signature as well. A rerun of the `publish` job replaces the assets of
its own draft and refuses to touch a published release.
