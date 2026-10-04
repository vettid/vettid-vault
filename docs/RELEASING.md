# Releasing the vault

How a vault release is built, checked, signed and published, and how
anyone can rebuild one and check that it matches. The plan behind it is
[VAULT-RELEASES](https://github.com/vettid/vettid.org/blob/master/docs/VAULT-RELEASES.md)
(§5 build, §6 keys, §7 manifest, §10 release process, §11 testing); the
formats are VAULT-MESSAGING 0.10.0 §11.10.

| Piece | Where |
|---|---|
| Release workflow (two clean arm64 builds, comparison, attestations, draft release) | [`.github/workflows/release.yml`](../.github/workflows/release.yml) |
| Pinned EIF toolchain (Amazon Linux 2023 by digest, `aws-nitro-enclaves-cli` RPMs and blobs by SHA-256) | [`release/Dockerfile.eif-builder`](../release/Dockerfile.eif-builder), [`release/eif-toolchain.lock`](../release/eif-toolchain.lock) |
| One clean build with that toolchain (CI and independent rebuilds) | [`release/rebuild.sh`](../release/rebuild.sh) → [`scripts/build-eif.sh`](../scripts/build-eif.sh) |
| EIF inspection: PCRs recomputed from the file, build comparison, measurement matching | [`cmd/eifinfo`](../cmd/eifinfo), [`internal/eif`](../internal/eif) |
| Per-channel release constants and the placeholder gate | [`enclave/releasecfg/`](../enclave/releasecfg), `go run ./cmd/releasecfg check <channel>` |
| Release-key check against a live KMS key | `vaultctl keycheck` ([`internal/keycheck`](../internal/keycheck)) |
| Manifest rendering, checking and signing | `vaultctl manifest` ([`internal/manifesttool`](../internal/manifesttool)) |
| Compatibility matrix and frozen vectors | [`.github/workflows/compat.yml`](../.github/workflows/compat.yml), [`scripts/compat-matrix.sh`](../scripts/compat-matrix.sh), [`compat/live-releases.txt`](../compat/live-releases.txt), [`testdata/releases/`](../testdata/releases) |

## Today: dry runs only

The committed channel files still have placeholders (`TODO-…`), so the
release gate refuses every `prod` and `staging` build, in the workflow,
in `Dockerfile.enclave` and in `scripts/build-eif.sh`. What runs today is
the **dry run** with channel `none`: the constant-free image of the
hardware smoke test, which refuses every enrollment and unlock. It
exercises everything else: the pinned toolchain, two clean builds on two
runners, the byte comparison, the PCR recomputation, the attestations.

A dry run starts on every pull request that touches the build, and by
hand from the Actions tab (`release` → *Run workflow*, channel `none`).
`vaultctl keycheck` and `vaultctl manifest sign` likewise refuse the
committed channel files (no account, no manifest keys yet) and work with
test files.

### Unblocking real releases

A channel builds once its file in `enclave/releasecfg/` has no
placeholder left (`go run ./cmd/releasecfg check prod` passes):

| Value | Waits for | Then |
|---|---|---|
| `seal_account`, `retirement_principal` (prod) | O1 and W3: the vault production account and its `vettid-org-vault-key-retirement` role (fixed name, VAULT-RELEASES §6.3) | the account id and the role ARN |
| `seal_account`, `retirement_principal` (staging) | O2 and W3: the staging account | as above, in the staging account |
| `manifest_keys` (prod) | O3 and W3: key A (KMS `ECC_NIST_P256`) and key B (offline token) | both SubjectPublicKeyInfo, base64 DER (`aws kms get-public-key`; the token's export) |
| `manifest_keys` (staging) | W3: the staging manifest key | its SubjectPublicKeyInfo |
| `android_signers` | O8: the Play app signing certificate and the upload certificate | their SHA-256, lowercase hex |
| `release` | the release commit | the release number |

Also needed before the first real tag:

- the owner's tag-signing key (SSH or GPG) added to their GitHub account,
  so that GitHub shows the tag as *Verified*; the workflow refuses an
  unsigned, lightweight or unverified tag;
- the release role in the vettid.org stacks (W5) for `vaultctl keycheck`,
  and the manifest-signer role for key A.

No workflow change is needed: the gate passes once the file is complete.

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
   `"release": n`.
2. `build` ×2: two `ubuntu-24.04-arm` runners, two checkout paths, each
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

**4. Staging**, hardware self-test and the compatibility run on staging
hardware (VAULT-RELEASES §10.1 step 4, §11).

**5–6. The key, then keycheck.** After `VettidOrgVaultStack` creates the
release key (vettid.org W5), render the draft manifest that will list
release N and check the live key against it, as the retirement role (a
reader in every release key's policy):

```sh
vaultctl manifest render -releases releases.json -previous published.json -out draft.json
AWS_PROFILE=vault-key-retirement vaultctl keycheck -channel prod \
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
AWS_PROFILE=vault-manifest-signer vaultctl manifest sign -in m.json \
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

Building on a Graviton host with nitro-cli installed from the Amazon
Linux repository (`scripts/smoke/run-on-host.sh build`) gives the same
PCRs if its `aws-nitro-enclaves-cli` version and blobs equal the lock's;
VAULT-RELEASES §5.1 asks for that comparison once on real hardware.

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
| C8 member API features | lock and status | recovery and host delete (the stand-in has no routes for them yet) |

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

A new nitro-cli version or a new Amazon Linux base changes the blobs and
therefore every PCR0: it is a release like any other. Update
`release/eif-toolchain.lock` (base image digest, `releasever`,
`nitro_cli_version`, then the RPM and blob hashes, from `dnf download`
in the new base image and `rpm2cpio … | cpio -idm` of the devel
package), and `release/Dockerfile.eif-builder`'s `FROM` to the same
digest (`scripts/lint_test.go` checks they agree). The workflow's dry
run on the pull request shows whether the new toolchain still builds and
reproduces.
