# The enclave kernel, built from source

Status: **in use from staging release 13.** `release/eif-toolchain.lock`
pins the blob set `vettid-6.6.158-1`, published as the vettid-vault
release `kernel/6.6.158-1` (built by the `enclave-kernel` workflow from
`a344277`; the source-built toolchain comparison and a hardware run
passed). Releases before 13 used AWS's `aws-nitro-enclaves-sdk-bootstrap`
`v6.6.79` set. This document describes how VettID builds its own blob set
from kernel.org source with a hardened configuration, how two builders
get the same bytes, how it enters the EIF, and how it is kept current.

Why: AWS's packaged enclave kernel is Linux 4.14 in every
`aws-nitro-enclaves-cli` release to date (v1.5.2, 2026-10-09: "No changes
to enclave blobs"). The only newer AWS build is
`aws-nitro-enclaves-sdk-bootstrap` `v6.6.79` (released 2025-02-24, the
repository's last commit). On 2026-10-14 kernel.org lists 6.6.158
(2026-10-03) as the newest 6.6 longterm release
(<https://www.kernel.org/releases.json>). Only a build of our own can be
current.

## 1. What is built

`release/kernel/` builds the six files nitro-cli takes from its blobs
directory:

| File | What | Source |
|---|---|---|
| `Image` | Linux 6.6.y, arm64, text_offset fix-up as AWS does | kernel.org tarball + 2 patches + config |
| `Image.config` | the resolved `.config` | AWS's config + `config/hardening.config` |
| `cmdline` | kernel command line | `release/kernel/cmdline` |
| `init` | AWS's init, static | `aws/init/init.c` + `patches/init-builtin-nsm.patch` |
| `linuxkit` | builds the EIF's ramdisks (runs at build time, not in the enclave) | AWS's linuxkit recipe, unchanged |
| `nsm.ko` | **empty placeholder** | the NSM driver is built into the kernel (§4) |

`extra/vmlinux` and `extra/System.map` are kept for comparison and
debugging; they do not go into the EIF.

### Layout

- `kernel.lock`: every input, by version and hash (the only place that
  names a version).
- `aws/`: files copied unchanged from
  `aws-nitro-enclaves-sdk-bootstrap` at `aws_bootstrap_commit`
  (`f718dea`, tag `v6.6.79`), with `aws/SHA256SUMS`; `scripts/lint_test.go`
  fails if any of them changes. Our changes are separate files:
- `config/hardening.config`, `patches/`, `cmdline`, `default.nix`,
  `kernel.nix`, `init.nix`, `linuxkit.nix`.
- `build.sh` (verify the source and the toolchain, build in the pinned
  container, write `SHA256SUMS`), `check-config.sh` (the fragment must
  hold in the result), `check-current.sh` (the freshness check),
  `eif-with-blobs.sh` (a channel-none EIF from a blob set, for tests).
- `.github/workflows/enclave-kernel.yml`: toolchain and config check, two
  builds, byte-for-byte comparison, an EIF from each, and on demand a
  build with the toolchain from source. `.github/workflows/kernel-freshness.yml`:
  weekly.

## 2. Source

- **The kernel.org tarball** `linux-6.6.159.tar.xz`, not a git mirror:
  `kernel_url` and `kernel_sha256` in the lock. The SHA-256 is also in
  kernel.org's `sha256sums.asc`, signed by the kernel.org checksum
  autosigner (`B8868C80BA62A1FFFAF5FDA9632D3A06589DA6B1`), checked when the
  value was written.
- **The developer's signature.** kernel.org signs the *uncompressed* tar
  (`linux-6.6.159.tar.sign`; <https://www.kernel.org/signature.html>:
  "the signature is made against the uncompressed version of the
  archive"). `build.sh` runs `xz -dc | gpgv` against
  `keys/kernel-org-signers.asc` and requires the `VALIDSIG` primary
  fingerprint to be one of `kernel_signers`. The keyring must hold
  exactly the fingerprints the lock names.
- **The signing keys** pinned: the two stable release signers, Greg
  Kroah-Hartman `647F28654894E3BD457199BE38DBBDC86092693E` (he signed
  6.6.158 and 6.6.159) and Sasha Levin `E27E5D8A3403A2EF66873BBCDEA66FF797772CDC`.
  Each key was taken from kernel.org's Web Key Directory
  (`gpg --locate-keys gregkh@kernel.org sashal@kernel.org`, the route
  kernel.org's page recommends) and from the kernel.org `pgpkeys.git`
  repository (`keys/38DBBDC86092693E.asc`, `keys/DEA66FF797772CDC.asc`);
  both sources give the same fingerprints. A release signed by any other
  key fails the build until that key is added: a deliberate, reviewed
  change.
- **Patches**, both from AWS's recipe:
  - `aws/kernel/nsm.patch`: the NSM driver (upstream since Linux 6.8,
    `drivers/misc/nsm.c`; a cherry-pick for 6.6), unchanged.
  - `patches/0001-vsock-virtio-Remove-queued_replies-pushback-logic.patch`:
    the parent/enclave virtio-vsock deadlock fix (Alexander Graf,
    2024-11-15). Not upstream: `queued_replies` is still in
    `net/vmw_vsock/virtio_transport.c` in v6.6.159 and in mainline
    (checked 2026-10-19; 6.6.159 does not touch the file). AWS's copy no longer applies to 6.6.158 (the rx
    work's context changed: `out_nofill`), so this is the same removal
    rebased, plus dropping the label it leaves unused.

## 3. Toolchain

**Nix, as AWS uses**, in a container pinned by digest:

- `nix_image`: `nixos/nix:2.21.4` by its multi-arch index digest (AWS's
  Dockerfile uses that tag, unpinned). The Nix tool only fetches and
  evaluates; the compiler comes from nixpkgs. The lock names it on Docker
  Hub, where an auditor pulls it; CI pulls the same digest from
  `ghcr.io/vettid/mirror/nix` (`VETTID_IMAGE_MIRROR`,
  `scripts/image-mirror.sh`; docs/RELEASING.md).
- `nixpkgs_url`/`nixpkgs_sha256`: nixpkgs `24.05`, the same pin as AWS's
  `nixpkgs.nix`, which fixes GCC 13.2.0, binutils 2.41 and musl (init).
  Binaries come from `cache.nixos.org`, checked by Nix against the cache's
  signing key and the derivation hashes.
- **Native arm64**, not cross-compiled: two `ubuntu-26.04-arm` runners, as
  the release workflow uses. AWS cross-compiles from x86_64; the compiler
  is the same version but a differently named build (the kernel's version
  string says `gcc (GCC) 13.2.0` rather than
  `aarch64-unknown-linux-gnu-gcc (GCC) 13.2.0`), so our bytes are not
  expected to equal AWS's, only each other's.

- **The toolchain's content is pinned too.** `kernel.lock` has a
  `toolchain=` line per compiler and library (GCC, binutils, the musl GCC
  and musl for init, Go for linuxkit): Nix store path and NAR hash;
  `build.sh` fetches these first and stops early if any differs. After the
  build it hashes the **whole build-time closure**: every store path the
  blob set's derivations depend on that came out of a derivation
  (compilers, libraries, shells, make, perl, fetched sources), except the
  blob set's own derivations, as sorted `path narHash` lines; the SHA-256
  of that list must equal `toolchain_closure_sha256`, or the build fails
  (the list is kept as `toolchain-closure.txt` and the CI compares it
  between builders). So cache.nixos.org's signature is not what vouches
  for any binary the build used.
- **A source-built comparison.** `KERNEL_NO_SUBSTITUTE=1 release/kernel/build.sh`
  (or the `enclave-kernel` workflow run by hand with `source_toolchain`)
  builds the whole toolchain from source, with no cache.nixos.org
  binaries (with `KERNEL_TOOLCHAIN_UNPINNED=1`): it reports where the
  toolchain's NAR hashes and the closure differ from the lock (not every
  nixpkgs package rebuilds bit for bit) and continues, and the blob set
  must equal the cached build's `SHA256SUMS`. Sources (fixed-output
  derivations: tarballs and patches, each checked against its pinned hash)
  and nixpkgs' bootstrap files may still come from cache.nixos.org, which
  keeps copies of sources that have moved or vanished upstream (one
  nixpkgs 24.05 bash patch on cgit.freebsd.org now answers 404);
  everything compiled is built locally. It takes hours; if it outgrows a
  GitHub runner's 6-hour job limit, the same command runs on any larger
  arm64 Linux machine with docker (the owner's, or a Graviton instance),
  with `KERNEL_NO_SUBSTITUTE=1 KERNEL_TOOLCHAIN_UNPINNED=1
  release/kernel/build.sh out "$PWD/release/kernel/SHA256SUMS"`. It is run once before the first blob
  set is adopted, preferably also off GitHub by the owner, and then
  occasionally (at least when nixpkgs or the Nix image changes). Not run
  yet.

Why not a Debian or Amazon Linux container with a compiler package: Nix
already pins the whole toolchain closure by hash, AWS's recipe is Nix
(less to translate, easier to compare with AWS's next change), and the
derivations put the build at fixed paths. The cost is one more tool in
the chain (Nix itself) and the dependency on cache.nixos.org, which the
NAR hashes and the source-built comparison bound.

Changes to AWS's kernel derivation: the tarball instead of `gregkh/linux`
on GitHub; `hardeningDisable = [ "all" ]` (the Nix compiler wrapper's
userland hardening flags stay out of the kernel, as for every kernel
nixpkgs builds; the kernel's own Kconfig sets its hardening); no modules
target; no `git` in the build inputs (nothing should look for a
repository).

## 4. The hardened config

`kernel.nix` appends `config/hardening.config` to AWS's
`microvm-kernel-config-aarch64` (later lines win in Kconfig), runs
`make olddefconfig`, then `check-config.sh` requires every line of the
fragment to hold in the result: an option that Kconfig drops because of
a dependency fails the build instead of being lost silently. The CI
`config` job prints the full difference against AWS's config.

| Change | Why |
|---|---|
| `MODULES=n`, `NSM=y` | No module loading at all after boot (or before). Removes `init_module`/`finit_module` as a way into the kernel, needs no module signing key (a signing key would make the build unreproducible or be public), and makes the command line's `nomodules` question moot. |
| `SECURITY_YAMA=y` | The supervisor already writes `kernel.yama.ptrace_scope=3`; AWS's arm64 config has no Yama, so today that write fails and is only reported. |
| `SECURITY_LOCKDOWN_LSM=y`, `_EARLY=y`, `LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y`, `LSM="lockdown,yama"` | Lockdown in confidentiality mode from boot: no `/dev/mem`, kcore, kprobes, BPF reads of kernel memory, hibernation or unsigned kexec, even for root. |
| `SECURITY_DMESG_RESTRICT=y` | The default the supervisor would otherwise set. |
| `BPF_SYSCALL=n` | No `bpf(2)` at all; seccomp filters are classic BPF and need none of it. Then `kernel.unprivileged_bpf_disabled` does not exist: the supervisor must accept its absence where an unfiltered `bpf(2)` answers `ENOSYS` (pull request #88), so this kernel needs #88 first. |
| `USER_NS=n` | The supervisor closes user namespaces with `max_user_namespaces=0`; now they do not exist. `clone(CLONE_NEWUSER)` answers `EINVAL` instead of `ENOSPC`; the self-test accepts both (`selftest.UserNamespaceNotBuilt`, in this change). `/proc/sys/user/max_user_namespaces` still exists, so the supervisor's write still succeeds. |
| `IO_URING=n` (needs `EXPERT=y`, which only exposes prompts) | Nothing in the enclave uses it; the vault processes' seccomp filter already denies it. |
| `COMPAT=n` | No 32-bit system call entry. The seccomp filter kills foreign-architecture calls; now there are none. |
| `USERFAULTFD=n`, `LEGACY_TIOCSTI=n`, `BINFMT_MISC=n`, `HIBERNATION=n`, `PROC_MEM_NO_FORCE=y` | Unused interfaces with a history of exploitation. |
| `DEBUG_FS=n`, `KPROBES=n`, `PROC_KCORE=n`, `DEVMEM=n`, `MAGIC_SYSRQ=n`, `PERF_EVENTS=n` | Debugging surface; a release enclave has no console access anyway. |
| `HARDENED_USERCOPY`, `SLAB_FREELIST_RANDOM`, `SLAB_MERGE_DEFAULT=n`, `SHUFFLE_PAGE_ALLOCATOR`, `INIT_ON_ALLOC_DEFAULT_ON`, `INIT_ON_FREE_DEFAULT_ON`, `ZERO_CALL_USED_REGS`, `RANDOMIZE_KSTACK_OFFSET_DEFAULT`, `SCHED_STACK_END_CHECK`, `PANIC_ON_OOPS` | Memory hardening. `INIT_ON_FREE` also wipes freed pages, which matters for vault secrets; it costs some CPU (hardware run measures). An oops panics the enclave (restart) rather than continuing in an unknown state. |
| `RANDOMIZE_BASE=y` (KASLR) | Works only if the kernel finds a seed at boot: `/chosen/kaslr-seed` from the loader, or the CPU's `RNDR` instruction (arm64 `kaslr_early_init`). Whether the Nitro loader or Graviton gives either inside an enclave is not documented; without a seed the kernel boots at the fixed address and logs "KASLR disabled". The hardware run reports which. |

Side effects of `MODULES=n` (Kconfig, not chosen separately): the BPF
JIT goes (`BPF_JIT` depends on `MODULES` in 6.6), so the seccomp
filters run in the kernel's interpreter. That removes JIT spraying but
costs a little per filtered system call in the vault processes (the
hardware run measures).
`EXPERT=y` also exposes a few prompts that default off
(`SGETMASK_SYSCALL`, `KCMP`). The `config` CI job lists every difference
against AWS's config.

Kept as AWS has them: `SECCOMP_FILTER`, `VSOCKETS`,
`VIRTIO_VSOCKETS`, `VIRTIO_MMIO`, `HW_RANDOM_VIRTIO`, `ACPI`, `NET`, `INET`
(not used by a release enclave, but not proven unneeded),
`STACKPROTECTOR_STRONG`, `INIT_STACK_ALL_ZERO`, PAC/BTI/MTE, `KEXEC=n`,
`IKCONFIG=n`.

Not done (later, each with its own hardware run): dropping drivers, file
systems, IPv6 and netfilter the enclave never uses; GCC plugins
(`RANDSTRUCT` needs a random seed per build, which conflicts with
reproducibility unless the seed is published, which defeats it).

**Command line**: AWS's, minus `nomodules` (which never did anything: the
kernel's parameter is `nomodule`; and with `MODULES=n` there is nothing
to switch off):
`reboot=k panic=30 pci=off console=ttyS0 random.trust_cpu=on root=/dev/ram0`.

### nsm.ko

The NSM driver is built in (`CONFIG_NSM=y`). nitro-cli 1.5.0 always puts
the blobs directory's `nsm.ko` into the first ramdisk
(`enclave_build/src/yaml_generator.rs`) and refuses to build without one;
AWS's `init` passes it to `finit_module`, which fails with `ENOSYS` on a
kernel without modules and stops the enclave. So:

- `nsm.ko` is an empty file (SHA-256 `e3b0c442…b855`);
- `patches/init-builtin-nsm.patch` makes init remove an empty `nsm.ko`
  without loading it (a non-empty one is loaded as before). It is the only
  change to AWS's init.

Alternatives considered: (a) AWS's init unchanged, `MODULES=y`, `NSM=m`,
and the supervisor writes `kernel.modules_disabled=1` once up: module
loading stays open from boot until then. (b) `MODULES=y` with
`MODULE_SIG_FORCE` and lockdown, `nsm.ko` signed with a key generated for
the build and destroyed afterwards: only that module could ever load, but
the signature makes the build unreproducible (a second builder gets a
different key), so the two-builder rule would cover only the unsigned
parts. Built in has neither problem.

## 5. Reproducibility

- Time: Nix's stdenv sets `SOURCE_DATE_EPOCH` to the newest file time in
  the unpacked kernel tarball (for 6.6.158: 2026-10-03 10:31:19 UTC, the
  release's own time); `KBUILD_BUILD_TIMESTAMP` is derived from it. `KBUILD_BUILD_USER`,
  `KBUILD_BUILD_HOST` (`build_user`, `build_host` in the lock) and
  `KBUILD_BUILD_VERSION=1` are fixed. The kernel says
  `Linux version 6.6.158 (vettid@enclave-kernel) (gcc (GCC) 13.2.0, GNU ld (GNU Binutils) 2.41) #1 SMP Sat Oct  3 10:31:19 UTC 2026`.
- Paths: an in-tree build in Nix's fixed build directory; the kernel
  records paths relative to the source tree. Nix copies the recipe into
  its store by content, so neither the checkout path nor the mount point
  reaches the build.
- What actually varies between the two CI builders: the runner VM, the
  host checkout path (`vettid-vault` vs `elsewhere/build-b/vettid-vault`)
  and the number of build cores (all vs 2, so a different parallel
  order). The workflow also sets a different mount point, umask, `TZ` and
  `LC_ALL` for the second builder, but Nix gives every derivation its own
  fixed environment and build directory, so those do not reach the
  compiler; they show only that the outer environment does not leak in.
  The runner image, docker and host kernel are the same.
- Time: the workflow also runs weekly (`schedule`) and requires the blob
  set to equal the committed `release/kernel/SHA256SUMS`, so builds on
  different dates are compared too. A recipe change updates that file.
- Build IDs: the linker's `--build-id` is a hash of the content, so it is
  the same when the content is.
- Nothing random: no module signing key (no modules), no `RANDSTRUCT`
  seed, `IKHEADERS`/`IKCONFIG` off.
- The archive (`vettid-enclave-blobs.txz`): sorted names, mtime 0, owner
  0, `xz -9 -T1`. Its bytes also depend on the tar and xz versions, so an
  auditor compares the six files, which the lock pins individually.

**Prototype result** (`enclave-kernel` run 38658491828, 2026-10-15
00:20 UTC, two `ubuntu-26.04-arm` runners, about 9 minutes each; that
configuration still had `BPF_SYSCALL=y`): every file identical. The
current configuration's hashes are in the pull request's CI.

```
7e1404640b5cdcc62bee30dc4372ad7caf7536e943a5b36da459efbe36db96fd  Image
af4ae3e6b130918f0fe81f19fa8fdc843dbf468fca773836edc85ed4d4f375ab  Image.config
38ea71e15647d21f0b10e20c5799f0d41936d3bc792476927b48b0580655a4df  cmdline
7cc596d64fac34f78023a7454f972436f7537ad3a1e0d3ff4b0b5821c1ad950d  init
7f973bee46f90c14642a3d459bf4400e9d48a57f8571a252858ec29c71dc4d17  linuxkit
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  nsm.ko
643104a9515b35ffe6acf669341130d882c275e0405566d6bafa490080a32086  extra/vmlinux
25f35cac12636d692c0e65e805d7183104f5a065abbcdd6598ab425a45963975  extra/System.map
6f7e07378a49787a4c9e7c85057515a5fbc07cf842ab8b0bbe822ae590bd3e8d  vettid-enclave-blobs.txz
```

`linuxkit` differs from AWS's v6.6.79 copy (`55788f34…`) although the
recipe is the same: AWS cross-compiled it on x86_64, we build natively.

## 6. Into the EIF

Done for `kernel/6.6.158-1` (staging release 13). The steps, for the next
blob set:

1. **Publishing.** The `enclave-kernel` workflow on `main` builds the
   set twice, compares, and checks it against `release/kernel/SHA256SUMS`.
   Its `blobs-a` artifact, every hash checked again, becomes the
   vettid-vault release `kernel/<version>-<n>` (tag on that commit; for
   `kernel/6.6.158-1` made by hand, with the run linked in the notes; an
   automated, attested publish job is still to do) with these assets:
   - `vettid-enclave-blobs-<version>-<n>.txz` and its `SHA256SUMS`;
   - **the corresponding source** (GPL-2.0 section 3): the exact
     `linux-<version>.tar.xz` and `linux-<version>.tar.sign` from
     kernel.org, and a source archive of `release/kernel/` at the tag
     (patches, config, recipe). The release notes link to both, to
     kernel.org and to the tag. init (MIT) is in `aws/init` with our patch;
     linuxkit (Apache-2.0) is named by version and hash in the recipe.
   The owner approves publishing it. Each vault release also attaches
   its own copy of the archive (docs/RELEASING.md, "Copies of the blobs").
2. **The lock.** `release/eif-toolchain.lock`: `blobs_version=vettid-<version>-<n>`,
   `blobs_url` = the vettid-vault asset, `blobs_dir=vettid-enclave-blobs/aarch64`,
   the archive's and the six files' SHA-256, and a new line
   `kernel_lock_sha256=` (the SHA-256 of `release/kernel/kernel.lock`
   the set was built from), so the chain source → blob set → EIF is
   explicit. `release/Dockerfile.eif-builder` does not change: it already
   downloads an archive, checks it and installs six files.
3. **The enclave binary** knows the pinned kernel: `release/enclave-kernel`
   (`kernel_release=<version>`, `kernel_hardened=true`) is embedded by
   package `release` (`go:embed`; like the release constants, a committed
   file, not build flags; it holds nothing else, so unrelated lock edits
   do not change the binary or PCR2). `scripts/lint_test.go` ties it to
   the lock: `false` needs AWS's `blobs_url` and `blobs_version`
   `v<release>`; `true` needs a vettid-vault release URL,
   `blobs_dir=vettid-enclave-blobs/aarch64` and `release/kernel/kernel.lock`'s
   version. The self-test requires `kernel.release` to equal
   `kernel_release` and, with `kernel_hardened=true`, Yama, lockdown and
   no module support (§8); on AWS's kernel (`false`) those are reported
   only. With `kernel_hardened=true` the supervisor also starts **no vault
   process** unless lockdown reads `[confidentiality]` (as for the user
   namespace and NSM checks), self-test or not.
4. **measurements.json** carries `blobs_version` already; add
   `kernel_lock_sha256`.
5. PCR0 and PCR1 change (kernel, command line, first ramdisk with init
   and `nsm.ko`); PCR2 changes with the binary. It rides an ordinary
   release with its hardware run.

**Before adoption**, `eif-with-blobs.sh BLOBS_DIR OUT` builds a
channel-none EIF from a blob set through exactly that path (the lock
and `release/enclave-kernel` rewritten for the build and restored on
exit, though a SIGKILL can leave them edited; the archive served to the
toolchain image from a local HTTP server on the docker bridge's gateway
address). The `enclave-kernel` workflow
does it for both builders' sets and requires identical PCRs; its `eif-a`
artifact is what the hardware test boots.

### How an auditor rebuilds and compares

On any arm64 Linux machine with docker, curl, xz, gpg, gpgv and git, at
the commit of a vault release that uses the set:

```sh
git checkout release/staging/13      # a release tag (or its commit)
release/kernel/rebuild-check.sh /tmp/kblobs
```

`rebuild-check.sh` requires that the recipe's inputs under
`release/kernel/` in the working tree are unchanged since the commit the
set was built from (`kernel_commit` in the lock; the clone needs that
history) and that `kernel.lock` is the one `kernel_lock_sha256` names;
builds the set with `build.sh` exactly as it was at `kernel_commit`
(which checks the tarball's SHA-256, kernel.org's signature, the
toolchain's NAR hashes and the build-time closure); and then requires the six blob hashes to be the
same in three places: the lock, the rebuild and the published set's
`SHA256SUMS`. It exits non-zero on any difference. With
`KERNEL_NO_SUBSTITUTE=1 KERNEL_TOOLCHAIN_UNPINNED=1` (the toolchain
compiled from source) the NAR and closure checks only report, and the
pass condition is the blob comparison alone.

At the blob set's own tag (`kernel/6.6.158-1`, before the lock pinned it)
the same build is `release/kernel/build.sh out "$PWD/release/kernel/SHA256SUMS"`
(an absolute path: `build.sh` there checks it from inside `out`).
`release/rebuild.sh` then rebuilds the EIF from the pinned hashes. The
two-builder rule covers the blob set (two runners identical, plus
anyone's rebuild), the EIF (two runners identical PCRs) and the owner's
own rebuild.

## 7. Keeping it current

A warning, never a block. **Weekly check** (`kernel-freshness`, Mondays
06:17 UTC, also on `workflow_dispatch`, and report-only on pull requests
that touch the lock): `check-current.sh` reads `kernel_version`, finds
its series in kernel.org's `releases.json` and

- a newer point release: opens (or updates) one issue, opened by the
  Actions bot, with the exact `kernel.lock` lines (version, URL, SHA-256
  from kernel.org's `sha256sums.asc`);
- the first newer release more than 30 days old (`MAX_DAYS_BEHIND`), or
  the series off kernel.org's list or marked end of life (`iseol`): the
  same issue and a workflow warning;
- AWS's bootstrap repository moved past `aws_bootstrap_commit`: an issue
  to compare their config, patches, init and linuxkit with ours;
- an answer it cannot read (kernel.org's version or date not in the
  expected form): the job fails; it never reports "current" then.

**At each release** the `release` workflow's gate runs the same check
against the kernel the release uses (`kernel_release` in
`release/enclave-kernel`) and shows a warning in the run when that kernel
is more than 30 days behind its series' newest point release or its
series is end of life.

It does not open a pull request (the repository's Actions token may not be
allowed to; and the bump needs a person anyway). **A new point release** is
then: the three lock lines; push; the `enclave-kernel` workflow verifies
the signature, checks the config and builds twice; check that the vsock
patch still applies and is still needed (`queued_replies` in
`net/vmw_vsock/virtio_transport.c`); diff the system call table
(`include/uapi/asm-generic/unistd.h`) against the vault's seccomp list
(none is expected inside a stable series); tag and publish the blob set;
run the source-built comparison if nixpkgs or the Nix image changed;
change `eif-toolchain.lock`; it rides the next monthly release, with the
hardware run every release has.

**Series:** 6.6 is maintained to December 2027 (kernel.org's projected
end of life). Moving to 6.12 or 6.18 (December 2028; NSM driver in tree,
so `nsm.patch` goes) is a config forward-port and its own hardware run;
plan it before mid-2027.

## 8. Before it can replace the AWS blob set: hardware

CI builds and compares; only Nitro hardware can boot it. On the staging
smoke host, with the channel-none EIF the `enclave-kernel` workflow
built from this blob set (artifact `eif-a`), after #88 is in it:

1. The enclave boots (the loader takes the Image, init runs, heartbeat on
   vsock 9000, `RUNNING`, not debug); boot time against 6.6.79.
2. `kernel.release` (now required) equals the lock's `kernel_release`,
   6.6.158 for the test EIF; `/proc/cmdline` equals `cmdline`.
3. NSM built in: `/dev/nsm` exists without any module load; no `nsm.ko`
   left in `/`; `nsm.measurements` and `nsm.attestation_verifies` pass;
   attested PCR0 equals CI's; the NSM hwrng feeds entropy (no blocking
   `getrandom`, time to first hello).
4. vsock, TLS egress, KMS with attestation, S3 checks; the capacity run
   with no stall (the vsock patch rebased onto 6.6.158).
5. **New check** `kernel.lockdown` (required with `kernel_hardened`): the
   supervisor mounts securityfs read-only if init has not (AWS's init
   does not) and `/sys/kernel/security/lockdown` must show
   `[confidentiality]`; and vault processes start only then.
6. `kernel.yama_ptrace_scope` (now required with `kernel_hardened`): the
   supervisor's `ptrace_scope=3` write succeeds.
7. User namespaces: `kernel.user_namespaces_off` passes (the sysctl still
   exists) and `vault_process.user_namespace_refused` reports
   `UserNamespaceNotBuilt` (EINVAL).
8. `kernel.unprivileged_bpf_off` (passes by absence: no bpf, with #88),
   the sysctl checks of #88 (absent ones as not built), `supervisor.nsm_closed`,
   `supervisor.not_dumpable`, `vault_process.seccomp_installed` and the
   three `seccomp_refuses_*` pass as before; Go 1.26's runtime and the
   vault code run with `COMPAT=n`, `IO_URING=n`, `USERFAULTFD=n`.
9. **New check** `kernel.modules_absent` (required with
   `kernel_hardened`): neither `/proc/modules` nor
   `/proc/sys/kernel/modules_disabled` exists.
10. **New, informational** `kernel.kaslr`: the KASLR line of the kernel
    log ("KASLR enabled" or "KASLR disabled …"). Not required unless it
    proves to work.
11. Memory (`memory.reported`, capacity `held` against the 6.6.79 run;
    `INIT_ON_FREE` costs CPU) and an idle soak with no console warnings in
    a debug run (`PANIC_ON_OOPS` makes any oops a restart).
