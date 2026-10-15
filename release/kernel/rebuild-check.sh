#!/usr/bin/env bash
# Rebuild the enclave kernel blob set that release/eif-toolchain.lock pins
# and compare it with the lock and with the published set
# (docs/KERNEL.md, "How an auditor rebuilds and compares"). For the
# independent rebuild of a release; exits non-zero on any difference.
#
#   release/kernel/rebuild-check.sh [OUT_DIR]     (default /tmp/kblobs)
#
# Needs an arm64 Linux machine with docker (usable by this user), git,
# curl, xz, gpg and gpgv, and a checkout of the release's commit with its
# history (for kernel_commit). The environment variables of build.sh
# apply; with KERNEL_NO_SUBSTITUTE=1 KERNEL_TOOLCHAIN_UNPINNED=1 (the
# toolchain compiled from source) build.sh's NAR and closure checks only
# report, and the pass condition is the blob comparison below alone.
set -euo pipefail

cd "$(dirname "$0")/../.."
out="${1:-/tmp/kblobs}"
lock=release/eif-toolchain.lock
val() { sed -n "s/^$1=//p" "$lock"; }

commit="$(val kernel_commit)"
url="$(val blobs_url)"
if [ -z "$commit" ] || [ -z "$url" ]; then
  echo "rebuild-check: the lock names no source-built blob set (kernel_commit, blobs_url)" >&2
  exit 1
fi

# 1. The recipe's inputs in this working tree are the ones the set was
# built from. The build itself runs with build.sh as it was at that commit
# (step 2), since build.sh holds the source, signature, NAR and closure
# checks; the scripts that only drive a check (check-current.sh,
# eif-with-blobs.sh, this one) may have changed since.
if ! git cat-file -e "$commit^{commit}" 2>/dev/null; then
  echo "rebuild-check: kernel_commit $commit is not in this clone: fetch full history (git fetch --unshallow, or clone without --depth)" >&2
  exit 1
fi
inputs=(release/kernel/aws release/kernel/config release/kernel/patches release/kernel/keys
  release/kernel/default.nix release/kernel/kernel.nix release/kernel/init.nix release/kernel/linuxkit.nix
  release/kernel/cmdline release/kernel/check-config.sh release/kernel/kernel.lock release/kernel/SHA256SUMS)
if ! git diff --exit-code --stat "$commit" -- "${inputs[@]}"; then
  echo "rebuild-check: release/kernel's inputs differ from $commit, which the blob set was built from" >&2
  exit 1
fi
want="$(val kernel_lock_sha256)"
have="$(sha256sum release/kernel/kernel.lock | cut -d' ' -f1)"
if [ "$want" != "$have" ]; then
  echo "rebuild-check: release/kernel/kernel.lock is $have, the lock's kernel_lock_sha256 $want" >&2
  exit 1
fi
echo "rebuild-check: recipe inputs as at $commit; kernel.lock $have"

# 2. The build, with build.sh exactly as at kernel_commit (it checks the
# source's SHA-256, kernel.org's signature, the toolchain's NAR hashes and
# the build-time closure). It sits next to the recipe for the run (it
# reads its directory's files) and is removed afterwards. No expected-
# hashes argument is passed (step 3 compares), which also avoids that
# commit's relative-path bug.
gated=release/kernel/.build-at-kernel-commit.sh
git show "$commit:release/kernel/build.sh" >"$gated"
chmod +x "$gated"
trap 'rm -f "$gated"' EXIT
echo "rebuild-check: build.sh from $commit ($(sha256sum "$gated" | cut -d' ' -f1))"
"$gated" "$out"
rm -f "$gated"
trap - EXIT

# 3. The six blob hashes: lock = rebuild = published.
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
awk '$2 ~ "^/usr/share/nitro_enclaves/blobs/" {n = $2; sub(".*/", "", n); print $1 "  " n}' "$lock" | sort -k2 >"$tmp/lock"
sort -k2 "$out/SHA256SUMS" >"$tmp/rebuild"
curl -fsSL --retry 3 -o "$tmp/published.all" "$(dirname "$url")/SHA256SUMS"
awk '$2 ~ "^vettid-enclave-blobs/aarch64/" {n = $2; sub(".*/", "", n); print $1 "  " n}' "$tmp/published.all" | sort -k2 >"$tmp/published"
for f in lock rebuild published; do
  if [ "$(wc -l <"$tmp/$f")" != 6 ]; then echo "rebuild-check: $f lists $(wc -l <"$tmp/$f") blobs, not 6" >&2; exit 1; fi
done
if ! diff -u "$tmp/lock" "$tmp/rebuild" || ! diff -u "$tmp/lock" "$tmp/published"; then
  echo "rebuild-check: FAIL: the blob hashes differ (lock, rebuild, published)" >&2
  exit 1
fi
echo "rebuild-check: PASS: the six blobs are the same in the lock, the rebuild and the published set:"
cat "$tmp/lock"
