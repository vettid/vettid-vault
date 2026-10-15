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

# 1. The recipe's inputs are the ones the set was built from. The scripts
# that only drive or check a build (build.sh, check-current.sh,
# eif-with-blobs.sh, this one) may have changed since.
inputs=(release/kernel/aws release/kernel/config release/kernel/patches release/kernel/keys
  release/kernel/default.nix release/kernel/kernel.nix release/kernel/init.nix release/kernel/linuxkit.nix
  release/kernel/cmdline release/kernel/check-config.sh release/kernel/kernel.lock release/kernel/SHA256SUMS)
if ! git diff --exit-code --stat "$commit" HEAD -- "${inputs[@]}"; then
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

# 2. The build (source, signature, toolchain and closure checked by build.sh).
release/kernel/build.sh "$out"

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
