#!/usr/bin/env bash
# Build the enclave blob set (kernel Image and config, command line, init,
# linuxkit, nsm.ko placeholder) from source with the inputs pinned in
# release/kernel/kernel.lock (docs/KERNEL.md). The enclave-kernel workflow
# runs exactly this on two arm64 runners and requires identical output;
# anyone can run it to check a published blob set.
#
#   release/kernel/build.sh OUT_DIR [EXPECTED_SHA256SUMS]
#
# Needs an arm64 (aarch64) Linux machine with docker, curl, xz, gpg and
# gpgv, and network access to cdn.kernel.org, github.com and
# cache.nixos.org. Takes 10 to 60 minutes. Environment:
#   KERNEL_TARGET=kernelConfig  stop after the configuration (OUT_DIR/Image.config)
#   KERNEL_DOWNLOADS=DIR        keep the kernel tarball there
#   KERNEL_NO_SUBSTITUTE=1      build the whole toolchain from source instead
#                               of taking cache.nixos.org's binaries (hours);
#                               only fixed-output derivations (sources,
#                               checked by hash; bootstrap files) may still
#                               come from the cache
#   KERNEL_TOOLCHAIN_UNPINNED=1 report the toolchain's NAR hashes and the
#                               build-time closure hash without requiring
#                               the lock's (to update the lock; the source-
#                               built comparison)
#   KERNEL_CORES=N              build cores (default all); the CI's second
#                               builder uses 2. KERNEL_MOUNT (default /src),
#                               KERNEL_UMASK, TZ and LC_ALL are passed to
#                               the container too, but Nix gives each
#                               derivation its own environment, so they do
#                               not reach the compiler.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
lock="$here/kernel.lock"
out="${1:?usage: release/kernel/build.sh OUT_DIR [EXPECTED_SHA256SUMS]}"
expected="${2:-}"
if [ -n "$expected" ]; then
  # Absolute, since the check runs from inside OUT_DIR.
  if [ ! -f "$expected" ]; then echo "build: $expected not found" >&2; exit 1; fi
  expected="$(cd "$(dirname "$expected")" && pwd)/$(basename "$expected")"
fi
target="${KERNEL_TARGET:-all}"

val() {
  local v
  v="$(sed -n "s/^$1=//p" "$lock")"
  if [ -z "$v" ]; then echo "build: kernel.lock lacks $1" >&2; exit 1; fi
  printf '%s' "$v"
}

if [ "$(uname -m)" != "$(val arch)" ]; then
  echo "build: the enclave kernel is built natively on $(val arch), not $(uname -m)" >&2
  exit 1
fi
case "$target" in all | kernelConfig) ;; *) echo "build: KERNEL_TARGET is all or kernelConfig" >&2; exit 1 ;; esac

version="$(val kernel_version)"
url="$(val kernel_url)"
sha="$(val kernel_sha256)"
tarball="linux-$version.tar.xz"
if [ "$(basename "$url")" != "$tarball" ]; then
  echo "build: kernel_url does not name $tarball" >&2
  exit 1
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"
dl="${KERNEL_DOWNLOADS:-$out/.downloads}"
mkdir -p "$dl"
dl="$(cd "$dl" && pwd)"

# 1. The source: the pinned SHA-256 and a pinned kernel.org signer.
if [ ! -f "$dl/$tarball" ]; then
  curl -fsSL --retry 3 -o "$dl/$tarball.part" "$url"
  mv "$dl/$tarball.part" "$dl/$tarball"
fi
curl -fsSL --retry 3 -o "$dl/linux-$version.tar.sign" "${url%.xz}.sign"
echo "$sha  $dl/$tarball" | sha256sum -c -

gnupg="$(mktemp -d)"
trap 'rm -rf "$gnupg"' EXIT
keys="$here/keys/kernel-org-signers.asc"
have_keys="$(GNUPGHOME="$gnupg" gpg --batch --show-keys --with-colons "$keys" |
  awk -F: '/^pub/ {p = 1; next} p && /^fpr/ {print $10; p = 0}' | sort | tr '\n' ' ')"
want_keys="$(val kernel_signers | tr ',' '\n' | sort | tr '\n' ' ')"
if [ "$have_keys" != "$want_keys" ]; then
  echo "build: keys/kernel-org-signers.asc holds [$have_keys], kernel.lock names [$want_keys]" >&2
  exit 1
fi
GNUPGHOME="$gnupg" gpg --batch --quiet --dearmor <"$keys" >"$gnupg/signers.gpg"
status="$(xz -dc "$dl/$tarball" | gpgv --status-fd 1 --keyring "$gnupg/signers.gpg" "$dl/linux-$version.tar.sign" - 2>"$gnupg/gpgv.err")" || {
  cat "$gnupg/gpgv.err" >&2
  echo "build: the signature on linux-$version.tar does not verify with a pinned key" >&2
  exit 1
}
signer="$(awk '$2 == "VALIDSIG" {print $NF}' <<<"$status")"
if [ -z "$signer" ] || ! grep -qw -- "$signer" <<<"$want_keys"; then
  echo "build: linux-$version.tar is signed by [$signer], not by a key in kernel_signers" >&2
  exit 1
fi
echo "build: $tarball: SHA-256 as pinned; signature by $signer"

# 2. The build: Nix in the pinned container, without the Nix sandbox
# (the container is the boundary). Every derivation input is fixed by
# nixpkgs and kernel.lock; Nix copies the recipe into its store by
# content, so the mount point does not matter. First the toolchain: its
# NAR hashes must equal the lock's toolchain lines; after the build, the
# whole build-time closure must hash to toolchain_closure_sha256.
mount="${KERNEL_MOUNT:-/src}"
substitute=true
if [ "${KERNEL_NO_SUBSTITUTE:-}" = 1 ]; then substitute=false; fi
# nix_image as the lock names it (upstream), or the same digest from
# VETTID_IMAGE_MIRROR in CI (scripts/image-mirror.sh).
nix_image="$("$here/../../scripts/image-mirror.sh" ref "$(val nix_image)")"
echo "build: container $nix_image"
rm -rf "$out/result.tmp"
mkdir -p "$out/result.tmp"
docker run --rm \
  -v "$here:$mount:ro" -v "$dl:/dl:ro" -v "$out/result.tmp:/out" \
  -e SRC="$mount" -e TARGET="$target" -e TARBALL="$tarball" -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -e NIXPKGS_URL="$(val nixpkgs_url)" -e NIXPKGS_SHA256="$(val nixpkgs_sha256)" \
  -e KVER="$version" -e KURL="$url" -e KSHA="$sha" \
  -e BUSER="$(val build_user)" -e BHOST="$(val build_host)" \
  -e CORES="${KERNEL_CORES:-0}" -e UMASK="${KERNEL_UMASK:-0022}" -e SUBSTITUTE="$substitute" \
  -e EXPECTED_TOOLCHAIN="$(grep '^toolchain=' "$lock" || true)" -e UNPINNED="${KERNEL_TOOLCHAIN_UNPINNED:-}" \
  -e EXPECTED_CLOSURE="$(sed -n 's/^toolchain_closure_sha256=//p' "$lock")" \
  -e TZ="${TZ:-UTC}" -e LC_ALL="${LC_ALL:-C}" \
  "$nix_image" sh -euc '
    umask "$UMASK"
    nix --version
    nb() {
      nix-build "$SRC" --option sandbox false --option substitute "$SUBSTITUTE" --cores "$CORES" --no-out-link \
        --argstr nixpkgsUrl "$NIXPKGS_URL" --argstr nixpkgsSha256 "$NIXPKGS_SHA256" \
        --argstr kernelVersion "$KVER" --argstr kernelUrl "$KURL" --argstr kernelSha256 "$KSHA" \
        --argstr buildUser "$BUSER" --argstr buildHost "$BHOST" "$@"
    }
    p="$(nix-store --add-fixed sha256 "/dl/$TARBALL")"
    echo "kernel source in the store: $p"
    if [ "$SUBSTITUTE" = false ]; then
      # Source-built toolchain: only fixed-output derivations (source
      # tarballs and patches, checked by their pinned hashes, and the
      # bootstrap files) may come from cache.nixos.org, which mirrors
      # sources that have since moved or vanished upstream; everything
      # that is compiled is built here.
      drvs="$(nix-instantiate "$SRC" -A all \
        --argstr nixpkgsUrl "$NIXPKGS_URL" --argstr nixpkgsSha256 "$NIXPKGS_SHA256" \
        --argstr kernelVersion "$KVER" --argstr kernelUrl "$KURL" --argstr kernelSha256 "$KSHA" \
        --argstr buildUser "$BUSER" --argstr buildHost "$BHOST")"
      nix-store --query --requisites $drvs | grep "\.drv\$" | while read -r d; do
        if grep -qE "^Derive\(\[\(\"out\",\"[^\"]*\",\"[^\"]+\"," "$d"; then echo "$d"; fi
      done >/tmp/fods
      echo "fixed-output derivations (sources) taken from the cache if there: $(wc -l </tmp/fods)"
      xargs nix-store --realise --option substitute true </tmp/fods >/dev/null
    fi
    : >/out/toolchain.lock-lines
    for a in gcc binutils muslGcc musl go; do
      for p in $(nb -A "toolchain.$a"); do
        echo "toolchain=$a $p $(nix-store --query --hash "$p")" >>/out/toolchain.lock-lines
      done
    done
    cat /out/toolchain.lock-lines
    if [ "$EXPECTED_TOOLCHAIN" != "$(cat /out/toolchain.lock-lines)" ]; then
      echo "build: the toolchain differs from kernel.lock'"'"'s toolchain lines:" >&2
      printf "%s\n" "$EXPECTED_TOOLCHAIN" >/tmp/expected
      diff /tmp/expected /out/toolchain.lock-lines >&2 || true
      if [ "$UNPINNED" != 1 ]; then chown -R "$HOST_UID:$HOST_GID" /out; exit 1; fi
      echo "build: KERNEL_TOOLCHAIN_UNPINNED=1: continuing" >&2
    fi
    r="$(nb -A "$TARGET")"
    echo "result: $r"
    if [ "$TARGET" = all ]; then
      # The whole build-time closure: every store path the blob set was
      # built with that came out of a derivation (compilers, libraries,
      # tools, fetched sources), except the blob set'"'"'s own derivations,
      # with its NAR hash; sorted, then hashed once. Recipe files copied
      # into the store (no deriver) are covered by the git commit.
      drv="$(nix-store --query --deriver "$r")"
      nix-store --query --requisites --include-outputs "$drv" | grep -v "\.drv\$" | while read -r p; do
        d="$(nix-store --query --deriver "$p")"
        case "$d" in unknown-deriver) continue ;; esac
        case "${d##*/}" in *-vettid-enclave-*.drv | *-linuxkit-1.5.2.drv) continue ;; esac
        echo "$p $(nix-store --query --hash "$p")"
      done | LC_ALL=C sort >/out/toolchain-closure.txt
      c="$(sha256sum </out/toolchain-closure.txt | cut -d" " -f1)"
      echo "build-time closure: $(wc -l </out/toolchain-closure.txt) paths, toolchain_closure_sha256=$c"
      if [ "$c" != "$EXPECTED_CLOSURE" ]; then
        echo "build: the build-time closure differs from kernel.lock'"'"'s toolchain_closure_sha256 ($EXPECTED_CLOSURE)" >&2
        if [ "$UNPINNED" != 1 ]; then chown -R "$HOST_UID:$HOST_GID" /out; exit 1; fi
        echo "build: KERNEL_TOOLCHAIN_UNPINNED=1: continuing" >&2
      fi
    fi
    cp -R "$r"/. /out/
    chmod -R u+w /out
    chown -R "$HOST_UID:$HOST_GID" /out
  '

# 3. The blob set and its hashes.
for f in "$out/result.tmp"/*; do
  rm -rf "${out:?}/$(basename "$f")"
  mv "$f" "$out/"
done
rmdir "$out/result.tmp"
if [ "$target" = all ]; then
  chmod 0644 "$out/Image" "$out/Image.config" "$out/cmdline" "$out/nsm.ko"
  chmod 0755 "$out/init" "$out/linuxkit"
  (cd "$out" && sha256sum Image Image.config cmdline init linuxkit nsm.ko >SHA256SUMS)
  (cd "$out" && find extra -type f | sort | xargs sha256sum >SHA256SUMS.extra)
  # The archive a release would publish (docs/KERNEL.md, "Publishing"):
  # the six files under vettid-enclave-blobs/aarch64/, with fixed order,
  # times and owners. Its bytes also depend on the tar and xz versions; the
  # lock pins each file as well, which is what an auditor compares.
  stage="$(mktemp -d)"
  mkdir -p "$stage/vettid-enclave-blobs/aarch64"
  (cd "$out" && cp -p Image Image.config cmdline init linuxkit nsm.ko "$stage/vettid-enclave-blobs/aarch64/")
  tar -C "$stage" --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
    --format=gnu -cf - vettid-enclave-blobs | xz -9 -T1 -c >"$out/vettid-enclave-blobs.txz"
  rm -rf "$stage"
  (cd "$out" && sha256sum vettid-enclave-blobs.txz >>SHA256SUMS.extra)
  cat "$out/SHA256SUMS"
  strings "$out/Image" | grep -m1 '^Linux version ' || true
fi
if [ -n "$expected" ]; then
  (cd "$out" && sha256sum -c "$expected")
fi
