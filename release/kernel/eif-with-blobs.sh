#!/usr/bin/env bash
# Build a channel-none EIF with a blob set from release/kernel/build.sh
# instead of the one release/eif-toolchain.lock pins, through the normal
# path (release/Dockerfile.eif-builder, release/rebuild.sh), for a
# hardware test before adoption (docs/KERNEL.md). Not a release build:
# release/eif-toolchain.lock and release/enclave-kernel are rewritten for
# the duration of the build and restored on exit; a SIGKILL can leave them
# edited (git checkout -- release/ restores them).
#
#   release/kernel/eif-with-blobs.sh BLOBS_DIR OUT_DIR
#
# BLOBS_DIR is build.sh's output (the six files and
# vettid-enclave-blobs.txz). Needs what release/rebuild.sh needs (arm64,
# docker, go, python3). The builder downloads the archive from a local
# HTTP server on the docker bridge's gateway address.
set -euo pipefail

cd "$(dirname "$0")/../.."
blobs="$(cd "${1:?usage: release/kernel/eif-with-blobs.sh BLOBS_DIR OUT_DIR}" && pwd)"
out="${2:?usage: release/kernel/eif-with-blobs.sh BLOBS_DIR OUT_DIR}"
lock=release/eif-toolchain.lock

for f in Image Image.config cmdline init linuxkit nsm.ko vettid-enclave-blobs.txz; do
  if [ ! -f "$blobs/$f" ]; then echo "eif-with-blobs: $blobs/$f missing" >&2; exit 1; fi
done
(cd "$blobs" && sha256sum -c SHA256SUMS)
kver="$(sed -n 's/^kernel_version=//p' release/kernel/kernel.lock)"
if ! strings "$blobs/Image" | grep -q "^Linux version $kver "; then
  echo "eif-with-blobs: $blobs/Image is not Linux $kver" >&2
  exit 1
fi

port=8719
gw="$(docker network inspect bridge -f '{{(index .IPAM.Config 0).Gateway}}')"
saved="$(mktemp)"
savedk="$(mktemp)"
cp "$lock" "$saved"
cp release/enclave-kernel "$savedk"
python3 -m http.server --bind "$gw" --directory "$blobs" "$port" >/dev/null 2>&1 &
server=$!
trap 'kill "$server" 2>/dev/null || true; cp "$saved" "$lock"; cp "$savedk" release/enclave-kernel; rm -f "$saved" "$savedk"' EXIT
sleep 1

sum() { sha256sum "$blobs/$1" | cut -d' ' -f1; }
python3 - "$lock" "$kver" "http://$gw:$port/vettid-enclave-blobs.txz" \
  "$(sum vettid-enclave-blobs.txz)" "$(sum Image)" "$(sum Image.config)" "$(sum cmdline)" \
  "$(sum init)" "$(sum linuxkit)" "$(sum nsm.ko)" <<'PY'
import re, sys
p, kver, url, arch, *blob = sys.argv[1:]
s = open(p).read()
def setv(k, v):
    global s
    s, n = re.subn(r"(?m)^" + k + r"=.*$", k + "=" + v, s)
    assert n == 1, k
setv("blobs_version", "vettid-test-" + kver)
setv("blobs_url", url)
setv("blobs_dir", "vettid-enclave-blobs/aarch64")
s, n = re.subn(r"(?m)^[0-9a-f]{64}(  /toolchain/)enclaves-blobs\.txz$", arch + r"\1enclaves-blobs.txz", s)
assert n == 1
for name, h in zip(["Image", "Image.config", "cmdline", "init", "linuxkit", "nsm.ko"], blob):
    s, n = re.subn(r"(?m)^[0-9a-f]{64}(  /usr/share/nitro_enclaves/blobs/)" + re.escape(name) + "$", h + r"\g<1>" + name, s)
    assert n == 1, name
open(p, "w").write(s)
PY
sed -i -e "s/^kernel_release=.*/kernel_release=$kver/" -e "s/^kernel_hardened=.*/kernel_hardened=true/" release/enclave-kernel
echo "eif-with-blobs: building with Linux $kver from $blobs (archive via $gw:$port)" >&2
ALLOW_DIRTY=1 CHANNEL=none release/rebuild.sh "$out"
