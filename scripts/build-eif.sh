#!/usr/bin/env bash
# Build the enclave image reproducibly and turn it into an EIF
# (docs/SMOKE.md, docs/RELEASING.md, VAULT-PLAN D3, VAULT-RELEASES §5).
# Writes OUT_DIR/vault-enclave.eif, the enclave and parent binaries and
# OUT_DIR/measurements.json, and prints the measurements on stdout;
# everything else goes to stderr.
#
#   CHANNEL=prod|staging|none scripts/build-eif.sh [OUT_DIR]   (default: none, out/)
#
# CHANNEL selects the release constants the image embeds (VAULT-MESSAGING
# §11.10.8, enclave/releasecfg/<channel>.json). A prod or staging image is
# refused while its channel file has a placeholder ("TODO-...") or a
# missing value; CHANNEL=none (the default) builds the constant-free image
# of the hardware smoke test and of release dry runs, which refuses every
# enrollment and unlock.
#
# Optional:
#   EIF_BUILDER=IMAGE  run nitro-cli inside IMAGE (release/Dockerfile.eif-builder,
#                      the pinned toolchain) with the docker socket mounted,
#                      instead of a nitro-cli on the host
#   DOCKER_SOCK=PATH   the docker socket to mount (default /var/run/docker.sock)
#   EIF_RUN_ARGS=...   extra docker run arguments for EIF_BUILDER (for example
#                      "--security-opt label=disable" on an SELinux host)
#   EIF_NO_CACHE=1     build the images without the docker build cache
#   GO=PATH            the go command for cmd/eifinfo (default: go)
#
# Needs docker, go and python3, and nitro-cli unless EIF_BUILDER is set.
# SOURCE_DATE_EPOCH defaults to the commit time of HEAD.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-out}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH
channel="${CHANNEL:-none}"
# A registry-qualified local name, so that linuxkit (inside nitro-cli) finds
# the image in the local store under docker and podman alike.
tag="localhost/vettid-vault-enclave:${commit:0:12}-${channel}"
go="${GO:-go}"
sock="${DOCKER_SOCK:-/var/run/docker.sock}"

log() { echo "build-eif: $*" >&2; }

cfgsum=""
release=0
case "$channel" in
  none) ;;
  prod|staging)
    cfg="enclave/releasecfg/${channel}.json"
    # The same check Dockerfile.enclave runs: TODO- placeholders and missing
    # values (release 0, empty key lists) alike.
    if ! out="$("$go" run ./cmd/releasecfg check "$channel" 2>&1)"; then
      log "FAIL $cfg still has placeholders; refusing to build a $channel release image:"
      echo "$out" >&2
      exit 1
    fi
    cfgsum="$(sha256sum "$cfg" | cut -d' ' -f1)"
    release="$(python3 -c 'import json,sys; print(int(json.load(open(sys.argv[1]))["release"]))' "$cfg")"
    ;;
  *) log "FAIL unknown CHANNEL $channel (prod, staging or none)"; exit 1 ;;
esac

command -v docker >/dev/null || { log "FAIL docker not found"; exit 1; }
command -v "$go" >/dev/null || { log "FAIL go not found (set GO)"; exit 1; }
if [ -z "${EIF_BUILDER:-}" ]; then
  command -v nitro-cli >/dev/null || { log "FAIL nitro-cli not found (or set EIF_BUILDER)"; exit 1; }
fi

nocache=()
if [ "${EIF_NO_CACHE:-}" = 1 ]; then nocache=(--no-cache); fi

log "building image $tag (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
DOCKER_BUILDKIT=1 docker build --pull=false "${nocache[@]}" -f Dockerfile.enclave \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --build-arg "CHANNEL=$channel" \
  -t "$tag" . >&2
DOCKER_BUILDKIT=1 docker build --pull=false "${nocache[@]}" -f Dockerfile.enclave --target parent \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --build-arg "CHANNEL=$channel" \
  -t "$tag-parent" . >&2

c="$(docker create "$tag")"
docker cp "$c:/vault-enclave" "$out/vault-enclave" >&2
docker rm "$c" >/dev/null
c="$(docker create "$tag-parent" /vault-parent)"
docker cp "$c:/vault-parent" "$out/vault-parent" >&2
docker rm "$c" >/dev/null
binsum="$(sha256sum "$out/vault-enclave" | cut -d' ' -f1)"
parentsum="$(sha256sum "$out/vault-parent" | cut -d' ' -f1)"
log "binary sha256 $binsum (compare with CI job enclave-image, arm64)"

log "building EIF"
rm -f "$out/vault-enclave.eif"
if [ -n "${EIF_BUILDER:-}" ]; then
  nitro_version="$(docker run --rm "$EIF_BUILDER" nitro-cli --version)"
  # shellcheck disable=SC2086 # EIF_RUN_ARGS is a list of arguments
  docker run --rm ${EIF_RUN_ARGS:-} -v "$sock:/var/run/docker.sock" -v "$out:/out" -e NITRO_CLI_ARTIFACTS=/tmp/nitro-artifacts \
    "$EIF_BUILDER" nitro-cli build-enclave --docker-uri "$tag" --output-file /out/vault-enclave.eif >"$out/build-enclave.json"
else
  nitro_version="$(nitro-cli --version)"
  arts="$(mktemp -d)"
  NITRO_CLI_ARTIFACTS="$arts" nitro-cli build-enclave --docker-uri "$tag" --output-file "$out/vault-enclave.eif" >"$out/build-enclave.json"
  rm -rf "$arts"
fi

# The PCRs nitro-cli reports must equal the ones recomputed from the EIF's
# sections (cmd/eifinfo), which also gives the hash of the measured part.
"$go" run ./cmd/eifinfo pcrs "$out/vault-enclave.eif" "$out/build-enclave.json" >&2
"$go" run ./cmd/eifinfo describe "$out/vault-enclave.eif" >"$out/eif.json"

locksum=""
if [ -n "${EIF_BUILDER:-}" ]; then locksum="$(sha256sum release/eif-toolchain.lock | cut -d' ' -f1)"; fi

python3 - "$out/eif.json" "$commit" "$binsum" "$channel" "$cfgsum" "$release" "$parentsum" "$nitro_version" "$locksum" "$SOURCE_DATE_EPOCH" <<'PY' | tee "$out/measurements.json"
import json, sys
e = json.load(open(sys.argv[1]))
print(json.dumps({
    "channel": sys.argv[4],
    "release": int(sys.argv[6]),
    "source_commit": sys.argv[2],
    "source_date_epoch": int(sys.argv[10]),
    "releasecfg_sha256": sys.argv[5],
    "binary_sha256": sys.argv[3],
    "parent_sha256": sys.argv[7],
    "eif_sha256": e["eif_sha256"],
    "eif_measured_sha256": e["eif_measured_sha256"],
    "pcr0": e["pcr0"], "pcr1": e["pcr1"], "pcr2": e["pcr2"],
    "nitro_cli_version": sys.argv[8],
    "toolchain_lock_sha256": sys.argv[9],
}, indent=2))
PY
log "PASS EIF at $out/vault-enclave.eif"
