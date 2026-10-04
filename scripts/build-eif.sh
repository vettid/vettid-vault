#!/usr/bin/env bash
# Build the enclave image reproducibly and turn it into an EIF
# (docs/SMOKE.md, VAULT-PLAN D3). Prints the EIF's measurements (PCR0, PCR1,
# PCR2) as JSON on stdout; everything else goes to stderr.
#
#   CHANNEL=prod|staging|none scripts/build-eif.sh [OUT_DIR]   (default: none, out/)
#
# CHANNEL selects the release constants the image embeds (VAULT-MESSAGING
# §11.10.8, enclave/releasecfg/<channel>.json). A prod or staging image is
# refused while its channel file has a placeholder ("TODO-...") or a
# missing value; CHANNEL=none (the default) builds the constant-free image
# of the hardware smoke test, which refuses every enrollment and unlock.
#
# Needs docker (nitro-cli reads the image from the docker daemon) and
# nitro-cli. SOURCE_DATE_EPOCH defaults to the commit time of HEAD.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:-out}"
mkdir -p "$out"

commit="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
: "${SOURCE_DATE_EPOCH:=$(git log -1 --format=%ct 2>/dev/null || echo 0)}"
export SOURCE_DATE_EPOCH
channel="${CHANNEL:-none}"
tag="vettid-vault-enclave:${commit:0:12}-${channel}"

log() { echo "build-eif: $*" >&2; }

cfgsum=""
case "$channel" in
  none) ;;
  prod|staging)
    cfg="enclave/releasecfg/${channel}.json"
    if grep -q '"TODO-' "$cfg"; then
      log "FAIL $cfg still has placeholders; refusing to build a $channel release image:"
      grep -n '"TODO-' "$cfg" >&2
      exit 1
    fi
    cfgsum="$(sha256sum "$cfg" | cut -d' ' -f1)"
    ;;
  *) log "FAIL unknown CHANNEL $channel (prod, staging or none)"; exit 1 ;;
esac

command -v docker >/dev/null || { log "FAIL docker not found"; exit 1; }
command -v nitro-cli >/dev/null || { log "FAIL nitro-cli not found"; exit 1; }

log "building image $tag (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
DOCKER_BUILDKIT=1 docker build --pull=false -f Dockerfile.enclave \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" --build-arg "CHANNEL=$channel" \
  -t "$tag" . >&2

c="$(docker create "$tag")"
docker cp "$c:/vault-enclave" "$out/vault-enclave" >&2
docker rm "$c" >/dev/null
binsum="$(sha256sum "$out/vault-enclave" | cut -d' ' -f1)"
log "binary sha256 $binsum (compare with CI job enclave-image, arm64)"

log "building EIF"
nitro-cli build-enclave --docker-uri "$tag" --output-file "$out/vault-enclave.eif" >"$out/build-enclave.json"

python3 - "$out/build-enclave.json" "$commit" "$binsum" "$channel" "$cfgsum" <<'PY' | tee "$out/measurements.json"
import json, sys
m = json.load(open(sys.argv[1]))["Measurements"]
print(json.dumps({"commit": sys.argv[2], "channel": sys.argv[4], "releasecfg_sha256": sys.argv[5], "binary_sha256": sys.argv[3],
                  "pcr0": m["PCR0"], "pcr1": m["PCR1"], "pcr2": m["PCR2"]}, indent=2))
PY
log "PASS EIF at $out/vault-enclave.eif"
