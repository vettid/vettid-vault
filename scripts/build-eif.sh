#!/usr/bin/env bash
# Build the enclave image reproducibly and turn it into an EIF
# (docs/SMOKE.md, VAULT-PLAN D3). Prints the EIF's measurements (PCR0, PCR1,
# PCR2) as JSON on stdout; everything else goes to stderr.
#
#   scripts/build-eif.sh [OUT_DIR]          (default: out/)
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
tag="vettid-vault-enclave:${commit:0:12}"

log() { echo "build-eif: $*" >&2; }

command -v docker >/dev/null || { log "FAIL docker not found"; exit 1; }
command -v nitro-cli >/dev/null || { log "FAIL nitro-cli not found"; exit 1; }

log "building image $tag (SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH)"
DOCKER_BUILDKIT=1 docker build --pull=false -f Dockerfile.enclave \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  -t "$tag" . >&2

c="$(docker create "$tag")"
docker cp "$c:/vault-enclave" "$out/vault-enclave" >&2
docker rm "$c" >/dev/null
binsum="$(sha256sum "$out/vault-enclave" | cut -d' ' -f1)"
log "binary sha256 $binsum (compare with CI job enclave-image, arm64)"

log "building EIF"
nitro-cli build-enclave --docker-uri "$tag" --output-file "$out/vault-enclave.eif" >"$out/build-enclave.json"

python3 - "$out/build-enclave.json" "$commit" "$binsum" <<'PY' | tee "$out/measurements.json"
import json, sys
m = json.load(open(sys.argv[1]))["Measurements"]
print(json.dumps({"commit": sys.argv[2], "binary_sha256": sys.argv[3], "pcr0": m["PCR0"], "pcr1": m["PCR1"], "pcr2": m["PCR2"]}, indent=2))
PY
log "PASS EIF at $out/vault-enclave.eif"
