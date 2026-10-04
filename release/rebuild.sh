#!/usr/bin/env bash
# Build a release EIF with the pinned toolchain, from clean, and
# optionally match it against published measurements (VAULT-RELEASES
# §5.1, §5.3; docs/RELEASING.md). The release workflow runs exactly this
# on two runners; the owner and anyone else run it to rebuild a release
# independently (the two-builder rule).
#
#   CHANNEL=prod|staging|none release/rebuild.sh OUT_DIR [PUBLISHED_MEASUREMENTS_JSON]
#
# Needs an arm64 (aarch64) Linux machine with docker, go and python3. It
# builds the toolchain image from release/Dockerfile.eif-builder (Amazon
# Linux 2023 by digest, aws-nitro-enclaves-cli and its blobs checked
# against release/eif-toolchain.lock), then runs scripts/build-eif.sh with
# nitro-cli inside it and without the docker build cache. The working tree
# must be clean: the measurements name the commit.
set -euo pipefail

cd "$(dirname "$0")/.."
out="${1:?usage: CHANNEL=prod|staging|none release/rebuild.sh OUT_DIR [PUBLISHED_MEASUREMENTS_JSON]}"
published="${2:-}"
go="${GO:-go}"

if [ -n "$(git status --porcelain --untracked-files=no)" ] && [ "${ALLOW_DIRTY:-}" != 1 ]; then
  echo "rebuild: the working tree has changes; a release build is of a commit (ALLOW_DIRTY=1 to override)" >&2
  exit 1
fi

lock="$(sha256sum release/eif-toolchain.lock | cut -d' ' -f1)"
builder="vettid-eif-builder:${lock:0:16}"
echo "rebuild: toolchain image $builder (release/eif-toolchain.lock $lock)" >&2
docker build --pull=false -q -f release/Dockerfile.eif-builder -t "$builder" release/ >&2

EIF_BUILDER="$builder" EIF_NO_CACHE=1 GO="$go" scripts/build-eif.sh "$out" >/dev/null
cat "$out/measurements.json"

if [ -n "$published" ]; then
  "$go" run ./cmd/eifinfo match "$published" "$out/measurements.json"
fi
