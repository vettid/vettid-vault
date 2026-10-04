#!/usr/bin/env bash
# The compatibility matrix (VAULT-RELEASES §3.4, §11.3): for every live
# release tag in compat/live-releases.txt, and for an optional synthetic
# "previous release" (any git ref), check the move-only contract against
# this tree:
#
#   1. the ref's frozen vectors (its testdata/vectors) with this tree's
#      code (vms/vectors.TestFrozenReleaseVectors);
#   2. the ref's vault-parent and dev vault-enclave, built from the ref,
#      run release 3 next to this tree's release 4, client, member API
#      stand-in and relay: enroll, unlock, lock, deprecated and retired
#      unlocks, the approved move into this tree's release, and an unlock
#      there (integration.TestCompatMoveOnly, against LocalStack).
#
#   VAULT_IT_LOCALSTACK=http://127.0.0.1:4566 scripts/compat-matrix.sh [--synthetic REF] [--no-list]
#
# --synthetic REF adds a row for any commit standing in for a previous
# release (before release 1, the pull request's base); --no-list skips
# compat/live-releases.txt.
#
# Rows run one at a time with -p 1 (memory). Exits non-zero if any row
# fails; with no tags listed and no --synthetic it has nothing to check
# and says so.
set -euo pipefail

cd "$(dirname "$0")/.."
go="${GO:-go}"

synthetic=""
list=1
while [ $# -gt 0 ]; do
  case "$1" in
    --synthetic) synthetic="${2:?--synthetic needs a git ref}"; shift 2 ;;
    --no-list) list=0; shift ;;
    *) echo "usage: scripts/compat-matrix.sh [--synthetic REF] [--no-list]" >&2; exit 2 ;;
  esac
done

refs=()
if [ "$list" = 1 ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    if [ -n "$line" ]; then refs+=("$line"); fi
  done < compat/live-releases.txt
fi
if [ -n "$synthetic" ]; then refs+=("$synthetic"); fi
if [ ${#refs[@]} -eq 0 ]; then
  echo "compat-matrix: no live releases in compat/live-releases.txt and no --synthetic ref; nothing to check"
  exit 0
fi
: "${VAULT_IT_LOCALSTACK:?VAULT_IT_LOCALSTACK must point at LocalStack (make integration starts one)}"

work="$(mktemp -d)"
cleanup() {
  for d in "$work"/tree-*; do [ -d "$d" ] && git worktree remove --force "$d" >/dev/null 2>&1 || true; done
  rm -rf "$work"
}
trap cleanup EXIT

failed=()
i=0
for ref in "${refs[@]}"; do
  i=$((i + 1))
  commit="$(git rev-parse --verify "$ref^{commit}")"
  echo "== compat-matrix: $ref ($commit)"
  tree="$work/tree-$i" bin="$work/bin-$i"
  git worktree add --detach "$tree" "$commit" >/dev/null
  mkdir -p "$bin"
  if ! (cd "$tree" && CGO_ENABLED=0 "$go" build -trimpath -o "$bin/vault-parent" ./cmd/vault-parent &&
        CGO_ENABLED=0 "$go" build -trimpath -tags devenclave -o "$bin/vault-enclave" ./cmd/vault-enclave); then
    echo "compat-matrix: FAIL $ref: build"; failed+=("$ref (build)"); continue
  fi
  if ! VMS_FROZEN_VECTORS="$tree/testdata/vectors" "$go" test -count=1 -run '^TestFrozenReleaseVectors$' ./vms/vectors/; then
    failed+=("$ref (frozen vectors)")
  fi
  if ! VAULT_COMPAT_PREV_BIN="$bin" VAULT_COMPAT_PREV_NAME="$ref" "$go" test -count=1 -p 1 -parallel 2 \
       -tags 'devenclave integration' -run '^TestCompatMoveOnly$' -v ./integration/; then
    failed+=("$ref (move-only contract)")
  fi
  git worktree remove --force "$tree" >/dev/null
done

if [ ${#failed[@]} -gt 0 ]; then
  printf 'compat-matrix: FAIL %s\n' "${failed[@]}"
  exit 1
fi
echo "compat-matrix: PASS ${refs[*]}"
