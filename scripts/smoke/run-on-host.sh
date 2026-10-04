#!/usr/bin/env bash
# V5 hardware smoke test, run ON the temporary AL2023 arm64 enclave host
# (as root, e.g. through SSM). docs/SMOKE.md has the whole procedure.
#
#   run-on-host.sh prepare           install pinned tools, configure the enclave allocator
#   run-on-host.sh build COMMIT      check out COMMIT, build vault-parent and the EIF, print PCR0-2
#   run-on-host.sh run               start the enclave (non-debug), run vault-parent -selftest, terminate
#   run-on-host.sh clean             terminate enclaves, remove the work directory
#
# run needs: SMOKE_REGION, SMOKE_BUCKET, SMOKE_KEY_ARN, SMOKE_ACCOUNT
# (optional: SMOKE_RUN_ID, SMOKE_EXPECT_KEY_CHECK=6, SMOKE_CPUS=1,
# SMOKE_MEMORY_MIB=3072, SMOKE_REPO). Every step is idempotent and ends
# with a PASS or FAIL line.
set -euo pipefail

WORK=/opt/vettid-smoke
REPO="${SMOKE_REPO:-https://github.com/vettid/vettid-vault.git}"
GO_VERSION=1.26.8
GO_SHA256_ARM64=211ffced9dcb9633a55eac6364816ec0ddd951389a740e88fa8b3337971bdda0
GO_SHA256_AMD64=d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b
CPUS="${SMOKE_CPUS:-1}"
MEMORY_MIB="${SMOKE_MEMORY_MIB:-3072}"
CID=16

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; exit 1; }
step() { echo "== $*"; }

need_root() { [ "$(id -u)" = 0 ] || fail "run as root"; }

go_bin() { echo "$WORK/go-$GO_VERSION/bin/go"; }

prepare() {
  need_root
  step "packages"
  dnf install -y -q aws-nitro-enclaves-cli aws-nitro-enclaves-cli-devel docker git python3 tar >/dev/null || fail "dnf install"
  rpm -q aws-nitro-enclaves-cli docker git | sed 's/^/  /'

  step "enclave allocator: $CPUS vCPU, $MEMORY_MIB MiB"
  mkdir -p /etc/nitro_enclaves
  cat >/etc/nitro_enclaves/allocator.yaml <<YAML
---
memory_mib: $MEMORY_MIB
cpu_count: $CPUS
YAML
  systemctl enable --now docker >/dev/null 2>&1 || fail "docker service"
  systemctl enable nitro-enclaves-allocator >/dev/null 2>&1 || true
  systemctl restart nitro-enclaves-allocator || fail "allocator service (memory/CPU reservation)"

  step "Go $GO_VERSION (checksum-pinned)"
  mkdir -p "$WORK"
  if [ ! -x "$(go_bin)" ]; then
    arch="$(uname -m)"
    case "$arch" in
      aarch64) a=arm64; sum=$GO_SHA256_ARM64 ;;
      x86_64) a=amd64; sum=$GO_SHA256_AMD64 ;;
      *) fail "architecture $arch" ;;
    esac
    curl -fsSLo "$WORK/go.tgz" "https://go.dev/dl/go$GO_VERSION.linux-$a.tar.gz"
    echo "$sum  $WORK/go.tgz" | sha256sum -c - >/dev/null || fail "Go checksum"
    rm -rf "$WORK/go-$GO_VERSION.tmp" && mkdir -p "$WORK/go-$GO_VERSION.tmp"
    tar -C "$WORK/go-$GO_VERSION.tmp" -xzf "$WORK/go.tgz"
    rm -rf "$WORK/go-$GO_VERSION" && mv "$WORK/go-$GO_VERSION.tmp/go" "$WORK/go-$GO_VERSION"
    rm -rf "$WORK/go.tgz" "$WORK/go-$GO_VERSION.tmp"
  fi
  "$(go_bin)" version | sed 's/^/  /'
  pass "prepare"
}

build() {
  need_root
  commit="${1:-}"
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || fail "build needs a full 40-hex commit id"
  step "source at $commit"
  if [ ! -d "$WORK/src/.git" ]; then
    git clone -q "$REPO" "$WORK/src" || fail "clone"
  fi
  git -C "$WORK/src" fetch -q origin || fail "fetch"
  git -C "$WORK/src" checkout -q --detach "$commit" || fail "checkout"
  git -C "$WORK/src" clean -qfdx -e out
  [ "$(git -C "$WORK/src" rev-parse HEAD)" = "$commit" ] || fail "HEAD is not $commit"

  step "vault-parent"
  mkdir -p "$WORK/bin"
  (cd "$WORK/src" && CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-mod=readonly "$(go_bin)" build -trimpath -buildvcs=false \
     -o "$WORK/bin/vault-parent" ./cmd/vault-parent) || fail "vault-parent build"

  step "EIF (reproducible image, nitro-cli $(rpm -q --qf '%{VERSION}' aws-nitro-enclaves-cli))"
  (cd "$WORK/src" && GO="$(go_bin)" GOTOOLCHAIN=local scripts/build-eif.sh "$WORK/out") || fail "EIF build"
  cp "$WORK/out/measurements.json" "$WORK/measurements.json"
  echo "measurements:"
  cat "$WORK/measurements.json"
  pass "build (put pcr0 into the test key policy, then: run-on-host.sh run)"
}

run() {
  need_root
  for v in SMOKE_REGION SMOKE_BUCKET SMOKE_KEY_ARN SMOKE_ACCOUNT; do
    [ -n "${!v:-}" ] || fail "$v is not set"
  done
  if [ ! -f "$WORK/out/vault-enclave.eif" ] || [ ! -x "$WORK/bin/vault-parent" ]; then
    fail "nothing built (run-on-host.sh build COMMIT)"
  fi
  run_id="${SMOKE_RUN_ID:-run-$(date -u +%Y%m%d%H%M%S)}"
  logs="$WORK/runs/$run_id"
  mkdir -p "$logs"

  step "clean slate"
  nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

  step "vault-parent -selftest (run $run_id)"
  "$WORK/bin/vault-parent" -selftest -region "$SMOKE_REGION" -bucket "$SMOKE_BUCKET" \
    -smoke-key-arn "$SMOKE_KEY_ARN" -smoke-account "$SMOKE_ACCOUNT" -run-id "$run_id" \
    -expect-key-check "${SMOKE_EXPECT_KEY_CHECK:-6}" -health "" \
    >"$logs/report.json" 2>"$logs/parent.log" &
  parent_pid=$!

  step "enclave (non-debug, $CPUS vCPU, $MEMORY_MIB MiB, CID $CID)"
  if ! nitro-cli run-enclave --eif-path "$WORK/out/vault-enclave.eif" --cpu-count "$CPUS" \
       --memory "$MEMORY_MIB" --enclave-cid "$CID" >"$logs/run-enclave.json" 2>&1; then
    kill "$parent_pid" 2>/dev/null || true
    cat "$logs/run-enclave.json"
    fail "run-enclave"
  fi
  nitro-cli describe-enclaves >"$logs/describe.json"
  if grep -q '"DEBUG_MODE"' "$logs/describe.json"; then
    nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
    fail "the enclave runs in debug mode"
  fi

  rc=0
  wait "$parent_pid" || rc=$?
  nitro-cli terminate-enclave --all >/dev/null 2>&1 || true

  echo "checks:"
  grep -E '^(PASS|FAIL|INFO) ' "$logs/parent.log" | sed 's/^/  /' || true
  built_pcr0="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pcr0"])' "$WORK/measurements.json")"
  ran_pcr0="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("report",{}).get("pcr0",""))' "$logs/report.json" 2>/dev/null || true)"
  if [ "$built_pcr0" = "$ran_pcr0" ]; then
    echo "PASS attested PCR0 equals the built EIF's"
  else
    echo "FAIL attested PCR0 ($ran_pcr0) differs from the built EIF's ($built_pcr0)"
    rc=1
  fi
  echo "report: $logs/report.json"
  [ "$rc" = 0 ] || fail "selftest (see $logs/parent.log)"
  pass "selftest"
}

clean() {
  need_root
  nitro-cli terminate-enclave --all >/dev/null 2>&1 || true
  rm -rf "$WORK"
  pass "clean"
}

case "${1:-}" in
  prepare) prepare ;;
  build) build "${2:-}" ;;
  run) run ;;
  clean) clean ;;
  *) echo "usage: $0 prepare | build COMMIT | run | clean" >&2; exit 2 ;;
esac
