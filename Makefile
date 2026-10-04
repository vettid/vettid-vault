GO        ?= go
FUZZTIME  ?= 50000x
FUZZMINIMIZE ?= 200x
# Extra flags for fuzzing, e.g. FUZZFLAGS=-parallel=2 on a small machine.
FUZZFLAGS ?=
# Packages that ship. They must never link the vector-only code, the dev
# enclave (dev sealer, PIN constructors) or test harnesses.
LIBPKGS   := ./vms/suite ./vms/envelope ./vms/handshake ./vms/invite ./vms/altchan ./vms/credwire ./vms/callwire \
             ./vms/pins ./vms/nitro ./vms/manifest ./vms/devattest ./vms/btc \
             ./enclave/... ./vault/... ./client/... ./features/... ./cmd/...
E2ETAGS   := devenclave e2e
# What runs inside the enclave (the release image's binary and everything it
# links). It must never link the AWS SDK, the parent, or any dev/test code.
ENCLAVEPKGS := ./cmd/vault-enclave

.PHONY: all test channels race lint vet staticcheck fuzz scan tidy vectors check-tcb e2e integration host-sums

all: lint check-tcb test

# The vmsvectors build regenerates the §16 vectors through the library's
# sending code and compares them byte for byte with testdata/vectors.
test:
	$(GO) test ./...
	$(GO) test -tags vmsvectors ./vms/vectors
	$(MAKE) channels

# The per-channel release constants (VAULT-MESSAGING §11.10.8): each
# channel's build embeds its committed file, and the release gate refuses
# placeholders (Dockerfile.enclave and scripts/build-eif.sh run it).
CHANNELS := prod staging
channels:
	@for ch in $(CHANNELS); do \
	  $(GO) test -count=1 -tags vettid_channel_$$ch ./enclave/releasecfg || exit 1; \
	  GOOS=linux $(GO) build -tags vettid_channel_$$ch -o /dev/null ./cmd/vault-enclave || exit 1; \
	done

race:
	$(GO) test -race ./...
	$(GO) test -race -tags vmsvectors ./...

vet:
	$(GO) vet ./...
	$(GO) vet -tags vmsvectors ./...
	$(GO) vet -tags '$(E2ETAGS)' ./...
	$(GO) vet -tags 'devenclave integration' ./...
	$(GO) vet -tags vettid_channel_prod ./enclave/... ./cmd/...
	$(GO) vet -tags vettid_channel_staging ./enclave/... ./cmd/...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -tags vmsvectors ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -tags '$(E2ETAGS)' ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -tags 'devenclave integration' ./...

lint: vet staticcheck

# Release builds must not contain deterministic randomness (derandomized
# HPKE, ML-KEM test encapsulation), the dev enclave, or test harnesses and
# test authorities (relaytest, enclavetest: fake NSM and KMS, test roots); and
# the dev enclave must not compile at all without its build tag.
check-tcb:
	@if $(GO) list -deps $(LIBPKGS) | grep -E 'hpkederand|mlkemtest|/devenclave|relaytest|enclavetest|parenttest|memberapitest|featuretest'; then \
	  echo "dev, test or vector-only code linked into release packages"; exit 1; fi
	@if $(GO) list ./devenclave >/dev/null 2>&1; then \
	  echo "devenclave compiles without the devenclave tag"; exit 1; fi
	@for f in devenclave/*.go cmd/vaultctl/vault_dev.go cmd/vault-enclave/vault_dev.go; do \
	  head -1 $$f | grep -qx '//go:build devenclave' || { echo "$$f lacks //go:build devenclave"; exit 1; }; done
	@head -1 cmd/vault-enclave/release.go | grep -qx '//go:build !devenclave' || { echo "cmd/vault-enclave/release.go lacks //go:build !devenclave"; exit 1; }
	@# Dev tooling (cmd/devstack, -dev-device-policy): devenclave builds
	@# only. Without the tag cmd/devstack is a stub that links no module
	@# code; every source file naming the dev device policy carries the
	@# tag; and a release enclave binary does not contain the flag.
	@for f in cmd/devstack/*.go; do [ "$$f" = cmd/devstack/release.go ] && continue; \
	  head -1 $$f | grep -qE '^//go:build devenclave( && [a-z]+)*$$' || { echo "$$f lacks //go:build devenclave"; exit 1; }; done
	@head -1 cmd/devstack/release.go | grep -qx '//go:build !devenclave' || { echo "cmd/devstack/release.go lacks //go:build !devenclave"; exit 1; }
	@if $(GO) list -deps ./cmd/devstack | grep -v '/cmd/devstack$$' | grep -E '^github\.com/|^golang\.org/x/'; then \
	  echo "cmd/devstack links module or third-party code without the devenclave tag"; exit 1; fi
	@for f in $$(grep -rlE 'dev-device-policy|DevDevicePolicy|DevVaultPolicyArgs' --include='*.go' . | grep -v '^./internal/enclavetest/'); do \
	  head -1 $$f | grep -qE '^//go:build devenclave( && [a-z]+)*$$' || { echo "$$f uses the dev device policy without //go:build devenclave"; exit 1; }; done
	@tmp=$$(mktemp -d) && trap 'rm -rf $$tmp' EXIT && GOOS=linux $(GO) build -o $$tmp/ve ./cmd/vault-enclave && \
	  if grep -aqE 'dev-device-policy|DevDevicePolicy|device-policy' $$tmp/ve; then \
	    echo "the release enclave binary contains the dev device policy"; exit 1; fi
	@for os in linux; do \
	  if GOOS=$$os $(GO) list -deps $(ENCLAVEPKGS) | grep -E 'aws-sdk-go|smithy-go|vettid-vault/parent|hpkederand|mlkemtest|/devenclave|relaytest|enclavetest|memberapitest|parenttest|featuretest'; then \
	    echo "the enclave binary links the AWS SDK, the parent, or dev/test code"; exit 1; fi; done
	@if GOOS=linux $(GO) list -deps $(ENCLAVEPKGS) | grep -q 'enclave/nsm' && GOOS=linux $(GO) list -deps $(ENCLAVEPKGS) | grep -q 'internal/vsock' && \
	  GOOS=linux $(GO) list -deps $(ENCLAVEPKGS) | grep -q 'internal/seccomp'; then :; else \
	  echo "the release enclave binary does not use the real NSM, vsock and seccomp"; exit 1; fi
	@# D4 (VAULT-PLAN §5.3): vault and feature code cannot reach the
	@# supervisor's internals, the vault process has no network, NSM or
	@# parent, the supervisor runs no feature code, and none of them uses
	@# unsafe or cgo directly.
	@if GOOS=linux $(GO) list -deps ./vault/... ./features/... | grep -E 'vettid-vault/(enclave|parent|internal/(hostproto|vsock|vaultipc))'; then \
	  echo "vault/feature code imports enclave, host or parent packages"; exit 1; fi
	@if GOOS=linux $(GO) list -deps ./enclave/vaultproc | grep -E 'enclave/(supervisor|egress|awskms|nsm)|internal/vsock|vettid-vault/parent'; then \
	  echo "the vault process links the supervisor, egress, KMS client, NSM, vsock or parent"; exit 1; fi
	@if GOOS=linux $(GO) list -deps ./enclave/supervisor | grep -E 'vettid-vault/features|enclave/vaultproc|vettid-vault/vms/btc|btcsuite|decred'; then \
	  echo "the supervisor links feature code, the vault process or the Bitcoin libraries"; exit 1; fi
	@if GOOS=linux $(GO) list -f '{{.ImportPath}} {{len .CgoFiles}} {{join .Imports " "}}' ./vault/... ./features/... ./enclave/vaultproc | \
	  grep -E ' [1-9][0-9]* | unsafe( |$$)'; then echo "unsafe or cgo in vault, feature or vault-process code"; exit 1; fi
	@# Release constants (VAULT-MESSAGING §11.10.8): one channel per
	@# build, chosen by build tag, embedded from the committed file; no
	@# -ldflags -X values; each channel's enclave binary links the same
	@# (clean) dependencies plus releasecfg.
	@head -1 enclave/releasecfg/embed_prod.go | grep -qx '//go:build vettid_channel_prod' || { echo "embed_prod.go build constraint"; exit 1; }
	@head -1 enclave/releasecfg/embed_staging.go | grep -qx '//go:build vettid_channel_staging' || { echo "embed_staging.go build constraint"; exit 1; }
	@head -1 enclave/releasecfg/embed_none.go | grep -qx '//go:build !vettid_channel_prod && !vettid_channel_staging' || { echo "embed_none.go build constraint"; exit 1; }
	@if $(GO) build -tags 'vettid_channel_prod vettid_channel_staging' ./enclave/releasecfg 2>/dev/null; then \
	  echo "the prod and staging channels compile into one binary"; exit 1; fi
	@if grep -nE 'ldflags.*-X' Dockerfile.enclave scripts/build-eif.sh; then echo "release constants set with -ldflags -X"; exit 1; fi
	@for ch in prod staging; do \
	  if GOOS=linux $(GO) list -tags vettid_channel_$$ch -deps $(ENCLAVEPKGS) | grep -E 'aws-sdk-go|smithy-go|vettid-vault/parent|hpkederand|mlkemtest|/devenclave|relaytest|enclavetest|memberapitest|parenttest|featuretest'; then \
	    echo "the $$ch enclave binary links the AWS SDK, the parent, or dev/test code"; exit 1; fi; \
	  GOOS=linux $(GO) list -tags vettid_channel_$$ch -deps $(ENCLAVEPKGS) | grep -q 'enclave/releasecfg$$' || { echo "the $$ch enclave binary does not embed releasecfg"; exit 1; }; \
	done
	@echo "check-tcb: ok"

# End-to-end tests against the real vettid-relay binary (built at the
# version in go.mod) and the dev enclave.
e2e:
	$(GO) test -race -count=1 -p 1 -parallel 2 -tags '$(E2ETAGS)' ./e2e/

# V3 exit test against LocalStack (VAULT-PLAN §4 V3): the real relay, the
# parent and dev enclave binaries, the member API stand-in and vaultctl,
# with LocalStack (S3, SQS, DynamoDB) from integration/docker-compose.yml
# (memory-capped). Tests run one package at a time.
COMPOSE    ?= docker compose
LOCALSTACK ?= http://127.0.0.1:4566
integration:
	$(COMPOSE) -f integration/docker-compose.yml up -d
	@for i in $$(seq 1 90); do curl -sf $(LOCALSTACK)/_localstack/health >/dev/null && break; sleep 2; done
	@VAULT_IT_LOCALSTACK=$(LOCALSTACK) $(GO) test -count=1 -p 1 -tags 'devenclave integration' ./parent/ ./integration/ ./cmd/devstack/; \
	  status=$$?; $(COMPOSE) -f integration/docker-compose.yml down; exit $$status

# Regenerate testdata/vectors.
vectors:
	$(GO) generate ./vms/vectors

# Every Fuzz* target in every package runs for FUZZTIME. Budgets are
# execution counts, not durations: a time-based -fuzztime can expire while a
# worker is minimizing and fail with "context deadline exceeded" on a loaded
# runner (golang/go#56238), with no finding. Minimization of a crasher is
# bounded by a count too. Seed corpora are the f.Add seeds in the tests (plus
# any regression inputs saved under testdata/fuzz).
fuzz:
	@set -e; for pkg in $$($(GO) list ./...); do \
	  for f in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz' || true); do \
	    echo "== $$pkg $$f"; \
	    $(GO) test $$pkg -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) -fuzzminimizetime $(FUZZMINIMIZE) $(FUZZFLAGS); \
	  done; \
	done

scan:
	gitleaks git --redact .

# deploy/host/SHA256SUMS: every other file of deploy/host (vettid.org pins
# this file's SHA-256 per release; scripts/lint_test.go checks it).
host-sums:
	cd deploy/host && find . -maxdepth 1 -type f ! -name SHA256SUMS -printf '%f\n' | LC_ALL=C sort | xargs sha256sum > SHA256SUMS

tidy:
	$(GO) mod tidy
