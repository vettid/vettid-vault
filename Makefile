GO        ?= go
FUZZTIME  ?= 50000x
FUZZMINIMIZE ?= 200x
# Packages that ship. They must never link the vector-only code, the dev
# enclave (dev sealer, PIN constructors) or test harnesses.
LIBPKGS   := ./vms/suite ./vms/envelope ./vms/handshake ./vms/invite ./vms/altchan \
             ./vault/... ./client/... ./features/... ./cmd/...
E2ETAGS   := devenclave e2e

.PHONY: all test race lint vet staticcheck fuzz scan tidy vectors check-tcb e2e

all: lint check-tcb test

# The vmsvectors build regenerates the §16 vectors through the library's
# sending code and compares them byte for byte with testdata/vectors.
test:
	$(GO) test ./...
	$(GO) test -tags vmsvectors ./vms/vectors

race:
	$(GO) test -race ./...
	$(GO) test -race -tags vmsvectors ./...

vet:
	$(GO) vet ./...
	$(GO) vet -tags vmsvectors ./...
	$(GO) vet -tags '$(E2ETAGS)' ./...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -tags vmsvectors ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -tags '$(E2ETAGS)' ./...

lint: vet staticcheck

# Release builds must not contain deterministic randomness (derandomized
# HPKE, ML-KEM test encapsulation), the dev enclave, or test harnesses and
# test authorities (relaytest, enclavetest: fake NSM and KMS, test roots); and
# the dev enclave must not compile at all without its build tag.
check-tcb:
	@if $(GO) list -deps $(LIBPKGS) | grep -E 'hpkederand|mlkemtest|/devenclave|relaytest|enclavetest'; then \
	  echo "dev, test or vector-only code linked into release packages"; exit 1; fi
	@if $(GO) list ./devenclave >/dev/null 2>&1; then \
	  echo "devenclave compiles without the devenclave tag"; exit 1; fi
	@for f in devenclave/*.go cmd/vaultctl/vault_dev.go; do \
	  head -1 $$f | grep -qx '//go:build devenclave' || { echo "$$f lacks //go:build devenclave"; exit 1; }; done
	@echo "check-tcb: ok"

# End-to-end tests against the real vettid-relay binary (built at the
# version in go.mod) and the dev enclave.
e2e:
	$(GO) test -race -count=1 -tags '$(E2ETAGS)' ./e2e/

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
	    $(GO) test $$pkg -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME) -fuzzminimizetime $(FUZZMINIMIZE); \
	  done; \
	done

scan:
	gitleaks git --redact .

tidy:
	$(GO) mod tidy
