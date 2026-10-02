GO        ?= go
FUZZTIME  ?= 20s
# Packages that ship. They must never link the vector-only code.
LIBPKGS   := ./vms/suite ./vms/envelope ./vms/handshake ./vms/invite ./vms/altchan

.PHONY: all test race lint vet staticcheck fuzz scan tidy vectors check-tcb

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

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 -tags vmsvectors ./...

lint: vet staticcheck

# Release builds must not contain deterministic randomness (derandomized
# HPKE, ML-KEM test encapsulation).
check-tcb:
	@if $(GO) list -deps $(LIBPKGS) | grep -E 'hpkederand|mlkemtest'; then \
	  echo "vector-only code linked into library packages"; exit 1; fi
	@echo "check-tcb: ok"

# Regenerate testdata/vectors.
vectors:
	$(GO) generate ./vms/vectors

# Every Fuzz* target in every package runs for FUZZTIME. Seed corpora are the
# f.Add seeds in the tests (plus any regression inputs under testdata/fuzz).
fuzz:
	@set -e; for pkg in $$($(GO) list ./...); do \
	  for f in $$($(GO) test -list '^Fuzz' $$pkg | grep '^Fuzz' || true); do \
	    echo "== $$pkg $$f"; \
	    $(GO) test $$pkg -run '^$$' -fuzz "^$$f\$$" -fuzztime $(FUZZTIME); \
	  done; \
	done

scan:
	gitleaks git --redact .

tidy:
	$(GO) mod tidy
