GO        ?= go
FUZZTIME  ?= 20s

.PHONY: all test race lint vet staticcheck fuzz scan tidy

all: lint test

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

# staticcheck is run at a pinned version via `go run` (fetched on first use).
staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...

lint: vet staticcheck

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
