FUZZ_TARGETS := $(patsubst fuzz/fuzz_targets/%.rs,%,$(wildcard fuzz/fuzz_targets/*.rs))
FUZZ_FLAGS ?= -runs=10000
HOURS ?= 2

.PHONY: all lint fmt fuzz fuzz-all fuzz-stress-all stress fuzz-lint bench bench-report deny test cov fuzz-cmin $(FUZZ_TARGETS) $(addprefix fuzz-,$(FUZZ_TARGETS)) $(addprefix fuzz-stress-,$(FUZZ_TARGETS))

all: lint test fuzz

$(FUZZ_TARGETS):
	cd fuzz && cargo +nightly fuzz run $@ -- $(FUZZ_FLAGS)

fuzz: fuzz-all

fuzz-all: $(FUZZ_TARGETS)

$(addprefix fuzz-,$(FUZZ_TARGETS)): fuzz-%:
	cd fuzz && cargo +nightly fuzz run $* -- $(FUZZ_FLAGS)

fuzz-stress-all:
	@STRESS_SEC=$$(($(HOURS) * 3600)); \
	$(MAKE) fuzz-all FUZZ_FLAGS="-max_total_time=$$STRESS_SEC"

stress: fuzz-stress-all

fuzz-cmin-all: $(addprefix fuzz-cmin-,$(FUZZ_TARGETS))

fuzz-cmin: fuzz-cmin-all

$(addprefix fuzz-cmin-,$(FUZZ_TARGETS)): fuzz-cmin-%:
	cd fuzz && cargo +nightly fuzz cmin $*

$(addprefix fuzz-stress-,$(FUZZ_TARGETS)): fuzz-stress-%:
	@STRESS_SEC=$$(($(HOURS) * 3600)); \
	cd fuzz && cargo +nightly fuzz run $* -- -max_total_time=$$STRESS_SEC

fuzz-lint:
	cd fuzz && cargo clippy --all-features --all-targets -- -D clippy::pedantic -D clippy::nursery -D clippy::all

deny:
	cargo deny check

test:
	cargo nextest run --all-features --all-targets

cov:
	cargo llvm-cov nextest --all-features --all-targets

bench:
	cargo bench --features testing

bench-report: bench
	@xdg-open target/criterion/report/index.html 2>/dev/null || open target/criterion/report/index.html 2>/dev/null || echo "Please open manually: target/criterion/report/index.html"

lint: fmt fuzz-lint deny
	cargo clippy --all-features --all-targets -- -D clippy::pedantic -D clippy::nursery -D clippy::all

report: fuzz-cmin
	cd fuzz && ./sync_report.sh

dev:
	docker compose -f infra/compose.dev.yaml up --build

fmt:
	cargo fmt --all
