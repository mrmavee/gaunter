FUZZ_TARGETS := $(patsubst fuzz/fuzz_targets/%.rs,%,$(wildcard fuzz/fuzz_targets/*.rs))
FUZZ_FLAGS ?= -runs=10000
HOURS ?= 2

.PHONY: all lint fmt fuzz fuzz-all fuzz-stress-all stress fuzz-lint bench bench-report deny test cov fuzz-cmin $(FUZZ_TARGETS) $(addprefix fuzz-,$(FUZZ_TARGETS)) $(addprefix fuzz-stress-,$(FUZZ_TARGETS))

all: lint test fuzz

waf_engine fuzz-waf_engine fuzz-stress-waf_engine: EXTRA_FUZZ_FLAGS = -dict=dicts/waf.dict
waf_rule_engine fuzz-waf_rule_engine fuzz-stress-waf_rule_engine: EXTRA_FUZZ_FLAGS = -dict=dicts/waf.dict
detect_mime fuzz-detect_mime fuzz-stress-detect_mime: EXTRA_FUZZ_FLAGS = -dict=dicts/detect_mime.dict
form_captcha fuzz-form_captcha fuzz-stress-form_captcha: EXTRA_FUZZ_FLAGS = -dict=dicts/form_captcha.dict
hs_setconf fuzz-hs_setconf fuzz-stress-hs_setconf: EXTRA_FUZZ_FLAGS = -dict=dicts/hs_setconf.dict
proxy_protocol fuzz-proxy_protocol fuzz-stress-proxy_protocol: EXTRA_FUZZ_FLAGS = -dict=dicts/proxy_protocol.dict
session_security fuzz-session_security fuzz-stress-session_security: EXTRA_FUZZ_FLAGS = -dict=dicts/session_security.dict

$(FUZZ_TARGETS):
	cd fuzz && cargo +nightly fuzz run $@ -- $(FUZZ_FLAGS) $(EXTRA_FUZZ_FLAGS)

fuzz: fuzz-all

fuzz-all: $(FUZZ_TARGETS)

$(addprefix fuzz-,$(FUZZ_TARGETS)): fuzz-%:
	cd fuzz && cargo +nightly fuzz run $* -- $(FUZZ_FLAGS) $(EXTRA_FUZZ_FLAGS)

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
	cd fuzz && cargo +nightly fuzz run $* -- -max_total_time=$$STRESS_SEC $(EXTRA_FUZZ_FLAGS)

fuzz-lint:
	cd fuzz && cargo clippy --all-features --all-targets -- -D clippy::pedantic -D clippy::nursery -D clippy::all

deny:
	cargo deny check

test:
	cargo nextest run --all-features --lib --tests

cov:
	cargo llvm-cov nextest --all-features --lib --tests

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
