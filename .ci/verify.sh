#!/usr/bin/env bash
set -euo pipefail
exec 2>&1
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-always}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-2}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-stable}"
export WASM_BINDGEN_TEST_TIMEOUT="${WASM_BINDGEN_TEST_TIMEOUT:-120}"
: "${CI_COMMIT_SHA:?verify requires the exact source revision}"
: "${ARTIFACT_ROOT:?verify requires an absolute ARTIFACT_ROOT}"
[[ "$ARTIFACT_ROOT" = /* ]] || { echo "ARTIFACT_ROOT must be absolute" >&2; exit 2; }
export RUNNER_TEMP="${RUNNER_TEMP:-$(mktemp -d)}"
export GITHUB_PATH="${GITHUB_PATH:-$RUNNER_TEMP/github_path}"
touch "$GITHUB_PATH"
python3 .github/scripts/check-lock.py
python3 .github/scripts/test-lock.py
node --test .github/scripts/test-auto-merge.mjs
python3 .github/scripts/test-coverage.py
rustc --version --verbose
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
# The nix wrapper `clang` on PATH breaks every wasm32 C build (host glibc
# headers; minicov compiles its C shims in clippy, wasm-pack, and coverage
# alike); resolve `clang` to the pinned unwrapped compiler for this leg
# only: the subshell keeps native builds on the wrapper.
: "${CPFL_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CPFL_WASM_CLANG_BIN:$PATH"
cargo clippy --locked --lib --target wasm32-unknown-unknown -- -D warnings
)
# The nix wrapper `clang` on PATH breaks the wasm32 C build (host glibc
# headers); resolve `clang` to the pinned unwrapped compiler for this leg
# only: the subshell keeps native builds on the wrapper.
: "${CPFL_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CPFL_WASM_CLANG_BIN:$PATH"
wasm-pack test --headless --chrome -- --locked
)
rustup run nightly rustc --version
NIGHTLY_RUSTC="$(rustup which --toolchain nightly rustc)"
NIGHTLY_CARGO="$(rustup which --toolchain nightly cargo)"
NIGHTLY_BIN="$(dirname "$NIGHTLY_RUSTC")"
export RUSTC="$NIGHTLY_RUSTC"
export CARGO="$NIGHTLY_CARGO"
export PATH="$NIGHTLY_BIN:$PATH"
export RUSTUP_TOOLCHAIN=nightly
"$NIGHTLY_CARGO" llvm-cov --version
# Bug 2 isolation: coverage data must not reuse the shared cargo target
# across jobs (stale checkout paths fail the next gate); scope the
# coverage target to this job only. Native gates keep the shared warm
# target; outer traps and services are untouched.
(
coverage_target="$(mktemp -d)"
case "$coverage_target" in ""|"$PWD"/*) echo 'unsafe coverage target' >&2; exit 2;; esac
trap 'rm -rf -- "$coverage_target"' EXIT
export CARGO_TARGET_DIR="$coverage_target"
"$NIGHTLY_CARGO" llvm-cov --locked --branch --json --output-path coverage.json --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --lcov --output-path coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --text --output-path coverage.txt --ignore-filename-regex '/tests/'
python3 .github/scripts/check-coverage.py coverage.lcov coverage.json coverage.txt
version=$(python3 -c "import tomllib; print(next(p['version'] for p in tomllib.load(open('Cargo.lock','rb'))['package'] if p['name']=='wasm-bindgen'))")
archive="wasm-bindgen-${version}-x86_64-unknown-linux-musl.tar.gz"
base="https://github.com/wasm-bindgen/wasm-bindgen/releases/download/${version}"
mkdir -p "$RUNNER_TEMP/wasm-runner"
(cd "$RUNNER_TEMP/wasm-runner" && curl --fail --location --retry 3 --remote-name "$base/$archive" && curl --fail --location --retry 3 --remote-name "$base/$archive.sha256sum" && checksum=$(cut -d ' ' -f1 "$archive.sha256sum") && printf '%s  %s\n' "$checksum" "$archive" | sha256sum --check && tar -xzf "$archive" --strip-components=1)
export PATH="$RUNNER_TEMP/wasm-runner:$PATH"
# Pinned python env above already satisfies requirements (selenium); install
# only as a fallback so a bare nix python never hits PEP 668 (reviewed csrh
# dependency-import pattern; unconditional install removed).
python3 -c 'import selenium; print(selenium.__version__)' || python3 -m pip install -r .github/requirements.txt
# Canonical .github/scripts/browser-coverage-runner.py hardcodes Service("/usr/bin/chromedriver"), absent from the
# nix closure (deterministic, not first-run judgment). Adapt exactly the
# driver-construction line in a job-temp copy (reviewed cwst/cbrd byte pattern):
# service path -> provisioned $CHROMEDRIVER, binary_location -> $CHROME_BIN.
# Canonical tests/options preserved byte for byte (diff audit 1 removed/2 added).
# Global filesystem untouched; stock runner discovery via PATH shim only.
export CHROMEDRIVER="${CHROMEDRIVER:-$(command -v chromedriver)}"
export CHROME_BIN="${CHROME_BIN:-$(command -v chromium)}"
test -x "$CHROMEDRIVER" || { echo "missing chromedriver at $CHROMEDRIVER" >&2; exit 2; }
test -x "$CHROME_BIN" || { echo "missing chromium at $CHROME_BIN" >&2; exit 2; }
mkdir -p "$RUNNER_TEMP/bin"
ln -sf "$CHROME_BIN" "$RUNNER_TEMP/bin/google-chrome"
export PATH="$RUNNER_TEMP/bin:$PATH"
runner_src=.github/scripts/browser-coverage-runner.py
runner_copy="$RUNNER_TEMP/browser-coverage-runner.py"
anchor_hits=$(grep -cF 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)' "$runner_src" || true)
test "$anchor_hits" -eq 1
existing_binary_location=$(grep -cF 'binary_location' "$runner_src" || true)
test "$existing_binary_location" -eq 0
python3 - "$runner_src" "$runner_copy" "$CHROMEDRIVER" "$CHROME_BIN" <<'PYEOF'
import sys
src, dst, driver, chrome = sys.argv[1:5]
text = open(src).read()
anchor = 'driver = webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=options)'
assert text.count(anchor) == 1, 'runner driver-construction text drifted'
replacement = 'options.binary_location = "' + chrome + '"\n        driver = webdriver.Chrome(service=Service("' + driver + '"), options=options)'
open(dst, 'w').write(text.replace(anchor, replacement))
PYEOF
drift_removed=$(diff "$runner_src" "$runner_copy" | grep -c '^<' || true)
drift_added=$(diff "$runner_src" "$runner_copy" | grep -c '^>' || true)
test "$drift_removed" -eq 1
test "$drift_added" -eq 2
grep -F "$CHROMEDRIVER" "$runner_copy"
grep -F "$CHROME_BIN" "$runner_copy"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER="python3 $runner_copy"
export CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS="-Zno-profiler-runtime -Clink-args=--no-gc-sections --cfg=owned_browser_coverage"
export WASM_BINDGEN_TEST_ONLY_WEB=1 WASM_BINDGEN_SPLIT_LINKED_MODULES=1 CHROMEDRIVER="$(command -v chromedriver)" CC_wasm32_unknown_unknown="$CPFL_WASM_CLANG"
: "${CPFL_WASM_CLANG_BIN:?Missing unwrapped wasm clang from run-cached.sh}"
(
export PATH="$CPFL_WASM_CLANG_BIN:$PATH"
"$NIGHTLY_CARGO" llvm-cov test --locked --branch --coverage-target-only --target wasm32-unknown-unknown --json --output-path wasm-coverage.json --ignore-filename-regex '/tests/'
)
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --lcov --output-path wasm-coverage.lcov --ignore-filename-regex '/tests/'
"$NIGHTLY_CARGO" llvm-cov report --target wasm32-unknown-unknown --text --output-path wasm-coverage.txt --ignore-filename-regex '/tests/'
)
python3 .github/scripts/check-coverage.py wasm-coverage.lcov wasm-coverage.json wasm-coverage.txt wasm
