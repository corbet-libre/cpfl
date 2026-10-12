#!/usr/bin/env bash
# Run the original native owner gates; wasm and coverage stay in verify.
set -euo pipefail
exec 2>&1
python3 .github/scripts/check-lock.py
rustc --version
cargo metadata --locked --format-version 1 > dependency-metadata.json
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
