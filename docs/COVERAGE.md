# Coverage contract

CI measures production Rust lines and branches with cargo-llvm-cov and requires
100% of both. A zero-count report fails. Test harness files are excluded from the
production denominator. No production paths are excluded at this stage. Browser
vectors execute in headless Chrome; a compile check is not execution evidence.
Native coverage does not establish coverage of wasm-only adapters.

Stable Rust runs product validation. Nightly is used only for upstream Rust's
experimental branch instrumentation. CI resolves dependencies once and uploads
Cargo.lock; all jobs consume that exact snapshot with --locked. Weekly CI refreshes
the snapshot and Dependabot proposes manifest/lock updates. A failed coverage gate
is an open requirement, never evidence of complete coverage.
