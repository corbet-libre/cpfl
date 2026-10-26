# cpfl agent notes

Work in a lane (`~/agents/scratch/lane-new <lane>`); never edit `~/agents/scratch/ws`.
Run from the lane root (`<lane>/ws`); `cbuild <lane> ...` builds there.

Build and test (quote the verdict line, never infer from a pipe):
- `cbuild <lane> fmt -p cpfl -- --check` — red at HEAD (pre-existing drift in `src/publication.rs`, `tests/profile.rs`); this docs change touches neither
- `cbuild <lane> test -p cpfl --locked` — `profile` `15`, doc `0` passed, exit 0; long, background it
- `cbuild <lane> clippy -p cpfl --locked --all-targets -- -D warnings` — red at HEAD from upstream `ckmg` lints (unused `SigningPhase`, dead `label`/`insert`), not this crate
- `cbuild <lane> check -p cpfl --locked --target wasm32-unknown-unknown` — exit 0
- Full gate (wasm-pack browser exec, 100% line+branch coverage) runs in CI; see `.github/workflows/ci.yml`, `docs/COVERAGE.md`.

Land: `cargo fmt` in touched repos, rebase on main (never force-push),
`cbuild <lane> xtask land --dry`, then `xtask land`.

Invariants (rule -> enforcing test):
- Authority ends at authenticated deadlines; stale credentials/schemas/pins refused
  -> `tests/profile.rs::verified_authority_ends_at_authenticated_deadlines`, `::outer_tampering_and_stale_policy_refuse`
- Restricted edits need fresh accepted pins and fences
  -> `::restricted_edits_require_fresh_accepted_pins_and_fences`
- Full presentations cannot be spliced or relabelled; exact signed bytes retained
  -> `::full_presentations_cannot_be_spliced_or_relabelled`, `::signed_projection_checkpoint_and_peer_round_trip`
- Delayed commit rechecks current admission and clock; the write is fenced afterwards
  -> `::delayed_commit_rechecks_current_admission_and_clock`, `::authorization_is_synchronous_and_the_write_is_fenced_afterwards`
- Unrelated envelope custody never releases a candidate; keys stay in bound custody
  -> `::unrelated_envelope_custody_never_releases_a_candidate`, `::authenticated_hpke_release_keeps_keys_in_original_bound_custody`

Pointers: `src/draft.rs`, `src/publication.rs`, `docs/CONTRACT.md`, `docs/COVERAGE.md`.
Commits: explicit paths, imperative, author per `~/agents/AGENT.md`; no AI trailers.
`publish=false`; LGPL-3.0-only WITH linking-exception; no GPL/AGPL-only deps.
