# cpfl — Profile

## Scope

**Purpose and home.** The member's own profile and rules as one signed revisioned
publication, under `cmsg → cbrd → cpfl`.

**Owns.** Typed drafts and edits, current-schema validation through Guard, restricted
field pins with fresh salts through `cpns` v2, separately signed public and full
projections, and an outer publication binding rules, ciphertext digest and opaque
reachability. Rules include blocking material supplied by Contacts. Profile packs
the full projection with `cprz` → Padme → Envelope. Link carries the encrypted
publication to the forum's RAM; keys travel only peer to peer.

**Never.** Implements another schema, rule or censor engine; sends private values
or salts to servers; publishes a restricted edit without accepted pin spending;
reuses salts or strips fields from signed bytes. Profiles use real values, with
ranges in rules. Pictures and coarse age bands are outside the initial scope.
Community gates do not certify profile attribute values.

**States and ports.** Empty → Draft → Validated → Sealed/Signed → Published(revision).
An edit, schema or credential change needs fresh validation; restricted edits wait
for an accepted pin change. Failure preserves the last valid publication. Ports
include draft `edit`, `validate`, `prepare_pins`, `prepare_publication`,
`commit_publication`, and `verify_publication`, with DeviceSigner and ProfileCodec
capabilities. A changed schema is validated on the next preparation and commit.

**Invariants and tests.** Person and profile are checked together; public and full
signed bytes remain exact across compress-pad-seal. Native and actual browser tests
cover current numeric, choice, location and text validation, unavailable contact
checks, private-opening omission, peer decryption, stale credentials/pins/schema,
splice attacks and clock regression. Every reachable source line and branch must
be covered. Accepted pin-spend credentials remain the accounting/issuer boundary.

See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Production device authority and independent acceptance review remain required.
