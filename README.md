# cpfl — Profile

## Scope

### Purpose

cpfl holds the member's own profile and own rules as one signed, revisioned publication.

### Owns

- Typed drafts and edits of profile values; profiles carry real values, ranges appear only in rules.
- Validation against the community's current schema through `cgrd`.
- Pins for restricted fields with fresh salts through `cpns` v2; a restricted change waits for an accepted spend.
- Separately signed public and full projections, plus an outer publication binding the rules (including blocks supplied by Contacts), the ciphertext digest, and opaque reachability.
- Packing the full projection with `cprz`, padding, and `cnvl`.
- Publishing the encrypted profile through Link; only the key travels peer to peer.

### Never

- Implements another schema, rule, or censor engine.
- Sends private values or salts to servers.
- Publishes a restricted edit without an accepted spend, reuses salts, or strips fields from signed bytes.
- Includes pictures at the start, or age bands and coarse values.
- Accepts proven attribute values from `cvld`.

### States

Empty → Draft → Validated → Sealed/Signed → Published (revision). An edit, schema, or credential change needs fresh validation; a restricted edit waits for an accepted pin change. Failure keeps the last valid version.

### Test obligations

- Current-schema validation (numeric, choice, location, text) on native and Wasm with identical vectors; the contact-details check fails closed when unavailable.
- The public projection omits private openings; the full projection verifies after peer decryption; exact signed bytes survive compress, pad, and seal.
- Stale credentials, pins, or schemas block publication; schema changes cannot forge signatures; splice attacks and clock regression are refused.
- Full line and branch coverage with real round trips and no mocks of own logic; injected delay, duplication, loss, cancellation, corruption, and storage conflicts; community isolation; bounded inputs; errors omit identifiers, plaintext, and secrets.

See [the contract](docs/CONTRACT.md) and [coverage requirements](docs/COVERAGE.md).
Production device authority and independent acceptance review remain required.
