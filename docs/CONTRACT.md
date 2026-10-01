# Profile contract

Draft owns one member's profile answers, private pin openings and personal rules.
Contacts supplies its authoritative blocks in the same revision; Profile stores
no second contacts journal. Draft has no public serializer for openings.

`edit` invalidates an opening when canonical value bytes or visibility change.
`prepare_pins` uses fresh CSPRNG salts and cpns v2, returning fingerprints only.
Current cshm validates types and uses the caller's deterministic contact detector.
Missing detection fails closed. cgrd validates personal rules and signed accepted
pins. Preparation is never evidence that a restricted change was accepted.
Free fields have no openings; stale credentials/schema cannot publish. Schema
changes require editing to the new exact schema and revalidation, not rewriting
old signed bytes. Optional withdrawal still must satisfy current Guard.

Public and full cgrd projections are serialized and device-signed separately.
Only public-field openings enter the public bundle. Their exact signed bytes
are retained. The full bundle is cprz-compressed then Padme-padded through the
ProfileCodec port before cnvl seals it. PortableCodec uses cprz with default features disabled and cprz-pad, preserving
exact signed bytes and bounding decoded output before it can grow. Native codecs
are excluded from the Wasm dependency graph.

The outer `Transcript` is JSON, signed over ASCII `cpfl:publication:v1` followed
by one NUL and the exact transcript bytes. It binds community/member/device,
positive publication/schema/key revisions, BLAKE3 hashes of the exact public
Bundle and Envelope serializations, personal rules including blocks and opaque
Mesh reachability. Rules and reachability cannot be replaced independently.
`verify_publication` uses cgrd's complete PublishedPolicy path, checks its
credential-authorized device signature, current schema and rules, and a trusted
publication revision floor. It does not prove live G3 device authority, current
accounting authority, session possession or freshness of supplied trust inputs.
Switchboard and Exchange must require those owner capabilities separately.

Candidate retains private draft bytes, wrapped per-publication read key and
public outbox bytes. It is bound to the checkpoint version observed before
preparation. `commit_publication` commits them together with dependent owner
changes through cwst's atomic fence; it exposes no publication on failure.
Trusted Charter updates and dependent changes must share that checkpoint fence.
Reopen and inspect committed operation/outbox after any unknown result. Keys
never appear in a public output. The previous published revision remains valid
until the new commit succeeds. Wrapped read keys remain stored by publication revision, and the exact current
publication survives outbox acknowledgement. Automatic key pruning is absent;
the storage bound fails closed until an authorized retention decision permits
cleanup. Profile never silently discards a previous-generation key.

All Profile-owned serialized objects are bounded to 256 KiB, including the
complete outer publication, before parsing. Reachability is at most 4096 bytes.
Limits can refuse inputs that are structurally valid under a larger schema.
Errors and Debug omit values, pseudonyms, keys and salts. No network or issuer
policy is implemented here. DeviceSigner and ProfileCodec are integration ports;
the production G3 signer remains dependent on the identity owner. Compression
uses the real maintained portable implementation and is tested on both targets.
