use crate::{
    Error, Publication, Transcript, VerifiedPublication, decode, encode, publication_binding,
};
use ckmg::Entropy;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// Vault-owned signer. Production must require current G3-authorized device
/// custody. Profile never accepts PRF/root bytes or implements device policy.
pub trait DeviceSigner {
    /// Community-local public key; Guard checks its credential authorization.
    fn public_key(&self) -> [u8; 32];
    /// Actual X25519 public key of the same opaque device custody. Both profile
    /// projections include this field inside their original device signature.
    fn hpke_public_key(&self) -> Result<[u8; 32], Error>;
    /// Sign exact domain-framed bytes with the authorized device capability.
    fn sign(&mut self, bytes: &[u8]) -> Result<[u8; 64], Error>;
}

// This adapter deliberately accepts only the lineage-device capability. Derived
// purpose signers cannot stand in for the credential-authorized Profile device.
impl DeviceSigner for ckmg::DeviceEd25519Signer<'_> {
    fn public_key(&self) -> [u8; 32] {
        *self.public_key()
    }

    fn hpke_public_key(&self) -> Result<[u8; 32], Error> {
        ckmg::DeviceEd25519Signer::hpke_public_key(self).map_err(|_| Error::Crypto)
    }

    fn sign(&mut self, bytes: &[u8]) -> Result<[u8; 64], Error> {
        ckmg::DeviceEd25519Signer::sign(self, bytes).map_err(|_| Error::Crypto)
    }
}
/// Compression port for cprz's maintained bounded codec and Padme implementation.
/// The production implementation is PortableCodec, using maintained Brotli and Padme.
pub trait ProfileCodec {
    /// Compress exact signed bytes, then Padme-pad them with a bounded length frame.
    fn pack(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>;
    /// Remove padding and expand exact original signed bytes, rejecting output over maximum.
    fn unpack(&self, bytes: &[u8], maximum: usize) -> Result<Zeroizing<Vec<u8>>, Error>;
}
/// Native/Wasm cprz exact-byte Brotli followed by its existing Padme implementation.
#[derive(Default)]
pub struct PortableCodec;
impl ProfileCodec for PortableCodec {
    fn pack(&self, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
        if bytes.len() > crate::MAX_PROFILE_BYTES {
            return Err(Error::Limit);
        }
        let compressed = Zeroizing::new(cprz::portable::compress(bytes).map_err(|_| Error::Codec)?);
        // Input is capped above; Envelope enforces the final packed byte budget.
        Ok(Zeroizing::new(cprz_pad::pad(&compressed)))
    }
    fn unpack(&self, bytes: &[u8], maximum: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
        if bytes.len() > cnvl::MAX_PLAINTEXT_BYTES || maximum > crate::MAX_PROFILE_BYTES {
            return Err(Error::Limit);
        }
        let compressed = Zeroizing::new(cprz_pad::unpad(bytes).map_err(|_| Error::Codec)?);
        cprz::portable::decompress(&compressed, cnvl::MAX_PLAINTEXT_BYTES, maximum)
            .map(Zeroizing::new)
            .map_err(|_| Error::Codec)
    }
}
/// Device-only working state. Its openings are retained only for unchanged values.
/// Draft serialization is confined to the encrypted checkpoint inside Candidate.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DraftState {
    member: String,
    profile: cshm::Profile,
    openings: Vec<cgrd::Opening>,
    rules: Vec<cgrd::Rule>,
    /// System field: the sponsor's signed endorsement, published only in the
    /// public bundle. It is not an answer and `edit` never touches it.
    #[serde(default)]
    vouched_by: Option<Vec<u8>>,
    /// System field: lineage evidence for `vouched_by` (`cvch::link::Snapshot` wire form),
    /// published only in the public bundle together with the endorsement.
    #[serde(default)]
    vouched_snapshot: Option<Vec<u8>>,
}
/// Private draft custody; it deliberately exposes no general serializer for salts.
pub struct Draft {
    state: DraftState,
}
impl Drop for DraftState {
    fn drop(&mut self) {
        for opening in &mut self.openings {
            opening.salt.zeroize();
        }
    }
}
impl std::fmt::Debug for Draft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Draft([redacted])")
    }
}
impl Draft {
    /// Start a new draft; validation is repeated at every publication attempt.
    pub fn new(member: String, profile: cshm::Profile) -> Result<Self, Error> {
        if member.is_empty() || member.len() > 256 {
            return Err(Error::Invalid);
        }
        let draft = Self {
            state: DraftState {
                member,
                profile,
                openings: vec![],
                rules: vec![],
                vouched_by: None,
                vouched_snapshot: None,
            },
        };
        encode(&draft.state)?;
        Ok(draft)
    }
    /// Device-local answers, never a public projection or admission capability.
    pub fn profile(&self) -> &cshm::Profile {
        &self.state.profile
    }
    /// Replace answers. A changed canonical value or visibility discards its old
    /// opening, so the next prepare_pins creates a fresh salt for a restricted edit.
    pub fn edit(&mut self, profile: cshm::Profile) -> Result<(), Error> {
        if profile.community != self.state.profile.community {
            return Err(Error::Invalid);
        }
        encode(&profile)?;
        self.state.openings.retain(|opening| {
            [
                (&self.state.profile.public, &profile.public),
                (&self.state.profile.private, &profile.private),
            ]
            .iter()
            .any(|(old, new)| {
                match (old.get(&opening.field), new.get(&opening.field)) {
                    (Some(a), Some(b)) => cgrd::pin_value_bytes(a) == cgrd::pin_value_bytes(b),
                    _ => false,
                }
            })
        });
        self.state.profile = profile;
        Ok(())
    }
    /// Own rules plus Contacts' block projection. Caller supplies both atomically;
    /// Profile does not own a second block journal.
    pub fn set_rules(&mut self, rules: Vec<cgrd::Rule>) -> Result<(), Error> {
        if rules.len() > cgrd::MAX_ITEMS {
            return Err(Error::Limit);
        }
        encode(&rules)?;
        self.state.rules = rules;
        Ok(())
    }
    /// Set or clear the system endorsement ("vouched for by"). `None` removes it,
    /// which is the one-way hidden-mode rule. The bytes are opaque here; display
    /// verifies them against the sponsor's lineage.
    pub fn set_vouched_by(&mut self, endorsement: Option<Vec<u8>>) -> Result<(), Error> {
        if endorsement
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > cgrd::MAX_ENDORSEMENT_BYTES)
        {
            return Err(Error::Limit);
        }
        self.state.vouched_by = endorsement;
        Ok(())
    }
    /// Set or clear the lineage snapshot that accompanies the endorsement. It is dropped
    /// whenever the endorsement is, so hidden mode leaves nothing behind.
    pub fn set_vouched_snapshot(&mut self, snapshot: Option<Vec<u8>>) -> Result<(), Error> {
        if snapshot
            .as_ref()
            .is_some_and(|bytes| bytes.is_empty() || bytes.len() > cgrd::MAX_SNAPSHOT_BYTES)
        {
            return Err(Error::Limit);
        }
        self.state.vouched_snapshot = snapshot;
        Ok(())
    }
    /// The endorsement currently set, if any.
    pub fn vouched_by(&self) -> Option<&[u8]> {
        self.state.vouched_by.as_deref()
    }
    /// Structural current-schema validation, never a credential admission.
    pub fn validate(
        &self,
        schema: &cshm::Schema,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
    ) -> Result<(), Error> {
        let compiled = schema.compile().map_err(|_| Error::Schema)?;
        if !compiled
            .validate_profile_with(&self.state.profile, contact)
            .is_valid()
        {
            return Err(Error::Schema);
        }
        cgrd::Participant::with_contact(
            &self.state.member,
            &cshm::PublicProfile::from(&self.state.profile),
            schema,
            &self.state.rules,
            contact,
        )
        .map_err(|_| Error::Schema)?;
        Ok(())
    }
    /// Prepare only fingerprints for pin registration/change. Values and salts
    /// remain device-side; a resulting credential must still pass Guard before publication.
    pub fn prepare_pins(
        &mut self,
        schema: &cshm::Schema,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        entropy: &mut impl Entropy,
    ) -> Result<Vec<cgrd::Pin>, Error> {
        self.validate(schema, contact)?;
        let restricted: Vec<_> = schema
            .public
            .iter()
            .chain(&schema.private)
            .filter(|f| f.change_preset != cshm::ChangePreset::Free)
            .collect();
        let mut openings = self.state.openings.clone();
        openings.retain(|o| restricted.iter().any(|f| f.id == o.field));
        let mut pins = Vec::new();
        for field in restricted {
            let Some(value) = self
                .state
                .profile
                .public
                .get(&field.id)
                .or_else(|| self.state.profile.private.get(&field.id))
            else {
                continue;
            };
            if !openings.iter().any(|o| o.field == field.id) {
                let mut salt = vec![0; 32];
                entropy.fill(&mut salt).map_err(|_| Error::Crypto)?;
                openings.push(cgrd::Opening {
                    field: field.id.clone(),
                    salt,
                });
            }
            let opening = openings
                .iter()
                .find(|o| o.field == field.id)
                .ok_or(Error::Invalid)?;
            let salt = cpns::Salt::from_bytes(opening.salt.clone()).map_err(|_| Error::Invalid)?;
            let fingerprint = cpns::fingerprint_v2(
                &cpns::FingerprintContext {
                    community: &self.state.profile.community,
                    member: &self.state.member,
                    field: &field.id,
                },
                &cgrd::pin_value_bytes(value),
                &salt,
            );
            pins.push(cgrd::Pin {
                field: field.id.clone(),
                fingerprint: *fingerprint.as_bytes(),
            });
        }
        self.state.openings = openings;
        Ok(pins)
    }
    /// Restore only from authenticated Vault checkpoint bytes; never from a public
    /// network reply. It remains unvalidated until prepare_publication runs Guard.
    pub fn from_checkpoint(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            state: decode(bytes)?,
        })
    }
    /// Prepare both projections independently; failures leave the committed version
    /// untouched. The opaque candidate exposes no publication before its atomic commit.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_publication(
        &self,
        credential: &[u8],
        policy: &cgrd::PublishedPolicy<'_>,
        signed_schema: &[u8],
        revision: u64,
        key_generation: u64,
        reachability: Vec<u8>,
        expected_checkpoint: u64,
        signer: &mut impl DeviceSigner,
        custody: &cnvl::Custodian<'_>,
        codec: &impl ProfileCodec,
        contact: &impl Fn(&str) -> cshm::ContactCheck,
        sponsors: cgrd::Sponsors<'_>,
    ) -> Result<Candidate, Error> {
        if revision == 0
            || key_generation == 0
            || reachability.len() > crate::MAX_REACHABILITY_BYTES
        {
            return Err(Error::Invalid);
        }
        let schema = crate::publication::authenticated_schema(policy, signed_schema)?;
        self.validate(&schema, contact)?;
        let public_profile = cshm::PublicProfile::from(&self.state.profile);
        let public_openings = self
            .state
            .openings
            .iter()
            .filter(|o| public_profile.public.contains_key(&o.field))
            .cloned()
            .collect();
        let public = self.bundle(
            credential,
            cgrd::Profile::Public(public_profile),
            public_openings,
            self.state.vouched_by.clone(),
            self.state
                .vouched_by
                .as_ref()
                .and(self.state.vouched_snapshot.clone()),
            signer,
        )?;
        let full = self.bundle(
            credential,
            cgrd::Profile::Full(self.state.profile.clone()),
            self.state.openings.clone(),
            None,
            None,
            signer,
        )?;
        // An endorsement is refused here unless its sponsor vouches now; Guard
        // also requires the bundle to record that verification.
        if !cgrd::check_published_with_sponsors(&public, policy, signed_schema, contact, sponsors)
            .is_admitted()
            || !cgrd::check_published_with_contact(&full, policy, signed_schema, contact)
                .is_admitted()
        {
            return Err(Error::Admission);
        }
        let public_bundle = encode(&public)?;
        let full_bytes = Zeroizing::new(encode(&full)?);
        let packed = codec.pack(&full_bytes)?;
        let context = cnvl::Context {
            community: self.state.profile.community.clone(),
            owner: self.state.member.clone(),
            profile_revision: revision,
            schema_revision: u64::from(self.state.profile.schema_version),
            key_generation,
        };
        if custody.public_key() != signer.hpke_public_key()? {
            return Err(Error::Crypto);
        }
        let (envelope, read_key) = custody.seal(context, &packed).map_err(|_| Error::Crypto)?;
        let envelope = envelope.to_bytes().map_err(|_| Error::Crypto)?;
        let wrapped_key = read_key
            .wrap()
            .map_err(|_| Error::Crypto)?
            .as_bytes()
            .to_vec();
        let transcript = Transcript {
            version: 1,
            community: self.state.profile.community.clone(),
            member: self.state.member.clone(),
            device: signer.public_key(),
            revision,
            schema_revision: u64::from(self.state.profile.schema_version),
            key_generation,
            public_digest: *blake3::hash(&public_bundle).as_bytes(),
            encrypted_digest: *blake3::hash(&envelope).as_bytes(),
            rules: self.state.rules.clone(),
            reachability,
        };
        let transcript = encode(&transcript)?;
        let signature = signer.sign(&publication_binding(&transcript))?.to_vec();
        let publication = Publication {
            transcript,
            signature,
            public_bundle,
            envelope,
        };
        crate::verify_publication(&publication, policy, signed_schema, revision, contact)?;
        let publication = encode(&publication)?;
        Ok(Candidate {
            expected_checkpoint,
            prepared_at: policy.policy.now,
            full_bundle: full_bytes,
            scope: self.state.profile.community.clone(),
            revision,
            read_key_id: revision.to_be_bytes(),
            checkpoint: Zeroizing::new(encode(&self.state)?),
            wrapped_key,
            publication,
        })
    }
    fn bundle(
        &self,
        credential: &[u8],
        profile: cgrd::Profile,
        openings: Vec<cgrd::Opening>,
        vouched_by: Option<Vec<u8>>,
        vouched_snapshot: Option<Vec<u8>>,
        signer: &mut impl DeviceSigner,
    ) -> Result<cgrd::Bundle, Error> {
        let payload = encode(&cgrd::BundleContent {
            community: self.state.profile.community.clone(),
            member: self.state.member.clone(),
            device: signer.public_key(),
            hpke_key: Some(signer.hpke_public_key()?),
            credential: credential.to_vec(),
            profile,
            openings,
            vouched_verified: vouched_by.is_some(),
            vouched_by,
            vouched_snapshot,
        })?;
        let signature = signer.sign(&cgrd::binding_bytes(&payload))?.to_vec();
        Ok(cgrd::Bundle { payload, signature })
    }
}
/// Current trusted verification inputs, supplied anew at the durable boundary.
/// This is not a serialized authority token; Charter owns these current snapshots.
pub struct Validation<'a> {
    /// Complete current published policy and injected current time.
    pub policy: cgrd::PublishedPolicy<'a>,
    /// Original current signed schema snapshot.
    pub signed_schema: &'a [u8],
    /// Deterministic contact detector used for both projections.
    pub contact: &'a dyn Fn(&str) -> cshm::ContactCheck,
}
/// Prepared publication and key material, released only by a durable multi-owner commit.
pub struct Candidate {
    expected_checkpoint: u64,
    prepared_at: u64,
    full_bundle: Zeroizing<Vec<u8>>,
    scope: String,
    revision: u64,
    read_key_id: [u8; 8],
    checkpoint: Zeroizing<Vec<u8>>,
    wrapped_key: Vec<u8>,
    publication: Vec<u8>,
}
impl Candidate {
    /// Save draft/openings/wrapped key/publication output together with any dependent
    /// owner changes. A failed/unknown write returns no publication; reopen Vault and
    /// reconcile the operation and outbox before retrying.
    pub async fn commit_publication<B: cwst::backend::Backend>(
        self,
        store: &mut cwst::Store<B>,
        current: Validation<'_>,
        operation: [u8; 32],
        dependent_changes: Vec<cwst::Change<'_>>,
    ) -> Result<u64, Error> {
        self.authorize(current)?
            .commit(store, operation, dependent_changes)
            .await
    }

    /// Check the prepared publication against the CURRENT policy, schema and
    /// contact detector, synchronously. A runtime that can only borrow the current
    /// trust state inside a synchronous callback calls this there and then awaits
    /// `Authorized::commit` outside it; the Store version fence still applies.
    pub fn authorize(self, current: Validation<'_>) -> Result<Authorized, Error> {
        if current.policy.policy.now < self.prepared_at {
            return Err(Error::Admission);
        }
        let publication = Publication::from_bytes(&self.publication)?;
        let contact = |text: &str| (current.contact)(text);
        crate::verify_publication(
            &publication,
            &current.policy,
            current.signed_schema,
            self.revision,
            &contact,
        )?;
        let full: cgrd::Bundle = decode(&self.full_bundle)?;
        if !cgrd::check_published_with_contact(
            &full,
            &current.policy,
            current.signed_schema,
            &contact,
        )
        .is_admitted()
        {
            return Err(Error::Admission);
        }
        Ok(Authorized(self))
    }
}

/// A candidate that passed the current-policy checks of `Candidate::authorize`.
/// It owns no policy borrow and only `commit` can persist it.
pub struct Authorized(Candidate);
impl Authorized {
    /// Persist atomically with any dependent owner changes (see `commit_publication`).
    pub async fn commit<B: cwst::backend::Backend>(
        self,
        store: &mut cwst::Store<B>,
        operation: [u8; 32],
        mut dependent_changes: Vec<cwst::Change<'_>>,
    ) -> Result<u64, Error> {
        let this = self.0;
        if !store.is_scope(&this.scope) {
            return Err(Error::Invalid);
        }
        if let Some(bytes) = store
            .read("profile", b"publication")
            .map_err(|_| Error::Storage)?
        {
            let previous = Publication::from_bytes(bytes)?;
            let previous: Transcript = decode(&previous.transcript)?;
            if this.revision <= previous.revision {
                return Err(Error::Invalid);
            }
        }
        // Prevent an injected dependent mutation from overwriting Profile's owned records.
        if dependent_changes.iter().any(|c| {
            matches!(
                c,
                cwst::Change::Put {
                    owner: "profile" | "profile.keys",
                    ..
                } | cwst::Change::Delete {
                    owner: "profile" | "profile.keys",
                    ..
                }
            )
        }) {
            return Err(Error::Invalid);
        }
        dependent_changes.push(cwst::Change::Put {
            owner: "profile",
            key: b"draft",
            value: &this.checkpoint,
        });
        dependent_changes.push(cwst::Change::Put {
            owner: "profile.keys",
            key: &this.read_key_id,
            value: &this.wrapped_key,
        });
        dependent_changes.push(cwst::Change::Put {
            owner: "profile",
            key: b"publication",
            value: &this.publication,
        });
        let output = cwst::Output {
            id: operation,
            bytes: this.publication.clone(),
        };
        store
            .commit(
                this.expected_checkpoint,
                operation,
                &dependent_changes,
                &[output],
            )
            .await
            .map_err(|_| Error::Storage)
    }
}

/// Open only a currently admitted owner's exact signed full projection. Decrypted
/// bytes still need Guard; encryption alone never grants schema/pin/device authority.
pub fn open_full(
    publication: &Publication,
    verified: &VerifiedPublication,
    key: &cnvl::ReadKey<'_>,
    codec: &impl ProfileCodec,
    policy: &cgrd::PublishedPolicy<'_>,
    signed_schema: &[u8],
    contact: &impl Fn(&str) -> cshm::ContactCheck,
) -> Result<cshm::Profile, Error> {
    if *blake3::hash(&publication.public_bundle).as_bytes() != verified.transcript().public_digest
        || *blake3::hash(&publication.envelope).as_bytes() != verified.transcript().encrypted_digest
    {
        return Err(Error::Invalid);
    }
    let envelope = cnvl::Envelope::from_bytes(&publication.envelope).map_err(|_| Error::Invalid)?;
    let packed = cnvl::open(&envelope, key, &verified.context()).map_err(|_| Error::Crypto)?;
    let bytes = codec.unpack(&packed, crate::MAX_PROFILE_BYTES)?;
    let bundle: cgrd::Bundle = decode(&bytes)?;
    if !cgrd::check_published_with_contact(&bundle, policy, signed_schema, contact).is_admitted() {
        return Err(Error::Admission);
    }
    let body: cgrd::BundleContent = decode(&bundle.payload)?;
    let cgrd::Profile::Full(profile) = body.profile else {
        return Err(Error::Invalid);
    };
    if body.community != verified.transcript().community
        || body.member != verified.transcript().member
        || body.device != verified.transcript().device
        || body.hpke_key.as_ref() != verified.hpke_public_key()
        || cshm::PublicProfile::from(&profile) != *verified.public()
    {
        return Err(Error::Invalid);
    }
    Ok(profile)
}
