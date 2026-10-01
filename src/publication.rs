use crate::{Error, MAX_REACHABILITY_BYTES, decode, encode};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Versioned outer transcript. It binds exact original signed bundle bytes,
/// ciphertext, personal rules (including Contacts blocks), and Mesh reachability.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transcript {
    /// Wire transcript version, currently one.
    pub version: u8,
    /// Community namespace.
    pub community: String,
    /// Community-local pseudonym.
    pub member: String,
    /// Device key authorized by the enclosed signed community credential.
    pub device: [u8; 32],
    /// Strictly positive owner publication revision; callers enforce their floor.
    pub revision: u64,
    /// Exact current profile schema version.
    pub schema_revision: u64,
    /// Positive profile read-key generation.
    pub key_generation: u64,
    /// BLAKE3 digest of the exact serialized public cgrd Bundle.
    pub public_digest: [u8; 32],
    /// BLAKE3 digest of the exact serialized cnvl Envelope.
    pub encrypted_digest: [u8; 32],
    /// Public personal rules and authoritative block projection supplied by Contacts.
    pub rules: Vec<cgrd::Rule>,
    /// Opaque message-network reachability descriptor.
    pub reachability: Vec<u8>,
}
/// Untrusted public wire data. Construction or deserialization never grants authority.
#[derive(Serialize)]
pub struct Publication {
    /// Exact UTF-8 Transcript bytes.
    pub transcript: Vec<u8>,
    /// Detached signature over publication_binding of transcript.
    pub signature: Vec<u8>,
    /// Separately signed exact cgrd public projection.
    pub public_bundle: Vec<u8>,
    /// Encrypted exact signed full projection, after compression and Padme padding.
    pub envelope: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicationWire {
    transcript: Vec<u8>,
    signature: Vec<u8>,
    public_bundle: Vec<u8>,
    envelope: Vec<u8>,
}
impl std::fmt::Debug for Publication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Publication([redacted])")
    }
}
impl Publication {
    /// Encode an untrusted publication; still requires verify_publication on receipt.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        if [
            &self.transcript,
            &self.signature,
            &self.public_bundle,
            &self.envelope,
        ]
        .iter()
        .any(|v| v.len() > crate::MAX_PROFILE_BYTES)
        {
            return Err(Error::Limit);
        }
        encode(self)
    }
    /// Bound serialized input before parsing. There is no public Deserialize path.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let wire: PublicationWire = decode(bytes)?;
        Ok(Self {
            transcript: wire.transcript,
            signature: wire.signature,
            public_bundle: wire.public_bundle,
            envelope: wire.envelope,
        })
    }
}
/// Exact signature framing; Ed25519 performs signing and verification.
pub fn publication_binding(transcript: &[u8]) -> Vec<u8> {
    [b"cpfl:publication:v1\0".as_slice(), transcript].concat()
}
/// A publication admitted under the supplied current Guard policy. This is not
/// a forum session, live G3 device attestation, or accounting release authority.
pub struct VerifiedPublication {
    transcript: Transcript,
    public: cshm::PublicProfile,
    participant: cgrd::Participant,
}
impl VerifiedPublication {
    /// Authenticated owner transcript.
    pub fn transcript(&self) -> &Transcript {
        &self.transcript
    }
    /// Schema-valid public projection, authenticated by the current credential.
    pub fn public(&self) -> &cshm::PublicProfile {
        &self.public
    }
    /// Guard's authenticated profile/rule projection for reciprocal checks.
    pub fn participant(&self) -> &cgrd::Participant {
        &self.participant
    }
    /// Exact Envelope context for authorized peer opening.
    pub fn context(&self) -> cnvl::Context {
        cnvl::Context {
            community: self.transcript.community.clone(),
            owner: self.transcript.member.clone(),
            profile_revision: self.transcript.revision,
            schema_revision: self.transcript.schema_revision,
            key_generation: self.transcript.key_generation,
        }
    }
}
/// Verify original bytes against complete published policy and a trusted revision
/// floor. No raw-key-only or legacy-settings admission path exists.
pub fn verify_publication(
    publication: &Publication,
    policy: &cgrd::PublishedPolicy<'_>,
    signed_schema: &[u8],
    minimum_revision: u64,
    contact: &impl Fn(&str) -> cshm::ContactCheck,
) -> Result<VerifiedPublication, Error> {
    // Bound each member even when an in-process caller bypasses deserialization.
    publication.to_bytes()?;
    let transcript: Transcript = decode(&publication.transcript)?;
    if transcript.version != 1
        || transcript.revision == 0
        || transcript.revision < minimum_revision
        || transcript.key_generation == 0
        || transcript.reachability.len() > MAX_REACHABILITY_BYTES
        || transcript.public_digest != *blake3::hash(&publication.public_bundle).as_bytes()
        || transcript.encrypted_digest != *blake3::hash(&publication.envelope).as_bytes()
    {
        return Err(Error::Invalid);
    }
    let bundle: cgrd::Bundle = decode(&publication.public_bundle)?;
    if !cgrd::check_published_with_contact(&bundle, policy, signed_schema, contact).is_admitted() {
        return Err(Error::Admission);
    }
    let body: cgrd::BundleContent = decode(&bundle.payload)?;
    let cgrd::Profile::Public(public) = body.profile else {
        return Err(Error::Invalid);
    };
    if transcript.community != body.community
        || transcript.member != body.member
        || transcript.device != body.device
        || transcript.schema_revision != u64::from(public.schema_version)
    {
        return Err(Error::Invalid);
    }
    let signature = Signature::from_slice(&publication.signature).map_err(|_| Error::Crypto)?;
    VerifyingKey::from_bytes(&body.device)
        .and_then(|key| {
            key.verify_strict(&publication_binding(&publication.transcript), &signature)
        })
        .map_err(|_| Error::Crypto)?;
    let schema = authenticated_schema(policy, signed_schema)?;
    let participant =
        cgrd::Participant::with_contact(&body.member, &public, &schema, &transcript.rules, contact)
            .map_err(|_| Error::Schema)?;
    // Parse now to refuse malformed ciphertext before Switchboard retains it.
    let verified = VerifiedPublication {
        transcript,
        public,
        participant,
    };
    let envelope = cnvl::Envelope::from_bytes(&publication.envelope).map_err(|_| Error::Invalid)?;
    if !envelope.matches_context(&verified.context()) {
        return Err(Error::Invalid);
    }
    Ok(verified)
}
pub(crate) fn authenticated_schema(
    policy: &cgrd::PublishedPolicy<'_>,
    bytes: &[u8],
) -> Result<cshm::Schema, Error> {
    let signed = policy
        .policy
        .keys
        .verify(bytes, csgn::Kind::SchemaSnapshot, policy.policy.now)
        .map_err(|_| Error::Admission)?;
    let snapshot: cgrd::Snapshot<cshm::Schema> = decode(signed.payload())?;
    Ok(snapshot.content)
}
