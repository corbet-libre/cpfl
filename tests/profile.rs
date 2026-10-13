//! Real issuer/device signatures, Guard, pins, Brotli/Padme and encrypted checkpoints.
//! Fixture issuer/device custody is never claimed as a production G3 adapter.
use ckmg::{
    SystemEntropy,
    passkey::{PrfOutput, StoreCipher, store_cipher},
};
use cpfl::{DeviceSigner, Draft, Error, PortableCodec, ProfileCodec, Publication, Transcript};
use csgn::{Kind, SecretKey, Signer};
use ed25519_dalek::{Digest, Sha512, Signer as _, SigningKey};
use serde_json::json;

const ISSUANCE_ACTION: &str = "admission";

#[cfg(target_arch = "wasm32")]
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);
macro_rules! shared {
    ($name:ident, $body:block) => {
        #[cfg(not(target_arch = "wasm32"))]
        #[test]
        fn $name() { futures_executor::block_on(async $body); }
        #[cfg(target_arch = "wasm32")]
        #[wasm_bindgen_test::wasm_bindgen_test]
        async fn $name() $body
    };
}
struct Device(SigningKey);
impl DeviceSigner for Device {
    fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }
    fn hpke_public_key(&self) -> Result<[u8; 32], Error> {
        Ok(self.0.verifying_key().to_montgomery().to_bytes())
    }
    fn sign(&mut self, bytes: &[u8]) -> Result<[u8; 64], Error> {
        Ok(self.0.sign(bytes).to_bytes())
    }
}
fn device() -> Device {
    Device(SigningKey::from_bytes(&[22; 32]))
}
fn cipher() -> StoreCipher {
    store_cipher(&PrfOutput::from_bytes(&[3; 32]).unwrap(), "garden").unwrap()
}
fn schema() -> cshm::Schema {
    serde_json::from_value(json!({
        "community":"garden","version":1,
        "public":[
            {"id":"age","label":"Age","kind":{"type":"integer","min":18,"max":120},"required":true,"filterable":true,"change_preset":"stable","no_contact_details":false},
            {"id":"bio","label":"Bio","kind":{"type":"short_text","min_length":0,"max_length":100},"required":false,"filterable":true,"change_preset":"free","no_contact_details":true},
            {"id":"hobby","label":"Hobby","kind":{"type":"choice","options":[{"id":"reading","label":"Reading"}]},"required":false,"filterable":true,"change_preset":"free","no_contact_details":false},
            {"id":"place","label":"Place","kind":{"type":"location"},"required":false,"filterable":true,"change_preset":"free","no_contact_details":false}
        ],
        "private":[{"id":"secret","label":"Secret","kind":{"type":"yes_no"},"required":true,"filterable":false,"change_preset":"occasional","no_contact_details":false},{"id":"private_bio","label":"Private biography","kind":{"type":"short_text","min_length":0,"max_length":100},"required":false,"filterable":false,"change_preset":"free","no_contact_details":true}]
    })).unwrap()
}
fn profile() -> cshm::Profile {
    cshm::Profile {
        community: "garden".into(),
        schema_version: 1,
        public: [("age".into(), json!(34)), ("bio".into(), json!("reading"))].into(),
        private: [
            ("secret".into(), json!(true)),
            ("private_bio".into(), json!("secret text")),
        ]
        .into(),
    }
}
fn clean(_: &str) -> cshm::ContactCheck {
    cshm::ContactCheck::Clear
}
struct Auth {
    community: String,
    member: String,
    keys: csgn::KeyRing,
    settings: Vec<u8>,
    schema: Vec<u8>,
    revocations: Vec<u8>,
    credential: Vec<u8>,
}
impl Auth {
    fn new(draft: &mut Draft, device: &Device) -> Self {
        Self::named(draft, device, "garden", "alice")
    }
    fn named(draft: &mut Draft, device: &Device, community: &str, member: &str) -> Self {
        let mut definition = schema();
        definition.community = community.into();
        let pins = draft
            .prepare_pins(&definition, &clean, &mut SystemEntropy)
            .unwrap();
        let mut issuer =
            Signer::new(community, SecretKey::from_seed(&mut [11; 32]), 1000, 10000).unwrap();
        let credential = cgrd::Credential {
            purpose: cgrd::CredentialPurpose::CommunityCredentialV2,
            issuance_action: ISSUANCE_ACTION.into(),
            community: community.into(),
            member: member.into(),
            handle: "mountain".into(),
            schema_version: 1,
            policy_epoch: 2,
            gates: vec![],
            pins,
            devices: vec![device.public_key()],
        };
        let mut sign = |kind, value: serde_json::Value| {
            issuer
                .sign(kind, &serde_json::to_vec(&value).unwrap(), 1000, 2000)
                .unwrap()
        };
        let credential = sign(Kind::Credential, serde_json::to_value(&credential).unwrap());
        let schema = sign(
            Kind::SchemaSnapshot,
            json!({"community":community,"revision":1,"policy_epoch":2,"content":definition}),
        );
        let settings = sign(
            Kind::SettingsSnapshot,
            json!({"community":community,"revision":1,"policy_epoch":2,"content":{"action/admission":{"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]}}}),
        );
        let revocations = sign(
            Kind::RevocationListSnapshot,
            json!({"community":community,"revision":1,"policy_epoch":2,"content":{"members":[],"devices":[]}}),
        );
        Self {
            community: community.into(),
            member: member.into(),
            keys: issuer.key_ring().clone(),
            settings,
            schema,
            revocations,
            credential,
        }
    }
    fn validation(&self) -> cpfl::Validation<'_> {
        cpfl::Validation {
            policy: self.policy(),
            signed_schema: &self.schema,
            contact: &clean,
        }
    }
    fn policy(&self) -> cgrd::PublishedPolicy<'_> {
        cgrd::PublishedPolicy {
            policy: cgrd::Policy {
                community: &self.community,
                expected_issuance_action: ISSUANCE_ACTION,
                keys: &self.keys,
                now: 1100,
                minimum_epoch: 2,
                minimum_settings_revision: 1,
                minimum_schema_revision: 1,
                maximum_snapshot_age: 300,
                settings: &self.settings,
            },
            revocations: &self.revocations,
            minimum_revocations_revision: 1,
        }
    }
}
// Test-only original device material; production uses Keys::with_profile_custody.
struct EnvelopeKeys {
    hpke: [u8; 32],
    community: String,
    member: String,
    device: [u8; 32],
}
impl EnvelopeKeys {
    fn new(device: &Device, auth: &Auth) -> Self {
        let expanded = Sha512::digest(device.0.as_bytes());
        Self {
            hpke: expanded[..32].try_into().unwrap(),
            community: auth.community.clone(),
            member: auth.member.clone(),
            device: device.public_key(),
        }
    }
    fn custody(&self) -> cnvl::Custodian<'_> {
        cnvl::Custodian::from_keys(
            &self.hpke,
            &[44; 32],
            &self.community,
            &self.member,
            self.device,
        )
        .unwrap()
    }
}
async fn prepare(
    draft: &Draft,
    auth: &Auth,
    device: &mut Device,
    _cipher: &StoreCipher,
    version: u64,
    revision: u64,
) -> Result<cpfl::Candidate, Error> {
    let keys = EnvelopeKeys::new(device, auth);
    draft.prepare_publication(
        &auth.credential,
        &auth.policy(),
        &auth.schema,
        revision,
        1,
        vec![1, 2],
        version,
        device,
        &keys.custody(),
        &PortableCodec,
        &clean,
    )
}
// Re-sign the actual authenticated fixture payload; never replace verification.
fn resign(
    auth: &Auth,
    bytes: &[u8],
    kind: Kind,
    issued: u64,
    until: u64,
    gate: Option<u64>,
) -> Vec<u8> {
    let envelope = auth.keys.verify(bytes, kind, 1100).unwrap();
    let mut body: serde_json::Value = serde_json::from_slice(envelope.payload()).unwrap();
    if let Some(expiry) = gate {
        body["gates"] = json!([{"gate":"optional","provider":"test","valid_until":expiry}]);
    }
    Signer::new(
        &auth.community,
        SecretKey::from_seed(&mut [11; 32]),
        1000,
        10000,
    )
    .unwrap()
    .sign(kind, &serde_json::to_vec(&body).unwrap(), issued, until)
    .unwrap()
}
shared!(verified_authority_ends_at_authenticated_deadlines, {
    // Credential, settings, schema, revocations and each snapshot age can
    // independently be the earliest deadline. Equality at maximum age is valid.
    for case in 0..9 {
        let mut draft = Draft::new("alice".into(), profile()).unwrap();
        let mut device = device();
        let mut auth = Auth::new(&mut draft, &device);
        let expected = match case {
            0 => {
                auth.credential =
                    resign(&auth, &auth.credential, Kind::Credential, 1000, 1200, None);
                1200
            }
            1 => {
                auth.settings = resign(
                    &auth,
                    &auth.settings,
                    Kind::SettingsSnapshot,
                    1000,
                    1201,
                    None,
                );
                1201
            }
            2 => {
                auth.schema = resign(&auth, &auth.schema, Kind::SchemaSnapshot, 1000, 1202, None);
                1202
            }
            3 => {
                auth.revocations = resign(
                    &auth,
                    &auth.revocations,
                    Kind::RevocationListSnapshot,
                    1000,
                    1203,
                    None,
                );
                1203
            }
            4 => {
                auth.credential = resign(
                    &auth,
                    &auth.credential,
                    Kind::Credential,
                    1000,
                    1199,
                    Some(1199),
                );
                1199
            }
            5 => 1301,
            6 => {
                auth.settings = resign(
                    &auth,
                    &auth.settings,
                    Kind::SettingsSnapshot,
                    1000,
                    2000,
                    None,
                );
                auth.schema = resign(&auth, &auth.schema, Kind::SchemaSnapshot, 1001, 2000, None);
                auth.revocations = resign(
                    &auth,
                    &auth.revocations,
                    Kind::RevocationListSnapshot,
                    1001,
                    2000,
                    None,
                );
                1301
            }
            7 => {
                auth.settings = resign(
                    &auth,
                    &auth.settings,
                    Kind::SettingsSnapshot,
                    1001,
                    2000,
                    None,
                );
                auth.revocations = resign(
                    &auth,
                    &auth.revocations,
                    Kind::RevocationListSnapshot,
                    1001,
                    2000,
                    None,
                );
                1301
            }
            _ => {
                auth.settings = resign(
                    &auth,
                    &auth.settings,
                    Kind::SettingsSnapshot,
                    1001,
                    2000,
                    None,
                );
                auth.schema = resign(&auth, &auth.schema, Kind::SchemaSnapshot, 1001, 2000, None);
                1301
            }
        };
        let cipher = cipher();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
            .await
            .unwrap();
        prepare(&draft, &auth, &mut device, &cipher, 0, 1)
            .await
            .unwrap()
            .commit_publication(&mut store, auth.validation(), [1; 32], vec![])
            .await
            .unwrap();
        let publication = Publication::from_bytes(&store.load_pending().unwrap()[0].bytes).unwrap();
        let mut policy = auth.policy();
        let verified =
            cpfl::verify_publication(&publication, &policy, &auth.schema, 1, &clean).unwrap();
        assert_eq!(verified.authority_until(), expected);
        policy.policy.now = expected - 1;
        assert_eq!(
            cpfl::verify_publication(&publication, &policy, &auth.schema, 1, &clean)
                .unwrap()
                .authority_until(),
            expected
        );
        policy.policy.now = expected;
        assert!(matches!(
            cpfl::verify_publication(&publication, &policy, &auth.schema, 1, &clean),
            Err(Error::Admission)
        ));
    }
    // Current Guard requires every included gate to cover the signed credential,
    // even when the action does not require it. Profile must preserve that rule.
    for gate in [1099, 1100, 1199] {
        let mut draft = Draft::new("alice".into(), profile()).unwrap();
        let mut device = device();
        let mut auth = Auth::new(&mut draft, &device);
        auth.credential = resign(
            &auth,
            &auth.credential,
            Kind::Credential,
            1000,
            1200,
            Some(gate),
        );
        assert!(matches!(
            prepare(&draft, &auth, &mut device, &cipher(), 0, 1).await,
            Err(Error::Admission)
        ));
    }
});

shared!(signed_projection_checkpoint_and_peer_round_trip, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    draft
        .set_rules(vec![
            cgrd::Rule::NumberRange {
                field: "age".into(),
                min: "18".into(),
                max: "70".into(),
            },
            cgrd::Rule::Block {
                member: "blocked".into(),
            },
        ])
        .unwrap();
    let cipher = cipher();
    let backend = cwst::backend::Memory::new();
    let mut store = cwst::Store::create(backend.clone(), &cipher, "garden")
        .await
        .unwrap();
    let candidate = prepare(&draft, &auth, &mut device, &cipher, 0, 1)
        .await
        .unwrap();
    assert!(store.load_pending().unwrap().is_empty());
    candidate
        .commit_publication(
            &mut store,
            auth.validation(),
            [1; 32],
            vec![cwst::Change::Put {
                owner: "contacts",
                key: b"blocks",
                value: b"opaque journal",
            }],
        )
        .await
        .unwrap();
    let wire = store.load_pending().unwrap()[0].bytes.clone();
    let publication = Publication::from_bytes(&wire).unwrap();
    assert_eq!(publication.to_bytes().unwrap(), wire);
    let verified =
        cpfl::verify_publication(&publication, &auth.policy(), &auth.schema, 1, &clean).unwrap();
    assert_eq!(verified.transcript().revision, 1);
    let _ = verified.participant();
    assert_eq!(
        verified.public(),
        &cshm::PublicProfile::from(draft.profile())
    );
    let public: cgrd::Bundle = serde_json::from_slice(&publication.public_bundle).unwrap();
    let body: cgrd::BundleContent = serde_json::from_slice(&public.payload).unwrap();
    assert_eq!(body.hpke_key, Some(device.hpke_public_key().unwrap()));
    let recipient = cgrd::verify_recipient_with_contact(
        &public,
        &body.member,
        &auth.policy(),
        &auth.schema,
        &clean,
    )
    .unwrap();
    assert_eq!(recipient.hpke_key(), &device.hpke_public_key().unwrap());
    let mut replaced = body.clone();
    replaced.hpke_key = Some([87; 32]);
    let tampered = cgrd::Bundle {
        payload: serde_json::to_vec(&replaced).unwrap(),
        signature: public.signature.clone(),
    };
    assert!(
        cgrd::verify_recipient_with_contact(
            &tampered,
            &body.member,
            &auth.policy(),
            &auth.schema,
            &clean,
        )
        .is_err()
    );
    assert!(matches!(body.profile, cgrd::Profile::Public(_)));
    assert_eq!(body.openings.len(), 1);
    assert_eq!(body.openings[0].field, "age");
    let envelope_keys = EnvelopeKeys::new(&device, &auth);
    let read_key = envelope_keys
        .custody()
        .restore(
            verified.context(),
            &cnvl::WrappedReadKey::from_bytes(
                store
                    .read("profile.keys", &1u64.to_be_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let full = cpfl::open_full(
        &publication,
        &verified,
        &read_key,
        &PortableCodec,
        &auth.policy(),
        &auth.schema,
        &clean,
    )
    .unwrap();
    assert_eq!(full, *draft.profile());
    store.ack_output(1, [2; 32], [1; 32]).await.unwrap();
    store.lock();
    let mut store = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
    assert_eq!(
        store.read("profile", b"publication").unwrap().unwrap(),
        wire
    );
    let restored =
        Draft::from_checkpoint(store.read("profile", b"draft").unwrap().unwrap()).unwrap();
    assert_eq!(restored.profile(), draft.profile());
    let second = prepare(&restored, &auth, &mut device, &cipher, 2, 2)
        .await
        .unwrap();
    second
        .commit_publication(&mut store, auth.validation(), [3; 32], vec![])
        .await
        .unwrap();
    assert!(
        store
            .read("profile.keys", &1u64.to_be_bytes())
            .unwrap()
            .is_some()
    );
    assert!(
        store
            .read("profile.keys", &2u64.to_be_bytes())
            .unwrap()
            .is_some()
    );
    assert_eq!(format!("{draft:?}"), "Draft([redacted])");
    assert_eq!(format!("{publication:?}"), "Publication([redacted])");
    assert_eq!(Error::Admission.to_string(), "profile: Admission");
});
shared!(restricted_edits_require_fresh_accepted_pins_and_fences, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    let before = draft
        .prepare_pins(&schema(), &clean, &mut SystemEntropy)
        .unwrap();
    let same = draft
        .prepare_pins(&schema(), &clean, &mut SystemEntropy)
        .unwrap();
    assert_eq!(before[0].fingerprint, same[0].fingerprint);
    let mut changed = draft.profile().clone();
    changed.public.insert("age".into(), json!(35));
    draft.edit(changed).unwrap();
    let after = draft
        .prepare_pins(&schema(), &clean, &mut SystemEntropy)
        .unwrap();
    assert_ne!(before[0].fingerprint, after[0].fingerprint);
    assert!(matches!(
        prepare(&draft, &auth, &mut device, &cipher(), 0, 1).await,
        Err(Error::Admission)
    ));
    let fresh = Auth::new(&mut draft, &device);
    let cipher = cipher();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
        .await
        .unwrap();
    let candidate = prepare(&draft, &fresh, &mut device, &cipher, 0, 1)
        .await
        .unwrap();
    store.commit(0, [9; 32], &[], &[]).await.unwrap();
    assert_eq!(
        candidate
            .commit_publication(&mut store, fresh.validation(), [1; 32], vec![])
            .await
            .unwrap_err(),
        Error::Storage
    );
    assert!(store.load_pending().unwrap().is_empty());
    let candidate = prepare(&draft, &fresh, &mut device, &cipher, 1, 1)
        .await
        .unwrap();
    assert_eq!(
        candidate
            .commit_publication(
                &mut store,
                fresh.validation(),
                [1; 32],
                vec![cwst::Change::Delete {
                    owner: "profile",
                    key: b"draft"
                }]
            )
            .await
            .unwrap_err(),
        Error::Invalid
    );
});
shared!(outer_tampering_and_stale_policy_refuse, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    let cipher = cipher();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
        .await
        .unwrap();
    prepare(&draft, &auth, &mut device, &cipher, 0, 1)
        .await
        .unwrap()
        .commit_publication(&mut store, auth.validation(), [1; 32], vec![])
        .await
        .unwrap();
    let wire = store.load_pending().unwrap()[0].bytes.clone();
    for case in 0..12 {
        let mut publication = Publication::from_bytes(&wire).unwrap();
        let mut transcript: Transcript = serde_json::from_slice(&publication.transcript).unwrap();
        match case {
            0 => transcript.version = 2,
            1 => transcript.revision = 0,
            2 => transcript.key_generation = 0,
            3 => transcript.community = "other".into(),
            4 => transcript.member = "other".into(),
            5 => transcript.device = [8; 32],
            6 => transcript.schema_revision = 2,
            7 => {
                transcript.rules = vec![cgrd::Rule::Block {
                    member: "other".into(),
                }]
            }
            8 => transcript.reachability = vec![1; cpfl::MAX_REACHABILITY_BYTES + 1],
            9 => publication.public_bundle[0] ^= 1,
            10 => publication.envelope[0] ^= 1,
            _ => publication.signature[0] ^= 1,
        }
        publication.transcript = serde_json::to_vec(&transcript).unwrap();
        assert!(
            cpfl::verify_publication(&publication, &auth.policy(), &auth.schema, 1, &clean)
                .is_err()
        );
    }
    let publication = Publication::from_bytes(&wire).unwrap();
    assert!(matches!(
        cpfl::verify_publication(&publication, &auth.policy(), &auth.schema, 2, &clean),
        Err(Error::Invalid)
    ));
    let mut expired = auth.policy();
    expired.policy.now = 2000;
    assert!(matches!(
        cpfl::verify_publication(&publication, &expired, &auth.schema, 1, &clean),
        Err(Error::Admission)
    ));
    assert!(Publication::from_bytes(b"{").is_err());
    assert!(Publication::from_bytes(&vec![0; cpfl::MAX_PROFILE_BYTES + 1]).is_err());
});
shared!(typed_schema_contact_and_codec_bounds, {
    let draft = Draft::new("alice".into(), profile()).unwrap();
    assert_eq!(
        draft
            .validate(&schema(), &|_| cshm::ContactCheck::Unavailable)
            .unwrap_err(),
        Error::Schema
    );
    for value in [json!(17), json!(121), json!("34"), json!(34.5)] {
        let mut bad = profile();
        bad.public.insert("age".into(), value);
        assert!(
            Draft::new("alice".into(), bad)
                .unwrap()
                .validate(&schema(), &clean)
                .is_err()
        );
    }
    let mut wrong_choice = profile();
    wrong_choice
        .public
        .insert("hobby".into(), json!("undeclared"));
    assert!(
        Draft::new("alice".into(), wrong_choice)
            .unwrap()
            .validate(&schema(), &clean)
            .is_err()
    );
    let mut wrong_location = profile();
    wrong_location
        .public
        .insert("place".into(), json!({"lat":91,"lon":0}));
    assert!(
        Draft::new("alice".into(), wrong_location)
            .unwrap()
            .validate(&schema(), &clean)
            .is_err()
    );
    let input = b"  { \"signed\": \"exact bytes survive compression\" }  ";
    let packed = PortableCodec.pack(input).unwrap();
    assert_eq!(
        packed.len(),
        cprz_pad::padded_len(cprz::portable::compress(input).unwrap().len())
    );
    assert_eq!(
        PortableCodec
            .unpack(&packed, cpfl::MAX_PROFILE_BYTES)
            .unwrap()
            .as_slice(),
        input
    );
    assert!(PortableCodec.unpack(&packed, 1).is_err());
    assert!(
        PortableCodec
            .unpack(b"short", cpfl::MAX_PROFILE_BYTES)
            .is_err()
    );
    assert!(
        PortableCodec
            .pack(&vec![0; cpfl::MAX_PROFILE_BYTES + 1])
            .is_err()
    );
    assert!(
        PortableCodec
            .unpack(
                &vec![0; cnvl::MAX_PLAINTEXT_BYTES + 1],
                cpfl::MAX_PROFILE_BYTES
            )
            .is_err()
    );
    assert!(
        PortableCodec
            .unpack(&packed, cpfl::MAX_PROFILE_BYTES + 1)
            .is_err()
    );
});

shared!(draft_and_publication_resource_refusals, {
    assert!(matches!(
        Draft::new("".into(), profile()),
        Err(Error::Invalid)
    ));
    assert!(matches!(
        Draft::new("m".repeat(257), profile()),
        Err(Error::Invalid)
    ));
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut foreign = profile();
    foreign.community = "other".into();
    assert_eq!(draft.edit(foreign).unwrap_err(), Error::Invalid);
    let mut large = profile();
    large
        .public
        .insert("bio".into(), json!("x".repeat(cpfl::MAX_PROFILE_BYTES)));
    assert_eq!(draft.edit(large).unwrap_err(), Error::Limit);
    assert_eq!(
        draft
            .set_rules(vec![
                cgrd::Rule::Block {
                    member: "peer".into()
                };
                cgrd::MAX_ITEMS + 1
            ])
            .unwrap_err(),
        Error::Limit
    );
    assert!(Draft::from_checkpoint(b"malformed").is_err());
    let mut definition = schema();
    let mut optional = definition.private[0].clone();
    optional.id = "optional".into();
    optional.required = false;
    definition.private.push(optional);
    assert_eq!(
        draft
            .prepare_pins(&definition, &clean, &mut SystemEntropy)
            .unwrap()
            .len(),
        2
    );
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    let cipher = cipher();
    for (revision, generation, reachability) in [
        (0, 1, vec![]),
        (1, 0, vec![]),
        (1, 1, vec![0; cpfl::MAX_REACHABILITY_BYTES + 1]),
    ] {
        assert!(matches!(
            draft.prepare_publication(
                &auth.credential,
                &auth.policy(),
                &auth.schema,
                revision,
                generation,
                reachability,
                0,
                &mut device,
                &EnvelopeKeys::new(&Device(SigningKey::from_bytes(&[22; 32])), &auth).custody(),
                &PortableCodec,
                &clean
            ),
            Err(Error::Invalid)
        ));
    }
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
        .await
        .unwrap();
    prepare(&draft, &auth, &mut device, &cipher, 0, 1)
        .await
        .unwrap()
        .commit_publication(&mut store, auth.validation(), [1; 32], vec![])
        .await
        .unwrap();
    let repeated = prepare(&draft, &auth, &mut device, &cipher, 1, 1)
        .await
        .unwrap();
    assert_eq!(
        repeated
            .commit_publication(&mut store, auth.validation(), [2; 32], vec![])
            .await
            .unwrap_err(),
        Error::Invalid
    );
    let mut other = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "other")
        .await
        .unwrap();
    let wrong = prepare(&draft, &auth, &mut device, &cipher, 0, 2)
        .await
        .unwrap();
    assert_eq!(
        wrong
            .commit_publication(&mut other, auth.validation(), [2; 32], vec![])
            .await
            .unwrap_err(),
        Error::Invalid
    );
    let mut publication = Publication::from_bytes(&store.load_pending().unwrap()[0].bytes).unwrap();
    publication.signature = vec![0; cpfl::MAX_PROFILE_BYTES + 1];
    assert_eq!(publication.to_bytes().unwrap_err(), Error::Limit);
    publication.signature = vec![0; 64];
    publication.envelope = vec![1; cpfl::MAX_PROFILE_BYTES];
    assert_eq!(publication.to_bytes().unwrap_err(), Error::Limit);
});

async fn fixture_publication(
    community: &str,
    member: &str,
    seed: u8,
) -> (
    Auth,
    Device,
    Publication,
    cnvl::WrappedReadKey,
    cgrd::Bundle,
) {
    let mut answers = profile();
    answers.community = community.into();
    let mut draft = Draft::new(member.into(), answers).unwrap();
    let mut device = Device(SigningKey::from_bytes(&[seed; 32]));
    let auth = Auth::named(&mut draft, &device, community, member);
    let cipher = cipher();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, community)
        .await
        .unwrap();
    prepare(&draft, &auth, &mut device, &cipher, 0, 1)
        .await
        .unwrap()
        .commit_publication(&mut store, auth.validation(), [1; 32], vec![])
        .await
        .unwrap();
    let publication = Publication::from_bytes(&store.load_pending().unwrap()[0].bytes).unwrap();
    let verified =
        cpfl::verify_publication(&publication, &auth.policy(), &auth.schema, 1, &clean).unwrap();
    let envelope_keys = EnvelopeKeys::new(&device, &auth);
    let key = envelope_keys
        .custody()
        .restore(
            verified.context(),
            &cnvl::WrappedReadKey::from_bytes(
                store
                    .read("profile.keys", &1u64.to_be_bytes())
                    .unwrap()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap();
    let packed = cnvl::open(
        &cnvl::Envelope::from_bytes(&publication.envelope).unwrap(),
        &key,
        &verified.context(),
    )
    .unwrap();
    let full = serde_json::from_slice(
        &PortableCodec
            .unpack(&packed, cpfl::MAX_PROFILE_BYTES)
            .unwrap(),
    )
    .unwrap();
    let wrapped = key.wrap().unwrap();
    (auth, device, publication, wrapped, full)
}
fn resign_publication(publication: &mut Publication, device: &mut Device) {
    let mut transcript: Transcript = serde_json::from_slice(&publication.transcript).unwrap();
    transcript.public_digest = *blake3::hash(&publication.public_bundle).as_bytes();
    transcript.encrypted_digest = *blake3::hash(&publication.envelope).as_bytes();
    publication.transcript = serde_json::to_vec(&transcript).unwrap();
    publication.signature = device
        .sign(&cpfl::publication_binding(&publication.transcript))
        .unwrap()
        .to_vec();
}
fn reseal<'key>(
    custody: &cnvl::Custodian<'key>,
    publication: &mut Publication,
    device: &mut Device,
    context: cnvl::Context,
    full: &cgrd::Bundle,
) -> cnvl::ReadKey<'key> {
    let packed = PortableCodec
        .pack(&serde_json::to_vec(full).unwrap())
        .unwrap();
    let (envelope, key) = custody.seal(context, &packed).unwrap();
    publication.envelope = envelope.to_bytes().unwrap();
    resign_publication(publication, device);
    key
}
shared!(full_presentations_cannot_be_spliced_or_relabelled, {
    let (auth, mut device, publication, wrapped, full) =
        fixture_publication("garden", "alice", 22).await;
    let original = publication.to_bytes().unwrap();
    let verified =
        cpfl::verify_publication(&publication, &auth.policy(), &auth.schema, 1, &clean).unwrap();
    let envelope_keys = EnvelopeKeys::new(&device, &auth);
    let custody = envelope_keys.custody();
    let key = custody.restore(verified.context(), &wrapped).unwrap();
    for field in 0..2 {
        let mut tampered = Publication::from_bytes(&original).unwrap();
        if field == 0 {
            tampered.public_bundle[0] ^= 1;
        } else {
            tampered.envelope[0] ^= 1;
        }
        assert!(matches!(
            cpfl::open_full(
                &tampered,
                &verified,
                &key,
                &PortableCodec,
                &auth.policy(),
                &auth.schema,
                &clean
            ),
            Err(Error::Invalid)
        ));
    }
    for (community, member, seed) in [
        ("other", "alice", 22),
        ("garden", "bob", 22),
        ("garden", "alice", 23),
    ] {
        let (other_auth, _, _, _, other_full) = fixture_publication(community, member, seed).await;
        let mut substituted = Publication::from_bytes(&original).unwrap();
        let other_key = reseal(
            &custody,
            &mut substituted,
            &mut device,
            verified.context(),
            &other_full,
        );
        let bound = cpfl::verify_publication(&substituted, &auth.policy(), &auth.schema, 1, &clean)
            .unwrap();
        assert!(matches!(
            cpfl::open_full(
                &substituted,
                &bound,
                &other_key,
                &PortableCodec,
                &other_auth.policy(),
                &other_auth.schema,
                &clean
            ),
            Err(Error::Invalid)
        ));
    }
    let mut substituted = Publication::from_bytes(&original).unwrap();
    let public: cgrd::Bundle = serde_json::from_slice(&substituted.public_bundle).unwrap();
    let wrong_scope_key = reseal(
        &custody,
        &mut substituted,
        &mut device,
        verified.context(),
        &public,
    );
    let bound =
        cpfl::verify_publication(&substituted, &auth.policy(), &auth.schema, 1, &clean).unwrap();
    assert!(matches!(
        cpfl::open_full(
            &substituted,
            &bound,
            &wrong_scope_key,
            &PortableCodec,
            &auth.policy(),
            &auth.schema,
            &clean
        ),
        Err(Error::Invalid)
    ));
    let mut edited = full.clone();
    let mut body: cgrd::BundleContent = serde_json::from_slice(&edited.payload).unwrap();
    let cgrd::Profile::Full(ref mut answers) = body.profile else {
        panic!("full fixture")
    };
    answers
        .public
        .insert("bio".into(), json!("changed public projection"));
    edited.payload = serde_json::to_vec(&body).unwrap();
    edited.signature = device
        .sign(&cgrd::binding_bytes(&edited.payload))
        .unwrap()
        .to_vec();
    let edited_key = reseal(
        &custody,
        &mut substituted,
        &mut device,
        verified.context(),
        &edited,
    );
    let bound =
        cpfl::verify_publication(&substituted, &auth.policy(), &auth.schema, 1, &clean).unwrap();
    assert!(matches!(
        cpfl::open_full(
            &substituted,
            &bound,
            &edited_key,
            &PortableCodec,
            &auth.policy(),
            &auth.schema,
            &clean
        ),
        Err(Error::Invalid)
    ));
    edited.signature[0] ^= 1;
    let edited_key = reseal(
        &custody,
        &mut substituted,
        &mut device,
        verified.context(),
        &edited,
    );
    let bound =
        cpfl::verify_publication(&substituted, &auth.policy(), &auth.schema, 1, &clean).unwrap();
    assert!(matches!(
        cpfl::open_full(
            &substituted,
            &bound,
            &edited_key,
            &PortableCodec,
            &auth.policy(),
            &auth.schema,
            &clean
        ),
        Err(Error::Admission)
    ));
    let mut wrong_context = verified.context();
    wrong_context.owner = "other".into();
    let mut wrong_owner = EnvelopeKeys::new(&device, &auth);
    wrong_owner.member = "other".into();
    reseal(
        &wrong_owner.custody(),
        &mut substituted,
        &mut device,
        wrong_context,
        &full,
    );
    assert!(matches!(
        cpfl::verify_publication(&substituted, &auth.policy(), &auth.schema, 1, &clean),
        Err(Error::Invalid)
    ));
    substituted = Publication::from_bytes(&original).unwrap();
    substituted.public_bundle = serde_json::to_vec(&full).unwrap();
    resign_publication(&mut substituted, &mut device);
    assert!(matches!(
        cpfl::verify_publication(&substituted, &auth.policy(), &auth.schema, 1, &clean),
        Err(Error::Invalid)
    ));
});

shared!(delayed_commit_rechecks_current_admission_and_clock, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    let cipher = cipher();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
        .await
        .unwrap();
    for now in [1099, 2000] {
        let candidate = prepare(&draft, &auth, &mut device, &cipher, 0, 1)
            .await
            .unwrap();
        let mut current = auth.validation();
        current.policy.policy.now = now;
        assert_eq!(
            candidate
                .commit_publication(&mut store, current, [1; 32], vec![])
                .await
                .unwrap_err(),
            Error::Admission
        );
        assert_eq!(store.version().unwrap(), 0);
        assert!(store.load_pending().unwrap().is_empty());
    }
});

shared!(
    authorization_is_synchronous_and_the_write_is_fenced_afterwards,
    {
        let mut draft = Draft::new("alice".into(), profile()).unwrap();
        let mut device = device();
        let auth = Auth::new(&mut draft, &device);
        let cipher = cipher();
        let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
            .await
            .unwrap();
        // Stale policy is refused at the synchronous step, before any store access.
        let mut stale = auth.validation();
        stale.policy.policy.now = 1099;
        assert_eq!(
            prepare(&draft, &auth, &mut device, &cipher, 0, 1)
                .await
                .unwrap()
                .authorize(stale)
                .err(),
            Some(Error::Admission)
        );
        // The authorized candidate holds no policy borrow and commits in a later await.
        let authorized = prepare(&draft, &auth, &mut device, &cipher, 0, 1)
            .await
            .unwrap()
            .authorize(auth.validation())
            .unwrap();
        assert!(authorized.commit(&mut store, [1; 32], vec![]).await.is_ok());
        assert_eq!(store.load_pending().unwrap().len(), 1);
        // The store version fence still rejects a candidate prepared on an old version.
        let old = prepare(&draft, &auth, &mut device, &cipher, 0, 2)
            .await
            .unwrap()
            .authorize(auth.validation())
            .unwrap();
        assert_eq!(
            old.commit(&mut store, [2; 32], vec![]).await,
            Err(Error::Storage)
        );
    }
);

shared!(current_contact_check_covers_the_private_projection, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    let cipher = cipher();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
        .await
        .unwrap();
    let candidate = prepare(&draft, &auth, &mut device, &cipher, 0, 1)
        .await
        .unwrap();
    let current_contact = |text: &str| {
        if text == "secret text" {
            cshm::ContactCheck::Unavailable
        } else {
            cshm::ContactCheck::Clear
        }
    };
    let mut current = auth.validation();
    current.contact = &current_contact;
    assert_eq!(
        candidate
            .commit_publication(&mut store, current, [1; 32], vec![])
            .await
            .unwrap_err(),
        Error::Admission
    );
    assert_eq!(store.version().unwrap(), 0);
    assert!(store.load_pending().unwrap().is_empty());
});

shared!(unrelated_envelope_custody_never_releases_a_candidate, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    let mut wrong = EnvelopeKeys::new(&device, &auth);
    wrong.hpke[0] ^= 128;
    assert!(matches!(
        draft.prepare_publication(
            &auth.credential,
            &auth.policy(),
            &auth.schema,
            1,
            1,
            vec![],
            0,
            &mut device,
            &wrong.custody(),
            &PortableCodec,
            &clean,
        ),
        Err(Error::Crypto)
    ));
});

shared!(current_schema_rules_and_locked_storage_refuse, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    let cipher = cipher();
    assert!(matches!(
        draft.prepare_publication(
            &auth.credential,
            &auth.policy(),
            b"invalid signed schema",
            1,
            1,
            vec![],
            0,
            &mut device,
            &EnvelopeKeys::new(&Device(SigningKey::from_bytes(&[22; 32])), &auth).custody(),
            &PortableCodec,
            &clean,
        ),
        Err(Error::Admission)
    ));
    let candidate = prepare(&draft, &auth, &mut device, &cipher, 0, 1)
        .await
        .unwrap();
    let mut store = cwst::Store::create(cwst::backend::Memory::new(), &cipher, "garden")
        .await
        .unwrap();
    store.lock_in_place();
    assert_eq!(
        candidate
            .commit_publication(&mut store, auth.validation(), [1; 32], vec![])
            .await
            .unwrap_err(),
        Error::Storage
    );
    draft
        .set_rules(vec![cgrd::Rule::Block {
            member: String::new(),
        }])
        .unwrap();
    assert_eq!(
        draft.validate(&schema(), &clean).unwrap_err(),
        Error::Schema
    );
    let (auth, mut device, mut publication, _, _) =
        fixture_publication("garden", "alice", 22).await;
    let mut transcript: Transcript = serde_json::from_slice(&publication.transcript).unwrap();
    transcript.rules = vec![cgrd::Rule::Block {
        member: String::new(),
    }];
    publication.transcript = serde_json::to_vec(&transcript).unwrap();
    resign_publication(&mut publication, &mut device);
    assert!(matches!(
        cpfl::verify_publication(&publication, &auth.policy(), &auth.schema, 1, &clean),
        Err(Error::Schema)
    ));
});

// Link the maintained profiling runtime only into the instrumented test binary.
#[cfg(all(target_arch = "wasm32", owned_browser_coverage))]
#[wasm_bindgen_test::wasm_bindgen_test]
fn profiling_runtime_is_linked() {
    let _ = browser_coverage_runtime::__owned_test_module_signature();
}

shared!(
    committed_publication_uses_actual_store_and_revalidates_original_authority,
    {
        let mut draft = Draft::new("alice".into(), profile()).unwrap();
        let mut device = device();
        let auth = Auth::new(&mut draft, &device);
        let cipher = cipher();
        let backend = cwst::backend::Memory::new();
        let mut store = cwst::Store::create(backend.clone(), &cipher, "garden")
            .await
            .unwrap();
        let binding = ckmg::Binding::new("garden", "alice").unwrap();
        assert!(
            cpfl::load_current_committed(&store, &binding, auth.validation())
                .unwrap()
                .is_none()
        );
        prepare(&draft, &auth, &mut device, &cipher, 0, 1)
            .await
            .unwrap()
            .commit_publication(&mut store, auth.validation(), [31; 32], vec![])
            .await
            .unwrap();
        let wire = store.load_pending().unwrap()[0].bytes.clone();
        {
            let committed = cpfl::load_current_committed(&store, &binding, auth.validation())
                .unwrap()
                .unwrap();
            assert_eq!(committed.bytes(), wire);
            assert_eq!(committed.publication().to_bytes().unwrap(), wire);
            assert_eq!(committed.verified().transcript().member, "alice");
            assert_eq!(committed.verified().transcript().revision, 1);
            assert_eq!(committed.checkpoint(), 1);
        }
        assert!(matches!(
            cpfl::load_committed(&store, &binding, auth.validation(), 2),
            Err(Error::Invalid)
        ));
        for foreign in [
            ckmg::Binding::new("garden", "other").unwrap(),
            ckmg::Binding::new("other", "alice").unwrap(),
        ] {
            assert!(matches!(
                cpfl::load_current_committed(&store, &foreign, auth.validation()),
                Err(Error::Invalid)
            ));
        }
        let mut expired = auth.validation();
        expired.policy.policy.now = 2000;
        assert!(matches!(
            cpfl::load_current_committed(&store, &binding, expired),
            Err(Error::Admission)
        ));
        let mut no_detector = auth.validation();
        let unavailable = |_: &str| cshm::ContactCheck::Unavailable;
        no_detector.contact = &unavailable;
        assert!(cpfl::load_current_committed(&store, &binding, no_detector).is_err());
        store.ack_output(1, [32; 32], [31; 32]).await.unwrap();
        store.lock_in_place();
        assert!(matches!(
            cpfl::load_current_committed(&store, &binding, auth.validation()),
            Err(Error::Storage)
        ));
        let mut store = cwst::Store::open(backend, &cipher, "garden").await.unwrap();
        assert_eq!(
            cpfl::load_current_committed(&store, &binding, auth.validation())
                .unwrap()
                .unwrap()
                .bytes(),
            wire
        );
        prepare(&draft, &auth, &mut device, &cipher, 2, 2)
            .await
            .unwrap()
            .commit_publication(&mut store, auth.validation(), [33; 32], vec![])
            .await
            .unwrap();
        assert_eq!(
            cpfl::load_current_committed(&store, &binding, auth.validation())
                .unwrap()
                .unwrap()
                .verified()
                .transcript()
                .revision,
            2
        );
        store
            .commit(
                3,
                [34; 32],
                &[cwst::Change::Put {
                    owner: "profile",
                    key: b"publication",
                    value: b"malformed",
                }],
                &[],
            )
            .await
            .unwrap();
        assert!(matches!(
            cpfl::load_current_committed(&store, &binding, auth.validation()),
            Err(Error::Invalid)
        ));
    }
);

shared!(
    authenticated_hpke_release_keeps_keys_in_original_bound_custody,
    {
        let (alice_auth, alice_device, alice, alice_wrapped, _) =
            fixture_publication("garden", "alice", 22).await;
        let (bob_auth, mut bob_device, bob, _, _) = fixture_publication("garden", "bob", 23).await;
        let alice_keys = EnvelopeKeys::new(&alice_device, &alice_auth);
        let bob_keys = EnvelopeKeys::new(&bob_device, &bob_auth);
        let alice_custody = alice_keys.custody();
        let bob_custody = bob_keys.custody();
        let alice_bundle: cgrd::Bundle = serde_json::from_slice(&alice.public_bundle).unwrap();
        let bob_bundle: cgrd::Bundle = serde_json::from_slice(&bob.public_bundle).unwrap();
        let sender = cgrd::verify_recipient_with_contact(
            &alice_bundle,
            "alice",
            &alice_auth.policy(),
            &alice_auth.schema,
            &clean,
        )
        .unwrap();
        let recipient = cgrd::verify_recipient_with_contact(
            &bob_bundle,
            "bob",
            &bob_auth.policy(),
            &bob_auth.schema,
            &clean,
        )
        .unwrap();
        let verified =
            cpfl::verify_publication(&alice, &alice_auth.policy(), &alice_auth.schema, 1, &clean)
                .unwrap();
        let context = verified.context();
        let reader = alice_custody
            .restore(context.clone(), &alice_wrapped)
            .unwrap();
        let a_wire = alice.to_bytes().unwrap();
        let b_wire = bob.to_bytes().unwrap();
        let binding = cnvl::TransferContext::new(&a_wire, &b_wire, 1, 1, [9; 32]).unwrap();
        let transfer = reader.release(&sender, &recipient, &binding).unwrap();
        let wire = transfer.to_bytes().unwrap();
        let transfer = cnvl::KeyTransfer::from_bytes(&wire).unwrap();
        let received = bob_custody
            .receive(&transfer, &context, &sender, &recipient, &binding)
            .unwrap();
        let opened = cpfl::open_full(
            &alice,
            &verified,
            &received,
            &PortableCodec,
            &alice_auth.policy(),
            &alice_auth.schema,
            &clean,
        )
        .unwrap();
        assert_eq!(opened, profile());
        // Recipient persistence belongs to recipient custody; the original sender
        // cannot reopen it using even the same test storage bytes and another member.
        let received_wrapped = received.wrap().unwrap();
        assert!(
            alice_custody
                .restore(context.clone(), &received_wrapped)
                .is_err()
        );
        let reopened = bob_custody
            .restore(context.clone(), &received_wrapped)
            .unwrap();
        assert!(reopened.release(&recipient, &sender, &binding).is_err());
        assert!(
            alice_custody
                .receive(&transfer, &context, &sender, &recipient, &binding)
                .is_err()
        );
        for changed in [
            cnvl::TransferContext::new(&a_wire, &b_wire, 1, 1, [10; 32]).unwrap(),
            cnvl::TransferContext::new(&b_wire, &a_wire, 1, 1, [9; 32]).unwrap(),
            cnvl::TransferContext::new(&a_wire, &b_wire, 2, 1, [9; 32]).unwrap(),
            cnvl::TransferContext::new(&a_wire, &b_wire, 1, 2, [9; 32]).unwrap(),
        ] {
            assert!(
                bob_custody
                    .receive(&transfer, &context, &sender, &recipient, &changed)
                    .is_err()
            );
        }
        for field in ["enc", "ciphertext"] {
            let mut changed: serde_json::Value = serde_json::from_slice(&wire).unwrap();
            changed[field][0] = json!(changed[field][0].as_u64().unwrap() ^ 1);
            let altered =
                cnvl::KeyTransfer::from_bytes(&serde_json::to_vec(&changed).unwrap()).unwrap();
            assert!(
                bob_custody
                    .receive(&altered, &context, &sender, &recipient, &binding)
                    .is_err()
            );
        }
        let mut body: cgrd::BundleContent = serde_json::from_slice(&bob_bundle.payload).unwrap();
        let mut low_order = [0; 32];
        low_order[0] = 1;
        body.hpke_key = Some(low_order);
        let payload = serde_json::to_vec(&body).unwrap();
        let low_order_bundle = cgrd::Bundle {
            signature: bob_device
                .sign(&cgrd::binding_bytes(&payload))
                .unwrap()
                .to_vec(),
            payload,
        };
        let low_order_recipient = cgrd::verify_recipient_with_contact(
            &low_order_bundle,
            "bob",
            &bob_auth.policy(),
            &bob_auth.schema,
            &clean,
        )
        .unwrap();
        assert!(
            reader
                .release(&sender, &low_order_recipient, &binding)
                .is_err()
        );
        let mut expired = alice_auth.policy();
        expired.policy.now = 2000;
        assert!(
            cgrd::verify_recipient_with_contact(
                &alice_bundle,
                "alice",
                &expired,
                &alice_auth.schema,
                &clean
            )
            .is_err()
        );
        // HPKE is stateless: Exchange MUST fence duplicate nonce adoption through
        // its actual Store CAS/receipt. This crypto vector does not claim that gate.
        assert!(
            bob_custody
                .receive(&transfer, &context, &sender, &recipient, &binding)
                .is_ok()
        );
    }
);
