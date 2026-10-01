//! Real issuer/device signatures, Guard, pins, Brotli/Padme and encrypted checkpoints.
//! Fixture issuer/device custody is never claimed as a production G3 adapter.
use ckmg::{
    SystemEntropy,
    passkey::{PrfOutput, StoreCipher, store_cipher},
};
use cpfl::{DeviceSigner, Draft, Error, PortableCodec, ProfileCodec, Publication, Transcript};
use csgn::{Kind, SecretKey, Signer};
use ed25519_dalek::{Signer as _, SigningKey};
use serde_json::json;

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
            action: "admission",
        }
    }
}
async fn prepare(
    draft: &Draft,
    auth: &Auth,
    device: &mut Device,
    cipher: &StoreCipher,
    version: u64,
    revision: u64,
) -> Result<cpfl::Candidate, Error> {
    draft.prepare_publication(
        &auth.credential,
        &auth.policy(),
        &auth.schema,
        revision,
        1,
        vec![1, 2],
        version,
        device,
        cipher,
        &PortableCodec,
        &mut SystemEntropy,
        &clean,
    )
}
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
    assert!(matches!(body.profile, cgrd::Profile::Public(_)));
    assert_eq!(body.openings.len(), 1);
    assert_eq!(body.openings[0].field, "age");
    let read_key = cnvl::ReadKey::unwrap(
        &cipher,
        verified.context(),
        store
            .read("profile.keys", &1u64.to_be_bytes())
            .unwrap()
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
                &cipher,
                &PortableCodec,
                &mut SystemEntropy,
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
) -> (Auth, Device, Publication, cnvl::ReadKey, cgrd::Bundle) {
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
    let key = cnvl::ReadKey::unwrap(
        &cipher,
        verified.context(),
        store
            .read("profile.keys", &1u64.to_be_bytes())
            .unwrap()
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
    (auth, device, publication, key, full)
}
fn resign(publication: &mut Publication, device: &mut Device) {
    let mut transcript: Transcript = serde_json::from_slice(&publication.transcript).unwrap();
    transcript.public_digest = *blake3::hash(&publication.public_bundle).as_bytes();
    transcript.encrypted_digest = *blake3::hash(&publication.envelope).as_bytes();
    publication.transcript = serde_json::to_vec(&transcript).unwrap();
    publication.signature = device
        .sign(&cpfl::publication_binding(&publication.transcript))
        .unwrap()
        .to_vec();
}
fn reseal(
    publication: &mut Publication,
    device: &mut Device,
    context: cnvl::Context,
    full: &cgrd::Bundle,
) -> cnvl::ReadKey {
    let packed = PortableCodec
        .pack(&serde_json::to_vec(full).unwrap())
        .unwrap();
    let (envelope, key) = cnvl::seal(
        cnvl::SealKey::generate(&mut SystemEntropy).unwrap(),
        context,
        &packed,
        &mut SystemEntropy,
    )
    .unwrap();
    publication.envelope = envelope.to_bytes().unwrap();
    resign(publication, device);
    key
}
shared!(full_presentations_cannot_be_spliced_or_relabelled, {
    let (auth, mut device, publication, key, full) =
        fixture_publication("garden", "alice", 22).await;
    let original = publication.to_bytes().unwrap();
    let verified =
        cpfl::verify_publication(&publication, &auth.policy(), &auth.schema, 1, &clean).unwrap();
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
    let wrong_scope_key = reseal(&mut substituted, &mut device, verified.context(), &public);
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
    let edited_key = reseal(&mut substituted, &mut device, verified.context(), &edited);
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
    let edited_key = reseal(&mut substituted, &mut device, verified.context(), &edited);
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
    reseal(&mut substituted, &mut device, wrong_context, &full);
    assert!(matches!(
        cpfl::verify_publication(&substituted, &auth.policy(), &auth.schema, 1, &clean),
        Err(Error::Invalid)
    ));
    substituted = Publication::from_bytes(&original).unwrap();
    substituted.public_bundle = serde_json::to_vec(&full).unwrap();
    resign(&mut substituted, &mut device);
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

/// Fail only the external entropy source; all preceding crypto is real.
struct FailEntropy(usize);
impl ckmg::Entropy for FailEntropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ckmg::Error> {
        if self.0 == 0 {
            return Err(ckmg::Error::Unavailable);
        }
        self.0 -= 1;
        ckmg::Entropy::fill(&mut SystemEntropy, bytes)
    }
}
shared!(envelope_entropy_failures_never_release_a_candidate, {
    let mut draft = Draft::new("alice".into(), profile()).unwrap();
    let mut device = device();
    let auth = Auth::new(&mut draft, &device);
    for fail_after in 0..3 {
        let result = draft.prepare_publication(
            &auth.credential,
            &auth.policy(),
            &auth.schema,
            1,
            1,
            vec![],
            0,
            &mut device,
            &cipher(),
            &PortableCodec,
            &mut FailEntropy(fail_after),
            &clean,
        );
        assert!(matches!(result, Err(Error::Crypto)));
    }
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
            &cipher,
            &PortableCodec,
            &mut SystemEntropy,
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
    resign(&mut publication, &mut device);
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
