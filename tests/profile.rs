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
        "private":[{"id":"secret","label":"Secret","kind":{"type":"yes_no"},"required":true,"filterable":false,"change_preset":"occasional","no_contact_details":false}]
    })).unwrap()
}
fn profile() -> cshm::Profile {
    cshm::Profile {
        community: "garden".into(),
        schema_version: 1,
        public: [("age".into(), json!(34)), ("bio".into(), json!("reading"))].into(),
        private: [("secret".into(), json!(true))].into(),
    }
}
fn clean(_: &str) -> cshm::ContactCheck {
    cshm::ContactCheck::Clear
}
struct Auth {
    keys: csgn::KeyRing,
    settings: Vec<u8>,
    schema: Vec<u8>,
    revocations: Vec<u8>,
    credential: Vec<u8>,
}
impl Auth {
    fn new(draft: &mut Draft, device: &Device) -> Self {
        let pins = draft
            .prepare_pins(&schema(), &clean, &mut SystemEntropy)
            .unwrap();
        let mut issuer =
            Signer::new("garden", SecretKey::from_seed(&mut [11; 32]), 1000, 10000).unwrap();
        let credential = cgrd::Credential {
            community: "garden".into(),
            member: "alice".into(),
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
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":schema()}),
        );
        let settings = sign(
            Kind::SettingsSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"action/admission":{"all_of":[],"any_of":[],"k_of_n":null,"maximum_proof_age":null,"membership":["admitted"]}}}),
        );
        let revocations = sign(
            Kind::RevocationListSnapshot,
            json!({"community":"garden","revision":1,"policy_epoch":2,"content":{"members":[],"devices":[]}}),
        );
        Self {
            keys: issuer.key_ring().clone(),
            settings,
            schema,
            revocations,
            credential,
        }
    }
    fn policy(&self) -> cgrd::PublishedPolicy<'_> {
        cgrd::PublishedPolicy {
            policy: cgrd::Policy {
                community: "garden",
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
    draft
        .prepare_publication(
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
        .commit_publication(&mut store, [3; 32], vec![])
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
            .commit_publication(&mut store, [1; 32], vec![])
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
        .commit_publication(&mut store, [1; 32], vec![])
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
