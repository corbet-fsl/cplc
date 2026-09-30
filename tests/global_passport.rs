//! Real global evidence affects cplc's decision but never enters the credential.
mod common;
use common::*;
use cplc::*;
use rand::{SeedableRng, rngs::StdRng};

#[tokio::test]
async fn verified_global_metadata_is_decided_but_not_disclosed() {
    let action = crbk::ActionPolicy {
        all_of: vec![requirement("phone", crbk::GateLevel::Global)],
        ..Default::default()
    };
    let mut rules = book(action);
    rules
        .define(
            crbk::provider_key(crbk::GateLevel::Global, "phone", "cpsd"),
            crbk::Setting {
                value_type: crbk::SettingType::Boolean,
                nullable: false,
                default: true.into(),
                bounds: crbk::Bounds::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    let mut policy = memory_with(rules).await;
    let snapshot = policy.verified_settings(NOW).await.unwrap();
    let mut rng = StdRng::seed_from_u64(93);
    let gate = cpsd::GateId::new("phone").unwrap();
    let issuer = cpsd::IssuerKey::generate(
        &mut rng,
        cpsd::KeyId::new("shared").unwrap(),
        vec![gate.clone()],
    )
    .unwrap();
    let secret = cpsd::HolderSecret::generate(&mut rng);
    let auth = cpsd::AuthenticatedIssuance::new([1; 32], [2; 32]);
    let store = cpsd::MemoryStore::new(cpsd::CommunityId::new("global").unwrap(), 10).unwrap();
    let challenge =
        cpsd::issuance_challenge(&mut rng, &store, issuer.public_key(), &auth, NOW + 10)
            .await
            .unwrap();
    let (request, pending) =
        cpsd::request_issue(&mut rng, &secret, issuer.public_key(), &challenge).unwrap();
    let attrs = cpsd::PassportAttributes::new(DAY, 7).with_gate(gate.clone(), DAY);
    let blind = cpsd::issue_blind_once(
        &mut rng, &store, &issuer, &auth, &request, &challenge, &attrs, NOW,
    )
    .await
    .unwrap();
    let passport = pending.finish(&blind).unwrap();
    let verifier = cpsd::Verifier::new(
        cpsd::MemoryStore::new(cpsd::CommunityId::new(COMMUNITY).unwrap(), 10).unwrap(),
        vec![issuer.public_key().clone()],
    )
    .unwrap();
    let request = verifier
        .request_for_epoch(&mut rng, 7, [gate], NOW + 10, DAY)
        .await
        .unwrap();
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(77),
        day(NOW),
        DAY,
    )
    .await
    .unwrap();
    let signed = signer
        .sign(
            csgn::Kind::Credential,
            &request.to_bytes(),
            day(NOW),
            NOW + 11,
        )
        .await
        .unwrap();
    let origin = cpsd::AuthenticatedCommunity::from_authenticated_origin(
        request.community().clone(),
        signer.key_ring().unwrap().clone(),
    );
    let proof = passport.present(&mut rng, &origin, &signed, NOW).unwrap();
    let witness = cgts::verify_passport(&verifier, &mut rng, &request, &proof, 7, NOW)
        .await
        .unwrap();
    let member = witness.pseudonym().to_hex();
    let context = cgts::Context {
        snapshot: snapshot.settings(),
        subject: &member,
        action: "admit",
        now: NOW as i64,
    };
    let keeper = cgts::Gatekeeper::new(
        cgts::MemoryStore::new(COMMUNITY).unwrap(),
        cgts::LegalGate::new(clbs::MemoryStore::new(COMMUNITY).unwrap(), NoAuthority),
    )
    .unwrap();
    let gates = keeper
        .check(context, witness.gates(context).unwrap())
        .await
        .unwrap();
    let source = FixtureMembership {
        member: member.clone(),
        state: crbk::MembershipState::Admitted,
        probation_until: Some(14 * DAY),
        lease_end: 90 * DAY,
    };
    let cose = policy
        .issue(
            &source,
            CredentialRequest {
                subject: crbk::Subject {
                    id: &member,
                    membership: crbk::MembershipState::Admitted,
                },
                handle: "testmember",
                schema_version: 1,
                snapshot: &snapshot,
                gates: &gates,
                pins: &[],
                devices: DEVICES,
            },
            NOW,
        )
        .await
        .unwrap();
    let verified = policy
        .key_ring()
        .unwrap()
        .verify(&cose, csgn::Kind::Credential, NOW)
        .unwrap();
    let payload = std::str::from_utf8(verified.payload()).unwrap();
    let credential: Credential = serde_json::from_slice(verified.payload()).unwrap();
    assert!(credential.gates.is_empty());
    assert!(!payload.contains("phone"));
    assert!(!payload.contains("proven_at"));
    assert_eq!(verified.valid_until(), DAY);
}
