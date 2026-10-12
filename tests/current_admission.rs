//! Original signed voucher receipts retain their timestamp at a later owner cut.
mod common;
use common::*;
use cplc::*;
use ed25519_dalek::{Signer, SigningKey};

async fn fixture() -> (MemoryPolicy, VerifiedSnapshot, cgts::CheckedGates) {
    let mut rules = book(crbk::ActionPolicy {
        all_of: vec![crbk::Requirement {
            gate: "cvch".into(),
            level: crbk::GateLevel::Community,
            provider: Some("invitation".into()),
        }],
        ..Default::default()
    });
    for setting in [
        crbk::gate_key(crbk::GateLevel::Community, "cvch"),
        crbk::provider_key(crbk::GateLevel::Community, "cvch", "invitation"),
    ] {
        rules
            .define(
                setting,
                crbk::Setting {
                    value_type: crbk::SettingType::Boolean,
                    nullable: true,
                    default: true.into(),
                    bounds: crbk::Bounds::default(),
                    lowest_layer: crbk::Layer::Community,
                    kind: crbk::SettingKind::Technical,
                },
            )
            .unwrap();
    }
    cgts::gates::define_settings(&mut rules).unwrap();
    let mut policy = memory_with(rules).await;
    let snapshot = policy.verified_settings(NOW).await.unwrap();
    let keeper = cgts::Gatekeeper::new(
        cgts::MemoryStore::new(COMMUNITY).unwrap(),
        cgts::LegalGate::new(clbs::MemoryStore::new(COMMUNITY).unwrap(), NoAuthority),
    )
    .unwrap();
    let context = cgts::Context {
        snapshot: snapshot.settings(),
        subject: MEMBER,
        action: "admit",
        now: NOW as i64,
    };
    let sponsor = SigningKey::from_bytes(&[7; 32]);
    let id = "actual-original-voucher";
    let binding = cvch::member_binding(&cvch::receipt_id(id), MEMBER.as_bytes());
    let expires = NOW + 2;
    let voucher = cvch::Voucher {
        member_binding: binding.clone(),
        id: id.into(),
        valid_until: expires,
        signature: sponsor
            .sign(&cvch::issuance_bytes(id, expires, COMMUNITY, &binding))
            .to_bytes()
            .to_vec(),
    };
    keeper
        .run(
            context,
            &cgts::gates::VoucherGate::new("invitation", sponsor.verifying_key()).unwrap(),
            &voucher,
        )
        .await
        .unwrap();
    let checked = keeper.check(context, vec![]).await.unwrap();
    (policy, snapshot, checked)
}

#[tokio::test]
async fn later_current_evaluation_preserves_the_actual_voucher_expiry() {
    let (policy, snapshot, checked) = fixture().await;
    assert!(
        policy
            .may(&snapshot, subject(), "admit", &checked, NOW)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        policy
            .may_current(&snapshot, subject(), "admit", &checked, NOW, NOW + 1)
            .await
            .unwrap()
            .allowed
    );
    // The signed deadline only bounds redemption. The retained receipt lives for
    // the configured validity days (default 30), counted from the checking day.
    assert!(
        policy
            .may_current(&snapshot, subject(), "admit", &checked, NOW, NOW + 2)
            .await
            .unwrap()
            .allowed
    );
    let expiry = 30 * 86_400;
    assert!(
        policy
            .may_current(&snapshot, subject(), "admit", &checked, NOW, expiry - 1)
            .await
            .unwrap()
            .allowed
    );
    assert!(
        !policy
            .may_current(&snapshot, subject(), "admit", &checked, NOW, expiry)
            .await
            .unwrap()
            .allowed
    );
    // A current decision does not alter the original checked receipt context.
    assert!(matches!(
        policy
            .may(&snapshot, subject(), "admit", &checked, NOW + 1)
            .await,
        Err(Error::Verification)
    ));
}

#[tokio::test]
async fn checked_timestamp_action_identity_and_current_policy_cannot_be_rebound() {
    let (mut policy, snapshot, checked) = fixture().await;
    for (checked_at, now) in [(NOW + 1, NOW + 1), (NOW, NOW - 1)] {
        assert!(matches!(
            policy
                .may_current(&snapshot, subject(), "admit", &checked, checked_at, now)
                .await,
            Err(Error::Verification)
        ));
    }
    assert!(matches!(
        policy
            .may_current(&snapshot, subject(), "other", &checked, NOW, NOW + 1)
            .await,
        Err(Error::Verification)
    ));
    let other = crbk::Subject {
        id: "other-member",
        membership: crbk::MembershipState::Admitted,
    };
    assert!(matches!(
        policy
            .may_current(&snapshot, other, "admit", &checked, NOW, NOW + 1)
            .await,
        Err(Error::Verification)
    ));
    policy.bump_epoch().await.unwrap();
    assert!(matches!(
        policy
            .may_current(&snapshot, subject(), "admit", &checked, NOW, NOW + 1)
            .await,
        Err(Error::Verification)
    ));
}
