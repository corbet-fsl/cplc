//! Real signed vouchers retain provider-specific facts through credential issuance.
mod common;
use common::*;
use cplc::*;

fn requirement_for(provider: &str) -> crbk::Requirement {
    crbk::Requirement {
        gate: "cvch".into(),
        level: crbk::GateLevel::Community,
        provider: Some(provider.into()),
    }
}

#[tokio::test]
async fn authenticated_providers_of_one_gate_can_issue_without_inflating_thresholds() {
    let action = crbk::ActionPolicy {
        all_of: vec![requirement_for("first")],
        any_of: vec![requirement_for("second")],
        ..Default::default()
    };
    let mut rules = book(action);
    for setting in [
        crbk::gate_key(crbk::GateLevel::Community, "cvch"),
        crbk::provider_key(crbk::GateLevel::Community, "cvch", "first"),
        crbk::provider_key(crbk::GateLevel::Community, "cvch", "second"),
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
    let links = std::sync::Arc::new(cvch::link::MemoryLinks::default());
    for provider in ["first", "second"] {
        let request = voucher_request(&links, COMMUNITY, MEMBER, provider, NOW, 100).await;
        keeper
            .run(
                context,
                &cgts::gates::VoucherGate::new(provider, links.clone()).unwrap(),
                &request,
            )
            .await
            .unwrap();
    }
    let checks = keeper.check(context, vec![]).await.unwrap();
    assert!(
        policy
            .may(&snapshot, subject(), "admit", &checks, NOW)
            .await
            .unwrap()
            .allowed
    );
    let source = FixtureMembership {
        member: MEMBER.into(),
        state: crbk::MembershipState::Admitted,
        probation_until: Some(14 * DAY),
        lease_end: 90 * DAY,
        authorized_devices: DEVICES.to_vec(),
    };
    let issued = policy
        .issue(
            &source,
            CredentialRequest {
                subject: subject(),
                handle: "testmember",
                schema_version: 1,
                snapshot: &snapshot,
                gates: &checks,
                pins: &[],
                devices: DEVICES,
            },
            NOW,
        )
        .await;
    assert!(
        issued.is_ok(),
        "distinct authenticated providers must issue a credential"
    );
    let cose = issued.unwrap();
    let (credential, _) = decode_credential(policy.key_ring().unwrap(), &cose, NOW);
    assert_eq!(credential.gates.len(), 2);
    assert_eq!(credential.gates[0].provider, "first");
    assert_eq!(credential.gates[1].provider, "second");

    let mut threshold = snapshot.settings().clone();
    threshold.content.insert(
        crbk::action_key("admit"),
        serde_json::to_value(crbk::ActionPolicy {
            k_of_n: Some(crbk::Threshold {
                k: 2,
                of: vec![
                    requirement_for("first"),
                    requirement("development", crbk::GateLevel::Community),
                ],
            }),
            ..Default::default()
        })
        .unwrap(),
    );
    assert!(
        !threshold
            .may(
                subject(),
                "admit",
                &checks.in_context(context).unwrap(),
                NOW as i64
            )
            .unwrap()
            .allowed
    );
}
