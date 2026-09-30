//! Policy facade round trips and adversarial inputs through the real leaves.

mod common;

use std::collections::BTreeSet;

use common::*;
use cplc::{crbk, csgn, cshm, *};
use serde_json::{Value, json};

#[tokio::test]
async fn publish_and_recover_all_snapshot_kinds() {
    let mut policy = memory().await;
    policy
        .set_communities(BTreeSet::from([
            COMMUNITY.into(),
            "another-public-community".into(),
        ]))
        .await
        .unwrap();
    let epoch = policy.epoch(NOW).await.unwrap();
    for kind in [
        SnapshotKind::Settings,
        SnapshotKind::Schema,
        SnapshotKind::SchemaVersions,
        SnapshotKind::Communities,
        SnapshotKind::RevocationList,
    ] {
        let cose = policy.publish(kind, NOW).await.unwrap();
        let snapshot: Snapshot<Value> = verify_snapshot(
            policy.key_ring().unwrap(),
            &cose,
            expectation(kind, epoch, NOW),
        )
        .unwrap();
        assert_eq!(snapshot.community, COMMUNITY);
        assert_eq!(snapshot.revision, 1);
        assert_eq!(
            policy.published(kind, NOW).await.unwrap(),
            Some(cose.clone())
        );
        let second = policy.publish(kind, NOW).await.unwrap();
        let refreshed: Snapshot<Value> = verify_snapshot(
            policy.key_ring().unwrap(),
            &second,
            expectation(kind, epoch, NOW),
        )
        .unwrap();
        assert_eq!(refreshed.revision, 2);
        assert_eq!(snapshot.content, refreshed.content);
        assert_ne!(cose, second);
        assert_eq!(
            policy
                .published(kind, NOW + config().snapshot_validity)
                .await
                .unwrap(),
            None
        );
    }
}

#[tokio::test]
async fn delegate_null_force_and_pinned_resolution() {
    let mut rules = book(admission());
    rules
        .publish_template(
            crbk::TemplatePin {
                name: "base".into(),
                version: 1,
            },
            crbk::Values::from([("quota".into(), json!(20))]),
        )
        .unwrap();
    rules
        .pin_template(Some(crbk::TemplatePin {
            name: "base".into(),
            version: 1,
        }))
        .unwrap();
    rules.set_community("quota", Some(Value::Null)).unwrap();
    let mut policy = memory_with(rules.clone()).await;
    let epoch = policy.epoch(NOW).await.unwrap();
    let cose = policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    let snapshot: Snapshot<crbk::Values> = verify_snapshot(
        policy.key_ring().unwrap(),
        &cose,
        expectation(SnapshotKind::Settings, epoch, NOW),
    )
    .unwrap();
    assert_eq!(snapshot.content["quota"], Value::Null);
    rules
        .set_platform(
            "quota",
            Some(crbk::PlatformValue {
                value: json!(33),
                force: true,
            }),
        )
        .unwrap();
    policy
        .schedule_rules(Some(1), change(rules, 2, 200))
        .await
        .unwrap();
    let cose = policy.publish(SnapshotKind::Settings, 200).await.unwrap();
    let snapshot: Snapshot<crbk::Values> = verify_snapshot(
        policy.key_ring().unwrap(),
        &cose,
        expectation(
            SnapshotKind::Settings,
            policy.epoch(200).await.unwrap(),
            200,
        ),
    )
    .unwrap();
    assert_eq!(snapshot.content["quota"], 33);
}

#[tokio::test]
async fn credential_roundtrip_uses_verdict_and_lifetime_class() {
    let mut policy = memory().await;
    let gates = [development_gate(i64::MAX)];
    let before = policy.key_ring().unwrap().to_cbor();
    for (class, validity) in [
        (MemberClass::New, NEW_MEMBER_VALIDITY),
        (MemberClass::Established, ESTABLISHED_MEMBER_VALIDITY),
    ] {
        let mut input = request(&gates);
        input.class = class;
        let cose = policy.issue_test(input, NOW).await.unwrap();
        let (credential, until) = decode_credential(policy.key_ring().unwrap(), &cose, NOW);
        assert_eq!(until, day(NOW) + validity);
        assert_eq!(credential.member, MEMBER);
        assert_eq!(credential.gates.len(), 1);
        assert_eq!(credential.devices, DEVICES);
        assert_eq!(credential.policy_epoch, policy.epoch(NOW).await.unwrap());
        assert!(
            policy
                .key_ring()
                .unwrap()
                .verify(&cose, csgn::Kind::Credential, until)
                .is_err()
        );
    }
    // Issuance must not expose an active-key activity timestamp in the public ring.
    assert_eq!(before, policy.key_ring().unwrap().to_cbor());
}

#[tokio::test]
async fn a_missing_or_disabled_gate_never_gets_a_signature() {
    let mut policy = memory().await;
    let decision = policy.may_test(subject(), "admit", &[], NOW).await.unwrap();
    assert!(!decision.allowed);
    assert!(!decision.missing.is_empty());
    assert!(matches!(
        policy.issue_test(request(&[]), NOW).await,
        Err(Error::Denied(_))
    ));
    let mut rules = book(admission());
    rules
        .set_community(
            &crbk::provider_key(crbk::GateLevel::Community, "development", "test"),
            Some(json!(false)),
        )
        .unwrap();
    let mut disabled = memory_with(rules).await;
    assert!(matches!(
        disabled
            .issue_test(request(&[development_gate(300)]), NOW)
            .await,
        Err(Error::Denied(_))
    ));
    assert!(
        !disabled
            .may_test(subject(), "unknown_action", &[], NOW)
            .await
            .unwrap()
            .allowed
    );
}

#[tokio::test]
async fn maximum_age_and_proof_expiry_bound_the_entire_credential() {
    let mut action = admission();
    action.maximum_proof_age = Some(10);
    let mut policy = memory_with(book(action)).await;
    let mut gate = development_gate(500);
    gate.proven_at = Some(95);
    // No gate can invent the authenticated issuance metadata required by max age.
    assert!(matches!(
        policy.issue_test(request(&[gate.clone()]), NOW).await,
        Err(Error::Denied(_))
    ));
    gate.proven_at = None;
    assert!(matches!(
        policy.issue_test(request(&[gate]), NOW).await,
        Err(Error::Denied(_))
    ));
    let mut policy = memory().await;
    let cose = policy
        .issue_test(request(&[development_gate(101)]), NOW)
        .await
        .unwrap();
    assert_eq!(
        decode_credential(policy.key_ring().unwrap(), &cose, NOW).1,
        101
    );
}

#[tokio::test]
async fn rulebook_any_and_threshold_policies_are_not_flattened() {
    let any = crbk::ActionPolicy {
        any_of: vec![
            requirement("development", crbk::GateLevel::Community),
            requirement("voucher", crbk::GateLevel::Community),
        ],
        ..Default::default()
    };
    let mut policy = memory_with(book(any)).await;
    assert!(
        policy
            .issue_test(request(&[development_gate(500)]), NOW)
            .await
            .is_ok()
    );
    let threshold = crbk::ActionPolicy {
        k_of_n: Some(crbk::Threshold {
            k: 2,
            of: vec![
                requirement("development", crbk::GateLevel::Community),
                requirement("voucher", crbk::GateLevel::Community),
            ],
        }),
        ..Default::default()
    };
    let mut policy = memory_with(book(threshold)).await;
    assert!(matches!(
        policy
            .issue_test(request(&[development_gate(500)]), NOW)
            .await,
        Err(Error::Denied(_))
    ));
    let mut voucher = development_gate(300);
    voucher.gate = "voucher".into();
    let cose = policy
        .issue_test(request(&[development_gate(500), voucher]), NOW)
        .await
        .unwrap();
    assert_eq!(
        decode_credential(policy.key_ring().unwrap(), &cose, NOW).1,
        300
    );
}

#[tokio::test]
async fn credential_binding_and_duplicate_failures_are_closed_even_for_empty_policy() {
    let mut policy = memory_with(book(crbk::ActionPolicy::default())).await;
    let mut gate = development_gate(500);
    gate.subject = "other-member".into();
    assert!(matches!(
        policy.issue_test(request(&[gate]), NOW).await,
        Err(Error::Invalid(_))
    ));
    let mut gate = development_gate(500);
    gate.community = Some("other".into());
    assert!(matches!(
        policy.issue_test(request(&[gate]), NOW).await,
        Err(Error::Invalid(_))
    ));
    let gate = development_gate(500);
    assert!(matches!(
        policy.issue_test(request(&[gate.clone(), gate]), NOW).await,
        Err(Error::Invalid(_))
    ));
    let mut gate = development_gate(500);
    gate.proven_at = Some(101);
    assert!(matches!(
        policy.issue_test(request(&[gate]), NOW).await,
        Err(Error::Invalid(_))
    ));
    let mut input = request(&[]);
    input.subject.membership = crbk::MembershipState::Released;
    assert!(matches!(
        policy.issue_test(input, NOW).await,
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn authorized_pins_and_devices_roundtrip_and_invalid_inputs_fail() {
    let mut policy = memory().await;
    let gates = [development_gate(500)];
    let pins = [Pin {
        field: "weekends".into(),
        fingerprint: [7; 32],
    }];
    let mut input = request(&gates);
    input.pins = &pins;
    let cose = policy.issue_test(input, NOW).await.unwrap();
    assert_eq!(
        decode_credential(policy.key_ring().unwrap(), &cose, NOW)
            .0
            .pins,
        pins
    );
    let duplicate = [pins[0].clone(), pins[0].clone()];
    let mut input = request(&gates);
    input.pins = &duplicate;
    assert!(matches!(
        policy.issue_test(input, NOW).await,
        Err(Error::Invalid(_))
    ));
    let invalid = [Pin {
        field: "unknown".into(),
        fingerprint: [7; 32],
    }];
    let mut input = request(&gates);
    input.pins = &invalid;
    assert!(matches!(
        policy.issue_test(input, NOW).await,
        Err(Error::Invalid(_))
    ));
    let mut input = request(&gates);
    input.devices = &[DEVICE, DEVICE];
    assert!(matches!(
        policy.issue_test(input, NOW).await,
        Err(Error::Invalid(_))
    ));
    let mut input = request(&gates);
    input.devices = &[];
    assert!(matches!(
        policy.issue_test(input, NOW).await,
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn schema_classification_versions_and_scope_are_owned_by_cshm() {
    let mut policy = memory().await;
    policy.publish(SnapshotKind::Schema, NOW).await.unwrap();
    let before = policy.epoch(NOW).await.unwrap();
    let mut next = schema(2);
    next.private = std::mem::take(&mut next.public);
    let changes = policy.set_schema(next).await.unwrap().unwrap();
    assert_eq!(changes.fields[0].class, cshm::ChangeClass::Hide);
    assert!(policy.epoch(NOW).await.unwrap() > before);
    assert_eq!(
        policy.published(SnapshotKind::Schema, NOW).await.unwrap(),
        None
    );
    assert!(matches!(
        policy
            .issue_test(request(&[development_gate(500)]), NOW)
            .await,
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        policy.set_schema(schema(1)).await,
        Err(Error::Schema)
    ));
    let mut foreign = schema(3);
    foreign.community = "elsewhere".into();
    assert!(matches!(
        policy.set_schema(foreign).await,
        Err(Error::Invalid(_))
    ));
    let mut invalid = schema(3);
    invalid.public[0].label.clear();
    assert!(matches!(
        policy.set_schema(invalid).await,
        Err(Error::Schema)
    ));
    assert_eq!(policy.schema().unwrap().unwrap().version, 2);
}

#[tokio::test]
async fn revocations_advance_epochs_and_block_members_and_devices() {
    let mut policy = memory().await;
    let old_epoch = policy.epoch(NOW).await.unwrap();
    let old = policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    policy
        .set_revocations(Revocations {
            members: BTreeSet::from([MEMBER.into()]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(policy.epoch(NOW).await.unwrap() > old_epoch);
    assert!(matches!(
        policy
            .issue_test(request(&[development_gate(500)]), NOW)
            .await,
        Err(Error::Revoked)
    ));
    assert!(matches!(
        policy
            .may_test(subject(), "admit", &[development_gate(500)], NOW)
            .await,
        Err(Error::Revoked)
    ));
    assert!(
        verify_snapshot::<Value>(
            policy.key_ring().unwrap(),
            &old,
            expectation(
                SnapshotKind::Settings,
                policy.epoch(NOW).await.unwrap(),
                NOW
            )
        )
        .is_err()
    );
    policy
        .set_revocations(Revocations {
            devices: BTreeSet::from([DEVICE]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(matches!(
        policy
            .issue_test(request(&[development_gate(500)]), NOW)
            .await,
        Err(Error::Revoked)
    ));
    let cose = policy
        .publish(SnapshotKind::RevocationList, NOW)
        .await
        .unwrap();
    let revocations: Snapshot<Revocations> = verify_snapshot(
        policy.key_ring().unwrap(),
        &cose,
        expectation(
            SnapshotKind::RevocationList,
            policy.epoch(NOW).await.unwrap(),
            NOW,
        ),
    )
    .unwrap();
    assert_eq!(revocations.content.devices, BTreeSet::from([DEVICE]));
}

#[tokio::test]
async fn scheduled_policy_does_not_activate_early_and_always_advances_epoch() {
    let mut policy = memory().await;
    let before = policy.epoch(NOW).await.unwrap();
    let mut rules = book(admission());
    rules
        .set_community(&crbk::action_key("admit"), Some(Value::Null))
        .unwrap();
    let mut update = change(rules, 2, 200);
    update.notice_seconds = 100;
    policy.schedule_rules(Some(1), update).await.unwrap();
    assert_eq!(policy.epoch(199).await.unwrap(), before);
    policy.bump_epoch().await.unwrap();
    let immediate = policy.epoch(199).await.unwrap();
    assert!(immediate > before);
    let cose = policy
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    assert_eq!(
        decode_credential(policy.key_ring().unwrap(), &cose, NOW).1,
        200
    );
    let snapshot = policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    assert_eq!(
        policy
            .key_ring()
            .unwrap()
            .verify(&snapshot, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap()
            .valid_until(),
        200
    );
    assert!(policy.epoch(200).await.unwrap() > immediate);
    assert_eq!(
        policy.published(SnapshotKind::Settings, 200).await.unwrap(),
        None
    );
    assert!(matches!(
        policy
            .issue_test(request(&[development_gate(500)]), 200)
            .await,
        Err(Error::Denied(_))
    ));
}

#[tokio::test]
async fn scheduling_rejects_notice_violations_and_nonadvancing_epochs() {
    let mut policy = memory().await;
    let mut update = change(book(admission()), 2, 199);
    update.notice_seconds = 100;
    assert!(matches!(
        policy.schedule_rules(Some(1), update).await,
        Err(Error::Rulebook)
    ));
    assert!(matches!(
        policy
            .schedule_rules(Some(1), change(book(admission()), 1, 200))
            .await,
        Err(Error::Invalid(_))
    ));
    assert!(
        policy
            .issue_test(request(&[development_gate(500)]), NOW)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn signatures_enforce_kind_scope_epoch_revision_and_tamper_rejection() {
    let mut policy = memory().await;
    let epoch = policy.epoch(NOW).await.unwrap();
    let cose = policy.publish(SnapshotKind::Schema, NOW).await.unwrap();
    assert!(
        verify_snapshot::<cshm::Schema>(
            policy.key_ring().unwrap(),
            &cose,
            expectation(SnapshotKind::Schema, epoch, NOW)
        )
        .is_ok()
    );
    assert!(
        verify_snapshot::<Value>(
            policy.key_ring().unwrap(),
            &cose,
            expectation(SnapshotKind::Settings, epoch, NOW)
        )
        .is_err()
    );
    assert!(
        verify_snapshot::<Value>(
            policy.key_ring().unwrap(),
            &cose,
            expectation(SnapshotKind::Schema, epoch + 1, NOW)
        )
        .is_err()
    );
    let mut expected = expectation(SnapshotKind::Schema, epoch, NOW);
    expected.minimum_revision = 2;
    assert!(verify_snapshot::<Value>(policy.key_ring().unwrap(), &cose, expected).is_err());
    let mut expected = expectation(SnapshotKind::Schema, epoch, NOW);
    expected.community = "other";
    assert!(verify_snapshot::<Value>(policy.key_ring().unwrap(), &cose, expected).is_err());
    for offset in [0, cose.len() / 2, cose.len() - 1] {
        let mut changed = cose.clone();
        changed[offset] ^= 1;
        assert!(
            verify_snapshot::<Value>(
                policy.key_ring().unwrap(),
                &changed,
                expectation(SnapshotKind::Schema, epoch, NOW)
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn rotate_retains_old_credential_and_uses_new_key() {
    let mut policy = memory().await;
    let old = policy
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    let previous_id = policy.key_ring().unwrap().active().unwrap().key_id();
    policy.rotate(key(2), 101).await.unwrap();
    assert_ne!(
        policy.key_ring().unwrap().active().unwrap().key_id(),
        previous_id
    );
    assert!(
        policy
            .key_ring()
            .unwrap()
            .verify(&old, csgn::Kind::Credential, 101)
            .is_ok()
    );
    let new = policy
        .issue_test(request(&[development_gate(500)]), 101)
        .await
        .unwrap();
    assert_eq!(
        policy
            .key_ring()
            .unwrap()
            .verify(&new, csgn::Kind::Credential, 101)
            .unwrap()
            .key_id(),
        policy.key_ring().unwrap().active().unwrap().key_id()
    );
    assert!(matches!(
        policy.rotate(key(1), 102).await,
        Err(Error::Signing)
    ));
    policy.prune_keys(86_400).await.unwrap();
    assert_eq!(policy.key_ring().unwrap().keys().len(), 1);
}

#[tokio::test]
async fn wrong_signer_scope_and_missing_configuration_fail() {
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "other",
        key(1),
        day(NOW),
        1000,
    )
    .await
    .unwrap();
    assert!(matches!(
        Policy::create(
            crbk::MemoryStore::default(),
            MemoryStore::new(COMMUNITY).unwrap(),
            signer,
            config()
        )
        .await,
        Err(Error::Invalid(_))
    ));
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(1),
        day(NOW),
        1000,
    )
    .await
    .unwrap();
    let mut policy = Policy::create(
        crbk::MemoryStore::default(),
        MemoryStore::new(COMMUNITY).unwrap(),
        signer,
        config(),
    )
    .await
    .unwrap();
    assert!(matches!(
        policy.issue_test(request(&[]), NOW).await,
        Err(Error::Missing)
    ));
    assert!(matches!(
        policy.publish(SnapshotKind::Settings, NOW).await,
        Err(Error::Missing)
    ));
}

#[tokio::test]
async fn limits_and_extreme_time_fail_without_logging_input() {
    let mut policy = memory().await;
    let gates = vec![development_gate(500); MAX_ENTRIES + 1];
    assert!(matches!(
        policy.issue_test(request(&gates), NOW).await,
        Err(Error::Invalid(_))
    ));
    assert!(
        policy
            .may_test(subject(), "admit", &[], u64::MAX)
            .await
            .is_err()
    );
    let mut input = request(&[]);
    input.handle = "";
    let error = policy.issue_test(input, NOW).await.unwrap_err();
    assert!(!format!("{error:?}").contains(MEMBER));
    let communities = (0..=MAX_ENTRIES)
        .map(|i| format!("community-{i}"))
        .collect();
    assert!(matches!(
        policy.set_communities(communities).await,
        Err(Error::Invalid(_))
    ));
    assert!(
        policy
            .issue_test(request(&[development_gate(500)]), NOW)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn malformed_signed_snapshot_payloads_are_rejected() {
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(1),
        day(NOW),
        1000,
    )
    .await
    .unwrap();
    for payload in [
        json!({"community":COMMUNITY,"revision":0,"policy_epoch":1,"content":{}}),
        json!({"community":"other","revision":1,"policy_epoch":1,"content":{}}),
        json!({"community":COMMUNITY,"revision":1,"policy_epoch":1,"content":{},"extra":true}),
    ] {
        let cose = signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&payload).unwrap(),
                NOW,
                200,
            )
            .await
            .unwrap();
        assert!(
            verify_snapshot::<Value>(
                signer.key_ring().unwrap(),
                &cose,
                expectation(SnapshotKind::Settings, 1, NOW)
            )
            .is_err()
        );
    }
}

#[tokio::test]
async fn sparse_door_edits_and_signed_trust_manifest_preserve_boundaries() {
    let mut policy = memory().await;
    let initial = policy.trust_manifest(NOW).await.unwrap();
    let verified = policy
        .key_ring()
        .unwrap()
        .verify(&initial, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap();
    let first: TrustManifest = serde_json::from_slice(verified.payload()).unwrap();
    assert_eq!(first.purpose, TrustPurpose::CommunityTrustV1);
    assert_eq!(first.community, COMMUNITY);
    assert!(serde_json::from_slice::<Snapshot<Value>>(verified.payload()).is_err());
    assert_eq!(
        csgn::KeyRing::from_cbor(&first.key_ring).unwrap().issuer(),
        COMMUNITY
    );
    policy
        .edit_setting(
            "quota",
            SettingEdit::Community(Some(json!(15))),
            NOW + 1,
            NOW + 1,
            0,
        )
        .await
        .unwrap();
    policy
        .edit_setting(
            "quota",
            SettingEdit::Platform(Some(crbk::PlatformValue {
                value: json!(25),
                force: true,
            })),
            NOW + 2,
            NOW + 2,
            0,
        )
        .await
        .unwrap();
    let epoch = policy.epoch(NOW + 2).await.unwrap();
    assert!(epoch > first.policy_epoch);
    let settings = policy
        .publish(SnapshotKind::Settings, NOW + 2)
        .await
        .unwrap();
    let settings: Snapshot<crbk::Values> = verify_snapshot(
        policy.key_ring().unwrap(),
        &settings,
        expectation(SnapshotKind::Settings, epoch, NOW + 2),
    )
    .unwrap();
    assert_eq!(settings.content["quota"], json!(25));
    assert!(
        policy
            .edit_setting(
                "quota",
                SettingEdit::Community(Some(json!(1000))),
                NOW,
                NOW,
                0
            )
            .await
            .is_err()
    );
    let next = policy.trust_manifest(NOW + 2).await.unwrap();
    let verified = policy
        .key_ring()
        .unwrap()
        .verify(&next, csgn::Kind::SettingsSnapshot, NOW + 2)
        .unwrap();
    let next: TrustManifest = serde_json::from_slice(verified.payload()).unwrap();
    assert!(next.revision > first.revision);
    assert_eq!(next.policy_epoch, epoch);
    assert!(policy.revocations().unwrap().members.is_empty());
}

#[tokio::test]
async fn empty_policy_never_issues_to_pending_lapsed_or_released_members() {
    let mut policy = memory_with(book(crbk::ActionPolicy::default())).await;
    for membership in [
        crbk::MembershipState::Pending,
        crbk::MembershipState::Lapsed,
        crbk::MembershipState::Released,
    ] {
        let mut input = request(&[]);
        input.subject.membership = membership;
        assert!(matches!(
            policy.issue_test(input, NOW).await,
            Err(Error::Invalid(_))
        ));
    }
    assert!(policy.issue_test(request(&[]), NOW).await.is_ok());
}

#[tokio::test]
async fn an_epoch_jump_cannot_exhaust_revocation_capacity() {
    let mut policy = memory().await;
    for epoch in [3, i64::MAX as u64 - 10] {
        assert!(matches!(
            policy
                .schedule_rules(Some(1), change(book(admission()), epoch, 200))
                .await,
            Err(Error::Invalid(_))
        ));
    }
    policy
        .set_revocations(Revocations {
            members: BTreeSet::from([MEMBER.into()]),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(matches!(
        policy.issue_test(request(&[]), NOW).await,
        Err(Error::Revoked)
    ));
}

#[tokio::test]
async fn credential_debug_omits_member_handle_pins_and_devices() {
    let mut policy = memory().await;
    let signed = policy
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    let (credential, _) = decode_credential(policy.key_ring().unwrap(), &signed, NOW);
    assert_eq!(format!("{credential:?}"), "Credential { .. }");
}

#[tokio::test]
async fn global_issuer_namespace_is_unavailable_to_communities() {
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "cglb:global",
        key(1),
        day(NOW),
        1000,
    )
    .await
    .unwrap();
    assert!(matches!(
        Policy::create(
            crbk::MemoryStore::default(),
            MemoryStore::new("cglb:global").unwrap(),
            signer,
            config(),
        )
        .await,
        Err(Error::Invalid(_))
    ));
}

#[tokio::test]
async fn settings_witness_preserves_the_envelope_and_rejects_stale_publications() {
    let mut policy = memory().await;
    let verified = policy.verified_settings(NOW).await.unwrap();
    assert_eq!(verified.settings().issued, day(NOW) as i64);
    assert_eq!(
        verified.settings().policy_epoch,
        policy.epoch(NOW).await.unwrap()
    );
    assert_eq!(
        verified.valid_until(),
        day(NOW) + config().snapshot_validity
    );
    policy.validate_snapshot(&verified, NOW).await.unwrap();
    policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    assert!(matches!(
        policy.validate_snapshot(&verified, NOW).await,
        Err(Error::Verification)
    ));
    let current = policy.verified_settings(NOW).await.unwrap();
    policy.bump_epoch().await.unwrap();
    assert!(matches!(
        policy.validate_snapshot(&current, NOW).await,
        Err(Error::Verification)
    ));
}

#[tokio::test]
async fn current_settings_check_does_not_publish_or_advance_epoch() {
    let mut policy = memory().await;
    let epoch = policy.epoch(NOW).await.unwrap();
    let settings = policy.settings(NOW).await.unwrap();
    assert_eq!(settings.community, COMMUNITY);
    assert_eq!(settings.content["quota"], json!(10));
    assert_eq!(policy.epoch(NOW).await.unwrap(), epoch);
    assert!(
        policy
            .published(SnapshotKind::Settings, NOW)
            .await
            .unwrap()
            .is_none()
    );
    let signed = policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    let view: Snapshot<crbk::Values> = verify_snapshot(
        policy.key_ring().unwrap(),
        &signed,
        expectation(SnapshotKind::Settings, epoch, NOW),
    )
    .unwrap();
    assert_eq!(settings.content, view.content);
}

#[tokio::test]
async fn a_foreign_signer_cannot_extend_the_current_publication() {
    let mut policy = memory().await;
    let current = policy.verified_settings(NOW).await.unwrap();
    let mut foreign = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(97),
        day(NOW),
        30 * DAY,
    )
    .await
    .unwrap();
    let document = Snapshot {
        community: COMMUNITY.into(),
        revision: current.settings().revision,
        policy_epoch: current.settings().policy_epoch,
        content: current.settings().content.clone(),
    };
    let cose = foreign
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&document).unwrap(),
            day(NOW),
            30 * DAY,
        )
        .await
        .unwrap();
    let wrong = verify_settings(
        foreign.key_ring().unwrap(),
        &cose,
        expectation(SnapshotKind::Settings, current.settings().policy_epoch, NOW),
    )
    .unwrap();
    assert!(matches!(
        policy.validate_snapshot(&wrong, NOW).await,
        Err(Error::Verification)
    ));
    policy.validate_snapshot(&current, NOW).await.unwrap();
}

#[tokio::test]
async fn pure_settings_carries_the_same_effective_epoch_as_verified_publications() {
    let mut policy = memory().await;
    policy.bump_epoch().await.unwrap();
    let before = policy.epoch(NOW).await.unwrap();
    let settings = policy.settings(NOW).await.unwrap();
    assert_eq!(settings.policy_epoch, before);
    assert_eq!(settings.issued, day(NOW) as i64);
    assert!(
        policy
            .published(SnapshotKind::Settings, NOW)
            .await
            .unwrap()
            .is_none()
    );
    let verified = policy.verified_settings(NOW).await.unwrap();
    assert_eq!(verified.settings().policy_epoch, settings.policy_epoch);
    assert_eq!(verified.settings().content, settings.content);
    assert_eq!(policy.epoch(NOW).await.unwrap(), before);
}

#[tokio::test]
async fn publish_schema_versions_with_the_original_change_classifications() {
    let mut policy = memory().await;
    let mut second = schema(2);
    second.private = std::mem::take(&mut second.public);
    let changes = policy.set_schema(second.clone()).await.unwrap().unwrap();
    let signed = policy
        .publish(SnapshotKind::SchemaVersions, NOW)
        .await
        .unwrap();
    let snapshot: Snapshot<SchemaVersions> = verify_snapshot(
        policy.key_ring().unwrap(),
        &signed,
        expectation(
            SnapshotKind::SchemaVersions,
            policy.epoch(NOW).await.unwrap(),
            NOW,
        ),
    )
    .unwrap();
    assert_eq!(snapshot.content.current, 2);
    assert_eq!(
        snapshot.content.purpose,
        SchemaVersionsPurpose::SchemaVersionsV1
    );
    assert_eq!(snapshot.content.versions.len(), 2);
    assert_eq!(snapshot.content.versions[0].schema, schema(1));
    assert_eq!(snapshot.content.versions[0].changes, None);
    assert_eq!(snapshot.content.versions[1].schema, second);
    assert_eq!(snapshot.content.versions[1].changes, Some(changes));
    assert!(
        verify_snapshot::<cshm::Schema>(
            policy.key_ring().unwrap(),
            &signed,
            expectation(SnapshotKind::Schema, policy.epoch(NOW).await.unwrap(), NOW)
        )
        .is_err()
    );
    assert!(policy.set_schema(schema(1)).await.is_err());
}
