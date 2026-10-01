//! Real signed publications and legacy SQL documents exercise owner boundaries.
mod common;
use common::*;
use cplc::*;
use serde_json::json;

#[tokio::test]
async fn signed_settings_still_require_current_scope_time_and_content() {
    let mut policy = memory().await;
    let current = policy.verified_settings(NOW).await.unwrap();
    for case in 0..4 {
        let community = if case == 0 { "foreign" } else { COMMUNITY };
        let issued = if case == 1 { DAY } else { 0 };
        let now = if case == 2 { DAY } else { NOW };
        let mut signer = csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            community,
            key(81),
            0,
            30 * DAY,
        )
        .await
        .unwrap();
        let mut content = current.settings().content.clone();
        if case == 3 {
            content.insert("quota".into(), json!(11));
        }
        let document = Snapshot {
            community: community.into(),
            revision: current.settings().revision,
            policy_epoch: current.settings().policy_epoch,
            content,
        };
        let signed = signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&document).unwrap(),
                issued,
                issued + DAY,
            )
            .await
            .unwrap();
        let verified = verify_settings(
            signer.key_ring().unwrap(),
            &signed,
            SnapshotExpectation {
                community,
                kind: SnapshotKind::Settings,
                minimum_revision: 1,
                policy_epoch: current.settings().policy_epoch,
                now: issued,
            },
        )
        .unwrap();
        assert!(matches!(
            policy.validate_snapshot(&verified, now).await,
            Err(Error::Verification)
        ));
    }
}

#[tokio::test]
async fn schema_limits_and_real_legacy_archive_upgrade_are_preserved() {
    let (_directory, db, rules_db, policy) = local().await;
    drop(policy);
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let stored = store.load().await.unwrap().unwrap();
    let mut document = serde_json::to_value(stored).unwrap();
    document.as_object_mut().unwrap().remove("schema_versions");
    db.community(COMMUNITY)
        .unwrap()
        .execute(
            "UPDATE cplc_policy SET document = ?1 WHERE slot = ?2",
            crlt::params![serde_json::to_string(&document).unwrap(), 1i64],
        )
        .await
        .unwrap();
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    let mut policy = Policy::open(crbk::LibsqlStore::new(rules_db), store, signer)
        .await
        .unwrap();
    let signed = policy
        .publish(SnapshotKind::SchemaVersions, NOW)
        .await
        .unwrap();
    let first: Snapshot<SchemaVersions> = verify_snapshot(
        policy.key_ring().unwrap(),
        &signed,
        expectation(
            SnapshotKind::SchemaVersions,
            policy.epoch(NOW).await.unwrap(),
            NOW,
        ),
    )
    .unwrap();
    assert_eq!(first.content.versions.len(), 1);
    assert_eq!(first.content.versions[0].schema, schema(1));
    let mut oversized = schema(2);
    oversized.public = vec![oversized.public[0].clone(); MAX_ENTRIES + 1];
    assert!(matches!(
        policy.set_schema(oversized).await,
        Err(Error::Invalid("schema scope or size"))
    ));
    policy.set_schema(schema(2)).await.unwrap();
    let signed = policy
        .publish(SnapshotKind::SchemaVersions, NOW)
        .await
        .unwrap();
    let updated: Snapshot<SchemaVersions> = verify_snapshot(
        policy.key_ring().unwrap(),
        &signed,
        expectation(
            SnapshotKind::SchemaVersions,
            policy.epoch(NOW).await.unwrap(),
            NOW,
        ),
    )
    .unwrap();
    assert_eq!(updated.content.versions.len(), 2);
    assert_eq!(updated.content.versions[0].schema, schema(1));
    assert_eq!(updated.content.versions[1].schema, schema(2));
}

#[tokio::test]
async fn live_decision_refuses_a_checked_collection_rebound_to_another_action() {
    let mut policy = memory().await;
    let current = policy.verified_settings(NOW).await.unwrap();
    let checked = checked(&current, MEMBER, "admit", &[], NOW).await.unwrap();
    assert!(matches!(
        policy
            .may(&current, subject(), "another", &checked, NOW)
            .await,
        Err(Error::Verification)
    ));
    assert!(
        verify_settings(
            policy.key_ring().unwrap(),
            b"malformed",
            expectation(SnapshotKind::Settings, current.settings().policy_epoch, NOW)
        )
        .is_err()
    );
}

#[tokio::test]
async fn complete_archive_and_resolved_settings_respect_signed_payload_budget() {
    let mut policy = memory().await;
    let mut first = schema(2);
    first.public[0].label = "a".repeat(300_000);
    policy.set_schema(first).await.unwrap();
    let mut next = schema(3);
    next.public[0].label = "b".repeat(800_000);
    assert!(matches!(
        policy.set_schema(next).await,
        Err(Error::Invalid("payload size"))
    ));
    // The rejected archive leaves the prior schema and signed publication usable.
    policy.publish(SnapshotKind::Schema, NOW).await.unwrap();

    let mut rules = book(admission());
    rules
        .define(
            "large",
            crbk::Setting {
                value_type: crbk::SettingType::String,
                nullable: false,
                default: json!("x".repeat(MAX_DOCUMENT_BYTES)),
                bounds: Default::default(),
                lowest_layer: crbk::Layer::Community,
                kind: crbk::SettingKind::Technical,
            },
        )
        .unwrap();
    let mut policy = memory_with(rules).await;
    assert!(matches!(
        policy.publish(SnapshotKind::Settings, NOW).await,
        Err(Error::Invalid("payload size"))
    ));
}
