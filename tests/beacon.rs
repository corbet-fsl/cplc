//! Real Beacon publication and durable writer-fence tests.
mod common;
use common::*;
use cplc::*;

#[tokio::test]
async fn beacon_preserves_current_bytes_and_refreshes_real_policy_changes() {
    let mut policy = memory().await;
    let initial = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(policy.trust_feed(NOW + 1).await.unwrap(), initial);
    assert!(
        !policy
            .trust_changes(initial.revision, NOW + 1)
            .await
            .unwrap()
            .changed
    );
    assert!(policy.trust_changes(0, NOW + 1).await.unwrap().changed);
    let ring = policy.key_ring().unwrap();
    assert!(
        ring.verify(&initial.settings, csgn::Kind::SettingsSnapshot, NOW)
            .is_ok()
    );
    assert!(
        ring.verify(
            &initial.revocations,
            csgn::Kind::RevocationListSnapshot,
            NOW
        )
        .is_ok()
    );
    policy
        .set_revocations(Revocations {
            members: [MEMBER.into()].into(),
            devices: [DEVICE].into(),
        })
        .await
        .unwrap();
    let revoked = policy.trust_feed(NOW + 2).await.unwrap();
    assert!(revoked.revision > initial.revision);
    assert!(revoked.policy_epoch > initial.policy_epoch);
    assert_ne!(revoked.revocations, initial.revocations);
    assert!(
        policy
            .trust_changes(initial.revision, NOW + 2)
            .await
            .unwrap()
            .changed
    );
    assert!(
        policy
            .trust_changes(revoked.revision + 1, NOW + 2)
            .await
            .is_err()
    );
    assert!(policy.trust_feed(NOW + 1).await.is_err());
}

#[tokio::test]
async fn beacon_uses_durable_real_sql_publications_and_reopen_fences() {
    let (_dir, db, rules_db, mut policy) = local().await;
    let first = policy.refresh_trust(NOW).await.unwrap();
    let (signer_store, store) = (
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
    );
    let signer = csgn::PersistentSigner::open(signer_store, COMMUNITY, key(1), day(NOW))
        .await
        .unwrap();
    let mut reopened = Policy::open(crbk::LibsqlStore::new(rules_db), store, signer)
        .await
        .unwrap();
    assert!(policy.trust_feed(NOW).await.is_err());
    let current = reopened.trust_feed(NOW).await.unwrap();
    assert!(current.revision > first.revision);
    assert_eq!(reopened.trust_feed(NOW + 1).await.unwrap(), current);
}

#[tokio::test]
async fn beacon_refreshes_rotated_keys_and_expired_envelopes() {
    let mut policy = memory().await;
    let initial = policy.trust_feed(NOW).await.unwrap();
    policy.rotate(key(99), NOW + 1).await.unwrap();
    let rotated = policy.trust_feed(NOW + 1).await.unwrap();
    assert_ne!(rotated.key_ring, initial.key_ring);
    assert!(rotated.revision > initial.revision);
    let refreshed = policy.trust_feed(NOW + DAY).await.unwrap();
    assert!(refreshed.revision > rotated.revision);
    assert!(
        policy
            .key_ring()
            .unwrap()
            .verify(&refreshed.settings, csgn::Kind::SettingsSnapshot, NOW + DAY,)
            .is_ok()
    );
}

#[tokio::test]
async fn beacon_refreshes_at_scheduled_policy_activation() {
    let mut policy = memory().await;
    policy
        .schedule_rules(Some(1), change(book(admission()), 2, DAY as i64))
        .await
        .unwrap();
    let before = policy.trust_feed(NOW).await.unwrap();
    let after = policy.trust_feed(DAY).await.unwrap();
    assert!(after.policy_epoch > before.policy_epoch);
    assert!(after.revision > before.revision);
}

#[tokio::test]
async fn beacon_detects_a_rulebook_change_without_a_policy_store_revision_change() {
    let (_directory, _db, rules_db, mut policy) = local().await;
    let rules = crbk::LibsqlStore::new(rules_db);
    let before = policy.trust_feed(NOW).await.unwrap();
    // Fault the actual upstream rulebook store independently of the facade's
    // publication counter. A cached feed must not hide the changed authority.
    let current = crbk::Storage::load(&rules, COMMUNITY, crbk::Selection::Latest)
        .await
        .unwrap()
        .unwrap();
    crbk::Storage::append(
        &rules,
        COMMUNITY,
        Some(1),
        change(current.change.rulebook, 2, (NOW + 1) as i64),
    )
    .await
    .unwrap();
    let after = policy.trust_feed(NOW + 1).await.unwrap();
    assert!(after.policy_epoch > before.policy_epoch);
    assert!(after.revision > before.revision);
}

#[tokio::test]
async fn partial_sql_publication_failure_never_exposes_a_mixed_cached_feed() {
    let (directory, db, rules_db, mut policy) = local().await;
    let before = policy.trust_feed(NOW).await.unwrap();
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    raw.connect().unwrap().execute_batch(
        "CREATE TRIGGER stop_partial BEFORE UPDATE ON cplc_policy WHEN json_extract(NEW.document, '$.publications.schema_versions.revision') > 1 BEGIN SELECT RAISE(ABORT, 'fault'); END;",
    ).await.unwrap();
    assert!(matches!(
        policy.refresh_trust(NOW + 1).await,
        Err(Error::Verification)
    ));
    assert!(policy.trust_feed(NOW + 1).await.is_err());
    raw.connect()
        .unwrap()
        .execute_batch("DROP TRIGGER stop_partial;")
        .await
        .unwrap();
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        0,
    )
    .await
    .unwrap();
    let mut reopened = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    let after = reopened.trust_feed(NOW + 2).await.unwrap();
    assert!(after.revision > before.revision);
    assert_ne!(after.settings, before.settings);
    assert_ne!(after.schema_versions, before.schema_versions);
}
