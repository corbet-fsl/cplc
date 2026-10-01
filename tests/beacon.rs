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
