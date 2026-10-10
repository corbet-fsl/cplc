//! Versioned admission decisions and migration through the real storage owners.
mod common;
use common::*;
use cplc::*;
use serde_json::{Value, json};

#[tokio::test]
async fn signed_action_attests_the_real_configured_decision() {
    let mut policy = memory().await;
    assert!(matches!(
        policy.issue_test(request(&[]), NOW).await,
        Err(Error::Denied(_))
    ));
    let bytes = policy
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    let (credential, until) = decode_credential(policy.key_ring().unwrap(), &bytes, NOW);
    assert_eq!(credential.purpose, CredentialPurpose::CommunityAdmission);
    assert_eq!(credential.issuance_action, config().credential_action);
    assert_eq!(credential.policy_epoch, policy.epoch(NOW).await.unwrap());
    assert_eq!(until, 500);
    assert_eq!(credential.gates.len(), 1);
    let envelope = policy
        .key_ring()
        .unwrap()
        .verify(&bytes, csgn::Kind::Credential, NOW)
        .unwrap();
    let payload: Value = serde_json::from_slice(envelope.payload()).unwrap();
    assert_eq!(payload["purpose"], "cplc.community-credential.v2");
    assert!(payload["gates"][0].get("proven_at").is_none());
    // Real global BBS issuance/presentation and privacy assertions are exercised
    // in global_passport.rs, through the only permitted global witness owner.
}

#[tokio::test]
async fn signed_format_never_defaults_an_absent_version_or_action() {
    let mut policy = memory().await;
    let bytes = policy
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    let (credential, _) = decode_credential(policy.key_ring().unwrap(), &bytes, NOW);
    let original = serde_json::to_value(credential).unwrap();
    for field in ["purpose", "issuance_action"] {
        let mut value = original.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(serde_json::from_value::<Credential>(value).is_err());
    }
    let mut future = original;
    future["purpose"] = json!("cplc.community-credential.v3");
    assert!(serde_json::from_value::<Credential>(future).is_err());
}

async fn reopen(db: &crlt::Db, rules: &crlt::Db) -> Result<SqlPolicy> {
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    Policy::open(
        crbk::LibsqlStore::new(rules.clone()),
        LibsqlStore::new(db, COMMUNITY).unwrap(),
        signer,
    )
    .await
}

async fn seed_legacy(db: &crlt::Db, stored: &StoredPolicy) {
    let mut document = serde_json::to_value(stored).unwrap();
    document
        .as_object_mut()
        .unwrap()
        .remove("credential_format");
    // Historical owner JSON is the migration input. This is scoped fixture
    // maintenance, not an alternate implementation of the migration.
    db.community(COMMUNITY)
        .unwrap()
        .execute(
            "UPDATE cplc_policy SET document = ?1 WHERE slot = ?2",
            crlt::params![serde_json::to_string(&document).unwrap(), 1i64],
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn reopening_legacy_sql_advances_epoch_once_and_preserves_publication_floors() {
    let (_directory, db, rules, mut stale) = local().await;
    let witness = stale.verified_settings(NOW).await.unwrap();
    let previous_feed = stale.trust_feed(NOW).await.unwrap();
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let previous = store.load().await.unwrap().unwrap();
    let previous_json = serde_json::to_value(&previous).unwrap();
    seed_legacy(&db, &previous).await;
    let mut current = reopen(&db, &rules).await.unwrap();
    assert_eq!(
        current.epoch(NOW).await.unwrap(),
        previous_feed.policy_epoch + 1
    );
    let upgraded = store.load().await.unwrap().unwrap();
    assert_eq!(upgraded.revision(), previous.revision() + 1);
    assert_eq!(upgraded.epoch(), previous.epoch() + 1);
    let upgraded_json = serde_json::to_value(&upgraded).unwrap();
    assert_eq!(
        upgraded_json["credential_format"],
        "cplc.community-credential.v2"
    );
    for (kind, publication) in previous_json["publications"].as_object().unwrap() {
        assert_eq!(
            upgraded_json["publications"][kind]["revision"],
            publication["revision"]
        );
        assert!(upgraded_json["publications"][kind]["cose"].is_null());
    }
    assert!(current.validate_snapshot(&witness, NOW).await.is_err());
    assert!(stale.publish(SnapshotKind::Settings, NOW).await.is_err());
    let bytes = current
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    let (credential, _) = decode_credential(current.key_ring().unwrap(), &bytes, NOW);
    assert_eq!(credential.policy_epoch, previous_feed.policy_epoch + 1);
    assert_eq!(credential.issuance_action, "admit");
    let refreshed = current.trust_feed(NOW).await.unwrap();
    assert_eq!(refreshed.policy_epoch, previous_feed.policy_epoch + 1);
    let before_reopen = store.load().await.unwrap().unwrap();
    drop(current);
    let reopened = reopen(&db, &rules).await.unwrap();
    assert_eq!(reopened.epoch(NOW).await.unwrap(), refreshed.policy_epoch);
    let after_reopen = store.load().await.unwrap().unwrap();
    assert_eq!(after_reopen.epoch(), before_reopen.epoch());
    assert_eq!(after_reopen.revision(), before_reopen.revision() + 1);
}

#[tokio::test]
async fn failed_upgrade_does_not_commit_a_marker_or_epoch_and_retry_upgrades_once() {
    let (directory, db, rules, policy) = local().await;
    drop(policy);
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let previous = store.load().await.unwrap().unwrap();
    seed_legacy(&db, &previous).await;
    let legacy = store.load().await.unwrap().unwrap();
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    connection
        .execute_batch(
            "CREATE TRIGGER stop_format_upgrade BEFORE UPDATE ON cplc_policy \
             BEGIN SELECT RAISE(ABORT, 'fault'); END;",
        )
        .await
        .unwrap();
    assert!(reopen(&db, &rules).await.is_err());
    assert_eq!(store.load().await.unwrap().unwrap(), legacy);
    connection
        .execute_batch("DROP TRIGGER stop_format_upgrade;")
        .await
        .unwrap();
    let upgraded = reopen(&db, &rules).await.unwrap();
    assert_eq!(
        store.load().await.unwrap().unwrap().epoch(),
        previous.epoch() + 1
    );
    drop(upgraded);
    reopen(&db, &rules).await.unwrap();
    assert_eq!(
        store.load().await.unwrap().unwrap().epoch(),
        previous.epoch() + 1
    );
}

#[tokio::test]
async fn actual_stores_reject_downgrades_and_migration_without_epoch_or_cache_invalidation() {
    let (_directory, db, _rules, mut policy) = local().await;
    policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    let sql = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let original = sql.load().await.unwrap().unwrap();
    let mut downgrade = serde_json::to_value(&original).unwrap();
    downgrade["revision"] = json!(original.revision() + 1);
    downgrade["epoch"] = json!(original.epoch() + 1);
    downgrade["credential_format"] = Value::Null;
    for publication in downgrade["publications"]
        .as_object_mut()
        .unwrap()
        .values_mut()
    {
        publication["cose"] = Value::Null;
    }
    let downgrade = serde_json::from_value(downgrade).unwrap();
    assert!(matches!(
        sql.compare_exchange(Some(original.revision()), &downgrade)
            .await,
        Err(Error::Corrupt)
    ));
    for keep_epoch in [false, true] {
        let memory = MemoryStore::new(COMMUNITY).unwrap();
        let mut legacy = serde_json::to_value(&original).unwrap();
        legacy["revision"] = json!(1);
        legacy.as_object_mut().unwrap().remove("credential_format");
        let old: StoredPolicy = serde_json::from_value(legacy.clone()).unwrap();
        memory.compare_exchange(None, &old).await.unwrap();
        legacy["revision"] = json!(2);
        legacy["credential_format"] = json!("cplc.community-credential.v2");
        if keep_epoch {
            for publication in legacy["publications"].as_object_mut().unwrap().values_mut() {
                publication["cose"] = Value::Null;
            }
        } else {
            legacy["epoch"] = json!(old.epoch() + 1);
        }
        let next = serde_json::from_value(legacy).unwrap();
        assert!(matches!(
            memory.compare_exchange(Some(1), &next).await,
            Err(Error::Corrupt)
        ));
        assert_eq!(memory.load().await.unwrap().unwrap(), old);
    }
}

#[tokio::test]
async fn unknown_stored_format_and_exhausted_migration_epochs_refuse_without_writing() {
    for case in ["future", "facade-overflow", "effective-overflow"] {
        let (_directory, db, rules, policy) = local().await;
        drop(policy);
        let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
        let stored = store.load().await.unwrap().unwrap();
        let mut document = serde_json::to_value(&stored).unwrap();
        document
            .as_object_mut()
            .unwrap()
            .remove("credential_format");
        match case {
            "future" => document["credential_format"] = json!("cplc.community-credential.v3"),
            "facade-overflow" => document["epoch"] = json!(i64::MAX),
            _ => document["epoch"] = json!(i64::MAX - 1),
        }
        let encoded = serde_json::to_string(&document).unwrap();
        let scope = db.community(COMMUNITY).unwrap();
        scope
            .execute(
                "UPDATE cplc_policy SET document = ?1 WHERE slot = ?2",
                crlt::params![encoded.clone(), 1i64],
            )
            .await
            .unwrap();
        assert!(reopen(&db, &rules).await.is_err(), "{case}");
        let rows = scope
            .query(
                "SELECT revision, document FROM cplc_policy WHERE slot = ?1",
                crlt::params![1i64],
            )
            .await
            .unwrap();
        assert_eq!(rows[0].get_i64(0).unwrap(), stored.revision() as i64);
        assert_eq!(rows[0].get_str(1).unwrap(), encoded);
    }
}
