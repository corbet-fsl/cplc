//! Real libSQL persistence, isolation, failure and cancellation integration tests.

mod common;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use common::*;
use cplc::{crbk, crlt, csgn, *};
use serde_json::{Value, json};

#[tokio::test]
async fn real_file_roundtrip_restart_rotation_and_index_plans() {
    let (dir, db, rules_db, mut policy) = local().await;
    db.migrate(&migrations()).await.unwrap();
    LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .check_query_plans()
        .await
        .unwrap();
    csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap())
        .check_query_plans()
        .await
        .unwrap();
    crbk::LibsqlStore::new(rules_db.clone())
        .check_query_plans(COMMUNITY)
        .await
        .unwrap();
    let old = policy
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    let published = policy.publish(SnapshotKind::Schema, NOW).await.unwrap();
    policy.rotate(key(2), 101).await.unwrap();
    drop(policy);
    drop(db);
    drop(rules_db);
    let url = format!("file://{}", dir.path().join("policy.db").display());
    let (db, rules_db) = databases(&url, "").await;
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(2),
        day(102),
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
    assert!(
        reopened
            .key_ring()
            .unwrap()
            .verify(&old, csgn::Kind::Credential, 102)
            .is_ok()
    );
    assert_eq!(
        reopened.published(SnapshotKind::Schema, 102).await.unwrap(),
        Some(published)
    );
    let refreshed = reopened.publish(SnapshotKind::Schema, 102).await.unwrap();
    let snapshot: Snapshot<Value> = verify_snapshot(
        reopened.key_ring().unwrap(),
        &refreshed,
        expectation(
            SnapshotKind::Schema,
            reopened.epoch(102).await.unwrap(),
            102,
        ),
    )
    .unwrap();
    assert_eq!(snapshot.revision, 2);
    assert!(
        reopened
            .issue_test(request(&[development_gate(500)]), 102)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn community_namespaces_cannot_read_each_other_in_one_test_database() {
    let (_dir, db, rules_db, mut first) = local().await;
    let second_store = LibsqlStore::new(&db, "second").unwrap();
    assert!(second_store.load().await.unwrap().is_none());
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(db.community("second").unwrap()),
        "second",
        key(2),
        day(NOW),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    let mut second = Policy::create(
        crbk::LibsqlStore::new(rules_db),
        second_store,
        signer,
        config(),
    )
    .await
    .unwrap();
    second
        .schedule_rules(None, change(book(admission()), 1, NOW as i64))
        .await
        .unwrap();
    let mut other_schema = schema(1);
    other_schema.community = "second".into();
    second.set_schema(other_schema).await.unwrap();
    let a = first.publish(SnapshotKind::Schema, NOW).await.unwrap();
    let b = second.publish(SnapshotKind::Schema, NOW).await.unwrap();
    assert_ne!(a, b);
    assert!(
        second
            .key_ring()
            .unwrap()
            .verify(&a, csgn::Kind::SchemaSnapshot, NOW)
            .is_err()
    );
    assert_eq!(
        first.published(SnapshotKind::Schema, NOW).await.unwrap(),
        Some(a)
    );
    assert_eq!(
        second.published(SnapshotKind::Schema, NOW).await.unwrap(),
        Some(b)
    );
}

#[tokio::test]
async fn issuance_keeps_no_member_credential_or_activity_record() {
    let (_dir, db, _rules_db, mut policy) = local().await;
    policy.verified_settings(NOW).await.unwrap();
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let before = store.load().await.unwrap().unwrap();
    policy
        .issue_test(request(&[development_gate(500)]), NOW)
        .await
        .unwrap();
    let after = store.load().await.unwrap().unwrap();
    assert_eq!(before, after);
    let policy_json = serde_json::to_string(&after).unwrap();
    assert!(!policy_json.contains(MEMBER));
    assert!(!policy_json.contains("testmember"));
    assert!(!policy_json.contains("proven_at"));
    let rows = db
        .community(COMMUNITY)
        .unwrap()
        .query(
            "SELECT state FROM csgn_state WHERE issuer = ?1",
            [COMMUNITY],
        )
        .await
        .unwrap();
    let crlt::Value::Blob(bytes) = rows[0].get_value(0).unwrap() else {
        panic!("signer metadata must be binary");
    };
    assert!(!bytes.windows(MEMBER.len()).any(|w| w == MEMBER.as_bytes()));
}

#[tokio::test]
async fn opening_new_writer_fences_old_policy_and_signer() {
    let (_dir, db, rules_db, mut old) = local().await;
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    let mut new = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert!(matches!(
        old.issue_test(request(&[development_gate(500)]), NOW).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(old.bump_epoch().await, Err(Error::Conflict)));
    assert!(matches!(
        old.publish(SnapshotKind::Schema, NOW).await,
        Err(Error::Conflict)
    ));
    assert!(
        new.issue_test(request(&[development_gate(500)]), NOW)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn atomic_compare_exchange_has_one_winner_and_never_resets_counters() {
    let (_dir, db, _rules_db, _policy) = local().await;
    let first = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let second = first.clone();
    let state = first.load().await.unwrap().unwrap();
    let mut json = serde_json::to_value(&state).unwrap();
    json["revision"] = (state.revision() + 1).into();
    let next: StoredPolicy = serde_json::from_value(json).unwrap();
    let (a, b) = tokio::join!(
        first.compare_exchange(Some(state.revision()), &next),
        second.compare_exchange(Some(state.revision()), &next)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    assert!(matches!(a, Err(Error::Conflict)) || matches!(b, Err(Error::Conflict)));
    assert!(matches!(
        first.compare_exchange(None, &state).await,
        Err(Error::Conflict)
    ));
    assert_eq!(first.load().await.unwrap().unwrap(), next);
}

#[tokio::test]
async fn storage_rejects_tampering_and_cross_scope_state() {
    let (_dir, db, _rules_db, _policy) = local().await;
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let state = store.load().await.unwrap().unwrap();
    let mut document = serde_json::to_value(&state).unwrap();
    document["revision"] = (state.revision() + 1).into();
    document["community"] = "foreign".into();
    let foreign: StoredPolicy = serde_json::from_value(document).unwrap();
    assert!(matches!(
        store
            .compare_exchange(Some(state.revision()), &foreign)
            .await,
        Err(Error::Corrupt)
    ));
    db.community(COMMUNITY)
        .unwrap()
        .execute(
            "UPDATE cplc_policy SET document = ?1 WHERE slot = ?2",
            crlt::params!["{not-json", 1i64],
        )
        .await
        .unwrap();
    assert!(matches!(store.load().await, Err(Error::Corrupt)));
}

#[tokio::test]
async fn real_database_failure_after_signing_returns_no_publication() {
    let dir = tempfile::tempdir().unwrap();
    let url = format!("file://{}", dir.path().join("constrained.db").display());
    let db = crlt::Db::open(crlt::Config::new(&url, "")).await.unwrap();
    // A real SQL constraint rejects the larger signed publication document,
    // while allowing initial configuration and csgn retention to commit.
    let constrained = SCHEMA.replace(
        "document TEXT NOT NULL",
        "document TEXT NOT NULL CHECK (length(document) < 1800)",
    );
    db.migrate(&[
        crlt::Migration::new(1, "rulebook", crbk::SCHEMA),
        crlt::Migration::new(2, "signing", csgn::SCHEMA),
        crlt::Migration::new(3, "policy", &constrained),
    ])
    .await
    .unwrap();
    let rules_db = db.clone();
    let mut policy = sql_policy(&db, &rules_db, COMMUNITY).await;
    configure(&mut policy, book(admission())).await;
    let before = LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .load()
        .await
        .unwrap();
    let error = policy
        .publish(SnapshotKind::Settings, NOW)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Storage));
    assert!(matches!(policy.key_ring(), Err(Error::ReloadRequired)));
    assert_eq!(
        before,
        LibsqlStore::new(&db, COMMUNITY)
            .unwrap()
            .load()
            .await
            .unwrap()
    );
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    let reopened = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened
            .published(SnapshotKind::Settings, NOW)
            .await
            .unwrap(),
        None
    );
}

// A scheduling barrier around real storage, not a substitute for persistence or
// policy logic. It lets the test drop a future at the exact publication boundary.
struct PausedStore {
    real: LibsqlStore,
    pause: Arc<AtomicBool>,
    entered: Arc<tokio::sync::Notify>,
    resume: Arc<tokio::sync::Notify>,
}
impl Storage for PausedStore {
    fn community(&self) -> &str {
        self.real.community()
    }
    async fn load(&self) -> Result<Option<StoredPolicy>> {
        self.real.load().await
    }
    async fn compare_exchange(&self, expected: Option<u64>, next: &StoredPolicy) -> Result<()> {
        if self.pause.load(Ordering::SeqCst) {
            self.entered.notify_one();
            self.resume.notified().await;
        }
        self.real.compare_exchange(expected, next).await
    }
}

#[tokio::test]
async fn cancelling_publication_disables_writer_and_preserves_committed_state() {
    let (_dir, db, rules_db, old) = local().await;
    drop(old);
    let pause = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(tokio::sync::Notify::new());
    let store = PausedStore {
        real: LibsqlStore::new(&db, COMMUNITY).unwrap(),
        pause: pause.clone(),
        entered: entered.clone(),
        resume: Arc::new(tokio::sync::Notify::new()),
    };
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
    let before = LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .load()
        .await
        .unwrap();
    pause.store(true, Ordering::SeqCst);
    {
        let publish = policy.publish(SnapshotKind::Schema, NOW);
        tokio::pin!(publish);
        tokio::select! {
            _ = entered.notified() => {},
            result = &mut publish => panic!("publication passed the barrier: {result:?}"),
        }
    }
    assert!(matches!(policy.key_ring(), Err(Error::ReloadRequired)));
    assert_eq!(
        before,
        LibsqlStore::new(&db, COMMUNITY)
            .unwrap()
            .load()
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn memory_and_sql_stores_reject_the_same_invalid_transition() {
    let (_dir, db, _rules_db, _policy) = local().await;
    let sql = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let state = sql.load().await.unwrap().unwrap();
    let memory = MemoryStore::new(COMMUNITY).unwrap();
    let mut initial = serde_json::to_value(&state).unwrap();
    initial["revision"] = 1.into();
    let initial: StoredPolicy = serde_json::from_value(initial).unwrap();
    memory.compare_exchange(None, &initial).await.unwrap();
    for (current, sql_backend) in [(state, true), (initial, false)] {
        let mut invalid = serde_json::to_value(&current).unwrap();
        invalid["revision"] = (current.revision() + 1).into();
        invalid["epoch"] = 0.into();
        let invalid: StoredPolicy = serde_json::from_value(invalid).unwrap();
        let result = if sql_backend {
            sql.compare_exchange(Some(current.revision()), &invalid)
                .await
        } else {
            memory
                .compare_exchange(Some(current.revision()), &invalid)
                .await
        };
        assert!(matches!(result, Err(Error::Corrupt)));
    }
}

#[tokio::test]
async fn storage_refuses_rewriting_admission_configuration() {
    let (_dir, db, _rules_db, _policy) = local().await;
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let state = store.load().await.unwrap().unwrap();
    let mut changed = serde_json::to_value(&state).unwrap();
    changed["revision"] = (state.revision() + 1).into();
    changed["config"]["credential_action"] = json!("unauthorized_action");
    let changed: StoredPolicy = serde_json::from_value(changed).unwrap();
    assert!(matches!(
        store
            .compare_exchange(Some(state.revision()), &changed)
            .await,
        Err(Error::Corrupt)
    ));
}

#[tokio::test]
async fn indexed_revocations_exceed_256_and_survive_reopening() {
    let (_dir, db, rules_db, mut policy) = local().await;
    let mut revocations = Revocations::default();
    for i in 0..257u32 {
        revocations.members.insert(format!("member-{i}"));
        let mut device = [0; 32];
        device[..4].copy_from_slice(&i.to_be_bytes());
        revocations.devices.insert(device);
    }
    policy.set_revocations(revocations.clone()).await.unwrap();
    drop(policy);
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    let mut policy = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert_eq!(policy.revocations().unwrap(), &revocations);
    let mut input = request(&[]);
    input.subject.id = "member-256";
    assert!(matches!(
        policy.issue_test(input, NOW).await,
        Err(Error::Revoked)
    ));
    policy
        .set_revocations(Revocations::default())
        .await
        .unwrap();
    assert!(policy.revocations().unwrap().members.is_empty());
    LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .check_query_plans()
        .await
        .unwrap();
}

#[tokio::test]
async fn bounded_schema_history_remains_publishable_after_rejection_and_restart() {
    let (_dir, db, rules_db, mut policy) = local().await;
    for version in 2..=5 {
        let mut next = schema(version);
        next.public[0].label = "x".repeat(180_000);
        policy.set_schema(next).await.unwrap();
    }
    let epoch = policy.epoch(NOW).await.unwrap();
    let mut oversized = schema(6);
    oversized.public[0].label = "x".repeat(180_000);
    assert!(policy.set_schema(oversized).await.is_err());
    assert_eq!(policy.schema().unwrap().unwrap().version, 5);
    assert_eq!(policy.epoch(NOW).await.unwrap(), epoch);
    let kinds = [
        SnapshotKind::Settings,
        SnapshotKind::Schema,
        SnapshotKind::SchemaVersions,
        SnapshotKind::Communities,
        SnapshotKind::RevocationList,
    ];
    for kind in kinds {
        policy.publish(kind, NOW).await.unwrap();
    }
    let state = LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .load()
        .await
        .unwrap()
        .unwrap();
    assert!(serde_json::to_vec(&state).unwrap().len() > MAX_DOCUMENT_BYTES);
    drop(policy);
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        day(NOW),
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
    reopened.bump_epoch().await.unwrap();
    for kind in kinds {
        let bytes = reopened.publish(kind, NOW).await.unwrap();
        let _: Snapshot<Value> = verify_snapshot(
            reopened.key_ring().unwrap(),
            &bytes,
            expectation(kind, reopened.epoch(NOW).await.unwrap(), NOW),
        )
        .unwrap();
    }
}
