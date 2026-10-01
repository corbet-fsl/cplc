//! Real policy stores reject corrupted documents and invalid transitions.
mod common;
use common::*;
use cplc::*;
use serde_json::{Value, json};

async fn baseline() -> (MemoryStore, StoredPolicy) {
    baseline_after(false).await
}

async fn baseline_after(advance: bool) -> (MemoryStore, StoredPolicy) {
    let store = MemoryStore::new(COMMUNITY).unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(1),
        day(NOW),
        30 * DAY,
    )
    .await
    .unwrap();
    let mut policy = Policy::create(
        crbk::MemoryStore::default(),
        store.clone(),
        signer,
        config(),
    )
    .await
    .unwrap();
    configure(&mut policy, book(admission())).await;
    policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    if advance {
        policy.set_schema(schema(2)).await.unwrap();
        policy.publish(SnapshotKind::Settings, NOW).await.unwrap();
    }
    (store.clone(), store.load().await.unwrap().unwrap())
}

#[tokio::test]
async fn actual_memory_store_rejects_each_corrupt_document_boundary() {
    let (store, old) = baseline().await;
    assert_eq!(old.community(), COMMUNITY);
    assert!(old.epoch() > 0);
    let base = serde_json::to_value(&old).unwrap();
    for case in 0..24 {
        let mut next = base.clone();
        next["revision"] = json!(old.revision() + 1);
        match case {
            0 => next["revision"] = json!(0),
            1 => next["revision"] = json!(u64::MAX),
            2 => next["epoch"] = json!(0),
            3 => next["epoch"] = json!(u64::MAX),
            4 => {
                next["communities"] = json!(
                    (0..=MAX_ENTRIES)
                        .map(|i| format!("c{i}"))
                        .collect::<Vec<_>>()
                )
            }
            5 => {
                next["schema"]["public"] =
                    json!(vec![next["schema"]["public"][0].clone(); MAX_ENTRIES + 1])
            }
            6 => next["schema"]["version"] = json!(0),
            7 => {
                next["schema_versions"] =
                    json!(vec![next["schema_versions"][0].clone(); MAX_ENTRIES + 1])
            }
            8 => next["schema_versions"][0]["schema"]["community"] = json!("other"),
            9 => {
                next["schema_versions"][0]["schema"]["public"] =
                    json!(vec![next["schema"]["public"][0].clone(); MAX_ENTRIES + 1])
            }
            10 => next["schema_versions"][0]["schema"]["version"] = json!(0),
            11 => {
                next["schema_versions"][0]["changes"] =
                    serde_json::to_value(cshm::classify_changes(&schema(1), &schema(2)).unwrap())
                        .unwrap()
            }
            12 => next["schema"]["version"] = json!(2),
            13 => next["publications"]["settings"]["revision"] = json!(0),
            14 => next["publications"]["settings"]["revision"] = json!(u64::MAX),
            15 => next["publications"]["settings"]["cose"] = json!([]),
            16 => {
                next["publications"]["settings"]["cose"] =
                    json!(vec![0u8; MAX_DOCUMENT_BYTES + 8193])
            }
            17 => next["communities"] = json!(["bad\u{0}community"]),
            18 => next["revocations"]["members"] = json!(["x".repeat(257)]),
            19 => next["schema"]["community"] = json!("other"),
            20 => next["community"] = json!(""),
            21 => next["schema"]["public"][0]["label"] = json!("x".repeat(MAX_DOCUMENT_BYTES)),
            22 => next["config"]["credential_action"] = json!(""),
            _ => next["schema_versions"] = json!(vec![next["schema_versions"][0].clone(); 2]),
        }
        let next: StoredPolicy = serde_json::from_value(next).unwrap();
        assert!(
            store
                .compare_exchange(Some(old.revision()), &next)
                .await
                .is_err(),
            "case {case}"
        );
        assert_eq!(store.load().await.unwrap().as_ref(), Some(&old));
    }
}

#[tokio::test]
async fn actual_memory_store_refuses_nonmonotonic_transition_metadata() {
    let (store, old) = baseline().await;
    let base = serde_json::to_value(&old).unwrap();
    for case in 0..9 {
        let mut next = base.clone();
        next["revision"] = json!(old.revision() + 1);
        match case {
            0 => next["revision"] = json!(old.revision() + 2),
            1 => {
                next["community"] = json!("other");
                next["schema"]["community"] = json!("other");
                next["schema_versions"][0]["schema"]["community"] = json!("other");
            }
            2 => next["epoch"] = json!(old.epoch() - 1),
            3 => next["config"]["snapshot_validity"] = json!(2 * DAY),
            4 => {
                next["schema"] = Value::Null;
                next["schema_versions"] = json!([]);
            }
            5 => {
                next["schema"]["public"][0]["label"] = json!("Changed at same version");
                next["schema_versions"] = json!([]);
            }
            6 => next["publications"] = json!({}),
            7 => next["publications"]["settings"]["cose"] = json!([1, 2, 3]),
            _ => next["revision"] = json!(old.revision()),
        }
        let next: StoredPolicy = serde_json::from_value(next).unwrap();
        assert!(
            store
                .compare_exchange(Some(old.revision()), &next)
                .await
                .is_err(),
            "case {case}"
        );
        assert_eq!(store.load().await.unwrap().as_ref(), Some(&old));
    }
}

#[tokio::test]
async fn actual_sql_decoder_rejects_bad_scope_revision_and_revocation_rows() {
    for case in 0..6 {
        let (_dir, db, _, _policy) = local().await;
        let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
        let old = store.load().await.unwrap().unwrap();
        let scope = db.community(COMMUNITY).unwrap();
        match case {
            0 => {
                scope
                    .execute(
                        "UPDATE cplc_policy SET document = ?1 WHERE slot = ?2",
                        crlt::params![
                            "x".repeat(
                                MAX_DOCUMENT_BYTES + 5 * 4 * (MAX_DOCUMENT_BYTES + 8192) + 1
                            ),
                            1i64
                        ],
                    )
                    .await
                    .unwrap();
            }
            1 => {
                let mut value = serde_json::to_value(&old).unwrap();
                value["community"] = json!("other");
                value["schema"] = Value::Null;
                value["schema_versions"] = json!([]);
                scope
                    .execute(
                        "UPDATE cplc_policy SET document = ?1 WHERE slot = ?2",
                        crlt::params![serde_json::to_string(&value).unwrap(), 1i64],
                    )
                    .await
                    .unwrap();
            }
            2 => {
                scope
                    .execute(
                        "UPDATE cplc_policy SET revision = ?1 WHERE slot = ?2",
                        crlt::params![99i64, 1i64],
                    )
                    .await
                    .unwrap();
            }
            3 => {
                scope
                    .execute(
                        "INSERT INTO cplc_revocation (entry) VALUES (?1)",
                        ["unknown:entry"],
                    )
                    .await
                    .unwrap();
            }
            4 => {
                scope
                    .execute(
                        "INSERT INTO cplc_revocation (entry) VALUES (?1)",
                        ["device:malformed"],
                    )
                    .await
                    .unwrap();
            }
            _ => {
                scope
                    .execute(
                        "UPDATE cplc_policy SET document = ?1 WHERE slot = ?2",
                        crlt::params!["{}", 1i64],
                    )
                    .await
                    .unwrap();
            }
        }
        assert!(
            matches!(store.load().await, Err(Error::Corrupt)),
            "case {case}"
        );
    }
}

#[tokio::test]
async fn real_sql_triggers_and_missing_revocation_storage_refuse_partial_writes() {
    for case in 0..4 {
        let (directory, db, _rules, mut policy) = local().await;
        if case == 2 {
            policy
                .set_revocations(Revocations {
                    members: [MEMBER.into()].into(),
                    devices: Default::default(),
                })
                .await
                .unwrap();
        }
        let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
        let old = store.load().await.unwrap().unwrap();
        let mut next = serde_json::to_value(&old).unwrap();
        next["revision"] = json!(old.revision() + 1);
        next["revocations"]["members"] = if case == 1 {
            json!([MEMBER])
        } else {
            json!([])
        };
        let next: StoredPolicy = serde_json::from_value(next).unwrap();
        // Deliberately fault the actual upstream database, outside the guarded crlt migration API.
        let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
            .build()
            .await
            .unwrap();
        let fault = match case {
            0 => {
                "CREATE TRIGGER stop_update BEFORE UPDATE ON cplc_policy BEGIN SELECT RAISE(IGNORE); END;"
            }
            1 => {
                "CREATE TRIGGER stop_revoke BEFORE INSERT ON cplc_revocation BEGIN SELECT RAISE(ABORT, 'fault'); END;"
            }
            2 => {
                "CREATE TRIGGER stop_restore BEFORE DELETE ON cplc_revocation BEGIN SELECT RAISE(ABORT, 'fault'); END;"
            }
            _ => "DROP TABLE cplc_revocation;",
        };
        raw.connect().unwrap().execute_batch(fault).await.unwrap();
        let result = store.compare_exchange(Some(old.revision()), &next).await;
        if case == 0 {
            assert!(matches!(result, Err(Error::Conflict)));
        } else {
            assert!(matches!(result, Err(Error::Storage)));
        }
        if case != 3 {
            assert_eq!(store.load().await.unwrap().as_ref(), Some(&old));
        }
    }
}

#[tokio::test]
async fn actual_store_refuses_lower_schema_and_publication_versions() {
    let (store, old) = baseline_after(true).await;
    for schema_rollback in [true, false] {
        let mut next = serde_json::to_value(&old).unwrap();
        next["revision"] = json!(old.revision() + 1);
        if schema_rollback {
            next["schema"] = serde_json::to_value(schema(1)).unwrap();
            next["schema_versions"] = json!([next["schema_versions"][0].clone()]);
        } else {
            next["publications"]["settings"]["revision"] = json!(1);
        }
        let next: StoredPolicy = serde_json::from_value(next).unwrap();
        assert!(matches!(
            store.compare_exchange(Some(old.revision()), &next).await,
            Err(Error::Corrupt)
        ));
        assert_eq!(store.load().await.unwrap().as_ref(), Some(&old));
    }
}

#[tokio::test]
async fn query_plan_checks_refuse_missing_storage() {
    let (directory, db, _, policy) = local().await;
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    raw.connect()
        .unwrap()
        .execute_batch("DROP TABLE cplc_revocation;")
        .await
        .unwrap();
    drop(policy);
    drop(db);
    drop(raw);
    let url = format!("file://{}", directory.path().join("policy.db").display());
    let (reopened, _) = databases(&url, "").await;
    let result = LibsqlStore::new(&reopened, COMMUNITY)
        .unwrap()
        .check_query_plans()
        .await;
    assert!(matches!(result, Err(Error::Storage)), "{result:?}");
}

#[tokio::test]
async fn refreshed_connection_refuses_an_actual_unindexed_plan() {
    let (directory, db, _, _policy) = local().await;
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    raw.connect().unwrap().execute_batch("DROP TABLE cplc_revocation; CREATE TABLE cplc_revocation (community_id TEXT NOT NULL, entry TEXT NOT NULL);").await.unwrap();
    // Execute a new statement to refresh SQLite's cached schema after external DDL.
    db.community(COMMUNITY)
        .unwrap()
        .query("SELECT slot FROM cplc_policy WHERE slot = ?1", [1i64])
        .await
        .unwrap();
    let result = LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .check_query_plans()
        .await;
    assert!(matches!(result, Err(Error::Storage)), "{result:?}");
}
