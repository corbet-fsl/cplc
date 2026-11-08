//! Committed policy reads under a real original writer, without member or proof
//! authority claims. The pause only controls when the real storage CAS commits.
use crate::common;

use cplc::{Error, LibsqlStore, Storage, StoredPolicy, crbk, crlt};
use serde_json::json;
use std::time::Duration;
use tokio::sync::oneshot;

async fn local(connections: usize) -> (tempfile::TempDir, crlt::Db, LibsqlStore, StoredPolicy) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crlt::Config::new(
        format!("file://{}", dir.path().join("writer.db").display()),
        "",
    );
    config.max_connections = connections;
    config.timeout = if connections == 1 {
        Duration::from_millis(300)
    } else {
        Duration::from_secs(3)
    };
    config.busy_timeout = Duration::from_millis(40);
    let db = crlt::Db::open(config).await.unwrap();
    db.migrate(&common::migrations()).await.unwrap();
    let _policy = common::sql_policy(&db, &db, common::COMMUNITY).await;
    let store = LibsqlStore::new(&db, common::COMMUNITY).unwrap();
    let original = store.load().await.unwrap().unwrap();
    (dir, db, store, original)
}

fn revoked(original: &StoredPolicy) -> StoredPolicy {
    let mut value = serde_json::to_value(original).unwrap();
    value["revision"] = json!(original.revision() + 1);
    value["revocations"]["members"] = json!(
        (0..300)
            .map(|i| format!("member-{i:04}"))
            .collect::<Vec<_>>()
    );
    value["revocations"]["devices"] = json!([vec![19u8; 32]]);
    value["revocations"]["passkeys"] = json!([[23u8, 24u8]]);
    serde_json::from_value(value).unwrap()
}

struct PausedCommit {
    staged: Option<oneshot::Sender<()>>,
    proceed: oneshot::Receiver<()>,
}

impl crbk::CommitGuard for PausedCommit {
    async fn check(&mut self) -> crbk::Result<()> {
        self.staged.take().unwrap().send(()).unwrap();
        (&mut self.proceed).await.map_err(|_| crbk::Error::Storage)
    }

    fn release(&mut self) -> crbk::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn committed_policy_load_succeeds_while_the_same_database_writer_is_held() {
    let (_dir, db, store, original) = local(2).await;
    let tx = db.community(common::COMMUNITY).unwrap().tx().await.unwrap();
    let loaded = tokio::time::timeout(Duration::from_secs(1), store.load())
        .await
        .expect("a committed read must not wait for a second writer")
        .unwrap();
    assert_eq!(loaded.as_ref(), Some(&original));
    tx.rollback().await.unwrap();
    assert_eq!(store.load().await.unwrap().as_ref(), Some(&original));
}

#[tokio::test]
async fn staged_real_cas_revocations_remain_invisible_until_the_original_writer_commits() {
    let (_dir, _db, store, original) = local(2).await;
    let next = revoked(&original);
    let (staged, wait_staged) = oneshot::channel();
    let (proceed, wait_proceed) = oneshot::channel();
    let writer_store = store.clone();
    let writer_next = next.clone();
    let expected = original.revision();
    let writer = tokio::spawn(async move {
        writer_store
            .compare_exchange_checked(
                Some(expected),
                &writer_next,
                &mut PausedCommit {
                    staged: Some(staged),
                    proceed: wait_proceed,
                },
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(1), wait_staged)
        .await
        .unwrap()
        .unwrap();
    let loaded = tokio::time::timeout(Duration::from_secs(1), store.load())
        .await
        .expect("staged CAS must not prevent a committed read")
        .unwrap();
    assert_eq!(loaded.as_ref(), Some(&original));
    proceed.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(1), writer)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(store.load().await.unwrap().as_ref(), Some(&next));
    assert_eq!(
        serde_json::to_value(&next).unwrap()["revocations"]["members"]
            .as_array()
            .unwrap()
            .len(),
        300
    );
}

#[tokio::test]
async fn one_connection_store_refuses_within_its_bound_instead_of_acquiring_a_second_writer() {
    let (_dir, db, store, original) = local(1).await;
    let tx = db.community(common::COMMUNITY).unwrap().tx().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), store.load())
        .await
        .expect("the original pool acquisition deadline must bound refusal");
    assert!(matches!(result, Err(Error::Storage)));
    drop(tx);
    assert_eq!(store.load().await.unwrap().as_ref(), Some(&original));
}
