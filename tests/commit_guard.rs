#![cfg(not(target_arch = "wasm32"))]
//! Actual policy SQL transactions; these cuts test persistence, not member proofs.
mod common;
use common::*;
use cplc::{crbk::CommitGuard, *};
use std::{sync::Arc, time::Duration};

struct Cut {
    deny: bool,
    releases: usize,
    fail_release: usize,
    checks: usize,
}
impl CommitGuard for Cut {
    async fn check(&mut self) -> crbk::Result<()> {
        self.checks += 1;
        if self.deny {
            Err(crbk::Error::Storage)
        } else {
            Ok(())
        }
    }
    fn release(&mut self) -> crbk::Result<()> {
        self.releases += 1;
        if self.releases == self.fail_release {
            Err(crbk::Error::Storage)
        } else {
            Ok(())
        }
    }
}
fn cut(deny: bool, fail_release: usize) -> Cut {
    Cut {
        deny,
        releases: 0,
        fail_release,
        checks: 0,
    }
}

#[tokio::test]
async fn memory_checked_schema_refuses_without_claiming_authority_support() {
    let mut policy = memory().await;
    let mut guard = cut(false, 0);
    assert!(matches!(
        policy.set_schema_checked(schema(2), &mut guard).await,
        Err(Error::Storage)
    ));
    assert_eq!(guard.checks, 0);
    assert!(matches!(policy.schema(), Err(Error::ReloadRequired)));
}

#[tokio::test]
async fn genuine_sql_schema_and_rulebook_remain_unchanged_after_final_refusal() {
    let (_dir, db, rules_db, mut policy) = local().await;
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let before = store.load().await.unwrap();
    assert!(
        policy
            .set_schema_checked(schema(2), &mut cut(true, 0))
            .await
            .is_err()
    );
    assert_eq!(store.load().await.unwrap(), before);
    assert!(matches!(policy.schema(), Err(Error::ReloadRequired)));
    let mut policy = Policy::open(
        crbk::LibsqlStore::new(rules_db.clone()),
        store,
        csgn::PersistentSigner::open(
            csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
            COMMUNITY,
            key(1),
            day(NOW),
        )
        .await
        .unwrap(),
    )
    .await
    .unwrap();
    let rules = crbk::LibsqlStore::new(rules_db);
    let before = rules
        .load(COMMUNITY, crbk::Selection::Latest)
        .await
        .unwrap();
    let mut setting_guard = cut(true, 0);
    assert!(
        policy
            .edit_setting_checked(
                "quota",
                SettingEdit::Community(Some(serde_json::json!(20))),
                NOW,
                NOW + 1,
                0,
                &mut setting_guard
            )
            .await
            .is_err()
    );
    assert_eq!(setting_guard.checks, 1);
    assert_eq!(
        rules
            .load(COMMUNITY, crbk::Selection::Latest)
            .await
            .unwrap(),
        before
    );
    assert!(matches!(policy.schema(), Err(Error::ReloadRequired)));
}

#[tokio::test]
async fn postcommit_cut_withholds_policy_but_keeps_actual_durable_schema() {
    let (_dir, db, _rules_db, mut policy) = local().await;
    let mut guard = cut(false, 2);
    assert!(matches!(
        policy.set_schema_checked(schema(2), &mut guard).await,
        Err(Error::Storage)
    ));
    assert_eq!((guard.checks, guard.releases), (1, 2));
    let actual = LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .load()
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(actual).unwrap()["schema"]["version"],
        2
    );
    assert!(matches!(policy.schema(), Err(Error::ReloadRequired)));
}

struct Waiting(Arc<tokio::sync::Notify>);
impl CommitGuard for Waiting {
    async fn check(&mut self) -> crbk::Result<()> {
        self.0.notify_one();
        std::future::pending().await
    }
    fn release(&mut self) -> crbk::Result<()> {
        panic!("cancelled owner check cannot commit")
    }
}
#[tokio::test]
async fn cancelled_current_owner_read_rolls_back_staged_schema_and_invalidates_cache() {
    let (_dir, db, _rules_db, mut policy) = local().await;
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let before = store.load().await.unwrap();
    let entered = Arc::new(tokio::sync::Notify::new());
    let mut guard = Waiting(entered.clone());
    let mut write = Box::pin(policy.set_schema_checked(schema(2), &mut guard));
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! { _ = entered.notified() => {}, result = &mut write => panic!("unexpected completed write: {result:?}") }
    }).await.unwrap();
    drop(write);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), store.load())
            .await
            .unwrap()
            .unwrap(),
        before
    );
    assert!(matches!(policy.schema(), Err(Error::ReloadRequired)));
}
