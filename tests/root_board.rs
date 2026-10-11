//! Original root-board producer and authenticated consumer scenarios.
mod common;
use common::*;
use cplc::*;
use cpsd::rand::{SeedableRng, rngs::StdRng};
use cpsd::{IssuerKey, ROOT_BOARD_COHORT_SECONDS, RootBoardPublicKey};
use serde_json::{Value, json};

const ROOT: &str = "root";
fn issuer(seed: u64) -> IssuerKey {
    IssuerKey::generate(
        &mut StdRng::seed_from_u64(seed),
        cpsd::KeyId::new("common-root").unwrap(),
        vec![cpsd::GateId::new("root-board").unwrap()],
    )
    .unwrap()
}

fn descriptor(key: &IssuerKey, epoch: u64, cohort: u64) -> RootBoardPublicKey {
    RootBoardPublicKey::from_authenticated_beacon(
        key.public_key().clone(),
        cpsd::CommunityId::new(ROOT.as_bytes()).unwrap(),
        epoch,
        cohort,
    )
    .unwrap()
}

async fn setup() -> (tempfile::TempDir, crlt::Db, crlt::Db, SqlPolicy) {
    let directory = tempfile::tempdir().unwrap();
    let url = format!("file://{}", directory.path().join("policy.db").display());
    let (db, rules) = databases(&url, "").await;
    let mut policy = sql_policy(&db, &rules, ROOT).await;
    policy
        .schedule_rules(None, change(book(admission()), 1, NOW as i64))
        .await
        .unwrap();
    let mut definition = schema(1);
    definition.community = ROOT.into();
    policy.set_schema(definition).await.unwrap();
    (directory, db, rules, policy)
}

async fn reopen(db: &crlt::Db, rules: crlt::Db, key_seed: u8, now: u64) -> SqlPolicy {
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(ROOT).unwrap()),
        ROOT,
        key(key_seed),
        day(now),
    )
    .await
    .unwrap();
    Policy::open(
        crbk::LibsqlStore::new(rules),
        LibsqlStore::new(db, ROOT).unwrap(),
        signer,
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn owner_refuses_wrong_scope_epoch_cohort_and_changed_issuer_without_replacement() {
    let (_directory, db, rules, mut policy) = setup().await;
    let key = issuer(802);
    let epoch = policy.epoch(NOW).await.unwrap();
    let foreign = RootBoardPublicKey::from_authenticated_beacon(
        key.public_key().clone(),
        cpsd::CommunityId::new(b"other").unwrap(),
        epoch,
        0,
    )
    .unwrap();
    for invalid in [
        foreign,
        descriptor(&key, epoch + 1, 0),
        descriptor(&key, epoch, ROOT_BOARD_COHORT_SECONDS),
    ] {
        assert!(policy.publish_root_board(&invalid, NOW).await.is_err());
        assert!(policy.root_board_publication(NOW).await.unwrap().is_none());
    }
    let common = descriptor(&key, epoch, 0);
    assert!(
        policy
            .publish_root_board(&common, ROOT_BOARD_COHORT_SECONDS)
            .await
            .is_err()
    );
    let original = policy.publish_root_board(&common, NOW).await.unwrap();
    let mut reopened = reopen(&db, rules, 1, NOW).await;
    let replacement = descriptor(&issuer(803), epoch, 0);
    assert!(
        reopened
            .publish_root_board(&replacement, NOW)
            .await
            .is_err()
    );
    assert_eq!(
        reopened.root_board_publication(NOW).await.unwrap(),
        Some(original)
    );
    reopened.publish_root_board(&common, NOW).await.unwrap();
    let feed = reopened.trust_feed(NOW).await.unwrap();
    assert_eq!(
        cbcn::root_board::RootBoard::verify(
            reopened.key_ring().unwrap(),
            feed.root_board.as_ref().unwrap(),
            epoch,
            2,
            NOW
        )
        .unwrap()
        .revision(),
        2
    );
}

#[tokio::test]
async fn durable_binding_and_cohort_cannot_be_removed_or_rewritten_after_invalidation() {
    let (_directory, db, _rules, mut policy) = setup().await;
    let common_key = issuer(808);
    let now = ROOT_BOARD_COHORT_SECONDS;
    let common = descriptor(&common_key, policy.epoch(now).await.unwrap(), now);
    policy.publish_root_board(&common, now).await.unwrap();
    let store = LibsqlStore::new(&db, ROOT).unwrap();
    let before = serde_json::to_value(store.load().await.unwrap().unwrap()).unwrap();
    policy.bump_epoch().await.unwrap();
    assert!(policy.root_board_publication(now).await.is_err());
    let stored = store.load().await.unwrap().unwrap();
    let baseline = serde_json::to_value(&stored).unwrap();
    assert_eq!(baseline["root_board_issuer"], before["root_board_issuer"]);
    assert_eq!(baseline["root_board_cohort"], before["root_board_cohort"]);
    assert!(baseline["root_board"]["cose"].is_null());
    let other = issuer(809).public_key().to_bytes();
    for case in 0..7 {
        let mut value = baseline.clone();
        value["revision"] = json!(stored.revision() + 1);
        match case {
            0 => value["root_board_issuer"] = Value::Null,
            1 => value["root_board_cohort"] = json!(0),
            2 => value["root_board_issuer"] = json!(other),
            3 => value["root_board_cohort"] = json!(ROOT_BOARD_COHORT_SECONDS * 2),
            4 => value["root_board_issuer"] = json!([0xff]),
            5 => value["root_board_cohort"] = json!(1),
            _ => {
                value["root_board"] = Value::Null;
                value["root_board_issuer"] = Value::Null;
                value["root_board_cohort"] = Value::Null;
            }
        }
        let next: StoredPolicy = serde_json::from_value(value).unwrap();
        assert!(
            matches!(
                store.compare_exchange(Some(stored.revision()), &next).await,
                Err(Error::Corrupt)
            ),
            "case {case}"
        );
        assert_eq!(store.load().await.unwrap().unwrap(), stored);
    }
}

#[path = "root_board/signing.rs"]
mod signing;
