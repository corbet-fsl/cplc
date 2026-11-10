//! Original root-board producer and authenticated consumer scenarios.
use crate::common;
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

#[tokio::test]
async fn descriptor_reader_returns_the_authenticated_descriptor_until_its_exclusive_expiry() {
    let (_directory, _db, _rules, mut policy) = setup().await;
    assert!(policy.root_board_descriptor(NOW).await.unwrap().is_none());
    let key = issuer(810);
    let epoch = policy.epoch(NOW).await.unwrap();
    let common = descriptor(&key, epoch, 0);
    policy.publish_root_board(&common, NOW).await.unwrap();
    let (read, until) = policy.root_board_descriptor(NOW).await.unwrap().unwrap();
    assert!(read == common);
    assert!(until > NOW && until <= common.expires_at());
    // The signed publication, then the descriptor, lapse together at `until`.
    assert!(matches!(
        policy.root_board_descriptor(until).await,
        Err(Error::Verification)
    ));
    assert!(matches!(
        policy.root_board_publication(until).await,
        Err(Error::Verification)
    ));
}

#[tokio::test]
async fn publication_never_lowers_the_recorded_cohort_floor() {
    let (_directory, _db, _rules, mut policy) = setup().await;
    let key = issuer(811);
    let epoch = policy.epoch(NOW).await.unwrap();
    let later = descriptor(&key, epoch, ROOT_BOARD_COHORT_SECONDS);
    policy
        .publish_root_board(&later, ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    let before = policy
        .root_board_publication(ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    let earlier = descriptor(&key, epoch, 0);
    // At an earlier trusted time the lower cohort is still current, yet below the floor.
    assert!(matches!(
        policy.publish_root_board(&earlier, NOW).await,
        Err(Error::Verification)
    ));
    assert_eq!(
        policy
            .root_board_publication(ROOT_BOARD_COHORT_SECONDS)
            .await
            .unwrap(),
        before
    );
}

#[tokio::test]
async fn stored_root_board_revision_never_regresses_or_changes_its_signature_in_place() {
    let (_directory, db, _rules, mut policy) = setup().await;
    let key = issuer(812);
    let epoch = policy.epoch(NOW).await.unwrap();
    let common = descriptor(&key, epoch, 0);
    policy.publish_root_board(&common, NOW).await.unwrap();
    policy.publish_root_board(&common, NOW).await.unwrap();
    let store = LibsqlStore::new(&db, ROOT).unwrap();
    let stored = store.load().await.unwrap().unwrap();
    let baseline = serde_json::to_value(&stored).unwrap();
    assert_eq!(baseline["root_board"]["revision"], 2);
    for case in 0..2 {
        let mut value = baseline.clone();
        value["revision"] = json!(stored.revision() + 1);
        match case {
            0 => value["root_board"]["revision"] = json!(1),
            _ => value["root_board"]["cose"][0] = json!(0xff),
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

#[tokio::test]
async fn stored_root_binding_must_be_canonical_and_fit_the_descriptor_community() {
    let (_directory, db, _rules, mut policy) = setup().await;
    let key = issuer(813);
    let epoch = policy.epoch(NOW).await.unwrap();
    policy
        .publish_root_board(&descriptor(&key, epoch, 0), NOW)
        .await
        .unwrap();
    let baseline = serde_json::to_value(
        LibsqlStore::new(&db, ROOT)
            .unwrap()
            .load()
            .await
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    let long = "c".repeat(256);
    for case in 0..3 {
        let mut value = baseline.clone();
        value["revision"] = json!(1);
        let mut scope = ROOT.to_string();
        match case {
            0 => {}
            1 => value["root_board_issuer"]
                .as_array_mut()
                .unwrap()
                .push(json!(0)),
            _ => {
                scope = long.clone();
                value["community"] = json!(long);
                value["schema"]["community"] = json!(long);
                for version in value["schema_versions"].as_array_mut().unwrap() {
                    version["schema"]["community"] = json!(long);
                }
            }
        }
        let next: StoredPolicy = serde_json::from_value(value).unwrap();
        let fresh = MemoryStore::new(scope).unwrap();
        let result = fresh.compare_exchange(None, &next).await;
        if case == 0 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(Error::Corrupt)), "case {case}");
            assert!(fresh.load().await.unwrap().is_none());
        }
    }
}

/// Replace the stored root-board publication with a genuinely signed (by the
/// community's own key) revision 2 that carries `descriptor` as its payload.
async fn forged_publication(
    db: &crlt::Db,
    descriptor: Vec<u8>,
    epoch: u64,
    signed_at: u64,
    until: u64,
) {
    let mut signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(ROOT).unwrap()),
        ROOT,
        key(1),
        day(signed_at),
    )
    .await
    .unwrap();
    let payload = cbcn::root_board::Payload {
        purpose: cbcn::root_board::PURPOSE.into(),
        community: ROOT.into(),
        revision: 2,
        policy_epoch: epoch,
        descriptor,
    };
    let cose = signer
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&payload).unwrap(),
            day(signed_at),
            until,
        )
        .await
        .unwrap();
    let store = LibsqlStore::new(db, ROOT).unwrap();
    let stored = store.load().await.unwrap().unwrap();
    let mut value = serde_json::to_value(&stored).unwrap();
    value["revision"] = json!(stored.revision() + 1);
    value["root_board"] = json!({"revision": 2, "cose": cose});
    let next: StoredPolicy = serde_json::from_value(value).unwrap();
    store
        .compare_exchange(Some(stored.revision()), &next)
        .await
        .unwrap();
}

#[tokio::test]
async fn signed_but_inconsistent_root_publications_are_never_read_as_a_descriptor() {
    for case in 0..3 {
        let (_directory, db, rules, mut policy) = setup().await;
        let key = issuer(814);
        let epoch = policy.epoch(NOW).await.unwrap();
        let bound = descriptor(&key, epoch, 0);
        policy.publish_root_board(&bound, NOW).await.unwrap();
        let (bytes, signed_at, until) = match case {
            // Not a descriptor at all.
            0 => (vec![1, 2, 3], NOW, NOW + 1000),
            // A well-formed descriptor of a later cohort than the recorded one.
            1 => (
                descriptor(&key, epoch, ROOT_BOARD_COHORT_SECONDS).to_bytes(),
                ROOT_BOARD_COHORT_SECONDS,
                ROOT_BOARD_COHORT_SECONDS + 1000,
            ),
            // The recorded descriptor, signed for longer than it is valid.
            _ => (bound.to_bytes(), 10 * DAY, bound.expires_at() + 1),
        };
        forged_publication(&db, bytes, epoch, signed_at, until).await;
        let reopened = reopen(&db, rules, 1, signed_at).await;
        assert!(
            matches!(
                reopened.root_board_publication(signed_at).await,
                Err(Error::Verification)
            ),
            "case {case}"
        );
        assert!(matches!(
            reopened.root_board_descriptor(signed_at).await,
            Err(Error::Verification)
        ));
    }
}
