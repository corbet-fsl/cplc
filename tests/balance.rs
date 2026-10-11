//! Canonical activated-issuer material through the real durable Policy/Beacon path.
mod common;
use cblc::publication::PublicVerifierMaterial;
use common::*;
use cplc::*;
use serde_json::Value;

fn fixture_material() -> PublicVerifierMaterial {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/balance-material-v2.json")).unwrap();
    let ring = csgn::KeyRing::from_cbor(
        &serde_json::from_value::<Vec<u8>>(fixture["configuredFixtureRing"].clone()).unwrap(),
    )
    .unwrap();
    let bytes: Vec<u8> = serde_json::from_value(fixture["signed"].clone()).unwrap();
    let signed = ring
        .verify(&bytes, csgn::Kind::SettingsSnapshot, 200)
        .unwrap();
    let material: PublicVerifierMaterial = serde_json::from_slice(signed.payload()).unwrap();
    material.validate_at(&material.community, NOW).unwrap();
    material
}

#[test]
fn genuine_legacy_signature_does_not_supply_required_v2_admission_authority() {
    let fixture: Value =
        serde_json::from_slice(include_bytes!("fixtures/balance-material.json")).unwrap();
    let ring = csgn::KeyRing::from_cbor(
        &serde_json::from_value::<Vec<u8>>(fixture["configuredFixtureRing"].clone()).unwrap(),
    )
    .unwrap();
    let bytes: Vec<u8> = serde_json::from_value(fixture["signed"].clone()).unwrap();
    let signed = ring
        .verify(&bytes, csgn::Kind::SettingsSnapshot, 200)
        .unwrap();
    assert!(serde_json::from_slice::<PublicVerifierMaterial>(signed.payload()).is_err());
}

async fn setup() -> (tempfile::TempDir, crlt::Db, crlt::Db, SqlPolicy) {
    let directory = tempfile::tempdir().unwrap();
    let url = format!("file://{}", directory.path().join("policy.db").display());
    let (db, rules) = databases(&url, "").await;
    let community = fixture_material().community;
    let mut policy = sql_policy(&db, &rules, &community).await;
    policy
        .schedule_rules(None, change(book(admission()), 1, NOW as i64))
        .await
        .unwrap();
    let mut schema = schema(1);
    schema.community = community;
    policy.set_schema(schema).await.unwrap();
    (directory, db, rules, policy)
}

async fn project(policy: &SqlPolicy, now: u64) -> PublicVerifierMaterial {
    let version = policy.balance_version(now).await.unwrap();
    let mut material = fixture_material();
    // Same owner-projected policy/artifact bytes, with the durable publisher's
    // required counters just as AccountService::public_verifier_material takes them.
    material.revision = version.revision;
    material.policy_epoch = version.epoch;
    material
}

#[tokio::test]
async fn canonical_balance_survives_signing_feed_cache_and_real_sql_reopen() {
    let (_directory, db, rules, mut policy) = setup().await;
    assert!(policy.balance_publication(NOW).await.unwrap().is_none());
    let before = policy.trust_feed(NOW).await.unwrap();
    assert!(before.balance.is_none());
    let material = project(&policy, NOW).await;
    let original_payload = serde_json::to_vec(&material).unwrap();
    let signed = policy.publish_balance(material.clone(), NOW).await.unwrap();
    assert!(policy.publish_balance(material, NOW).await.is_err());
    let feed = policy.trust_feed(NOW).await.unwrap();
    assert!(feed.revision > before.revision);
    assert_eq!(feed.balance.as_ref().unwrap(), &signed);
    assert_eq!(policy.trust_feed(NOW + 1).await.unwrap(), feed);
    assert_eq!(
        policy
            .key_ring()
            .unwrap()
            .verify(&signed, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap()
            .payload(),
        original_payload
    );
    let manifest: TrustManifest = serde_json::from_slice(
        policy
            .key_ring()
            .unwrap()
            .verify(&feed.manifest, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap()
            .payload(),
    )
    .unwrap();
    assert_eq!(manifest.balance_revision, Some(1));

    let community = fixture_material().community;
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(&community).unwrap()),
        &community,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    let mut reopened = Policy::open(
        crbk::LibsqlStore::new(rules),
        LibsqlStore::new(&db, &community).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert!(policy.balance_publication(NOW).await.is_err());
    assert_eq!(
        reopened.trust_feed(NOW).await.unwrap().balance,
        Some(signed)
    );
    assert!(reopened.trust_feed(2000).await.is_err());
    assert!(reopened.balance_publication(2000).await.is_err());
}

#[tokio::test]
async fn owner_scope_epoch_and_policy_errors_cannot_replace_accounting_material() {
    let (_directory, _db, _rules, mut policy) = setup().await;
    for case in 0..4 {
        let mut material = project(&policy, NOW).await;
        match case {
            0 => material.community = "other.example".into(),
            1 => material.policy_epoch += 1,
            2 => material.policy_digest[0] ^= 1,
            _ => material.policy.account.policy_valid_until = NOW,
        }
        assert!(policy.publish_balance(material, NOW).await.is_err());
        assert!(policy.balance_publication(NOW).await.unwrap().is_none());
    }
    let material = project(&policy, NOW).await;
    policy.publish_balance(material, NOW).await.unwrap();
    policy.bump_epoch().await.unwrap();
    assert!(policy.balance_publication(NOW).await.is_err());
    assert!(policy.trust_feed(NOW).await.is_err());
    let material = project(&policy, NOW).await;
    assert_eq!(material.revision, 2);
    let epoch = material.policy_epoch;
    let signed = policy.publish_balance(material, NOW).await.unwrap();
    let feed = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(feed.policy_epoch, epoch);
    assert_eq!(feed.balance, Some(signed));
}

#[tokio::test]
async fn interrupted_balance_publication_requires_reopen_and_never_returns_a_signature() {
    let (directory, db, rules, mut policy) = setup().await;
    let material = project(&policy, NOW).await;
    let signed = policy.publish_balance(material, NOW).await.unwrap();
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    raw.connect().unwrap().execute_batch("CREATE TRIGGER stop_balance BEFORE UPDATE ON cplc_policy WHEN json_extract(NEW.document, '$.balance.revision') > 1 BEGIN SELECT RAISE(ABORT, 'fault'); END;").await.unwrap();
    let material = project(&policy, NOW).await;
    assert!(policy.publish_balance(material, NOW).await.is_err());
    assert!(matches!(
        policy.balance_publication(NOW).await,
        Err(Error::ReloadRequired)
    ));
    assert!(policy.trust_feed(NOW).await.is_err());
    raw.connect()
        .unwrap()
        .execute_batch("DROP TRIGGER stop_balance;")
        .await
        .unwrap();
    let community = fixture_material().community;
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(&community).unwrap()),
        &community,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    let mut reopened = Policy::open(
        crbk::LibsqlStore::new(rules),
        LibsqlStore::new(&db, &community).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert_eq!(
        reopened.trust_feed(NOW).await.unwrap().balance,
        Some(signed)
    );
    let material = project(&reopened, NOW).await;
    assert_eq!(material.revision, 2);
    reopened.publish_balance(material, NOW).await.unwrap();
}
