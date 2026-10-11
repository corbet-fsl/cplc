//! The production header fence observes genuine committed changes between real
//! revocation pages; no query hook or fabricated storage response is used.
use super::*;
use serde_json::json;

#[tokio::test]
async fn original_cas_between_real_pages_invalidates_the_retained_header() {
    let dir = tempfile::tempdir().unwrap();
    let mut config = crlt::Config::new(
        format!("file://{}", dir.path().join("header.db").display()),
        "",
    );
    config.max_connections = 2;
    let db = Db::open(config).await.unwrap();
    db.migrate(&[
        crlt::Migration::new(1, "rulebook", crbk::SCHEMA),
        crlt::Migration::new(2, "signing", csgn::SCHEMA),
        crlt::Migration::new(3, "policy", SCHEMA),
    ])
    .await
    .unwrap();
    let scope = db.community("header").unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(scope.clone()),
        "header",
        csgn::SecretKey::from_seed(&mut [7; 32]),
        crate::day(100),
        crate::ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    let store = LibsqlStore::new(&db, "header").unwrap();
    let _policy = crate::Policy::create(
        crbk::LibsqlStore::new(db.clone()),
        store.clone(),
        signer,
        crate::Config {
            credential_action: "admit".into(),
            snapshot_validity: crate::DAY,
        },
    )
    .await
    .unwrap();
    let initial = store.load().await.unwrap().unwrap();
    let mut value = serde_json::to_value(&initial).unwrap();
    value["revision"] = json!(initial.revision() + 1);
    value["revocations"]["members"] = json!(
        (0..300)
            .map(|i| format!("member-{i:04}"))
            .collect::<Vec<_>>()
    );
    let first: StoredPolicy = serde_json::from_value(value).unwrap();
    store
        .compare_exchange(Some(initial.revision()), &first)
        .await
        .unwrap();

    let before = scope.query(SELECT, [1i64]).await.unwrap();
    let identical = scope.query(SELECT, [1i64]).await.unwrap();
    same_header(&before, &identical).unwrap();
    let first_page = scope.query(REVOKED, [""]).await.unwrap();
    assert_eq!(first_page.len(), 256);
    let cursor = first_page.last().unwrap().get_str(0).unwrap().to_owned();

    let mut value = serde_json::to_value(&first).unwrap();
    value["revision"] = json!(first.revision() + 1);
    value["revocations"]["members"] = json!(
        (200..500)
            .map(|i| format!("member-{i:04}"))
            .chain(std::iter::once("member-0000-added".to_owned()))
            .collect::<Vec<_>>()
    );
    let second: StoredPolicy = serde_json::from_value(value).unwrap();
    store
        .compare_exchange(Some(first.revision()), &second)
        .await
        .unwrap();
    let second_page = scope.query(REVOKED, [cursor.as_str()]).await.unwrap();
    assert!(!second_page.is_empty());
    // The newly committed revocation sorts before the retained cursor and is
    // absent from both mixed pages. Releasing that hybrid would miss it.
    assert!(
        first_page
            .iter()
            .chain(&second_page)
            .all(|row| row.get_str(0).unwrap() != "member:member-0000-added")
    );
    assert!(
        second_page
            .iter()
            .any(|row| row.get_str(0).unwrap() == "member:member-0499")
    );
    let after = scope.query(SELECT, [1i64]).await.unwrap();
    assert!(matches!(same_header(&before, &after), Err(Error::Conflict)));
    assert_eq!(store.load().await.unwrap().as_ref(), Some(&second));
}
