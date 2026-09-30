//! Optional live Turso round trip; never configured with secrets in public CI.

mod common;

use common::*;
use cplc::*;

#[tokio::test]
async fn optional_real_turso() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        eprintln!("skipped: both TURSO_URL and TURSO_TOKEN are required");
        return;
    };
    if url.is_empty() || token.is_empty() {
        eprintln!("skipped: both Turso variables must be nonempty");
        return;
    }
    // tempfile supplies a random test suffix without a host name or user identity.
    let isolated = tempfile::Builder::new()
        .prefix("cplc-test-")
        .tempdir()
        .unwrap();
    let scope = isolated.path().file_name().unwrap().to_str().unwrap();
    let (db, rules_db) = databases(&url, &token).await;
    let mut policy = sql_policy(&db, &rules_db, scope).await;
    policy
        .schedule_rules(None, change(book(admission()), 1, NOW as i64))
        .await
        .unwrap();
    let mut schema = schema(1);
    schema.community = scope.into();
    policy.set_schema(schema).await.unwrap();
    let mut gate = development_gate(500);
    gate.community = Some(scope.into());
    let cose = policy.issue_test(request(&[gate]), NOW).await.unwrap();
    assert!(
        policy
            .key_ring()
            .unwrap()
            .verify(&cose, csgn::Kind::Credential, NOW)
            .is_ok()
    );
    let snapshot = policy.publish(SnapshotKind::Schema, NOW).await.unwrap();
    assert_eq!(
        policy.published(SnapshotKind::Schema, NOW).await.unwrap(),
        Some(snapshot)
    );
    LibsqlStore::new(&db, scope)
        .unwrap()
        .check_query_plans()
        .await
        .unwrap();
}
