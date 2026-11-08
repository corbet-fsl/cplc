//! Actual active Rulebook and original signed settings; no quota from a request.
use crate::common;
use common::*;
use cplc::{crbk::OutcomeQuotaSettings, *};
use serde_json::json;
const KEY: &str = "fixture/outcome_allowance";
fn configured() -> crbk::Rulebook {
    let mut book = book(admission());
    OutcomeQuotaSettings::define(&mut book, KEY).unwrap();
    book.set_community(KEY, Some(json!(7))).unwrap();
    book
}
#[tokio::test]
async fn current_owner_projection_matches_genuine_signed_settings_and_activation() {
    let mut policy = memory_with(configured()).await;
    assert!(
        policy
            .outcome_quota_settings("different", NOW)
            .await
            .is_err()
    );
    // This other integer is a member/template setting and cannot be substituted
    // just because its resolved numeric value fits the outcome allowance.
    assert!(policy.outcome_quota_settings("quota", NOW).await.is_err());
    let projected = policy.outcome_quota_settings(KEY, NOW).await.unwrap();
    assert_eq!(projected.quota, 7);
    let signed = policy.verified_settings(NOW).await.unwrap();
    assert_eq!(
        signed.settings().policy_epoch,
        policy.epoch(NOW).await.unwrap()
    );
    assert_eq!(
        OutcomeQuotaSettings::from_snapshot(signed.settings(), KEY).unwrap(),
        projected
    );
    let mut next = configured();
    next.set_community(KEY, Some(json!(9))).unwrap();
    policy
        .schedule_rules(Some(1), change(next, 2, (NOW + 10) as i64))
        .await
        .unwrap();
    // The earlier publication outlives the activation; it is republished with
    // its validity cut at the next effective revision.
    let cut = policy.verified_settings(NOW + 1).await.unwrap();
    assert!(cut.valid_until() <= NOW + 10);
    for (now, quota) in [(NOW + 9, 7), (NOW + 10, 9)] {
        let current = policy.outcome_quota_settings(KEY, now).await.unwrap();
        let signed = policy.verified_settings(now).await.unwrap();
        assert_eq!(current.quota, quota);
        assert_eq!(
            signed.settings().policy_epoch,
            policy.epoch(now).await.unwrap()
        );
        assert_eq!(
            OutcomeQuotaSettings::from_snapshot(signed.settings(), KEY).unwrap(),
            current
        );
    }
}
#[tokio::test]
async fn missing_or_null_current_configuration_has_no_usable_fallback() {
    let policy = memory().await;
    assert!(policy.outcome_quota_settings(KEY, NOW).await.is_err());
    let mut null = configured();
    null.set_community(KEY, Some(json!(null))).unwrap();
    let policy = memory_with(null).await;
    assert!(policy.outcome_quota_settings(KEY, NOW).await.is_err());
}
#[tokio::test]
async fn actual_sql_policy_reload_uses_same_active_catalogue_and_values() {
    let (_directory, db, rules_db, mut policy) = local().await;
    policy
        .schedule_rules(Some(1), change(configured(), 2, (NOW + 1) as i64))
        .await
        .unwrap();
    assert!(policy.outcome_quota_settings(KEY, NOW).await.is_err());
    assert_eq!(
        policy
            .outcome_quota_settings(KEY, NOW + 1)
            .await
            .unwrap()
            .quota,
        7
    );
    drop(policy);
    let policy = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
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
    let now = NOW + 1;
    let current = policy.settings(now).await.unwrap();
    assert_eq!(current.policy_epoch, policy.epoch(now).await.unwrap());
    assert_eq!(
        OutcomeQuotaSettings::from_snapshot(&current, KEY).unwrap(),
        policy.outcome_quota_settings(KEY, now).await.unwrap()
    );
}
