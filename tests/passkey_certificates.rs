//! Original Keyhole registration projected through the actual Policy signer.
mod common;
use common::*;
use cplc::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

async fn registered() -> (
    tempfile::TempDir,
    ckyh::certificate::RegistrationCertificate,
) {
    let directory = tempfile::tempdir().unwrap();
    let url = ckyh::Url::from_file_path(directory.path().join("keyhole.db")).unwrap();
    let db = crlt::Db::open(crlt::Config::new(url.as_str(), ""))
        .await
        .unwrap();
    db.migrate(&[crlt::Migration::new(1, "keyhole", ckyh::LIBSQL_SCHEMA)])
        .await
        .unwrap();
    // The synchronous passkey store blocks its thread: never run it on an async task.
    let handle = tokio::runtime::Handle::current();
    let certificate = tokio::task::spawn_blocking(move || {
        let keys = ckyh::Passkeys::new(
            ckyh::LibsqlStore::new(&db, COMMUNITY, handle.clone()).unwrap(),
            COMMUNITY,
            "members.example.test",
            &[ckyh::Url::parse("https://members.example.test").unwrap()],
        )
        .unwrap();
        let user = ckyh::Uuid::from_u128(31);
        let (mut options, pending) = keys.start_registration(user).unwrap();
        options
            .public_key
            .authenticator_selection
            .as_mut()
            .unwrap()
            .require_resident_key = false;
        let response = SoftToken::new(true)
            .unwrap()
            .0
            .perform_register(
                ckyh::Url::parse("https://members.example.test").unwrap(),
                options.public_key,
                300_000,
            )
            .unwrap();
        let registration = keys
            .finish_registration(
                pending,
                &response.into(),
                ckyh::CreationMonth::new(2026, 10).unwrap(),
            )
            .unwrap();
        let certificate = keys
            .registration_certificate(user, registration.credential_id(), MEMBER)
            .unwrap();
        certificate
    })
    .await
    .unwrap();
    (directory, certificate)
}

#[tokio::test(flavor = "multi_thread")]
async fn genuine_passkey_certificate_does_not_issue_membership_or_advance_policy() {
    let (_directory, registered) = registered().await;
    let mut policy = memory().await;
    let epoch = policy.epoch(NOW).await.unwrap();
    let bytes = policy
        .issue_passkey_certificate(&registered, NOW)
        .await
        .unwrap();
    let certificate =
        ckyh::certificate::verify(policy.key_ring().unwrap(), &bytes, MEMBER, NOW).unwrap();
    assert_eq!(certificate.credential_id(), registered.credential_id());
    assert_eq!(certificate.issued_at(), day(NOW));
    assert_eq!(policy.epoch(NOW).await.unwrap(), epoch);
    let signed = policy
        .key_ring()
        .unwrap()
        .verify(&bytes, csgn::Kind::Credential, NOW)
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(body["purpose"], "ckyh.passkey-certificate.v1");
    assert!(body.get("devices").is_none());
    assert!(body.get("user").is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn original_passkey_revocations_refuse_renewal_and_survive_signed_publication() {
    let (_directory, registered) = registered().await;
    let mut policy = memory().await;
    for bad in [Vec::new(), vec![9u8; 1025]] {
        assert!(matches!(
            policy
                .set_revocations(Revocations {
                    passkeys: [bad].into(),
                    ..Default::default()
                })
                .await,
            Err(Error::Invalid(_))
        ));
    }
    let credential = registered.credential_id().to_vec();
    policy
        .set_revocations(Revocations {
            passkeys: [credential.clone()].into(),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(matches!(
        policy.issue_passkey_certificate(&registered, NOW).await,
        Err(Error::Revoked)
    ));
    let bytes = policy
        .publish(SnapshotKind::RevocationList, NOW)
        .await
        .unwrap();
    let verified = verify_snapshot::<Revocations>(
        policy.key_ring().unwrap(),
        &bytes,
        SnapshotExpectation {
            community: COMMUNITY,
            kind: SnapshotKind::RevocationList,
            minimum_revision: 1,
            policy_epoch: policy.epoch(NOW).await.unwrap(),
            now: NOW,
        },
    )
    .unwrap();
    assert!(verified.content.passkeys.contains(&credential));
}

#[tokio::test(flavor = "multi_thread")]
async fn original_passkey_revocation_survives_sql_reload_mutation_and_reopen() {
    let (_keyhole_directory, registered) = registered().await;
    let credential = registered.credential_id().to_vec();
    let (directory, db, rules, mut policy) = local().await;
    policy
        .set_revocations(Revocations {
            passkeys: [credential.clone()].into(),
            ..Default::default()
        })
        .await
        .unwrap();
    let store = LibsqlStore::new(&db, COMMUNITY).unwrap();
    let retained = store.load().await.unwrap().unwrap();
    assert_eq!(retained.community(), COMMUNITY);
    // Compare the exact current writer to the durable load, including the real
    // registered ID; a memory-only success cannot satisfy this assertion.
    assert_eq!(
        serde_json::to_value(&retained).unwrap()["revocations"]["passkeys"],
        serde_json::json!([credential.clone()])
    );
    assert!(matches!(
        store
            .compare_exchange(Some(retained.revision() - 1), &retained)
            .await,
        Err(Error::Conflict)
    ));
    assert_eq!(store.load().await.unwrap().as_ref(), Some(&retained));
    policy.bump_epoch().await.unwrap();
    let changed = store.load().await.unwrap().unwrap();
    assert!(changed.epoch() > retained.epoch());
    assert_eq!(
        serde_json::to_value(&changed).unwrap()["revocations"]["passkeys"],
        serde_json::json!([credential.clone()])
    );
    drop(policy);
    drop(store);
    drop(rules);
    drop(db);
    let url = format!("file://{}", directory.path().join("policy.db").display());
    let (reopened, rules) = databases(&url, "").await;
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(reopened.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(1),
        day(NOW),
    )
    .await
    .unwrap();
    let mut policy = Policy::open(
        crbk::LibsqlStore::new(rules),
        LibsqlStore::new(&reopened, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert!(policy.revocations().unwrap().passkeys.contains(&credential));
    assert!(matches!(
        policy.issue_passkey_certificate(&registered, NOW).await,
        Err(Error::Revoked)
    ));
    let feed = policy.refresh_trust(NOW).await.unwrap();
    let revoked = verify_snapshot::<Revocations>(
        policy.key_ring().unwrap(),
        &feed.revocations,
        expectation(
            SnapshotKind::RevocationList,
            policy.epoch(NOW).await.unwrap(),
            NOW,
        ),
    )
    .unwrap();
    assert!(revoked.content.passkeys.contains(&credential));
}
