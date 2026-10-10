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
    let keys = ckyh::Passkeys::new(
        ckyh::LibsqlStore::new(&db, COMMUNITY, tokio::runtime::Handle::current()).unwrap(),
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
