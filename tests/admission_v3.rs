//! Same actual Policy evaluation and signer, with Balance-owned claim encoding.
mod common;
use common::*;
use cplc::*;
use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
use sha2::{Digest, Sha256};

async fn configured() -> MemoryPolicy {
    let mut policy = memory_with(book(crbk::ActionPolicy::default())).await;
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/balance-material-v2.json")).unwrap();
    let mut material: PublicVerifierMaterial =
        serde_json::from_value(fixture["material"].clone()).unwrap();
    material.community = COMMUNITY.into();
    material.policy_digest = material
        .policy
        .account
        .digest(&Sha256::digest(COMMUNITY.as_bytes()).into())
        .unwrap();
    let version = policy.balance_version(NOW).await.unwrap();
    material.revision = version.revision;
    material.policy_epoch = version.epoch;
    policy.publish_balance(material, NOW).await.unwrap();
    policy
}
async fn issue(
    policy: &mut MemoryPolicy,
    source: &FixtureMembership,
    selected: [u8; 32],
) -> Result<cblc::admission::AdmissionGrant> {
    issue_with_context(
        policy,
        source,
        selected,
        AccountGrantContext {
            passport_policy_digest: [11; 32],
            passport_valid_until: 1500,
        },
    )
    .await
}
async fn issue_with_context(
    policy: &mut MemoryPolicy,
    source: &FixtureMembership,
    selected: [u8; 32],
    context: AccountGrantContext,
) -> Result<cblc::admission::AdmissionGrant> {
    let snapshot = policy.verified_settings(NOW).await?;
    let gates = checked(&snapshot, &source.member, "admit", &[], NOW).await?;
    policy
        .issue_account_grant(
            source,
            CredentialRequest {
                subject: crbk::Subject {
                    id: &source.member,
                    membership: crbk::MembershipState::Admitted,
                },
                handle: "testmember",
                schema_version: 1,
                snapshot: &snapshot,
                gates: &gates,
                pins: &[],
                devices: DEVICES,
            },
            selected,
            context,
            NOW,
        )
        .await
}
#[tokio::test]
async fn current_policy_ring_grant_binds_same_member_device_policy_and_window() {
    let mut policy = configured().await;
    let mut source = FixtureMembership {
        member: HEXLOWER.encode(&[7; 48]),
        state: crbk::MembershipState::Admitted,
        probation_until: None,
        lease_end: 90 * DAY,
        authorized_devices: DEVICES.to_vec(),
    };
    let grant = issue(&mut policy, &source, DEVICE).await.unwrap();
    assert_eq!(grant.version, 3);
    assert_eq!(grant.issued_at, day(NOW));
    assert_eq!(grant.expires_at, 1500);
    assert_eq!(grant.policy_epoch, policy.epoch(NOW).await.unwrap());
    assert_eq!(grant.passport_policy_digest, B64.encode(&[11; 32]));
    // The native fixture configures encoded(3) as immutable admission trust.
    // Community rebinding above changes economics, never that eligibility key.
    assert_eq!(grant.policy_digest, B64.encode(&[3; 32]));
    let trust = cblc::admission::AdmissionTrust {
        community_id: COMMUNITY.into(),
        policy_digest: B64.encode(&[3; 32]),
        policy_keys: policy.key_ring().unwrap().clone(),
    };
    cblc::admission::verify_admission(&grant, &trust, NOW).unwrap();
    let signed = B64.decode(grant.signature.as_bytes()).unwrap();
    let verified = trust
        .policy_keys
        .verify(&signed, csgn::Kind::Credential, NOW)
        .unwrap();
    assert_eq!(
        verified.payload(),
        cblc::admission::admission_bytes(&grant).unwrap()
    );
    assert_eq!(grant.member_id, cblc::admission::member_id(&[7; 48]));
    assert_eq!(grant.chat_public_key, B64.encode(&DEVICE));
    for case in 0..10 {
        let mut altered = grant.clone();
        match case {
            0 => altered.version = 2,
            1 => altered.community_id = "other".into(),
            2 => altered.chat_public_key = B64.encode(&[8; 32]),
            3 => altered.policy_digest = B64.encode(&[9; 32]),
            4 => altered.expires_at += 1,
            5 => altered.issued_at += 1,
            6 => altered.policy_epoch += 1,
            7 => altered.policy_epoch = 0,
            8 => altered.passport_policy_digest = B64.encode(&[12; 32]),
            _ => altered.passport_policy_digest = "malformed".into(),
        }
        assert!(cblc::admission::verify_admission(&altered, &trust, NOW).is_err());
    }
    assert!(cblc::admission::verify_admission(&grant, &trust, 1500).is_err());
    assert!(issue(&mut policy, &source, [8; 32]).await.is_err());
    source.authorized_devices.clear();
    assert!(issue(&mut policy, &source, DEVICE).await.is_err());
    source.authorized_devices = DEVICES.to_vec();
    source.state = crbk::MembershipState::Lapsed;
    assert!(issue(&mut policy, &source, DEVICE).await.is_err());
    source.state = crbk::MembershipState::Admitted;
    source.member = "noncanonical-member".into();
    assert!(issue(&mut policy, &source, DEVICE).await.is_err());
}

#[tokio::test]
async fn ordinary_credential_issuance_retains_its_current_purpose_and_action() {
    let mut policy = configured().await;
    let source = FixtureMembership {
        member: HEXLOWER.encode(&[7; 48]),
        state: crbk::MembershipState::Admitted,
        probation_until: None,
        lease_end: 90 * DAY,
        authorized_devices: DEVICES.to_vec(),
    };
    let snapshot = policy.verified_settings(NOW).await.unwrap();
    let gates = checked(&snapshot, &source.member, "admit", &[], NOW)
        .await
        .unwrap();
    let cose = policy
        .issue(
            &source,
            CredentialRequest {
                subject: crbk::Subject {
                    id: &source.member,
                    membership: crbk::MembershipState::Admitted,
                },
                handle: "testmember",
                schema_version: 1,
                snapshot: &snapshot,
                gates: &gates,
                pins: &[],
                devices: DEVICES,
            },
            NOW,
        )
        .await
        .unwrap();
    let signed = policy
        .key_ring()
        .unwrap()
        .verify(&cose, csgn::Kind::Credential, NOW)
        .unwrap();
    let credential: Credential = serde_json::from_slice(signed.payload()).unwrap();
    assert_eq!(credential.purpose, CredentialPurpose::CommunityAdmission);
    assert_eq!(credential.issuance_action, "admit");
    assert_eq!(credential.member, source.member);
    assert_eq!(credential.community, COMMUNITY);
    assert_eq!(credential.devices, DEVICES);
    assert_eq!(credential.policy_epoch, snapshot.settings().policy_epoch);
    assert_eq!(signed.issued_at(), day(NOW));
    assert!(credential.gates.is_empty());
    // The ordinary credential still carries neither account nor global facts.
    let payload: serde_json::Value = serde_json::from_slice(signed.payload()).unwrap();
    assert!(payload.get("passportPolicyDigest").is_none());
    assert!(payload.get("account").is_none());
    let grant = issue(&mut policy, &source, DEVICE).await.unwrap();
    assert_eq!(grant.policy_epoch, credential.policy_epoch);
    assert_eq!(grant.pseudonym, credential.member);
}

#[tokio::test]
async fn missing_invalid_or_invalidated_owner_authority_returns_no_grant() {
    let source = FixtureMembership {
        member: HEXLOWER.encode(&[7; 48]),
        state: crbk::MembershipState::Admitted,
        probation_until: None,
        lease_end: 90 * DAY,
        authorized_devices: DEVICES.to_vec(),
    };
    let mut missing = memory_with(book(crbk::ActionPolicy::default())).await;
    assert!(matches!(
        issue(&mut missing, &source, DEVICE).await,
        Err(Error::Missing)
    ));
    let mut policy = configured().await;
    for (digest, end) in [
        ([0; 32], 1500),
        ([11; 32], NOW),
        ([11; 32], i64::MAX as u64 + 1),
    ] {
        assert!(matches!(
            issue_with_context(
                &mut policy,
                &source,
                DEVICE,
                AccountGrantContext {
                    passport_policy_digest: digest,
                    passport_valid_until: end
                },
            )
            .await,
            Err(Error::Invalid("account passport cohort"))
        ));
    }
    policy.bump_epoch().await.unwrap();
    assert!(matches!(
        issue(&mut policy, &source, DEVICE).await,
        Err(Error::Missing)
    ));
}

#[tokio::test]
async fn period_projection_checks_actual_current_catalogue_without_defaults() {
    const KEY: &str = "record/window";
    let mut rules = book(crbk::ActionPolicy::default());
    crbk::RecordEpochSettings::define(&mut rules, KEY).unwrap();
    let mut policy = memory_with(rules.clone()).await;
    assert!(policy.record_epoch_settings(KEY, NOW).await.is_err());
    rules
        .set_community(KEY, Some(serde_json::json!(100)))
        .unwrap();
    policy
        .schedule_rules(Some(1), change(rules, 2, NOW as i64))
        .await
        .unwrap();
    let period = policy.record_epoch_settings(KEY, NOW).await.unwrap();
    assert_eq!(period.period_seconds, 100);
    assert!(
        policy
            .record_epoch_settings("member/window", NOW)
            .await
            .is_err()
    );
}
