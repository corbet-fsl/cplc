//! Actual target Policy signer and original role codec; no host creation claim.
mod common;
use common::*;
use cvch::role::{Context, Invitation, Purpose};

#[tokio::test]
async fn original_target_policy_signs_exact_recipient_purpose_and_deadline() {
    let mut policy = memory().await;
    for purpose in [Purpose::BootstrapRoot, Purpose::FounderAdmin] {
        let id = "original-creation-invitation";
        let binding = cvch::member_binding(&cvch::receipt_id(id), MEMBER.as_bytes());
        let invitation = Invitation {
            id,
            community: COMMUNITY,
            member_binding: &binding,
            purpose,
            issued_at: cplc::day(NOW),
            valid_until: NOW + 100,
        };
        let signed = policy.issue_role_invitation(&invitation).await.unwrap();
        let ring = policy.key_ring().unwrap();
        let check = |community, member, purpose, now| {
            cvch::role::verify(
                &signed,
                ring,
                &Context {
                    community,
                    member,
                    purpose,
                    now,
                },
            )
        };
        let verified = check(COMMUNITY, MEMBER.as_bytes(), purpose, NOW).unwrap();
        assert_eq!(verified.receipt(), cvch::receipt_id(id));
        assert_eq!(verified.binding(), binding);
        assert_eq!(verified.valid_until(), NOW + 100);
        assert!(check(COMMUNITY, MEMBER.as_bytes(), purpose, NOW + 100).is_err());
        assert!(check("foreign", MEMBER.as_bytes(), purpose, NOW).is_err());
        assert!(check(COMMUNITY, b"another-recipient", purpose, NOW).is_err());
        let other = if purpose == Purpose::BootstrapRoot {
            Purpose::FounderAdmin
        } else {
            Purpose::BootstrapRoot
        };
        assert!(check(COMMUNITY, MEMBER.as_bytes(), other, NOW).is_err());
        let envelope = ring
            .verify(&signed, cplc::csgn::Kind::Credential, NOW)
            .unwrap();
        assert_eq!(envelope.issued_at(), cplc::day(NOW));
        assert_eq!(envelope.valid_until(), NOW + 100);
    }
}

#[tokio::test]
async fn foreign_target_and_transferable_root_board_role_are_not_signed() {
    let mut policy = memory().await;
    let binding = cvch::member_binding(&cvch::receipt_id("first-root"), MEMBER.as_bytes());
    for (community, purpose, until) in [
        ("foreign", Purpose::BootstrapRoot, NOW + 100),
        (COMMUNITY, Purpose::RootBoardMember, NOW + 100),
        (COMMUNITY, Purpose::FounderAdmin, NOW),
    ] {
        assert!(
            policy
                .issue_role_invitation(&Invitation {
                    id: "first-root",
                    community,
                    member_binding: &binding,
                    purpose,
                    issued_at: cplc::day(NOW),
                    valid_until: until,
                })
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn actual_root_policy_refuses_the_codec_valid_transferable_board_purpose() {
    let signer = cplc::csgn::PersistentSigner::create(
        cplc::csgn::MemoryStore::default(),
        "root",
        key(1),
        cplc::day(NOW),
        cplc::ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    let mut policy = cplc::Policy::create(
        cplc::crbk::MemoryStore::default(),
        cplc::MemoryStore::new("root").unwrap(),
        signer,
        config(),
    )
    .await
    .unwrap();
    let binding = cvch::member_binding(&cvch::receipt_id("board"), MEMBER.as_bytes());
    let invitation = Invitation {
        id: "board",
        community: "root",
        member_binding: &binding,
        purpose: Purpose::RootBoardMember,
        issued_at: cplc::day(NOW),
        valid_until: NOW + 100,
    };
    // The legacy role codec can encode this purpose, so the actual Policy
    // boundary must refuse it even when target and envelope would be valid.
    assert!(cvch::role::issuance_bytes(&invitation).is_ok());
    assert!(matches!(
        policy.issue_role_invitation(&invitation).await,
        Err(cplc::Error::Verification)
    ));
}

#[tokio::test]
async fn second_precision_issue_times_are_refused_before_signing() {
    let mut policy = memory().await;
    let binding = cvch::member_binding(&cvch::receipt_id("exact"), MEMBER.as_bytes());
    for issued_at in [NOW, 86_400 + 1, 1_800_000_000] {
        let invitation = Invitation {
            id: "exact",
            community: COMMUNITY,
            member_binding: &binding,
            purpose: Purpose::BootstrapRoot,
            issued_at,
            valid_until: issued_at + 100,
        };
        assert!(matches!(
            policy.issue_role_invitation(&invitation).await,
            Err(cplc::Error::Invalid(_))
        ));
    }
    // A signature at the aligned boundary still verifies at the exact later second.
    let invitation = Invitation {
        id: "exact",
        community: COMMUNITY,
        member_binding: &binding,
        purpose: Purpose::BootstrapRoot,
        issued_at: cplc::day(1_800_000_000),
        valid_until: 1_800_000_100,
    };
    assert!(policy.issue_role_invitation(&invitation).await.is_ok());
}
