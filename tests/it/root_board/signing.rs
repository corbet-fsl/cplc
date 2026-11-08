use super::*;

fn signer_requests(
    descriptor: &RootBoardPublicKey,
    deadline: u64,
    seed: u64,
) -> (cpsd::RootBoardIssuanceContext, cpsd::RootBoardRequest) {
    let mut rng = StdRng::seed_from_u64(seed);
    let source = cpsd::PresentationRequest::new(
        &mut rng,
        cpsd::CommunityId::new(COMMUNITY.as_bytes()).unwrap(),
        1,
        [cpsd::GateId::new("phone").unwrap()],
        deadline,
    )
    .unwrap();
    let global = cpsd::PresentationRequest::new(
        &mut rng,
        descriptor.community().clone(),
        1,
        [cpsd::GateId::new("phone").unwrap()],
        deadline,
    )
    .unwrap();
    (
        cpsd::RootBoardIssuanceContext::new(&mut rng, source, descriptor.clone()).unwrap(),
        cpsd::RootBoardRequest::new(global, descriptor.clone()).unwrap(),
    )
}

fn signer_anchor(policy: &SqlPolicy, community: &str) -> cpsd::AuthenticatedCommunity {
    cpsd::AuthenticatedCommunity::from_authenticated_origin(
        cpsd::CommunityId::new(community.as_bytes()).unwrap(),
        policy.key_ring().unwrap().clone(),
    )
}

#[tokio::test]
async fn typed_root_requests_authenticate_under_independent_real_policy_signers() {
    let (_directory, db, rules, mut root) = setup().await;
    let signer = csgn::PersistentSigner::create(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(77),
        day(NOW),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    let mut source = Policy::create(
        crbk::LibsqlStore::new(rules),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
        config(),
    )
    .await
    .unwrap();
    let common = descriptor(&issuer(820), root.epoch(NOW).await.unwrap(), 0);
    root.publish_root_board(&common, NOW).await.unwrap();
    let (context, request) = signer_requests(&common, NOW + 10, 820);
    let signed_source = source
        .sign_presentation_request(context.source_request(), NOW)
        .await
        .unwrap();
    let signed_context = root
        .sign_root_board_issuance_context(&context, NOW)
        .await
        .unwrap();
    let signed_request = root.sign_root_board_request(&request, NOW).await.unwrap();
    let root_anchor = signer_anchor(&root, ROOT);
    let source_anchor = signer_anchor(&source, COMMUNITY);
    assert!(
        root_anchor
            .authenticate_root_board_issuance(&signed_context, &source_anchor, &signed_source, NOW,)
            .unwrap()
            == context
    );
    assert!(
        root_anchor
            .authenticate_root_board_request(&signed_request, NOW)
            .unwrap()
            == request
    );
    for bytes in [&signed_context, &signed_request] {
        let signed = root
            .key_ring()
            .unwrap()
            .verify(bytes, csgn::Kind::Credential, NOW)
            .unwrap();
        assert_eq!(signed.valid_until(), NOW + 11);
    }
    assert!(
        root_anchor
            .authenticate_root_board_issuance(&signed_context, &root_anchor, &signed_source, NOW,)
            .is_err()
    );
    let (other, _) = signer_requests(&common, NOW + 10, 821);
    let other_source = source
        .sign_presentation_request(other.source_request(), NOW)
        .await
        .unwrap();
    assert!(
        root_anchor
            .authenticate_root_board_issuance(&signed_context, &source_anchor, &other_source, NOW,)
            .is_err()
    );
    assert!(
        root_anchor
            .authenticate_root_board_request(&signed_request, NOW + 11)
            .is_err()
    );
}

#[tokio::test]
async fn typed_root_signers_preserve_inclusive_deadline_and_publication_expiry() {
    let (_directory, _db, _rules, mut policy) = setup().await;
    let common = descriptor(&issuer(822), policy.epoch(NOW).await.unwrap(), 0);
    let publication = policy.publish_root_board(&common, NOW).await.unwrap();
    for (deadline, accepted) in [
        (NOW - 1, false),
        (NOW, true),
        (NOW + 300, true),
        (NOW + 301, false),
    ] {
        let (context, request) = signer_requests(&common, deadline, deadline);
        assert_eq!(
            policy
                .sign_root_board_issuance_context(&context, NOW)
                .await
                .is_ok(),
            accepted
        );
        assert_eq!(
            policy.sign_root_board_request(&request, NOW).await.is_ok(),
            accepted
        );
    }
    let until = policy
        .key_ring()
        .unwrap()
        .verify(&publication, csgn::Kind::SettingsSnapshot, NOW)
        .unwrap()
        .valid_until();
    assert!(until < common.expires_at());
    let late = until - 10;
    for (deadline, accepted) in [(until - 1, true), (until, false)] {
        let (context, request) = signer_requests(&common, deadline, deadline);
        let issuance = policy
            .sign_root_board_issuance_context(&context, late)
            .await;
        let presentation = policy.sign_root_board_request(&request, late).await;
        assert_eq!(issuance.is_ok(), accepted);
        assert_eq!(presentation.is_ok(), accepted);
        if accepted {
            for bytes in [issuance.unwrap(), presentation.unwrap()] {
                assert_eq!(
                    policy
                        .key_ring()
                        .unwrap()
                        .verify(&bytes, csgn::Kind::Credential, late)
                        .unwrap()
                        .valid_until(),
                    until
                );
            }
        }
    }
    let late = common.expires_at() - 10;
    policy.publish_root_board(&common, late).await.unwrap();
    let (context, request) = signer_requests(&common, common.expires_at() - 1, 823);
    let issuance = policy
        .sign_root_board_issuance_context(&context, late)
        .await
        .unwrap();
    let presentation = policy
        .sign_root_board_request(&request, late)
        .await
        .unwrap();
    for bytes in [issuance, presentation] {
        assert_eq!(
            policy
                .key_ring()
                .unwrap()
                .verify(&bytes, csgn::Kind::Credential, late)
                .unwrap()
                .valid_until(),
            common.expires_at()
        );
    }
}

#[tokio::test]
async fn typed_root_signers_require_the_exact_published_descriptor() {
    let (_directory, _db, _rules, mut policy) = setup().await;
    let root_issuer = issuer(824);
    let epoch = policy.epoch(NOW).await.unwrap();
    let common = descriptor(&root_issuer, epoch, 0);
    let (context, request) = signer_requests(&common, NOW + 10, 824);
    assert!(
        policy
            .sign_root_board_issuance_context(&context, NOW)
            .await
            .is_err()
    );
    assert!(policy.sign_root_board_request(&request, NOW).await.is_err());
    policy.publish_root_board(&common, NOW).await.unwrap();
    let foreign_scope = RootBoardPublicKey::from_authenticated_beacon(
        root_issuer.public_key().clone(),
        cpsd::CommunityId::new(b"other-root").unwrap(),
        epoch,
        0,
    )
    .unwrap();
    let other_issuer = issuer(825);
    for wrong in [
        descriptor(&other_issuer, epoch, 0),
        descriptor(&root_issuer, epoch + 1, 0),
        foreign_scope,
    ] {
        let (context, request) = signer_requests(&wrong, NOW + 10, 825);
        assert!(
            policy
                .sign_root_board_issuance_context(&context, NOW)
                .await
                .is_err()
        );
        assert!(policy.sign_root_board_request(&request, NOW).await.is_err());
    }
    assert!(
        policy
            .sign_root_board_issuance_context(&context, NOW)
            .await
            .is_ok()
    );
    let signed = policy.sign_root_board_request(&request, NOW).await.unwrap();
    assert!(
        signer_anchor(&policy, ROOT)
            .authenticate_root_board_request(&signed, NOW)
            .unwrap()
            == request
    );
}

#[tokio::test]
async fn typed_root_signers_follow_real_rotation_sql_fencing_and_epoch_invalidation() {
    let (_directory, db, rules, mut policy) = setup().await;
    let root_issuer = issuer(826);
    let common = descriptor(&root_issuer, policy.epoch(NOW).await.unwrap(), 0);
    policy.publish_root_board(&common, NOW).await.unwrap();
    let (context, request) = signer_requests(&common, NOW + 10, 826);
    let old = policy.sign_root_board_request(&request, NOW).await.unwrap();
    let old_key = policy
        .key_ring()
        .unwrap()
        .verify(&old, csgn::Kind::Credential, NOW)
        .unwrap()
        .key_id();
    policy.rotate(key(2), NOW).await.unwrap();
    assert!(
        signer_anchor(&policy, ROOT)
            .authenticate_root_board_request(&old, NOW)
            .unwrap()
            == request
    );
    let rotated = policy.sign_root_board_request(&request, NOW).await.unwrap();
    assert_ne!(
        policy
            .key_ring()
            .unwrap()
            .verify(&rotated, csgn::Kind::Credential, NOW)
            .unwrap()
            .key_id(),
        old_key
    );
    assert!(
        policy
            .sign_root_board_issuance_context(&context, NOW)
            .await
            .is_ok()
    );
    let mut reopened = reopen(&db, rules, 2, NOW).await;
    assert!(
        policy
            .sign_root_board_issuance_context(&context, NOW)
            .await
            .is_err()
    );
    assert!(policy.sign_root_board_request(&request, NOW).await.is_err());
    reopened.bump_epoch().await.unwrap();
    assert!(
        reopened
            .sign_root_board_issuance_context(&context, NOW)
            .await
            .is_err()
    );
    assert!(
        reopened
            .sign_root_board_request(&request, NOW)
            .await
            .is_err()
    );
    let next = descriptor(&root_issuer, reopened.epoch(NOW).await.unwrap(), 0);
    reopened.publish_root_board(&next, NOW).await.unwrap();
    // The publication is live again: these failures isolate the stale epoch binding.
    assert!(
        reopened
            .sign_root_board_issuance_context(&context, NOW)
            .await
            .is_err()
    );
    assert!(
        reopened
            .sign_root_board_request(&request, NOW)
            .await
            .is_err()
    );
    let (context, request) = signer_requests(&next, NOW + 10, 827);
    assert!(
        reopened
            .sign_root_board_issuance_context(&context, NOW)
            .await
            .is_ok()
    );
    let signed = reopened
        .sign_root_board_request(&request, NOW)
        .await
        .unwrap();
    assert!(
        signer_anchor(&reopened, ROOT)
            .authenticate_root_board_request(&signed, NOW)
            .unwrap()
            == request
    );
}
