//! Real durable issuer-publication ownership through Beacon and configured Charter.
mod common;
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
fn charter(ring: &csgn::KeyRing) -> cchr::Charter {
    cchr::Charter::new(cchr::Configuration {
        origin: "https://root.example.test".into(),
        community: ROOT.into(),
        key_ring: ring.to_cbor(),
        minimum_revision: 1,
        ring_revision: 0,
    })
    .unwrap()
}
fn decoded(view: &cchr::VerifiedCharter, now: u64) -> RootBoardPublicKey {
    assert!(now < view.valid_until());
    let material = view.root_board().unwrap();
    let payload: cbcn::root_board::Payload = serde_json::from_slice(material.payload()).unwrap();
    let descriptor = RootBoardPublicKey::from_bytes(&payload.descriptor).unwrap();
    assert_eq!(descriptor.to_bytes(), payload.descriptor);
    assert_eq!(
        descriptor.community().as_bytes(),
        view.community().as_bytes()
    );
    assert_eq!(descriptor.policy_epoch(), view.policy_epoch());
    assert!(descriptor.cohort_start() <= now && now < descriptor.expires_at());
    assert!(material.valid_until() <= descriptor.expires_at());
    descriptor
}

#[tokio::test]
async fn actual_signer_beacon_charter_and_original_codec_survive_sql_reopen() {
    let (_directory, db, rules, mut policy) = setup().await;
    assert!(policy.root_board_publication(NOW).await.unwrap().is_none());
    assert!(policy.root_board_descriptor(NOW).await.unwrap().is_none());
    let before = policy.trust_feed(NOW).await.unwrap();
    assert!(before.root_board.is_none());
    assert!(
        serde_json::to_value(&*before)
            .unwrap()
            .get("root_board")
            .is_none()
    );
    let ring = policy.key_ring().unwrap().clone();
    let common = descriptor(&issuer(801), policy.epoch(NOW).await.unwrap(), 0);
    let original = policy.publish_root_board(&common, NOW).await.unwrap();
    let (current, until) = policy.root_board_descriptor(NOW).await.unwrap().unwrap();
    assert!(current == common);
    assert_eq!(
        until,
        policy
            .key_ring()
            .unwrap()
            .verify(&original, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap()
            .valid_until()
    );
    assert!(policy.root_board_descriptor(until).await.is_err());
    let feed = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(feed.root_board.as_ref(), Some(&original));
    assert_eq!(policy.trust_feed(NOW + 1).await.unwrap(), feed);
    let mut device = charter(&ring);
    let view = device
        .install(&serde_json::to_vec(&*feed).unwrap(), NOW)
        .unwrap();
    assert!(decoded(view, NOW) == common);
    assert_eq!(view.root_board().unwrap().signed_bytes(), original);
    assert_eq!(view.root_board().unwrap().revision(), 1);
    let manifest: TrustManifest = serde_json::from_slice(
        ring.verify(&feed.manifest, csgn::Kind::SettingsSnapshot, NOW)
            .unwrap()
            .payload(),
    )
    .unwrap();
    assert_eq!(manifest.root_board_revision, Some(1));
    // Export only real public material for replay by the device-side CI suites.
    if let Ok(directory) = std::env::var("CPLC_ROOT_BOARD_VECTOR_DIR") {
        let directory = std::path::Path::new(&directory);
        std::fs::create_dir_all(directory).unwrap();
        std::fs::write(directory.join("root-board-public.bin"), common.to_bytes()).unwrap();
        std::fs::write(
            directory.join("root-board-feed.json"),
            serde_json::to_vec(&*feed).unwrap(),
        )
        .unwrap();
        std::fs::write(
            directory.join("root-board-anchor.json"),
            serde_json::to_vec(&json!({
            "community":ROOT,"key_ring":ring.to_cbor(),"now":NOW}))
            .unwrap(),
        )
        .unwrap();
    }
    let mut reopened = reopen(&db, rules, 1, NOW).await;
    assert!(policy.root_board_publication(NOW).await.is_err());
    assert_eq!(
        reopened.root_board_publication(NOW).await.unwrap(),
        Some(original.clone())
    );
    let reopened_feed = reopened.trust_feed(NOW).await.unwrap();
    assert_eq!(reopened_feed.root_board, Some(original));
    assert!(
        decoded(
            device
                .install(&serde_json::to_vec(&*reopened_feed).unwrap(), NOW)
                .unwrap(),
            NOW
        ) == common
    );
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
async fn signing_rotation_and_epoch_invalidation_preserve_the_common_issuer() {
    let (_directory, db, rules, mut policy) = setup().await;
    let key = issuer(804);
    let common = descriptor(&key, policy.epoch(NOW).await.unwrap(), 0);
    policy.publish_root_board(&common, NOW).await.unwrap();
    let ring = policy.key_ring().unwrap().clone();
    let mut device = charter(&ring);
    device
        .install(
            &serde_json::to_vec(&*policy.trust_feed(NOW).await.unwrap()).unwrap(),
            NOW,
        )
        .unwrap();
    policy.rotate(common::key(2), NOW).await.unwrap();
    let rotated = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(rotated.key_transitions.len(), 1);
    let view = device
        .install(&serde_json::to_vec(&*rotated).unwrap(), NOW)
        .unwrap();
    assert!(decoded(view, NOW) == common);
    policy.bump_epoch().await.unwrap();
    assert!(policy.root_board_publication(NOW).await.is_err());
    assert!(policy.trust_feed(NOW).await.is_err());
    assert!(policy.publish_root_board(&common, NOW).await.is_err());
    let next = descriptor(&key, policy.epoch(NOW).await.unwrap(), 0);
    policy.publish_root_board(&next, NOW).await.unwrap();
    let mut reopened = reopen(&db, rules, 2, NOW).await;
    let updated = reopened.trust_feed(NOW).await.unwrap();
    assert!(
        decoded(
            device
                .install(&serde_json::to_vec(&*updated).unwrap(), NOW)
                .unwrap(),
            NOW
        ) == next
    );
    assert!(
        reopened
            .publish_root_board(&descriptor(&issuer(805), next.policy_epoch(), 0), NOW)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn fixed_cohort_clips_deadline_and_rollover_retains_the_issuer_and_floor() {
    let (_directory, db, rules, mut policy) = setup().await;
    let key = issuer(806);
    let epoch = policy.epoch(NOW).await.unwrap();
    let first = descriptor(&key, epoch, 0);
    let late = ROOT_BOARD_COHORT_SECONDS - 10;
    policy.publish_root_board(&first, late).await.unwrap();
    let mut device = charter(policy.key_ring().unwrap());
    let feed = policy.trust_feed(late).await.unwrap();
    assert_eq!(
        device
            .install(&serde_json::to_vec(&*feed).unwrap(), late)
            .unwrap()
            .valid_until(),
        ROOT_BOARD_COHORT_SECONDS
    );
    assert!(
        policy
            .root_board_publication(ROOT_BOARD_COHORT_SECONDS)
            .await
            .is_err()
    );
    assert_eq!(
        device.current(ROOT_BOARD_COHORT_SECONDS).unwrap_err(),
        cchr::Error::Expired
    );
    let second = descriptor(&key, epoch, ROOT_BOARD_COHORT_SECONDS);
    policy
        .publish_root_board(&second, ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    policy.bump_epoch().await.unwrap();
    let epoch = policy.epoch(ROOT_BOARD_COHORT_SECONDS).await.unwrap();
    let mut reopened = reopen(&db, rules, 1, ROOT_BOARD_COHORT_SECONDS).await;
    // A caller's regressed time makes the old cohort live, but cannot lower its durable floor.
    assert!(
        reopened
            .publish_root_board(&descriptor(&key, epoch, 0), NOW)
            .await
            .is_err()
    );
    let second = descriptor(&key, epoch, ROOT_BOARD_COHORT_SECONDS);
    reopened
        .publish_root_board(&second, ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    let feed = reopened
        .trust_feed(ROOT_BOARD_COHORT_SECONDS)
        .await
        .unwrap();
    assert!(
        decoded(
            device
                .install(
                    &serde_json::to_vec(&*feed).unwrap(),
                    ROOT_BOARD_COHORT_SECONDS
                )
                .unwrap(),
            ROOT_BOARD_COHORT_SECONDS
        ) == second
    );
}

#[tokio::test]
async fn authenticated_transport_is_not_a_decoded_credential_capability() {
    let (_directory, _db, _rules, mut policy) = setup().await;
    let common = descriptor(&issuer(807), policy.epoch(NOW).await.unwrap(), 0);
    policy.publish_root_board(&common, NOW).await.unwrap();
    let feed = policy.trust_feed(NOW).await.unwrap();
    let ring = policy.key_ring().unwrap().clone();
    let mut value = serde_json::to_value(&*feed).unwrap();
    let signed = ring
        .verify(
            feed.root_board.as_ref().unwrap(),
            csgn::Kind::SettingsSnapshot,
            NOW,
        )
        .unwrap();
    let mut payload: cbcn::root_board::Payload = serde_json::from_slice(signed.payload()).unwrap();
    payload.descriptor = vec![0xff];
    let mut fixture_signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        ROOT,
        key(1),
        day(NOW),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    assert_eq!(fixture_signer.key_ring().unwrap(), &ring);
    value["root_board"] = json!(
        fixture_signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&payload).unwrap(),
                day(NOW),
                signed.valid_until()
            )
            .await
            .unwrap()
    );
    let mut device = charter(&ring);
    let view = device
        .install(&serde_json::to_vec(&value).unwrap(), NOW)
        .unwrap();
    let authenticated: cbcn::root_board::Payload =
        serde_json::from_slice(view.root_board().unwrap().payload()).unwrap();
    assert_eq!(authenticated.descriptor, vec![0xff]);
    assert!(RootBoardPublicKey::from_bytes(&authenticated.descriptor).is_err());
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

#[tokio::test]
async fn failed_actual_sql_cas_requires_reopen_and_preserves_prior_publication() {
    let (directory, db, rules, mut policy) = setup().await;
    let common = descriptor(&issuer(810), policy.epoch(NOW).await.unwrap(), 0);
    let original = policy.publish_root_board(&common, NOW).await.unwrap();
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    connection.execute_batch("CREATE TRIGGER stop_root BEFORE UPDATE ON cplc_policy WHEN json_extract(NEW.document, '$.root_board.revision') > 1 BEGIN SELECT RAISE(ABORT, 'fault'); END;").await.unwrap();
    assert!(policy.publish_root_board(&common, NOW).await.is_err());
    assert!(matches!(
        policy.root_board_publication(NOW).await,
        Err(Error::ReloadRequired)
    ));
    assert!(policy.trust_feed(NOW).await.is_err());
    connection
        .execute_batch("DROP TRIGGER stop_root;")
        .await
        .unwrap();
    let mut reopened = reopen(&db, rules, 1, NOW).await;
    assert_eq!(
        reopened.root_board_publication(NOW).await.unwrap(),
        Some(original)
    );
    reopened.publish_root_board(&common, NOW).await.unwrap();
    let feed = reopened.trust_feed(NOW).await.unwrap();
    let mut device = charter(reopened.key_ring().unwrap());
    assert!(
        decoded(
            device
                .install(&serde_json::to_vec(&*feed).unwrap(), NOW)
                .unwrap(),
            NOW
        ) == common
    );
}

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
