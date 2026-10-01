//! Original csgn proofs survive actual durable-owner handoff and process reopen.
mod common;
use common::*;
use cplc::*;
use serde_json::json;

#[tokio::test]
async fn interrupted_key_handoff_recovers_before_and_after_policy_retention() {
    for phase in 0..3 {
        let directory = tempfile::tempdir().unwrap();
        let url = format!("file://{}", directory.path().join("rules.db").display());
        let (_, rules) = databases(&url, "").await;
        let store = MemoryStore::new(COMMUNITY).unwrap();
        let keys = csgn::MemoryStore::default();
        let signer = csgn::PersistentSigner::create(
            keys.clone(),
            COMMUNITY,
            key(1),
            day(NOW),
            ESTABLISHED_MEMBER_VALIDITY,
        )
        .await
        .unwrap();
        let root = signer.key_ring().unwrap().clone();
        let mut policy = Policy::create(
            crbk::LibsqlStore::new(rules.clone()),
            store.clone(),
            signer,
            config(),
        )
        .await
        .unwrap();
        configure(&mut policy, book(admission())).await;
        let initial = policy.trust_feed(NOW).await.unwrap();
        drop(policy);

        // The real signer commits its successor and original endorsement first.
        let mut signer = csgn::PersistentSigner::open(keys.clone(), COMMUNITY, key(1), day(NOW))
            .await
            .unwrap();
        let proof = signer
            .rotate_with_proof(key(2), day(NOW), ESTABLISHED_MEMBER_VALIDITY)
            .await
            .unwrap();
        assert_eq!(signer.ring_revision().unwrap(), 1);
        if phase > 0 {
            // Persist the exact handoff through the actual Policy store, then
            // simulate interruption before or after the signer acknowledgement.
            let old = store.load().await.unwrap().unwrap();
            let mut next = serde_json::to_value(&old).unwrap();
            next["revision"] = json!(old.revision() + 1);
            next["key_transitions"] = json!([{"revision":1,"proof":proof}]);
            let next: StoredPolicy = serde_json::from_value(next).unwrap();
            store
                .compare_exchange(Some(old.revision()), &next)
                .await
                .unwrap();
        }
        if phase == 2 {
            signer.acknowledge_transition(1).await.unwrap();
        }
        drop(signer);
        let signer = csgn::PersistentSigner::open(keys.clone(), COMMUNITY, key(2), day(NOW))
            .await
            .unwrap();
        let mut reopened = Policy::open(crbk::LibsqlStore::new(rules), store, signer)
            .await
            .unwrap();
        assert_eq!(reopened.key_transitions().unwrap().len(), 1);
        assert_eq!(reopened.key_transitions().unwrap()[0].proof, proof);
        let verified = csgn::verify_transition(&root, &proof, NOW).unwrap();
        assert_eq!(verified.revision(), 1);
        assert_eq!(verified.previous(), &root);
        assert_eq!(verified.next(), reopened.key_ring().unwrap());
        let refreshed = reopened.trust_feed(NOW).await.unwrap();
        assert_eq!(
            refreshed.key_transitions,
            reopened.key_transitions().unwrap()
        );
        assert_eq!(refreshed.policy_epoch, initial.policy_epoch);
        // Ordinary issuance and publication may update private CAS state only.
        reopened
            .issue_test(request(&[development_gate(500)]), NOW)
            .await
            .unwrap();
        assert_eq!(reopened.key_transitions().unwrap()[0].proof, proof);
        drop(reopened);
        let signer = csgn::PersistentSigner::open(keys, COMMUNITY, key(2), day(NOW))
            .await
            .unwrap();
        assert_eq!(signer.ring_revision().unwrap(), 1);
        assert!(signer.pending_transition().unwrap().is_none());
    }
}

#[tokio::test]
async fn real_sql_rotation_and_pruning_publish_original_monotonic_proofs() {
    let (_directory, db, rules_db, mut policy) = local().await;
    let root = policy.key_ring().unwrap().clone();
    let initial = policy.trust_feed(NOW).await.unwrap();
    policy.rotate(key(2), NOW).await.unwrap();
    let rotated = policy.trust_feed(NOW).await.unwrap();
    assert_eq!(rotated.key_transitions.len(), 1);
    assert_eq!(rotated.policy_epoch, initial.policy_epoch);
    let transition =
        csgn::verify_transition(&root, &rotated.key_transitions[0].proof, NOW).unwrap();
    let intermediate = transition.next().clone();
    // A no-op prune does not expose a new public ring revision.
    policy.prune_keys(NOW).await.unwrap();
    assert_eq!(policy.key_transitions().unwrap(), rotated.key_transitions);
    policy
        .prune_keys(ESTABLISHED_MEMBER_VALIDITY)
        .await
        .unwrap();
    assert_eq!(policy.key_transitions().unwrap().len(), 2);
    let original = policy.key_transitions().unwrap().to_vec();
    let pruned = csgn::verify_transition(
        &intermediate,
        &original[1].proof,
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .unwrap();
    assert_eq!(pruned.revision(), 2);
    assert_eq!(pruned.previous(), &intermediate);
    assert_eq!(pruned.next(), policy.key_ring().unwrap());
    drop(policy);
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(2),
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    let reopened = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert_eq!(reopened.key_transitions().unwrap(), original);
}

#[tokio::test]
async fn rotated_signers_require_the_existing_policy_history() {
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(1),
        0,
        ESTABLISHED_MEMBER_VALIDITY,
    )
    .await
    .unwrap();
    signer
        .rotate_with_proof(key(2), 0, ESTABLISHED_MEMBER_VALIDITY)
        .await
        .unwrap();
    assert!(matches!(
        Policy::create(
            crbk::MemoryStore::default(),
            MemoryStore::new(COMMUNITY).unwrap(),
            signer,
            config()
        )
        .await,
        Err(Error::Invalid("unretained key history"))
    ));
}

#[tokio::test]
async fn a_real_policy_write_refusal_keeps_the_signer_proof_recoverable() {
    let (directory, db, rules_db, mut policy) = local().await;
    let root = policy.key_ring().unwrap().clone();
    policy.trust_feed(NOW).await.unwrap();
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    connection.execute_batch("CREATE TRIGGER stop_continuity BEFORE UPDATE ON cplc_policy BEGIN SELECT RAISE(IGNORE); END;").await.unwrap();
    assert!(matches!(
        policy.rotate(key(2), NOW).await,
        Err(Error::Conflict)
    ));
    assert!(matches!(policy.key_ring(), Err(Error::ReloadRequired)));
    assert!(matches!(
        policy.trust_feed(NOW).await,
        Err(Error::ReloadRequired)
    ));
    assert!(matches!(
        policy.trust_manifest(NOW).await,
        Err(Error::ReloadRequired)
    ));
    assert!(matches!(
        policy.publish(SnapshotKind::Settings, NOW).await,
        Err(Error::ReloadRequired)
    ));
    drop(policy);
    connection
        .execute_batch("DROP TRIGGER stop_continuity;")
        .await
        .unwrap();
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(2),
        day(NOW),
    )
    .await
    .unwrap();
    let original = signer.pending_transition().unwrap().unwrap().to_vec();
    let mut recovered = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert_eq!(recovered.key_transitions().unwrap()[0].proof, original);
    let verified = csgn::verify_transition(&root, &original, NOW).unwrap();
    assert_eq!(verified.next(), recovered.key_ring().unwrap());
    assert_eq!(
        recovered.trust_feed(NOW).await.unwrap().key_transitions[0].proof,
        original
    );
}

#[tokio::test]
async fn signer_acknowledgement_refusal_retains_one_proof_and_fences_outputs() {
    let (directory, db, rules_db, mut policy) = local().await;
    let root = policy.key_ring().unwrap().clone();
    let initial = policy.trust_feed(NOW).await.unwrap();
    let snapshot = policy.verified_settings(NOW).await.unwrap();
    let gates = checked(&snapshot, MEMBER, "admit", &[development_gate(500)], NOW)
        .await
        .unwrap();
    let membership = FixtureMembership {
        member: MEMBER.into(),
        state: crbk::MembershipState::Admitted,
        probation_until: None,
        lease_end: 90 * DAY,
        authorized_devices: DEVICES.to_vec(),
    };
    let request = || CredentialRequest {
        subject: subject(),
        handle: "testmember",
        schema_version: 1,
        snapshot: &snapshot,
        gates: &gates,
        pins: &[],
        devices: DEVICES,
    };
    policy.issue(&membership, request(), NOW).await.unwrap();
    let signer_store = csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap());
    let original_revision = csgn::Store::load(&signer_store, COMMUNITY)
        .await
        .unwrap()
        .unwrap()
        .revision;
    let blocked = original_revision + 1;
    let raw = libsql::Builder::new_local(directory.path().join("policy.db"))
        .build()
        .await
        .unwrap();
    let connection = raw.connect().unwrap();
    // Rotation advances the signer once; refuse only its later acknowledgement.
    connection
        .execute_batch(&format!(
            "CREATE TRIGGER block_signer_ack BEFORE UPDATE ON csgn_state \
             WHEN OLD.revision = {blocked} AND OLD.issuer = '{COMMUNITY}' \
             AND OLD.community_id = '{COMMUNITY}' \
             BEGIN SELECT RAISE(IGNORE); END;"
        ))
        .await
        .unwrap();
    assert!(matches!(
        policy.rotate(key(2), NOW).await,
        Err(Error::Signing)
    ));
    // The signer invalidates itself on the refused write. Neither cached bytes
    // nor an already checked credential request may bypass its refusal.
    assert!(matches!(policy.key_ring(), Err(Error::Signing)));
    assert!(matches!(policy.trust_feed(NOW).await, Err(Error::Signing)));
    assert!(matches!(
        policy.trust_manifest(NOW).await,
        Err(Error::Signing)
    ));
    assert!(matches!(
        policy.publish(SnapshotKind::Settings, NOW).await,
        Err(Error::Signing)
    ));
    assert!(matches!(
        policy.issue(&membership, request(), NOW).await,
        Err(Error::Signing)
    ));
    let stored = LibsqlStore::new(&db, COMMUNITY)
        .unwrap()
        .load()
        .await
        .unwrap()
        .unwrap();
    let value = serde_json::to_value(&stored).unwrap();
    let retained: Vec<cbcn::KeyTransition> =
        serde_json::from_value(value["key_transitions"].clone()).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].revision, 1);
    drop(policy);
    connection
        .execute_batch("DROP TRIGGER block_signer_ack;")
        .await
        .unwrap();
    let signer = csgn::PersistentSigner::open(signer_store, COMMUNITY, key(2), day(NOW))
        .await
        .unwrap();
    let pending = signer.pending_transition().unwrap().unwrap();
    assert_eq!(pending, retained[0].proof);
    let verified = csgn::verify_transition(&root, pending, NOW).unwrap();
    assert_eq!(verified.revision(), 1);
    assert_eq!(verified.previous(), &root);
    assert_eq!(verified.next(), signer.key_ring().unwrap());
    let mut reopened = Policy::open(
        crbk::LibsqlStore::new(rules_db.clone()),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert_eq!(reopened.key_transitions().unwrap(), retained);
    let feed = reopened.trust_feed(NOW).await.unwrap();
    assert_eq!(feed.policy_epoch, initial.policy_epoch);
    assert_eq!(feed.key_transitions, retained);
    drop(reopened);
    let signer = csgn::PersistentSigner::open(
        csgn::LibsqlStore::new(db.community(COMMUNITY).unwrap()),
        COMMUNITY,
        key(2),
        day(NOW),
    )
    .await
    .unwrap();
    assert!(signer.pending_transition().unwrap().is_none());
    assert_eq!(signer.ring_revision().unwrap(), 1);
    let reopened = Policy::open(
        crbk::LibsqlStore::new(rules_db),
        LibsqlStore::new(&db, COMMUNITY).unwrap(),
        signer,
    )
    .await
    .unwrap();
    assert_eq!(reopened.key_transitions().unwrap(), retained);
}

#[tokio::test]
async fn retained_history_cannot_be_rewritten_or_silently_reset_at_capacity() {
    let store = MemoryStore::new(COMMUNITY).unwrap();
    let signer =
        csgn::PersistentSigner::create(csgn::MemoryStore::default(), COMMUNITY, key(1), 0, DAY)
            .await
            .unwrap();
    let mut policy = Policy::create(
        crbk::MemoryStore::default(),
        store.clone(),
        signer,
        config(),
    )
    .await
    .unwrap();
    assert!(matches!(
        policy.rotate(key(2), u64::MAX).await,
        Err(Error::Invalid("time overflow"))
    ));
    for index in 1..=128u8 {
        let now = u64::from(index) * DAY;
        policy.rotate(key(index + 1), now).await.unwrap();
        policy.prune_keys(now + DAY).await.unwrap();
    }
    assert_eq!(policy.key_transitions().unwrap().len(), 256);
    let original = policy.key_transitions().unwrap().to_vec();
    for rewrite in [false, true] {
        let old = store.load().await.unwrap().unwrap();
        let mut next = serde_json::to_value(&old).unwrap();
        next["revision"] = json!(old.revision() + 1);
        if rewrite {
            next["key_transitions"][0]["proof"][0] = json!(0);
        } else {
            next["key_transitions"] = json!([]);
        }
        let next: StoredPolicy = serde_json::from_value(next).unwrap();
        assert!(matches!(
            store.compare_exchange(Some(old.revision()), &next).await,
            Err(Error::Corrupt)
        ));
    }
    assert!(matches!(
        policy.rotate(key(130), 129 * DAY).await,
        Err(Error::Invalid("key history exhausted"))
    ));
    assert!(matches!(
        policy.prune_keys(129 * DAY).await,
        Err(Error::Invalid("key history exhausted"))
    ));
    assert_eq!(policy.key_transitions().unwrap(), original);
}
