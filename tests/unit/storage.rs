use super::*;

async fn created(community: &str) -> (MemoryStore, StoredPolicy) {
    let store = MemoryStore::new(community).unwrap();
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        community,
        csgn::SecretKey::from_seed(&mut [11; 32]),
        0,
        30 * crate::DAY,
    )
    .await
    .unwrap();
    crate::Policy::create(
        crbk::MemoryStore::default(),
        store.clone(),
        signer,
        Config {
            credential_action: "admit".into(),
            snapshot_validity: crate::DAY,
        },
    )
    .await
    .unwrap();
    let state = store.load().await.unwrap().unwrap();
    (store, state)
}

#[tokio::test]
async fn real_poisoned_memory_lock_refuses_reads_and_writes() {
    let (store, state) = created("garden").await;
    let shared = store.state.clone();
    assert!(
        std::thread::spawn(move || {
            let _held = shared.lock().unwrap();
            panic!("interrupt the actual held state lock");
        })
        .join()
        .is_err()
    );
    assert!(matches!(store.load().await, Err(Error::Storage)));
    assert!(matches!(
        store.compare_exchange(None, &state).await,
        Err(Error::Storage)
    ));
}

#[tokio::test]
async fn reopened_policy_refuses_foreign_state_in_the_actual_memory_store() {
    let (foreign, state) = created("other").await;
    assert_eq!(foreign.community(), "other");
    let store = MemoryStore::new("garden").unwrap();
    // Corrupt the actual backend's retained bytes/state rather than replace the
    // policy or storage protocol with a successful stand-in implementation.
    *store.state.lock().unwrap() = Some(state);
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        "garden",
        csgn::SecretKey::from_seed(&mut [12; 32]),
        0,
        30 * crate::DAY,
    )
    .await
    .unwrap();
    assert!(matches!(
        crate::Policy::open(crbk::MemoryStore::default(), store, signer).await,
        Err(Error::Corrupt)
    ));
}

#[tokio::test]
async fn signed_balance_floor_survives_rejected_current_state_transitions() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("../fixtures/balance-material.json")).unwrap();
    let material: crate::PublicVerifierMaterial =
        serde_json::from_value(fixture["material"].clone()).unwrap();
    material.validate_at(&material.community, 100).unwrap();
    let (store, initial) = created(&material.community).await;
    // Genuine canonical material signed by the same independently configured
    // test root as created(). This exercises storage, not native proof authority.
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        &material.community,
        csgn::SecretKey::from_seed(&mut [11; 32]),
        0,
        30 * crate::DAY,
    )
    .await
    .unwrap();
    let bytes = signer
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&material).unwrap(),
            0,
            2000,
        )
        .await
        .unwrap();
    signer
        .key_ring()
        .unwrap()
        .verify(&bytes, csgn::Kind::SettingsSnapshot, 100)
        .unwrap();
    let mut committed = initial.clone();
    committed.revision += 1;
    committed.balance = Some(Publication {
        revision: 1,
        cose: Some(bytes),
    });
    store
        .compare_exchange(Some(initial.revision), &committed)
        .await
        .unwrap();
    for case in 0..5 {
        let mut next = committed.clone();
        next.revision += 1;
        match case {
            0 => next.balance = None,
            1 => next.balance.as_mut().unwrap().revision = 0,
            2 => next.balance.as_mut().unwrap().cose.as_mut().unwrap()[0] ^= 1,
            3 => next.balance.as_mut().unwrap().cose = Some(vec![]),
            _ => next.balance.as_mut().unwrap().cose = Some(vec![0; MAX_DOCUMENT_BYTES + 8193]),
        }
        assert!(
            store
                .compare_exchange(Some(committed.revision), &next)
                .await
                .is_err()
        );
        assert_eq!(store.load().await.unwrap(), Some(committed.clone()));
    }
    // Invalidation removes signed authority, never the required publication floor.
    let mut invalidated = committed.clone();
    invalidated.revision += 1;
    invalidated.epoch += 1;
    invalidated.balance.as_mut().unwrap().cose = None;
    store
        .compare_exchange(Some(committed.revision), &invalidated)
        .await
        .unwrap();
    assert_eq!(store.load().await.unwrap(), Some(invalidated.clone()));
    let mut stale = invalidated.clone();
    stale.revision += 1;
    stale.balance = committed.balance;
    assert!(
        store
            .compare_exchange(Some(initial.revision), &stale)
            .await
            .is_err()
    );
    assert_eq!(store.load().await.unwrap(), Some(invalidated));
}
