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
