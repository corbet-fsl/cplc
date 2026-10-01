//! Real signer/configuration and authenticated snapshot boundary refusals.
mod common;
use common::*;
use cplc::*;
use serde_json::{Value, json};

#[tokio::test]
async fn configuration_and_signer_day_boundaries_are_mandatory() {
    assert!(MemoryStore::new("x".repeat(257)).is_err());
    assert!(MemoryStore::new("bad\u{0}scope").is_err());
    for case in 0..5 {
        let signer = csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            COMMUNITY,
            key(1),
            day(NOW),
            30 * DAY,
        )
        .await
        .unwrap();
        let mut bad = config();
        match case {
            0 => bad.credential_action = "a".repeat(201),
            1 => bad.credential_action = "not/an/action".into(),
            2 => bad.snapshot_validity = 0,
            3 => bad.snapshot_validity = DAY + 1,
            _ => bad.snapshot_validity = (i64::MAX as u64 / DAY + 1) * DAY,
        }
        assert!(
            Policy::create(
                crbk::MemoryStore::default(),
                MemoryStore::new(COMMUNITY).unwrap(),
                signer,
                bad
            )
            .await
            .is_err()
        );
    }
    let signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(1),
        1,
        30 * DAY,
    )
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
        Err(Error::Invalid("signer day boundary"))
    ));
}

#[tokio::test]
async fn real_signed_snapshots_refuse_zero_epoch_oversized_revision_and_wrong_kind() {
    let mut signer = csgn::PersistentSigner::create(
        csgn::MemoryStore::default(),
        COMMUNITY,
        key(1),
        day(NOW),
        30 * DAY,
    )
    .await
    .unwrap();
    let payload = json!({"community":COMMUNITY,"revision":u64::MAX,"policy_epoch":1,"content":{}});
    let signed = signer
        .sign(
            csgn::Kind::SettingsSnapshot,
            &serde_json::to_vec(&payload).unwrap(),
            day(NOW),
            DAY,
        )
        .await
        .unwrap();
    assert!(
        verify_snapshot::<Value>(
            signer.key_ring().unwrap(),
            &signed,
            expectation(SnapshotKind::Settings, 1, NOW)
        )
        .is_err()
    );
    assert!(
        verify_snapshot::<Value>(
            signer.key_ring().unwrap(),
            &signed,
            expectation(SnapshotKind::Settings, 0, NOW)
        )
        .is_err()
    );
    assert!(
        verify_settings(
            signer.key_ring().unwrap(),
            &signed,
            expectation(SnapshotKind::Schema, 1, NOW)
        )
        .is_err()
    );
}
