use serde::de::DeserializeOwned;

use crate::{Error, Result, Snapshot, SnapshotKind};

/// Caller-authenticated scope and freshness requirements, never peer input.
pub struct SnapshotExpectation<'a> {
    /// Expected community and ring issuer.
    pub community: &'a str,
    /// Expected protected COSE kind.
    pub kind: SnapshotKind,
    /// Lowest acceptable publication revision for this kind.
    pub minimum_revision: u64,
    /// Exact current policy epoch from an authenticated authority.
    pub policy_epoch: u64,
    /// Trusted current Unix seconds.
    pub now: u64,
}

/// Authenticate and decode a typed snapshot, rejecting wrong scope, kind, time,
/// epoch and revision. The caller authenticates the ring and freshness floors.
/// Validate content semantics with the appropriate leaf before relying on it.
pub fn verify_snapshot<T: DeserializeOwned>(
    ring: &csgn::KeyRing,
    cose: &[u8],
    expected: SnapshotExpectation<'_>,
) -> Result<Snapshot<T>> {
    if ring.issuer() != expected.community || expected.policy_epoch == 0 {
        return Err(Error::Verification);
    }
    let verified = ring
        .verify(cose, expected.kind.signing_kind(), expected.now)
        .map_err(|_| Error::Verification)?;
    let snapshot: Snapshot<T> =
        serde_json::from_slice(verified.payload()).map_err(|_| Error::Verification)?;
    if snapshot.community != expected.community
        || snapshot.revision == 0
        || snapshot.revision > i64::MAX as u64
        || snapshot.revision < expected.minimum_revision
        || snapshot.policy_epoch != expected.policy_epoch
    {
        return Err(Error::Verification);
    }
    Ok(snapshot)
}

/// Authenticated settings and envelope metadata. Only signature verification or
/// the current policy publisher can construct this capability.
///
/// ```compile_fail
/// let unverified: crbk::Snapshot = todo!();
/// let verified: cplc::VerifiedSnapshot = unverified.into();
/// ```
#[derive(Clone)]
pub struct VerifiedSnapshot {
    pub(crate) snapshot: crbk::Snapshot,
    pub(crate) valid_until: u64,
    pub(crate) publication: Vec<u8>,
}

impl VerifiedSnapshot {
    /// Immutable settings for gate execution; mutation cannot alter this witness.
    pub fn settings(&self) -> &crbk::Snapshot {
        &self.snapshot
    }
    /// Exclusive authenticated publication expiry.
    pub fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

/// Verify a settings publication while retaining all authenticated metadata.
pub fn verify_settings(
    ring: &csgn::KeyRing,
    cose: &[u8],
    expected: SnapshotExpectation<'_>,
) -> Result<VerifiedSnapshot> {
    if expected.kind != SnapshotKind::Settings {
        return Err(Error::Verification);
    }
    let verified = ring
        .verify(cose, csgn::Kind::SettingsSnapshot, expected.now)
        .map_err(|_| Error::Verification)?;
    let document: Snapshot<crbk::Values> = verify_snapshot(ring, cose, expected)?;
    Ok(VerifiedSnapshot {
        snapshot: crbk::Snapshot {
            community: document.community,
            kind: crbk::SnapshotKind::Settings,
            revision: document.revision,
            policy_epoch: document.policy_epoch,
            issued: crate::timestamp(verified.issued_at())?,
            content: document.content,
        },
        valid_until: verified.valid_until(),
        publication: cose.to_vec(),
    })
}
