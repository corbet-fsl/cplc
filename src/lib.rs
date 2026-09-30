//! Community policy composition over crbk, cshm, csgn and crlt.
//!
//! See [`Policy`] and the implemented contract in `docs/CONTRACT.md`.
#![forbid(unsafe_code)]

mod policy;
mod storage;
mod types;
mod verification;

pub use policy::Policy;
pub use storage::{LibsqlStore, MemoryStore, SCHEMA, Storage, StoredPolicy};
pub use types::*;
pub use verification::{SnapshotExpectation, VerifiedSnapshot, verify_settings, verify_snapshot};

/// Leaf APIs used by the composition root; no alternate policy/crypto engine.
pub use {cpsd, crbk, crlt, csgn, cshm};

/// Redacted failures; supplied values and upstream SQL never enter diagnostics.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A facade input is invalid.
    #[error("invalid policy input: {0}")]
    Invalid(&'static str),
    /// No active rulebook or schema exists yet.
    #[error("required policy configuration is missing")]
    Missing,
    /// The rulebook refused the configured credential action.
    #[error("credential policy refused")]
    Denied(crbk::Decision),
    /// A current revocation prevents issuance.
    #[error("community authorization revoked")]
    Revoked,
    /// Another policy writer committed first.
    #[error("policy revision conflict")]
    Conflict,
    /// Stored state failed validation.
    #[error("invalid stored policy")]
    Corrupt,
    /// Storage failed; a remote commit outcome may be unknown.
    #[error("policy storage unavailable; reload required")]
    Storage,
    /// A cancelled or failed mutation requires reopening.
    #[error("reload policy before continuing")]
    ReloadRequired,
    /// An operation in the rulebook leaf failed.
    #[error("rulebook operation failed")]
    Rulebook,
    /// An operation in the schema leaf failed.
    #[error("schema validation failed")]
    Schema,
    /// Signing or its durable state update failed.
    #[error("signing operation failed; inspect or reopen the signer")]
    Signing,
    /// Signature, issuer, epoch, revision or payload validation failed.
    #[error("signed policy verification failed")]
    Verification,
}

/// Result with value-free error messages.
pub type Result<T> = std::result::Result<T, Error>;

impl From<crbk::Error> for Error {
    fn from(error: crbk::Error) -> Self {
        match error {
            crbk::Error::Conflict => Self::Conflict,
            _ => Self::Rulebook,
        }
    }
}

pub(crate) fn identifier(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 256 || value.contains('\0') {
        return Err(Error::Invalid("identifier"));
    }
    Ok(())
}

pub(crate) fn timestamp(now: u64) -> Result<i64> {
    i64::try_from(now).map_err(|_| Error::Invalid("time range"))
}

/// Seconds in a UTC day; persisted membership and issuance buckets use this unit.
pub const DAY: u64 = 86_400;
/// Start of the containing UTC day, never later than the supplied time.
pub const fn day(now: u64) -> u64 {
    now / DAY * DAY
}
