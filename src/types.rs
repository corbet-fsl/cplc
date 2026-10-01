use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Result, identifier};

/// Maximum size of a facade state document or signed JSON payload.
pub const MAX_DOCUMENT_BYTES: usize = 1 << 20;
/// Maximum count per public policy or credential collection.
pub const MAX_ENTRIES: usize = 256;
/// Maximum lifetime of a newly admitted member's credential, in seconds.
pub const NEW_MEMBER_VALIDITY: u64 = 86_400;
/// Maximum lifetime of an established member's credential, in seconds.
pub const ESTABLISHED_MEMBER_VALIDITY: u64 = 30 * NEW_MEMBER_VALIDITY;

/// Trusted service configuration, persisted once for this policy scope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Action evaluated by credential issuance; never selected by a member request.
    pub credential_action: String,
    /// Maximum lifetime of public snapshots, in whole days expressed as seconds.
    pub snapshot_validity: u64,
}

impl Config {
    pub(crate) fn validate(&self) -> Result<()> {
        identifier(&self.credential_action)?;
        if self.credential_action.len() > 200
            || !self
                .credential_action
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
            || self.snapshot_validity == 0
            || !self.snapshot_validity.is_multiple_of(crate::DAY)
            || self.snapshot_validity > i64::MAX as u64
        {
            return Err(crate::Error::Invalid("configuration"));
        }
        Ok(())
    }
}

/// The four public policy documents. The COSE protected header binds the kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotKind {
    /// Flat resolved crbk values; no member overrides or proof metadata.
    Settings,
    /// Validated cshm profile schema.
    Schema,
    /// All retained schema versions and their cshm change classifications.
    SchemaVersions,
    /// Explicitly supplied public community identifiers, never memberships.
    Communities,
    /// Current community revocations, never global suspension data.
    RevocationList,
}

impl SnapshotKind {
    /// Corresponding authenticated csgn content kind.
    pub fn signing_kind(self) -> csgn::Kind {
        match self {
            Self::Settings => csgn::Kind::SettingsSnapshot,
            Self::Schema | Self::SchemaVersions => csgn::Kind::SchemaSnapshot,
            Self::Communities => csgn::Kind::CommunitiesSnapshot,
            Self::RevocationList => csgn::Kind::RevocationListSnapshot,
        }
    }
}

/// Typed JSON inside COSE. Issued time, expiry, kind and key ID are in its
/// authenticated csgn envelope, so they cannot disagree with duplicate fields.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot<T> {
    /// Community namespace, also the csgn issuer.
    pub community: String,
    /// Positive publication sequence, independent for each kind.
    pub revision: u64,
    /// Policy epoch applying to this document.
    pub policy_epoch: u64,
    /// Resolved settings, schema, public communities or revocations.
    pub content: T,
}

/// Current revocations for this community only, with no event history or times.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Revocations {
    /// Revoked community pseudonyms.
    pub members: BTreeSet<String>,
    /// Revoked public device keys.
    pub devices: BTreeSet<[u8; 32]>,
}

/// Current membership facts read by the owning membership facade.
/// Selecting an implementation of MembershipSource is a privileged service task.
pub struct MembershipFacts {
    /// Fixed community of the source.
    pub community: String,
    /// Canonical community pseudonym.
    pub member: String,
    /// Persisted lifecycle state, never a caller-selected issuance class.
    pub state: crbk::MembershipState,
    /// Exclusive UTC-day probation end; absent once probation has finished.
    pub probation_until: Option<u64>,
    /// Exclusive UTC-day lease end derived from the register's coarse month.
    pub lease_end: u64,
}

/// Read authoritative membership state at issuance. cmbr implements this boundary;
/// cplc does not maintain a second member database or accept a lifetime class.
pub trait MembershipSource {
    /// Per-member serialization capability, held until signing has completed.
    /// cmbr uses its member queue guard; read-only lobby calls never acquire it.
    type Lease: Send + Sync;
    /// Read current lifecycle, probation and lease for this authenticated member.
    fn membership(
        &self,
        member: &str,
        now: u64,
    ) -> impl std::future::Future<Output = Result<(MembershipFacts, Self::Lease)>>;
}

/// A pin fingerprint supplied by the membership facade; never an opening/salt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pin {
    /// Stable schema field ID.
    pub field: String,
    /// cpns fingerprint, already authorized and checked by membership.
    pub fingerprint: [u8; 32],
}

/// Community proof metadata inside a credential. Subject and level are implied
/// by the enclosing credential, and no proof time or raw evidence is included.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialGate {
    /// Gate identifier.
    pub gate: String,
    /// Provider identifier.
    pub provider: String,
    /// Exclusive proof expiry in Unix seconds.
    pub valid_until: u64,
}

/// Credential payload; never stored by cplc. COSE binds issuance, expiry and key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// Community namespace.
    pub community: String,
    /// Community pseudonym, never a global identity.
    pub member: String,
    /// Canonical, reserved handle supplied by membership.
    pub handle: String,
    /// Profile schema version.
    pub schema_version: u32,
    /// Effective policy epoch.
    pub policy_epoch: u64,
    /// Community gates only; global results remain transient.
    pub gates: Vec<CredentialGate>,
    /// Restricted-field fingerprints.
    pub pins: Vec<Pin>,
    /// Public device keys authorized by membership.
    pub devices: Vec<[u8; 32]>,
}

/// Trusted inputs assembled by cmty from membership and gatekeeping.
/// This is deliberately not deserializable as an untrusted request body.
///
/// ```compile_fail
/// let raw: Vec<crbk::GateResult> = vec![];
/// let _: &cgts::CheckedGates = &raw;
/// ```
pub struct CredentialRequest<'a> {
    /// Verified subject and current membership state.
    pub subject: crbk::Subject<'a>,
    /// Canonical handle already validated/reserved by the membership leaf.
    pub handle: &'a str,
    /// Current schema version checked by the profile gate.
    pub schema_version: u32,
    /// Authenticated current policy publication.
    pub snapshot: &'a crate::VerifiedSnapshot,
    /// cgts receipts, including the mandatory legal check even with no gates.
    pub gates: &'a cgts::CheckedGates,
    /// Authorized pins; no values, salts or openings.
    pub pins: &'a [Pin],
    /// Authorized public device keys, never passkey secrets.
    pub devices: &'a [[u8; 32]],
}

/// Signed transport manifest. The fixed purpose separates it from flat settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustManifest {
    /// Always the single supported manifest format.
    pub purpose: TrustPurpose,
    /// Canonical community and signer issuer.
    pub community: String,
    /// Durable policy-state revision.
    pub revision: u64,
    /// Effective policy epoch, including activated rulebook changes.
    pub policy_epoch: u64,
    /// Current public key ring, in csgn's canonical encoding.
    pub key_ring: Vec<u8>,
    /// Current schema version.
    pub schema_version: u32,
}
/// Domain separation for the signed manifest payload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustPurpose {
    /// Version-one community trust publication.
    #[serde(rename = "cplc.trust.v1")]
    CommunityTrustV1,
}
/// A sparse setting edit. The outer service authenticates the allowed layer.
pub enum SettingEdit {
    /// Community deviation; None removes the row, Some(Null) terminates resolution.
    Community(Option<serde_json::Value>),
    /// Root-only platform value and force flag.
    Platform(Option<crbk::PlatformValue>),
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential").finish_non_exhaustive()
    }
}

/// One validated public schema definition and its predecessor classification.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersion {
    /// Profile definition only; never a member's profile values.
    pub schema: cshm::Schema,
    /// cshm's classification against the preceding retained version.
    pub changes: Option<cshm::ChangeSet>,
}
/// Domain separation for the schema version collection.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SchemaVersionsPurpose {
    /// Version-one archive of public schema definitions.
    #[serde(rename = "cplc.schema-versions.v1")]
    SchemaVersionsV1,
}
/// Public schema history signed under the current community policy epoch.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SchemaVersions {
    /// Prevent confusing this collection with one current schema snapshot.
    pub purpose: SchemaVersionsPurpose,
    /// Schema required for new credentials; history alone grants no grandfathering.
    pub current: u32,
    /// Ordered by increasing schema version, with no member information.
    pub versions: Vec<SchemaVersion>,
}
