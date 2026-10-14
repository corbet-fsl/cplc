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
    /// Revoked original community-scoped passkey credential IDs. Older stored
    /// state predates certificate issuance; newly signed snapshots emit this set.
    #[serde(default)]
    pub passkeys: BTreeSet<Vec<u8>>,
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
    /// Current community device keys bound to live passkeys by the membership
    /// owner. Never copy these from the credential request. The returned lease
    /// prevents revocation or rebinding until signing has completed.
    pub authorized_devices: Vec<[u8; 32]>,
}

/// Read authoritative membership state at issuance. cmbr implements this boundary;
/// cplc does not maintain a second member database or accept a lifetime class.
pub trait MembershipSource {
    /// Per-member serialization capability, held until signing has completed.
    /// cmbr uses its member queue guard; read-only lobby calls never acquire it.
    type Lease: Send + Sync;
    /// Read current lifecycle, lease and authorized devices for this member.
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

/// The versioned issuer admission assertion, distinct from a passkey certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialPurpose {
    /// The issuer evaluated its configured action with the complete real evidence.
    #[serde(rename = "cplc.community-credential.v2")]
    CommunityAdmission,
}

/// Credential payload; never stored by cplc. COSE binds issuance, expiry and key.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Credential {
    /// Required version; older unbound credentials cannot assert this decision.
    pub purpose: CredentialPurpose,
    /// Actual persisted issuer action, never selected by the issuance request.
    pub issuance_action: String,
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

/// The original authenticated global cohort selected by the community facade.
/// This is a privileged owner input, never decoded from an account request.
/// cmty owns canonical hashing of its entire PassportPolicy (epoch, deadline,
/// and disclosed gate set), and retains its current policy lease through signing.
pub struct AccountGrantContext {
    /// Hash of the exact authenticated global passport policy.
    pub passport_policy_digest: [u8; 32],
    /// Original exclusive cohort expiry, also bounds the grant envelope.
    pub passport_valid_until: u64,
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
    /// Required Balance publication floor, absent only before configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub balance_revision: Option<u64>,
    /// Required common root-board publication floor after configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_board_revision: Option<u64>,
    /// Oblivious HTTP relay and gateway key entries (several during a
    /// rotation overlap). Absent when the community does not use OHTTP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ohttp: Option<cblv::keys::Directory>,
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

/// Why a community's key chain ended, as the public feed states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndReasonClass {
    /// The community's admins dissolved it.
    Dissolved,
    /// The platform ended it (legal order, terms, name dispute).
    Banned,
}

/// One end-of-chain statement of the platform feed: a member device that pins this
/// founding fingerprint deletes its local data of that community. No names and no
/// member information; the wire shape is the one `cchr::Ended` verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndedChain {
    /// SHA-256 of the ended community's genesis document, lowercase hex on the wire.
    #[serde(with = "hex_fingerprint")]
    pub fingerprint: [u8; 32],
    /// Dissolved by its admins, or ended by the platform.
    pub reason_class: EndReasonClass,
    /// Unix seconds at which the chain ended.
    pub ended_at: u64,
}

/// End-of-chain statements older than this are no longer published (one year).
pub const ENDED_RETENTION_SECONDS: u64 = 366 * 86_400;

/// The Communities snapshot content: the plain list while nothing ended, else the
/// detailed object with the ended chains (at most [`MAX_ENTRIES`], newest first
/// kept, nothing older than [`ENDED_RETENTION_SECONDS`] before `now`).
pub fn communities_content(
    communities: &BTreeSet<String>,
    ended: &[EndedChain],
    now: u64,
) -> serde_json::Value {
    let mut kept: Vec<EndedChain> = ended
        .iter()
        .copied()
        .filter(|entry| entry.ended_at.saturating_add(ENDED_RETENTION_SECONDS) > now)
        .collect();
    kept.sort_by_key(|entry| std::cmp::Reverse(entry.ended_at));
    kept.truncate(MAX_ENTRIES);
    if kept.is_empty() {
        return serde_json::json!(communities);
    }
    serde_json::json!({ "communities": communities, "ended": kept })
}

mod hex_fingerprint {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let text: String = value.iter().map(|byte| format!("{byte:02x}")).collect();
        serializer.serialize_str(&text)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        let bad = || serde::de::Error::custom("fingerprint");
        if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return Err(bad());
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| bad())?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod ended_tests {
    use super::*;

    fn entry(byte: u8, at: u64) -> EndedChain {
        EndedChain {
            fingerprint: [byte; 32],
            reason_class: EndReasonClass::Banned,
            ended_at: at,
        }
    }

    #[test]
    fn nothing_ended_keeps_the_plain_list() {
        let names = BTreeSet::from(["a".to_owned()]);
        assert_eq!(
            communities_content(&names, &[], 10),
            serde_json::json!(["a"])
        );
    }

    #[test]
    fn ended_chains_use_the_detailed_shape_and_expire() {
        let names = BTreeSet::from(["a".to_owned()]);
        let old = entry(1, 1);
        let fresh = entry(2, ENDED_RETENTION_SECONDS + 5);
        let content = communities_content(&names, &[old, fresh], ENDED_RETENTION_SECONDS + 10);
        assert_eq!(content["ended"].as_array().unwrap().len(), 1);
        assert_eq!(content["ended"][0]["fingerprint"], "02".repeat(32));
        assert_eq!(content["ended"][0]["reason_class"], "banned");
        let back: EndedChain = serde_json::from_value(content["ended"][0].clone()).unwrap();
        assert_eq!(back, fresh);
    }
}

/// Gate id of the platform role Root in the global passport.
pub const ROOT_ROLE_GATE: &str = "root";
/// The admission action the Root role satisfies in every community (the action
/// name `cmty::ADMISSION_ACTION`).
pub const ROOT_ADMISSION_ACTION: &str = "community.admit";

/// Whether the verified results carry the Root role for `subject` at `now`:
/// only the admission action, only a global-level result, only this subject.
pub(crate) fn holds_root_role(
    action: &str,
    subject: &str,
    results: &[crbk::GateResult],
    now: i64,
) -> bool {
    action == ROOT_ADMISSION_ACTION
        && results.iter().any(|result| {
            result.gate == ROOT_ROLE_GATE
                && result.level == crbk::GateLevel::Global
                && result.subject == subject
                && result.valid_until > now
        })
}

#[cfg(test)]
mod root_role_tests {
    use super::*;

    fn result(gate: &str, level: crbk::GateLevel, subject: &str, until: i64) -> crbk::GateResult {
        crbk::GateResult {
            gate: gate.into(),
            level,
            subject: subject.into(),
            community: (level == crbk::GateLevel::Community).then(|| "c".into()),
            provider: "p".into(),
            valid_until: until,
            proven_at: None,
        }
    }

    #[test]
    fn only_a_current_global_root_result_for_the_subject_on_admission_counts() {
        use crbk::GateLevel::{Community, Global};
        let root = [result("root", Global, "me", 100)];
        assert!(holds_root_role(ROOT_ADMISSION_ACTION, "me", &root, 99));
        assert!(!holds_root_role(ROOT_ADMISSION_ACTION, "me", &root, 100));
        assert!(!holds_root_role(ROOT_ADMISSION_ACTION, "you", &root, 1));
        assert!(!holds_root_role("other", "me", &root, 1));
        // A community-level gate that merely carries the name is no role.
        let fake = [result("root", Community, "me", 100)];
        assert!(!holds_root_role(ROOT_ADMISSION_ACTION, "me", &fake, 1));
        let other = [result("voucher", Global, "me", 100)];
        assert!(!holds_root_role(ROOT_ADMISSION_ACTION, "me", &other, 1));
    }
}
