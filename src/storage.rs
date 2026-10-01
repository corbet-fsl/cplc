use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};

use crate::{
    Config, Error, MAX_DOCUMENT_BYTES, MAX_ENTRIES, Result, Revocations, SnapshotKind, identifier,
};

mod sql;
pub use sql::{LibsqlStore, SCHEMA};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Publication {
    pub revision: u64,
    pub cose: Option<Vec<u8>>,
}

/// Opaque current policy state. Storage implementations serialize this value;
/// only the facade constructs transitions. Contains no member credentials.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPolicy {
    pub(crate) community: String,
    pub(crate) revision: u64,
    pub(crate) epoch: u64,
    pub(crate) config: Config,
    pub(crate) schema: Option<cshm::Schema>,
    #[serde(default)]
    pub(crate) schema_versions: Vec<crate::SchemaVersion>,
    pub(crate) communities: BTreeSet<String>,
    pub(crate) revocations: Revocations,
    pub(crate) publications: BTreeMap<SnapshotKind, Publication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) key_transitions: Vec<cbcn::KeyTransition>,
}

// Five independently bounded COSE publications, each encoded as JSON byte
// arrays (at most four bytes per byte), plus the bounded core document.
pub(crate) const MAX_STORED_DOCUMENT_BYTES: usize =
    MAX_DOCUMENT_BYTES + 5 * 4 * (MAX_DOCUMENT_BYTES + 8192) + 4 * cbcn::MAX_KEY_TRANSITION_BYTES;

impl StoredPolicy {
    /// Scope permanently bound to this document.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// Current storage compare-and-swap revision.
    pub fn revision(&self) -> u64 {
        self.revision
    }
    /// Immediate facade epoch; an active rulebook can impose a higher epoch.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub(crate) fn validate(&self) -> Result<()> {
        identifier(&self.community)?;
        self.config.validate()?;
        cbcn::validate_transition_history(&self.key_transitions).map_err(|_| Error::Corrupt)?;
        if self.revision == 0
            || self.revision > i64::MAX as u64
            || self.epoch == 0
            || self.epoch > i64::MAX as u64
            || self.communities.len() > MAX_ENTRIES
        {
            return Err(Error::Corrupt);
        }
        for id in self.communities.iter().chain(&self.revocations.members) {
            identifier(id)?;
        }
        if let Some(schema) = &self.schema {
            if schema.community != self.community
                || schema.public.len() + schema.private.len() > MAX_ENTRIES
            {
                return Err(Error::Corrupt);
            }
            schema.validate_definition().map_err(|_| Error::Corrupt)?;
        }
        if self.schema_versions.len() > MAX_ENTRIES {
            return Err(Error::Corrupt);
        }
        let mut previous: Option<&cshm::Schema> = None;
        for version in &self.schema_versions {
            let schema = &version.schema;
            if schema.community != self.community
                || schema.public.len() + schema.private.len() > MAX_ENTRIES
            {
                return Err(Error::Corrupt);
            }
            schema.validate_definition().map_err(|_| Error::Corrupt)?;
            let expected = previous
                .map(|old| cshm::classify_changes(old, schema).map_err(|_| Error::Corrupt))
                .transpose()?;
            if version.changes != expected {
                return Err(Error::Corrupt);
            }
            previous = Some(schema);
        }
        if previous.is_some() && previous != self.schema.as_ref() {
            return Err(Error::Corrupt);
        }
        for publication in self.publications.values() {
            if publication.revision == 0
                || publication.revision > i64::MAX as u64
                || publication.cose.as_ref().is_some_and(|bytes| {
                    bytes.is_empty() || bytes.len() > MAX_DOCUMENT_BYTES + 8192
                })
            {
                return Err(Error::Corrupt);
            }
        }
        let mut document = self.clone();
        document.revocations = Revocations::default();
        document.key_transitions.clear();
        // Publications have independent bounded envelopes. Charging their JSON
        // byte-array expansion against the core budget makes a valid schema
        // impossible to publish after it has already replaced the old epoch.
        for publication in document.publications.values_mut() {
            publication.cose = None;
        }
        if serde_json::to_vec(&document)
            .map_err(|_| Error::Corrupt)?
            .len()
            > MAX_DOCUMENT_BYTES
        {
            return Err(Error::Invalid("policy size"));
        }
        Ok(())
    }
}

/// Small current-state boundary for one authorized community.
/// Success means durable atomic replacement. Never reset a live scope.
/// On uncertain writes reconcile by loading; never blindly retry.
pub trait Storage: Send + Sync {
    /// Fixed community namespace, chosen by the trusted composition root.
    fn community(&self) -> &str;
    /// Read the complete current document consistently.
    fn load(&self) -> impl Future<Output = Result<Option<StoredPolicy>>> + Send;
    /// Compare the current revision and commit the next valid document.
    /// `None` means create-only. A stale revision returns `Error::Conflict`.
    fn compare_exchange(
        &self,
        expected: Option<u64>,
        next: &StoredPolicy,
    ) -> impl Future<Output = Result<()>> + Send;
}

pub(crate) fn validate_transition(
    scope: &str,
    previous: Option<&StoredPolicy>,
    expected: Option<u64>,
    next: &StoredPolicy,
) -> Result<()> {
    if previous.map(|state| state.revision) != expected {
        return Err(Error::Conflict);
    }
    next.validate()?;
    if next.community != scope || next.revision != next_counter(expected.unwrap_or(0))? {
        return Err(Error::Corrupt);
    }
    if let Some(previous) = previous {
        if next.epoch < previous.epoch
            || next.config != previous.config
            || !next.key_transitions.starts_with(&previous.key_transitions)
        {
            return Err(Error::Corrupt);
        }
        if let Some(old) = &previous.schema {
            let new = next.schema.as_ref().ok_or(Error::Corrupt)?;
            if new.version < old.version || (new.version == old.version && new != old) {
                return Err(Error::Corrupt);
            }
        }
        for (kind, old) in &previous.publications {
            let new = next.publications.get(kind).ok_or(Error::Corrupt)?;
            if new.revision < old.revision
                || (new.revision == old.revision && new.cose.is_some() && new.cose != old.cose)
            {
                return Err(Error::Corrupt);
            }
        }
    }
    Ok(())
}

pub(crate) fn next_counter(current: u64) -> Result<u64> {
    current
        .checked_add(1)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Error::Invalid("counter exhausted"))
}

/// Real volatile backend. Clones share one scope; separate constructors do not.
#[derive(Clone)]
pub struct MemoryStore {
    community: String,
    state: Arc<Mutex<Option<StoredPolicy>>>,
}

impl MemoryStore {
    /// Create an empty store for a caller-authorized community.
    pub fn new(community: impl Into<String>) -> Result<Self> {
        let community = community.into();
        identifier(&community)?;
        Ok(Self {
            community,
            state: Arc::new(Mutex::new(None)),
        })
    }
}

impl Storage for MemoryStore {
    fn community(&self) -> &str {
        &self.community
    }
    async fn load(&self) -> Result<Option<StoredPolicy>> {
        Ok(self.state.lock().map_err(|_| Error::Storage)?.clone())
    }
    async fn compare_exchange(&self, expected: Option<u64>, next: &StoredPolicy) -> Result<()> {
        let mut state = self.state.lock().map_err(|_| Error::Storage)?;
        validate_transition(&self.community, state.as_ref(), expected, next)?;
        *state = Some(next.clone());
        Ok(())
    }
}

#[cfg(test)]
#[path = "../tests/unit/storage.rs"]
mod unit_tests;
