use std::collections::{BTreeMap, BTreeSet};

use crbk::{GateLevel, Selection};
use serde::Serialize;

use crate::storage::{Publication, next_counter};
use crate::{
    Config, Credential, CredentialGate, CredentialRequest, Error, MAX_DOCUMENT_BYTES, MAX_ENTRIES,
    Result, Revocations, Snapshot, SnapshotKind, Storage, StoredPolicy, identifier, timestamp,
};

/// Single community writer composing rulebook decisions, schemas and durable signing.
///
/// Construct only in the authenticated service composition root. All gate,
/// membership, handle, pin and device inputs must already be verified there.
/// Reopening both this facade and its csgn signer fences stale stored revisions;
/// the service still must serialize writers and external publication.
pub struct Policy<R, S, K> {
    rules: R,
    store: S,
    signer: csgn::PersistentSigner<K>,
    state: Option<StoredPolicy>,
    beacon: cbcn::Beacon,
}

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// Create an empty policy scope. The signer's issuer must equal the scope.
    /// Provision/create the signer before this call and reconcile partial setup
    /// after uncertain failures; neither issuer nor policy state is overwritten.
    pub async fn create(
        rules: R,
        store: S,
        signer: csgn::PersistentSigner<K>,
        config: Config,
    ) -> Result<Self> {
        config.validate()?;
        check_issuer(&signer, store.community())?;
        let state = StoredPolicy {
            community: store.community().into(),
            revision: 1,
            epoch: 1,
            config,
            schema: None,
            schema_versions: Vec::new(),
            communities: BTreeSet::new(),
            revocations: Revocations::default(),
            publications: BTreeMap::new(),
        };
        store.compare_exchange(None, &state).await?;
        Ok(Self {
            rules,
            store,
            signer,
            state: Some(state),
            beacon: cbcn::Beacon::default(),
        })
    }

    /// Load current policy and claim its next revision. Supply a freshly reopened
    /// persistent signer with its matching secret-store key, never a stale signer.
    pub async fn open(rules: R, store: S, signer: csgn::PersistentSigner<K>) -> Result<Self> {
        check_issuer(&signer, store.community())?;
        let mut state = store.load().await?.ok_or(Error::Missing)?;
        state.validate()?;
        if state.community != store.community() {
            return Err(Error::Corrupt);
        }
        let expected = state.revision;
        state.revision = next_counter(expected)?;
        store.compare_exchange(Some(expected), &state).await?;
        Ok(Self {
            rules,
            store,
            signer,
            state: Some(state),
            beacon: cbcn::Beacon::default(),
        })
    }

    fn state(&self) -> Result<&StoredPolicy> {
        self.state.as_ref().ok_or(Error::ReloadRequired)
    }

    async fn current(&self) -> Result<&StoredPolicy> {
        let state = self.state()?;
        self.signer.key_ring().map_err(|_| Error::Signing)?;
        let stored = self.store.load().await?.ok_or(Error::Missing)?;
        if stored != *state {
            return Err(Error::Conflict);
        }
        Ok(state)
    }

    async fn commit(&mut self, mut next: StoredPolicy) -> Result<()> {
        let expected = self.state()?.revision;
        next.revision = next_counter(expected)?;
        next.validate()?;
        // Take before awaiting: cancellation or an uncertain commit cannot leave
        // an apparently usable writer with stale policy/publication state.
        self.state = None;
        self.store.compare_exchange(Some(expected), &next).await?;
        self.state = Some(next);
        Ok(())
    }

    async fn active(&self, now: u64) -> Result<crbk::Revision> {
        self.rules
            .load(&self.state()?.community, Selection::At(timestamp(now)?))
            .await?
            .ok_or(Error::Missing)
    }

    async fn next_activation(&self, active: &crbk::Revision) -> Result<Option<u64>> {
        let next = self
            .rules
            .load(
                &self.state()?.community,
                Selection::Revision(next_counter(active.revision)?),
            )
            .await?;
        next.map(|r| u64::try_from(r.change.effective_at).map_err(|_| Error::Corrupt))
            .transpose()
    }

    async fn advance_epoch(&self, next: &mut StoredPolicy) -> Result<()> {
        let latest = self.rules.load(&next.community, Selection::Latest).await?;
        next.epoch = next_counter(next.epoch)?;
        effective_epoch(next.epoch, latest.map_or(0, |r| r.change.policy_epoch))?;
        for publication in next.publications.values_mut() {
            publication.cose = None;
        }
        Ok(())
    }

    /// Current public verification ring. Distribute through an authenticated
    /// channel serialized with this writer; this operation is not a freshness proof.
    pub fn key_ring(&self) -> Result<&csgn::KeyRing> {
        self.state()?;
        self.signer.key_ring().map_err(|_| Error::Signing)
    }

    /// Current validated schema, when installed. No member profile is stored.
    pub fn schema(&self) -> Result<Option<&cshm::Schema>> {
        Ok(self.state()?.schema.as_ref())
    }

    /// Effective epoch at a trusted time; future rulebook epochs remain inactive.
    pub async fn epoch(&self, now: u64) -> Result<u64> {
        let state = self.current().await?;
        effective_epoch(state.epoch, self.active(now).await?.change.policy_epoch)
    }

    /// Resolve current settings without signing, publishing or recording a read.
    pub async fn settings(&self, now: u64) -> Result<crbk::Snapshot> {
        let state = self.current().await?;
        let active = self.active(now).await?;
        let mut snapshot = active.snapshot(&state.community, timestamp(now)?)?;
        snapshot.policy_epoch = effective_epoch(state.epoch, active.change.policy_epoch)?;
        snapshot.issued = timestamp(crate::day(now))?;
        Ok(snapshot)
    }

    /// Append a prospective rulebook change through crbk. Caller authorization
    /// and notice delivery are service duties. Epochs increase on each revision.
    pub async fn schedule_rules(
        &mut self,
        expected: Option<u64>,
        mut change: crbk::Change,
    ) -> Result<crbk::Revision> {
        let state = self.current().await?.clone();
        let latest = self.rules.load(&state.community, Selection::Latest).await?;
        effective_epoch(state.epoch, change.policy_epoch)?;
        if change.policy_epoch
            != next_counter(latest.as_ref().map_or(0, |r| r.change.policy_epoch))?
        {
            return Err(Error::Invalid("policy epoch must advance by one"));
        }
        crbk::define_membership_settings(&mut change.rulebook)?;
        cgts::gates::define_settings(&mut change.rulebook)
            .map_err(|_| Error::Invalid("gate settings"))?;
        change.rulebook.validate()?;
        self.state = None;
        let result = self.rules.append(&state.community, expected, change).await;
        match result {
            Ok(revision) => {
                self.state = Some(state);
                Ok(revision)
            }
            Err(error) => {
                // Validation failures have no ambiguous write outcome. Storage
                // errors and stale writers require explicit reconciliation.
                if matches!(error, crbk::Error::Invalid(_) | crbk::Error::NotFound) {
                    self.state = Some(state);
                }
                Err(error.into())
            }
        }
    }

    /// Validate and install a newer schema, returning the leaf's classification.
    /// This authorized operation advances the epoch immediately. Call
    /// `cshm::classify_changes` first when presenting an administrator preview.
    pub async fn set_schema(&mut self, schema: cshm::Schema) -> Result<Option<cshm::ChangeSet>> {
        let mut next = self.current().await?.clone();
        if schema.community != next.community
            || schema.public.len() + schema.private.len() > MAX_ENTRIES
        {
            return Err(Error::Invalid("schema scope or size"));
        }
        schema.validate_definition().map_err(|_| Error::Schema)?;
        let changes = next
            .schema
            .as_ref()
            .map(|old| cshm::classify_changes(old, &schema).map_err(|_| Error::Schema))
            .transpose()?;
        // Old stored documents contain only the current schema; preserve it as
        // the initial archive entry when they first receive an update.
        if next.schema_versions.is_empty()
            && let Some(previous) = &next.schema
        {
            next.schema_versions.push(crate::SchemaVersion {
                schema: previous.clone(),
                changes: None,
            });
        }
        next.schema_versions.push(crate::SchemaVersion {
            schema: schema.clone(),
            changes: changes.clone(),
        });
        next.schema = Some(schema);
        // Ensure both schema publications fit before changing durable policy.
        // Use maximal counters so future refreshes cannot exceed the envelope.
        encode_snapshot(&next, u64::MAX, u64::MAX, &next.schema)?;
        encode_snapshot(
            &next,
            u64::MAX,
            u64::MAX,
            crate::SchemaVersions {
                purpose: crate::SchemaVersionsPurpose::SchemaVersionsV1,
                current: next.schema.as_ref().ok_or(Error::Missing)?.version,
                versions: next.schema_versions.clone(),
            },
        )?;
        self.advance_epoch(&mut next).await?;
        self.commit(next).await?;
        Ok(changes)
    }

    /// Replace the explicit public directory and advance the epoch.
    /// Never pass a member's joined communities or infer this list from activity.
    pub async fn set_communities(&mut self, communities: BTreeSet<String>) -> Result<()> {
        let mut next = self.current().await?.clone();
        if communities.len() > MAX_ENTRIES {
            return Err(Error::Invalid("community count"));
        }
        for community in &communities {
            identifier(community)?;
        }
        next.communities = communities;
        self.advance_epoch(&mut next).await?;
        self.commit(next).await
    }

    /// Replace current community revocations and advance the epoch immediately.
    /// Global suspension belongs exclusively to cglb.
    pub async fn set_revocations(&mut self, revocations: Revocations) -> Result<()> {
        let mut next = self.current().await?.clone();
        for member in &revocations.members {
            identifier(member)?;
        }
        next.revocations = revocations;
        self.advance_epoch(&mut next).await?;
        self.commit(next).await
    }

    /// Edit one sparse setting through crbk, retaining every other layer.
    /// Authorization of platform versus community edits belongs to the door.
    pub async fn edit_setting(
        &mut self,
        key: &str,
        edit: crate::SettingEdit,
        now: u64,
        effective_at: u64,
        notice_seconds: u64,
    ) -> Result<crbk::Revision> {
        let state = self.current().await?;
        let latest = self
            .rules
            .load(&state.community, Selection::Latest)
            .await?
            .ok_or(Error::Missing)?;
        let mut rulebook = latest.change.rulebook;
        match edit {
            crate::SettingEdit::Community(value) => rulebook.set_community(key, value)?,
            crate::SettingEdit::Platform(value) => rulebook.set_platform(key, value)?,
        }
        self.schedule_rules(
            Some(latest.revision),
            crbk::Change {
                rulebook,
                announced_at: timestamp(now)?,
                effective_at: timestamp(effective_at)?,
                notice_seconds,
                policy_epoch: next_counter(latest.change.policy_epoch)?,
            },
        )
        .await
    }

    /// Current revocation state, with no member activity history.
    pub fn revocations(&self) -> Result<&Revocations> {
        Ok(&self.state()?.revocations)
    }

    /// Publish the complete original signed feed through Beacon. Partial signing
    /// or storage failure cannot replace the previously installed complete view.
    pub async fn refresh_trust(&mut self, now: u64) -> Result<std::sync::Arc<cbcn::Feed>> {
        let candidate = cbcn::collect(self, now)
            .await
            .map_err(|_| Error::Verification)?;
        self.beacon
            .install(candidate, now)
            .map_err(|_| Error::Verification)
    }

    /// Current public feed, refreshing only when configuration, keys or validity
    /// changed. Ordinary registration/lobby reads do not create publications.
    pub async fn trust_feed(&mut self, now: u64) -> Result<std::sync::Arc<cbcn::Feed>> {
        let revision = self.current().await?.revision;
        let epoch = self.epoch(now).await?;
        match self.beacon.current(now) {
            Ok(feed)
                if feed.revision == revision
                    && feed.policy_epoch == epoch
                    && feed.key_ring == self.key_ring()?.to_cbor() =>
            {
                Ok(feed)
            }
            Err(cbcn::Error::ClockRegression) => Err(Error::Verification),
            _ => self.refresh_trust(now).await,
        }
    }

    /// Current whole-view change hint; no member identifiers or event history.
    pub async fn trust_changes(&mut self, revision: u64, now: u64) -> Result<cbcn::Announcement> {
        self.trust_feed(now).await?;
        self.beacon
            .changes_since(revision, now)
            .map_err(|_| Error::Verification)
    }

    /// Sign current public keys, schema version and policy epoch for trust consumers.
    /// This is a typed SettingsSnapshot envelope with a distinct top-level purpose,
    /// not an arbitrary-payload signing API and not a flat settings snapshot.
    pub async fn trust_manifest(&mut self, now: u64) -> Result<Vec<u8>> {
        let state = self.current().await?.clone();
        let active = self.active(now).await?;
        let manifest = crate::TrustManifest {
            purpose: crate::TrustPurpose::CommunityTrustV1,
            community: state.community.clone(),
            revision: state.revision,
            policy_epoch: effective_epoch(state.epoch, active.change.policy_epoch)?,
            key_ring: self.key_ring()?.to_cbor(),
            schema_version: state.schema.as_ref().ok_or(Error::Missing)?.version,
        };
        let until = self
            .validity_limit(now, state.config.snapshot_validity, &active)
            .await?;
        self.signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &serde_json::to_vec(&manifest).map_err(|_| Error::Corrupt)?,
                crate::day(now),
                until,
            )
            .await
            .map_err(|_| Error::Signing)
    }

    /// Invalidate prior epochs without changing settings or storing member events.
    ///
    /// This does not permanently revoke a member who can satisfy the gates again.
    pub async fn bump_epoch(&mut self) -> Result<()> {
        let mut next = self.current().await?.clone();
        self.advance_epoch(&mut next).await?;
        self.commit(next).await
    }

    /// Authenticate a short-lived cpsd request for this community's wallet flow.
    /// The owning community facade supplies its server-held challenge; holders
    /// cannot choose an arbitrary payload, namespace or unbounded deadline.
    pub async fn sign_presentation_request(
        &mut self,
        request: &cpsd::PresentationRequest,
        now: u64,
    ) -> Result<Vec<u8>> {
        let state = self.current().await?;
        if request.community().as_bytes() != state.community.as_bytes()
            || request.now() < now
            || request.now()
                > now
                    .checked_add(300)
                    .ok_or(Error::Invalid("time overflow"))?
        {
            return Err(Error::Invalid("presentation request scope or deadline"));
        }
        let until = request
            .now()
            .checked_add(1)
            .ok_or(Error::Invalid("time overflow"))?;
        self.signer
            .sign(
                csgn::Kind::Credential,
                &request.to_bytes(),
                crate::day(now),
                until,
            )
            .await
            .map_err(|_| Error::Signing)
    }

    /// Sole admission decision over verified settings and bound gate receipts.
    /// The source of membership state is cmbr; cmty only wires these capabilities.
    pub async fn may(
        &self,
        snapshot: &crate::VerifiedSnapshot,
        subject: crbk::Subject<'_>,
        action: &str,
        checked: &cgts::CheckedGates,
        now: u64,
    ) -> Result<crbk::Decision> {
        self.validate_snapshot(snapshot, now).await?;
        let state = self.current().await?;
        if state.revocations.members.contains(subject.id) {
            return Err(Error::Revoked);
        }
        let gates = checked
            .in_context(cgts::Context {
                snapshot: snapshot.settings(),
                subject: subject.id,
                action,
                now: timestamp(now)?,
            })
            .map_err(|_| Error::Verification)?;
        Ok(snapshot
            .settings()
            .may(subject, action, &gates, timestamp(now)?)?)
    }

    /// Sign and durably publish one current snapshot, returning its COSE bytes.
    /// A refreshed publication always gets a new revision, even for equal content.
    pub async fn publish(&mut self, kind: SnapshotKind, now: u64) -> Result<Vec<u8>> {
        let mut next = self.current().await?.clone();
        let active = self.active(now).await?;
        let revision = next_counter(next.publications.get(&kind).map_or(0, |p| p.revision))?;
        let epoch = effective_epoch(next.epoch, active.change.policy_epoch)?;
        let payload = match kind {
            SnapshotKind::Settings => encode_snapshot(
                &next,
                revision,
                epoch,
                active.snapshot(&next.community, timestamp(now)?)?.content,
            )?,
            SnapshotKind::Schema => encode_snapshot(
                &next,
                revision,
                epoch,
                next.schema.clone().ok_or(Error::Missing)?,
            )?,
            SnapshotKind::SchemaVersions => {
                let schema = next.schema.as_ref().ok_or(Error::Missing)?;
                let versions = if next.schema_versions.is_empty() {
                    vec![crate::SchemaVersion {
                        schema: schema.clone(),
                        changes: None,
                    }]
                } else {
                    next.schema_versions.clone()
                };
                encode_snapshot(
                    &next,
                    revision,
                    epoch,
                    crate::SchemaVersions {
                        purpose: crate::SchemaVersionsPurpose::SchemaVersionsV1,
                        current: schema.version,
                        versions,
                    },
                )?
            }
            SnapshotKind::Communities => {
                encode_snapshot(&next, revision, epoch, &next.communities)?
            }
            SnapshotKind::RevocationList => {
                encode_snapshot(&next, revision, epoch, &next.revocations)?
            }
        };
        let until = self
            .validity_limit(now, next.config.snapshot_validity, &active)
            .await?;
        let cose = self
            .signer
            .sign(kind.signing_kind(), &payload, crate::day(now), until)
            .await
            .map_err(|_| Error::Signing)?;
        next.publications.insert(
            kind,
            Publication {
                revision,
                cose: Some(cose.clone()),
            },
        );
        self.commit(next).await?;
        Ok(cose)
    }

    /// Publish and authenticate the current settings, carrying the effective epoch.
    pub async fn verified_settings(&mut self, now: u64) -> Result<crate::VerifiedSnapshot> {
        let cose = match self.published(SnapshotKind::Settings, now).await? {
            Some(cose) => cose,
            None => self.publish(SnapshotKind::Settings, now).await?,
        };
        let state = self.current().await?;
        crate::verify_settings(
            self.key_ring()?,
            &cose,
            crate::SnapshotExpectation {
                community: &state.community,
                kind: SnapshotKind::Settings,
                minimum_revision: state.publications[&SnapshotKind::Settings].revision,
                policy_epoch: self.epoch(now).await?,
                now,
            },
        )
    }

    /// Reject stale, foreign or caller-altered policy inputs before using receipts.
    pub async fn validate_snapshot(
        &self,
        snapshot: &crate::VerifiedSnapshot,
        now: u64,
    ) -> Result<()> {
        let state = self.current().await?;
        let active = self.active(now).await?;
        let current = active.snapshot(&state.community, timestamp(now)?)?;
        if snapshot.snapshot.community != state.community
            || snapshot.snapshot.policy_epoch != self.epoch(now).await?
            || snapshot.snapshot.issued > timestamp(now)?
            || snapshot.valid_until <= now
            || snapshot.snapshot.content != current.content
            || state
                .publications
                .get(&SnapshotKind::Settings)
                .is_none_or(|p| {
                    p.revision != snapshot.snapshot.revision
                        || p.cose.as_deref() != Some(snapshot.publication.as_slice())
                })
        {
            return Err(Error::Verification);
        }
        Ok(())
    }

    /// Read the exact latest publication only while it remains valid for current
    /// policy. This permits response recovery without reissuing a revision.
    pub async fn published(&self, kind: SnapshotKind, now: u64) -> Result<Option<Vec<u8>>> {
        let state = self.current().await?;
        let Some(publication) = state.publications.get(&kind) else {
            return Ok(None);
        };
        let Some(cose) = &publication.cose else {
            return Ok(None);
        };
        let expected = crate::SnapshotExpectation {
            community: &state.community,
            kind,
            minimum_revision: publication.revision,
            policy_epoch: self.epoch(now).await?,
            now,
        };
        match crate::verify_snapshot::<serde_json::Value>(self.key_ring()?, cose, expected) {
            Ok(_) => Ok(Some(cose.clone())),
            Err(_) => Ok(None),
        }
    }

    async fn validity_limit(
        &self,
        now: u64,
        lifetime: u64,
        active: &crbk::Revision,
    ) -> Result<u64> {
        let max = lifetime.min(self.key_ring()?.max_validity());
        let mut until = crate::day(now)
            .checked_add(max)
            .ok_or(Error::Invalid("time overflow"))?;
        until = until.min(i64::MAX as u64);
        if let Some(activation) = self.next_activation(active).await? {
            until = until.min(activation);
        }
        if until <= now {
            return Err(Error::Invalid("empty validity"));
        }
        Ok(until)
    }

    /// Evaluate the configured action and sign a credential only on a positive
    /// current verdict. Stores no credential bytes, subject or proof metadata.
    pub async fn issue<M: crate::MembershipSource>(
        &mut self,
        membership: &M,
        request: CredentialRequest<'_>,
        now: u64,
    ) -> Result<Vec<u8>> {
        let state = self.current().await?.clone();
        self.validate_snapshot(request.snapshot, now).await?;
        let gates = request
            .gates
            .in_context(cgts::Context {
                snapshot: request.snapshot.settings(),
                subject: request.subject.id,
                action: &state.config.credential_action,
                now: timestamp(now)?,
            })
            .map_err(|_| Error::Verification)?;
        validate_request(&state, &request, &gates)?;
        let (facts, _membership_lease) = membership.membership(request.subject.id, now).await?;
        if facts.community != state.community
            || facts.member != request.subject.id
            || facts.state != crbk::MembershipState::Admitted
            || facts.lease_end <= now
            || facts.lease_end % crate::DAY != 0
            || facts
                .probation_until
                .is_some_and(|end| end % crate::DAY != 0)
        {
            return Err(Error::Invalid("membership state or lease"));
        }
        let durations = crbk::MembershipSettings::from_snapshot(request.snapshot.settings())?;
        let days = if facts.probation_until.is_some_and(|end| end > now) {
            durations.new_credential_days
        } else {
            durations.established_credential_days
        };
        let active = self.active(now).await?;
        let snapshot = active.snapshot(&state.community, timestamp(now)?)?;
        let decide = |at| {
            snapshot.may(
                crbk::Subject {
                    id: request.subject.id,
                    membership: request.subject.membership,
                },
                &state.config.credential_action,
                &gates,
                at,
            )
        };
        let decision = decide(timestamp(now)?)?;
        if !decision.allowed {
            return Err(Error::Denied(decision));
        }
        let mut until = self
            .validity_limit(now, u64::from(days) * crate::DAY, &active)
            .await?;
        until = until.min(facts.lease_end);
        let mut community_gates = Vec::new();
        for gate in &gates {
            // Ask the leaf whether each supplied assertion is usable before
            // attesting to it, including switches, provider and proof metadata.
            if !usable_gate(&snapshot, &request.subject, gate, timestamp(now)?)? {
                return Err(Error::Invalid("unusable gate result"));
            }
            until = until
                .min(u64::try_from(gate.valid_until).map_err(|_| Error::Invalid("proof expiry"))?);
            if gate.level == GateLevel::Community {
                community_gates.push(CredentialGate {
                    gate: gate.gate.clone(),
                    provider: gate.provider.clone(),
                    valid_until: gate.valid_until as u64,
                });
            }
        }
        // Within one fixed policy, verified proofs can only age out. Query the
        // real evaluator to find the exclusive end, including inclusive max age.
        if !decide(timestamp(until - 1)?)?.allowed {
            let (mut low, mut high) = (now, until - 1);
            while high - low > 1 {
                let middle = low + (high - low) / 2;
                if decide(timestamp(middle)?)?.allowed {
                    low = middle;
                } else {
                    high = middle;
                }
            }
            until = high;
        }
        let credential = Credential {
            community: state.community,
            member: request.subject.id.into(),
            handle: request.handle.into(),
            schema_version: request.schema_version,
            policy_epoch: effective_epoch(state.epoch, active.change.policy_epoch)?,
            gates: community_gates,
            pins: request.pins.to_vec(),
            devices: request.devices.to_vec(),
        };
        let payload = encode(&credential)?;
        self.signer
            .sign(csgn::Kind::Credential, &payload, crate::day(now), until)
            .await
            .map_err(|_| Error::Signing)
    }

    /// Rotate using an already provisioned secret-store key. Old public keys are
    /// retained by csgn for all still-valid signatures, including snapshots.
    pub async fn rotate(&mut self, key: csgn::SecretKey, now: u64) -> Result<()> {
        self.current().await?;
        self.signer
            .rotate(key, crate::day(now))
            .await
            .map_err(|_| Error::Signing)
    }

    /// Prune only expired retired public keys through csgn.
    pub async fn prune_keys(&mut self, now: u64) -> Result<()> {
        self.current().await?;
        self.signer
            .prune(crate::day(now))
            .await
            .map_err(|_| Error::Signing)
    }
}

fn check_issuer<K: csgn::Store>(signer: &csgn::PersistentSigner<K>, community: &str) -> Result<()> {
    identifier(community)?;
    if !community
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
    {
        return Err(Error::Invalid("community namespace"));
    }
    if signer.key_ring().map_err(|_| Error::Signing)?.issuer() != community {
        return Err(Error::Invalid("signer scope"));
    }
    if signer
        .key_ring()
        .map_err(|_| Error::Signing)?
        .active()
        .ok_or(Error::Signing)?
        .activated_at()
        % crate::DAY
        != 0
    {
        return Err(Error::Invalid("signer day boundary"));
    }
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::Invalid("encoding"))?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::Invalid("payload size"));
    }
    Ok(bytes)
}

fn encode_snapshot<T: Serialize>(
    state: &StoredPolicy,
    revision: u64,
    policy_epoch: u64,
    content: T,
) -> Result<Vec<u8>> {
    encode(&Snapshot {
        community: state.community.clone(),
        revision,
        policy_epoch,
        content,
    })
}

fn validate_request(
    state: &StoredPolicy,
    request: &CredentialRequest<'_>,
    gates: &[crbk::GateResult],
) -> Result<()> {
    identifier(request.subject.id)?;
    identifier(request.handle)?;
    let schema = state.schema.as_ref().ok_or(Error::Missing)?;
    if request.schema_version != schema.version
        || request.subject.membership != crbk::MembershipState::Admitted
        || gates.len() > MAX_ENTRIES
        || request.pins.len() > MAX_ENTRIES
        || request.devices.is_empty()
        || request.devices.len() > MAX_ENTRIES
    {
        return Err(Error::Invalid("credential scope or size"));
    }
    if state.revocations.members.contains(request.subject.id)
        || request
            .devices
            .iter()
            .any(|key| state.revocations.devices.contains(key))
    {
        return Err(Error::Revoked);
    }
    let mut gate_ids = BTreeSet::new();
    for gate in gates {
        if gate.subject != request.subject.id
            || match gate.level {
                GateLevel::Community => gate.community.as_deref() != Some(&state.community),
                GateLevel::Global => gate.community.is_some(),
            }
            || !gate_ids.insert((gate.level, &gate.gate))
        {
            return Err(Error::Invalid("gate binding or duplicate"));
        }
    }
    if request.devices.iter().collect::<BTreeSet<_>>().len() != request.devices.len() {
        return Err(Error::Invalid("duplicate device"));
    }
    let mut pins = BTreeSet::new();
    for pin in request.pins {
        let field = schema
            .public
            .iter()
            .chain(&schema.private)
            .find(|f| f.id == pin.field)
            .ok_or(Error::Invalid("pin field"))?;
        if field.change_preset == cshm::ChangePreset::Free || !pins.insert(&pin.field) {
            return Err(Error::Invalid("pin field or duplicate"));
        }
    }
    Ok(())
}

fn usable_gate(
    snapshot: &crbk::Snapshot,
    subject: &crbk::Subject<'_>,
    gate: &crbk::GateResult,
    now: i64,
) -> Result<bool> {
    let mut single = snapshot.clone();
    let policy = crbk::ActionPolicy {
        all_of: vec![crbk::Requirement {
            gate: gate.gate.clone(),
            level: gate.level,
            provider: Some(gate.provider.clone()),
        }],
        ..Default::default()
    };
    single.content.insert(
        crbk::action_key("cplc_assertion"),
        serde_json::to_value(policy).map_err(|_| Error::Invalid("gate policy"))?,
    );
    Ok(single
        .may(
            crbk::Subject {
                id: subject.id,
                membership: subject.membership,
            },
            "cplc_assertion",
            std::slice::from_ref(gate),
            now,
        )?
        .allowed)
}

fn effective_epoch(facade: u64, rulebook: u64) -> Result<u64> {
    facade
        .checked_add(rulebook)
        .filter(|n| *n <= i64::MAX as u64)
        .ok_or(Error::Invalid("epoch exhausted"))
}
