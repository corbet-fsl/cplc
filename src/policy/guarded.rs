//! Explicit final authority checks in the existing policy/rulebook transactions.
use super::*;

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// Install a schema only after the real retained owner is checked under the
    /// actual CAS writer. Unsupported checked stores refuse; no fallback occurs.
    pub async fn set_schema_checked<G: crbk::CommitGuard>(
        &mut self,
        schema: cshm::Schema,
        guard: &mut G,
    ) -> Result<Option<cshm::ChangeSet>> {
        let (mut next, changes) = self.prepare_schema(schema).await?;
        let expected = self.state()?.revision;
        next.revision = next_counter(expected)?;
        next.validate()?;
        // Cancellation/possible commit cannot leave an apparently usable writer.
        self.state = None;
        self.store
            .compare_exchange_checked(Some(expected), &next, guard)
            .await?;
        self.state = Some(next);
        Ok(changes)
    }

    /// Append an original prospective rulebook under the real commit authority.
    pub async fn schedule_rules_checked<G: crbk::CommitGuard>(
        &mut self,
        expected: Option<u64>,
        change: crbk::Change,
        guard: &mut G,
    ) -> Result<crbk::Revision> {
        let (state, change) = self.prepare_rules(change).await?;
        self.state = None;
        let result = self
            .rules
            .append_checked(&state.community, expected, change, guard)
            .await;
        self.finish_rules(state, result)
    }

    /// Edit an original sparse setting with authority checked at the CRBK commit.
    /// The caller fixes the operation/policy; this method accepts no role assertion.
    pub async fn edit_setting_checked<G: crbk::CommitGuard>(
        &mut self,
        key: &str,
        edit: crate::SettingEdit,
        now: u64,
        effective_at: u64,
        notice_seconds: u64,
        guard: &mut G,
    ) -> Result<crbk::Revision> {
        let (expected, change) = self
            .prepare_setting(key, edit, now, effective_at, notice_seconds)
            .await?;
        self.schedule_rules_checked(Some(expected), change, guard)
            .await
    }
}
