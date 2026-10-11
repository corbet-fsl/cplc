//! Current common outcome allowance from the original Policy-owned Rulebook.
use super::*;

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// The application fixes the key independently of member/anonymous input.
    /// Validate its immutable catalogue in THIS active Rulebook, then project
    /// the same common snapshot/effective epoch. Caller serialization and final
    /// live owner rechecks remain required; this method signs nothing.
    pub async fn outcome_quota_settings(
        &self,
        key: &str,
        now: u64,
    ) -> Result<crbk::OutcomeQuotaSettings> {
        let state = self.current().await?;
        let active = self.active(now).await?;
        crbk::OutcomeQuotaSettings::validate_catalogue(&active.change.rulebook, key)?;
        let mut snapshot = active.snapshot(&state.community, timestamp(now)?)?;
        snapshot.policy_epoch = effective_epoch(state.epoch, active.change.policy_epoch)?;
        crbk::OutcomeQuotaSettings::from_snapshot(&snapshot, key).map_err(Error::from)
    }
}
