//! Original canonical Balance publication through the existing durable signer.
use super::*;

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// Version supplied to the configured AccountService's canonical producer.
    /// Serialize projection and publication with community configuration changes.
    pub async fn balance_version(&self, now: u64) -> Result<cbcn::document::Version> {
        let state = self.current().await?;
        Ok(cbcn::document::Version {
            revision: next_counter(state.balance.as_ref().map_or(0, |p| p.revision))?,
            epoch: self.epoch(now).await?,
        })
    }

    /// Publish the actual Balance owner's document through this durable signer.
    /// No member request may supply this host-only configuration operation.
    pub async fn publish_balance(
        &mut self,
        material: cblc::publication::PublicVerifierMaterial,
        now: u64,
    ) -> Result<Vec<u8>> {
        let version = self.balance_version(now).await?;
        let mut next = self.current().await?.clone();
        if material.revision != version.revision || material.policy_epoch != version.epoch {
            return Err(Error::Verification);
        }
        material
            .validate_at(&next.community, now)
            .map_err(|_| Error::Verification)?;
        let payload = serde_json::to_vec(&material).map_err(|_| Error::Corrupt)?;
        let active = self.active(now).await?;
        let until = self
            .validity_limit(now, next.config.snapshot_validity, &active)
            .await?
            .min(material.policy.account.policy_valid_until);
        let cose = self
            .signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &payload,
                crate::day(now),
                until,
            )
            .await?;
        next.balance = Some(Publication {
            revision: version.revision,
            cose: Some(cose.clone()),
        });
        self.commit(next).await?;
        Ok(cose)
    }

    /// Original Balance bytes, or absence only if accounting was never configured.
    /// An invalidated or expired document requires a fresh owner projection.
    pub async fn balance_publication(&self, now: u64) -> Result<Option<Vec<u8>>> {
        let state = self.current().await?;
        let Some(publication) = &state.balance else {
            return Ok(None);
        };
        let cose = publication.cose.as_ref().ok_or(Error::Missing)?;
        let ring = self.key_ring()?;
        cbcn::balance::Balance::verify(
            ring,
            cose,
            self.epoch(now).await?,
            publication.revision,
            now,
        )
        .map_err(|_| Error::Verification)?;
        let signed = ring
            .verify(cose, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Verification)?;
        let material: cblc::publication::PublicVerifierMaterial =
            serde_json::from_slice(signed.payload()).map_err(|_| Error::Corrupt)?;
        material
            .validate_at(&state.community, now)
            .map_err(|_| Error::Verification)?;
        Ok(Some(cose.clone()))
    }
}
