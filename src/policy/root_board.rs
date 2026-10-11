//! Original durable common root-board publication and typed request signing.
use super::*;

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// Sign the retained root context after the service's own authorization.
    /// This authenticates bytes; it does not grant a role or consume a nonce.
    pub async fn sign_root_board_issuance_context(
        &mut self,
        context: &cpsd::RootBoardIssuanceContext,
        now: u64,
    ) -> Result<Vec<u8>> {
        let payload = context.to_bytes();
        let decoded = cpsd::RootBoardIssuanceContext::from_bytes(&payload)
            .map_err(|_| Error::Verification)?;
        if decoded != *context || decoded.to_bytes() != payload {
            return Err(Error::Verification);
        }
        let until = self
            .root_board_signing_deadline(context.root(), context.deadline(), now)
            .await?;
        self.signer
            .sign(csgn::Kind::Credential, &payload, crate::day(now), until)
            .await
            .map_err(Error::from)
    }

    /// Sign the service's retained joint root presentation request.
    /// Nonce storage and admission remain the owning service's responsibilities.
    pub async fn sign_root_board_request(
        &mut self,
        request: &cpsd::RootBoardRequest,
        now: u64,
    ) -> Result<Vec<u8>> {
        let payload = request.to_bytes();
        let decoded =
            cpsd::RootBoardRequest::from_bytes(&payload).map_err(|_| Error::Verification)?;
        if decoded != *request || decoded.to_bytes() != payload {
            return Err(Error::Verification);
        }
        let until = self
            .root_board_signing_deadline(request.root(), request.deadline(), now)
            .await?;
        self.signer
            .sign(csgn::Kind::Credential, &payload, crate::day(now), until)
            .await
            .map_err(Error::from)
    }

    async fn root_board_signing_deadline(
        &self,
        descriptor: &cpsd::RootBoardPublicKey,
        deadline: u64,
        now: u64,
    ) -> Result<u64> {
        let limit = now
            .checked_add(300)
            .ok_or(Error::Invalid("time overflow"))?;
        let until = deadline
            .checked_add(1)
            .ok_or(Error::Invalid("time overflow"))?;
        if deadline < now || deadline > limit {
            return Err(Error::Invalid("root-board request deadline"));
        }
        let cose = self
            .root_board_publication(now)
            .await?
            .ok_or(Error::Missing)?;
        let signed = self
            .key_ring()?
            .verify(&cose, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Verification)?;
        let payload: cbcn::root_board::Payload =
            serde_json::from_slice(signed.payload()).map_err(|_| Error::Corrupt)?;
        if payload.descriptor != descriptor.to_bytes() || until > signed.valid_until() {
            return Err(Error::Verification);
        }
        Ok(until)
    }

    /// Publish the configured common PUBLIC descriptor. This privileged operation
    /// supplies no role, member, nonce or private-key authority. The BBS issuer is
    /// bound once; subsequent publications may refresh its current cohort only.
    pub async fn publish_root_board(
        &mut self,
        descriptor: &cpsd::RootBoardPublicKey,
        now: u64,
    ) -> Result<Vec<u8>> {
        let mut next = self.current().await?.clone();
        let epoch = self.epoch(now).await?;
        let bytes = validate_root_board(descriptor, &next, epoch, now)?;
        let revision = next_counter(next.root_board.as_ref().map_or(0, |p| p.revision))?;
        let payload = cbcn::root_board::Payload {
            purpose: cbcn::root_board::PURPOSE.into(),
            community: next.community.clone(),
            revision,
            policy_epoch: epoch,
            descriptor: bytes,
        };
        let payload = serde_json::to_vec(&payload).map_err(|_| Error::Corrupt)?;
        if payload.len() > MAX_DOCUMENT_BYTES {
            return Err(Error::Invalid("root-board size"));
        }
        let active = self.active(now).await?;
        let until = self
            .validity_limit(now, next.config.snapshot_validity, &active)
            .await?
            .min(descriptor.expires_at());
        let cose = self
            .signer
            .sign(
                csgn::Kind::SettingsSnapshot,
                &payload,
                crate::day(now),
                until,
            )
            .await?;
        next.root_board = Some(Publication {
            revision,
            cose: Some(cose.clone()),
        });
        next.root_board_issuer = Some(descriptor.issuer().to_bytes());
        next.root_board_cohort = Some(descriptor.cohort_start());
        self.commit(next).await?;
        Ok(cose)
    }

    /// Original public descriptor bytes. Absence means never configured;
    /// invalidation or expiry requires a fresh projection by the configured owner.
    pub async fn root_board_publication(&self, now: u64) -> Result<Option<Vec<u8>>> {
        Ok(self.current_root_board(now).await?.map(|(cose, _, _)| cose))
    }

    /// Decode only the current authenticated root descriptor and its exclusive
    /// publication expiry. Consumers must re-read after policy changes; absence
    /// or invalidation cannot authorize ordinary-passport root admission.
    pub async fn root_board_descriptor(
        &self,
        now: u64,
    ) -> Result<Option<(cpsd::RootBoardPublicKey, u64)>> {
        Ok(self
            .current_root_board(now)
            .await?
            .map(|(_, descriptor, until)| (descriptor, until)))
    }

    async fn current_root_board(
        &self,
        now: u64,
    ) -> Result<Option<(Vec<u8>, cpsd::RootBoardPublicKey, u64)>> {
        let state = self.current().await?;
        let Some(publication) = &state.root_board else {
            return Ok(None);
        };
        let cose = publication.cose.as_ref().ok_or(Error::Missing)?;
        let epoch = self.epoch(now).await?;
        let material = cbcn::root_board::RootBoard::verify(
            self.key_ring()?,
            cose,
            epoch,
            publication.revision,
            now,
        )
        .map_err(|_| Error::Verification)?;
        let payload: cbcn::root_board::Payload =
            serde_json::from_slice(material.payload()).map_err(|_| Error::Corrupt)?;
        let descriptor = cpsd::RootBoardPublicKey::from_bytes(&payload.descriptor)
            .map_err(|_| Error::Verification)?;
        if validate_root_board(&descriptor, state, epoch, now)? != payload.descriptor
            || state.root_board_cohort != Some(descriptor.cohort_start())
            || material.valid_until() > descriptor.expires_at()
        {
            return Err(Error::Verification);
        }
        Ok(Some((cose.clone(), descriptor, material.valid_until())))
    }
}

fn validate_root_board(
    descriptor: &cpsd::RootBoardPublicKey,
    state: &StoredPolicy,
    epoch: u64,
    now: u64,
) -> Result<Vec<u8>> {
    timestamp(now)?;
    let bytes = descriptor.to_bytes();
    let decoded = cpsd::RootBoardPublicKey::from_bytes(&bytes).map_err(|_| Error::Verification)?;
    if decoded != *descriptor
        || decoded.to_bytes() != bytes
        || descriptor.community().as_bytes() != state.community.as_bytes()
        || descriptor.policy_epoch() != epoch
        || now < descriptor.cohort_start()
        || now >= descriptor.expires_at()
        || state
            .root_board_issuer
            .as_ref()
            .is_some_and(|issuer| *issuer != descriptor.issuer().to_bytes())
        || state
            .root_board_cohort
            .is_some_and(|floor| descriptor.cohort_start() < floor)
    {
        return Err(Error::Verification);
    }
    Ok(bytes)
}
