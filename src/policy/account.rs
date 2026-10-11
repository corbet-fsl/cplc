//! Original account grant issuance from the retained admission decision.
use super::*;

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// Project the configured record period from this actual active Rulebook.
    /// Validate its immutable catalogue metadata on the same record used for the
    /// effective settings. Caller serialization/currentness remains required.
    pub async fn record_epoch_settings(
        &self,
        key: &str,
        now: u64,
    ) -> Result<crbk::RecordEpochSettings> {
        let state = self.current().await?;
        let active = self.active(now).await?;
        crbk::RecordEpochSettings::validate_catalogue(&active.change.rulebook, key)?;
        let mut snapshot = active.snapshot(&state.community, timestamp(now)?)?;
        snapshot.policy_epoch = effective_epoch(state.epoch, active.change.policy_epoch)?;
        crbk::RecordEpochSettings::from_snapshot(&snapshot, key).map_err(Error::from)
    }

    /// Issue the v3 account grant from the same current admission decision as a
    /// credential. Policy owns the signing key and projects the actual retained
    /// Balance digest; the caller selects only one already-authorized device.
    pub async fn issue_account_grant<M: crate::MembershipSource>(
        &mut self,
        membership: &M,
        request: CredentialRequest<'_>,
        device: [u8; 32],
        context: crate::AccountGrantContext,
        now: u64,
    ) -> Result<cblc::admission::AdmissionGrant> {
        use data_encoding::{BASE64URL_NOPAD as B64, HEXLOWER};
        if context.passport_policy_digest == [0; 32]
            || context.passport_valid_until <= now
            || context.passport_valid_until > i64::MAX as u64
        {
            return Err(Error::Invalid("account passport cohort"));
        }
        let (credential, until, _lease) =
            self.credential_candidate(membership, request, now).await?;
        if !credential.devices.contains(&device) {
            return Err(Error::Invalid("unauthorized account device"));
        }
        let pseudonym: [u8; 48] = HEXLOWER
            .decode(credential.member.as_bytes())
            .map_err(|_| Error::Invalid("account pseudonym"))?
            .try_into()
            .map_err(|_| Error::Invalid("account pseudonym"))?;
        let original = self.balance_publication(now).await?.ok_or(Error::Missing)?;
        let signed = self
            .key_ring()?
            .verify(&original, csgn::Kind::SettingsSnapshot, now)
            .map_err(|_| Error::Verification)?;
        let material: cblc::publication::PublicVerifierMaterial =
            serde_json::from_slice(signed.payload()).map_err(|_| Error::Corrupt)?;
        let until = until
            .min(context.passport_valid_until)
            .min(signed.valid_until())
            .min(material.policy.account.policy_valid_until);
        if now >= until {
            return Err(Error::Verification);
        }
        let key = self
            .key_ring()?
            .active()
            .ok_or(Error::Corrupt)?
            .public_key();
        let mut grant = cblc::admission::AdmissionGrant {
            version: 3,
            issuer_key_id: cblc::admission::policy_key_id(&key),
            community_id: credential.community,
            member_id: cblc::admission::member_id(&pseudonym),
            pseudonym: credential.member,
            chat_public_key: B64.encode(&device),
            policy_digest: B64.encode(&material.admission_policy_digest),
            policy_epoch: credential.policy_epoch,
            passport_policy_digest: B64.encode(&context.passport_policy_digest),
            issued_at: crate::day(now),
            expires_at: until,
            signature: String::new(),
        };
        let payload = cblc::admission::admission_bytes(&grant).map_err(|_| Error::Verification)?;
        let signed = self
            .signer
            .sign(csgn::Kind::Credential, &payload, grant.issued_at, until)
            .await?;
        grant.signature = B64.encode(&signed);
        Ok(grant)
    }
}
