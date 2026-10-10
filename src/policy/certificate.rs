//! Original registered-key certificate issuance through the one Policy signer.
use super::*;

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// Issue Keyhole's original registered-key certificate using this one durable
    /// signer and Beacon ring. This is not admission and does not advance policy
    /// epochs or public activity revisions. The caller retains Membership's
    /// certificate lease through this await and checks its deadline before return.
    pub async fn issue_passkey_certificate(
        &mut self,
        registration: &ckyh::certificate::RegistrationCertificate,
        now: u64,
    ) -> Result<Vec<u8>> {
        self.key_ring()?;
        let state = self.current().await?;
        if registration.community() != self.key_ring()?.issuer() {
            return Err(Error::Invalid("passkey certificate scope"));
        }
        if state.revocations.members.contains(registration.member())
            || state
                .revocations
                .passkeys
                .contains(registration.credential_id())
        {
            return Err(Error::Revoked);
        }
        // The public registration certificate retains coarse issuance, as do
        // existing public Policy signatures. No login/activity timestamp persists.
        let bytes = registration
            .sign(&mut self.signer, crate::day(now))
            .await
            .map_err(|_| Error::Invalid("passkey certificate signing"))?;
        self.key_ring()?
            .verify(&bytes, csgn::Kind::Credential, now)
            .map_err(|_| Error::Invalid("passkey certificate lifetime"))?;
        Ok(bytes)
    }
}
