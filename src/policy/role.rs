//! Original one-use role entitlement, distinct from admission or root-board proofs.
use super::*;

impl<R: crbk::Storage, S: Storage, K: csgn::Store> Policy<R, S, K> {
    /// Sign the original target-community role invitation with this Policy's
    /// persistent signer. The trusted hosting service must first authorize its
    /// creation/founder flow and derive the actual recipient's member binding.
    /// This method grants no role or admission and consumes no receipt; those
    /// effects belong to membership's complete atomic admission transaction.
    /// Root-board membership uses its separate holder-bound blind credential.
    pub async fn issue_role_invitation(
        &mut self,
        invitation: &cvch::role::Invitation<'_>,
    ) -> Result<Vec<u8>> {
        if invitation.community != self.current().await?.community
            || invitation.purpose == cvch::role::Purpose::RootBoardMember
        {
            return Err(Error::Verification);
        }
        // Every Policy signature is issued at UTC-day precision, so this signer
        // refuses a second-precision timestamp instead of letting the next day
        // signature look like a regression. The caller rounds; it is never done here.
        if invitation.issued_at != crate::day(invitation.issued_at) {
            return Err(Error::Invalid(
                "role invitation must be issued at a UTC day boundary",
            ));
        }
        let payload = cvch::role::issuance_bytes(invitation)
            .map_err(|_| Error::Invalid("role invitation"))?;
        // The original role codec binds these exact envelope timestamps: issued_at
        // is the day boundary checked above and valid_until is never extended.
        let signed = self
            .signer
            .sign(
                csgn::Kind::Credential,
                &payload,
                invitation.issued_at,
                invitation.valid_until,
            )
            .await?;
        self.current().await?;
        Ok(signed)
    }
}
