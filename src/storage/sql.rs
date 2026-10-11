use crlt::{Community, Db, Value, params};

use super::MAX_STORED_DOCUMENT_BYTES;
use super::{Storage, StoredPolicy, validate_transition};
use crate::{Error, Result, identifier};

#[cfg(test)]
#[path = "sql/writer_tests.rs"]
mod writer_tests;

/// Append to the composition root's complete numbered migration history.
pub const SCHEMA: &str = "
CREATE TABLE cplc_policy (
    community_id TEXT NOT NULL,
    slot INTEGER NOT NULL CHECK (slot = 1),
    revision INTEGER NOT NULL CHECK (revision > 0),
    document TEXT NOT NULL,
    PRIMARY KEY (community_id, slot)
) WITHOUT ROWID;
CREATE TABLE cplc_revocation (
    community_id TEXT NOT NULL,
    entry TEXT NOT NULL,
    PRIMARY KEY (community_id, entry)
) WITHOUT ROWID;
";

const REVOKED: &str = "SELECT entry FROM cplc_revocation WHERE entry > ?1 ORDER BY entry LIMIT 256";
const REVOKE: &str = "INSERT INTO cplc_revocation (entry) VALUES (?1)";
const RESTORE: &str = "DELETE FROM cplc_revocation WHERE entry = ?1";

const SELECT: &str = "SELECT revision, document FROM cplc_policy WHERE slot = ?1";
const INSERT: &str = "INSERT INTO cplc_policy (slot, revision, document) VALUES (?1, ?2, ?3)";
const UPDATE: &str =
    "UPDATE cplc_policy SET revision = ?1, document = ?2 WHERE slot = ?3 AND revision = ?4";

/// Native libSQL storage through the shared crlt database facade.
#[derive(Clone)]
pub struct LibsqlStore {
    name: String,
    scope: Community,
}

impl LibsqlStore {
    /// Bind to an authorized community in an already migrated database.
    /// Deploy a separate physical database per community.
    pub fn new(db: &Db, community: impl Into<String>) -> Result<Self> {
        let name = community.into();
        identifier(&name)?;
        let scope = db.community(name.clone())?;
        Ok(Self { name, scope })
    }

    /// Verify every SQL statement's query plan without changing data.
    pub async fn check_query_plans(&self) -> Result<()> {
        for (sql, parameters) in [
            (SELECT, vec![Value::Integer(1)]),
            (
                INSERT,
                vec![
                    Value::Integer(1),
                    Value::Integer(1),
                    Value::Text("{}".into()),
                ],
            ),
            (
                UPDATE,
                vec![
                    Value::Integer(2),
                    Value::Text("{}".into()),
                    Value::Integer(1),
                    Value::Integer(1),
                ],
            ),
            (REVOKED, vec![Value::Text("member:example".into())]),
            (REVOKE, vec![Value::Text("member:example".into())]),
            (RESTORE, vec![Value::Text("member:example".into())]),
        ] {
            self.scope
                .explain(sql, parameters)
                .await?
                .assert_indexed()?;
        }
        Ok(())
    }
}

fn entries(revocations: &crate::Revocations) -> Result<std::collections::BTreeSet<String>> {
    let mut entries: std::collections::BTreeSet<_> = revocations
        .members
        .iter()
        .map(|member| format!("member:{member}"))
        .collect();
    for device in &revocations.devices {
        entries.insert(format!(
            "device:{}",
            serde_json::to_string(device).map_err(|_| Error::Corrupt)?
        ));
    }
    for credential in &revocations.passkeys {
        entries.insert(format!(
            "passkey:{}",
            serde_json::to_string(credential).map_err(|_| Error::Corrupt)?
        ));
    }
    Ok(entries)
}

enum Reader<'a> {
    Committed(&'a Community),
    Writer(&'a mut crlt::Transaction),
}

impl Reader<'_> {
    async fn query(
        &mut self,
        sql: &str,
        params: impl crlt::IntoParams,
    ) -> crlt::Result<Vec<crlt::Row>> {
        match self {
            Self::Committed(scope) => scope.query(sql, params).await,
            Self::Writer(tx) => tx.query(sql, params).await,
        }
    }
}

async fn read(tx: &mut Reader<'_>, scope: &str) -> Result<Option<StoredPolicy>> {
    let header = tx.query(SELECT, [1i64]).await?;
    let mut state = decode(&header, scope)?;
    if let Some(state) = &mut state {
        let mut after = String::new();
        loop {
            let rows = tx.query(REVOKED, [after.as_str()]).await?;
            if rows.is_empty() {
                break;
            }
            for row in rows {
                let entry = row.get_str(0).map_err(|_| Error::Corrupt)?;
                if let Some(member) = entry.strip_prefix("member:") {
                    state.revocations.members.insert(member.to_owned());
                } else if let Some(device) = entry.strip_prefix("device:") {
                    state
                        .revocations
                        .devices
                        .insert(serde_json::from_str(device).map_err(|_| Error::Corrupt)?);
                } else if let Some(credential) = entry.strip_prefix("passkey:") {
                    state
                        .revocations
                        .passkeys
                        .insert(serde_json::from_str(credential).map_err(|_| Error::Corrupt)?);
                } else {
                    return Err(Error::Corrupt);
                }
                after = entry.to_owned();
            }
        }
        state.validate()?;
        if matches!(tx, Reader::Committed(_)) {
            // Every revocation change and the strictly increasing Policy
            // revision commit together. Bracket all pages with the exact
            // committed header; a concurrent mutation refuses this read rather
            // than combining authority from different snapshots. This avoids
            // acquiring a second writer inside an owner's final transaction.
            let after = tx.query(SELECT, [1i64]).await?;
            same_header(&header, &after)?;
        }
    }
    Ok(state)
}

fn same_header(before: &[crlt::Row], after: &[crlt::Row]) -> Result<()> {
    let before = before.first().ok_or(Error::Corrupt)?;
    let after = after.first().ok_or(Error::Conflict)?;
    if before.get_i64(0).map_err(|_| Error::Corrupt)?
        != after.get_i64(0).map_err(|_| Error::Corrupt)?
        || before.get_str(1).map_err(|_| Error::Corrupt)?
            != after.get_str(1).map_err(|_| Error::Corrupt)?
    {
        return Err(Error::Conflict);
    }
    Ok(())
}

fn decode(rows: &[crlt::Row], scope: &str) -> Result<Option<StoredPolicy>> {
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let document = row.get_str(1).map_err(|_| Error::Corrupt)?;
    if document.len() > MAX_STORED_DOCUMENT_BYTES {
        return Err(Error::Corrupt);
    }
    let state: StoredPolicy = serde_json::from_str(document).map_err(|_| Error::Corrupt)?;
    state.validate().map_err(|_| Error::Corrupt)?;
    if state.community != scope
        || row.get_i64(0).map_err(|_| Error::Corrupt)? != state.revision as i64
    {
        return Err(Error::Corrupt);
    }
    Ok(Some(state))
}

impl Storage for LibsqlStore {
    fn community(&self) -> &str {
        &self.name
    }
    async fn load(&self) -> Result<Option<StoredPolicy>> {
        read(&mut Reader::Committed(&self.scope), &self.name).await
    }
    async fn compare_exchange(&self, expected: Option<u64>, next: &StoredPolicy) -> Result<()> {
        self.exchange_with_guard(expected, next, &mut CallerAuthorized)
            .await
    }
    async fn compare_exchange_checked<G: crbk::CommitGuard>(
        &self,
        expected: Option<u64>,
        next: &StoredPolicy,
        guard: &mut G,
    ) -> Result<()> {
        self.exchange_with_guard(expected, next, guard).await
    }
}

// Only the unchanged caller-authorized API uses this private adapter.
struct CallerAuthorized;
impl crbk::CommitGuard for CallerAuthorized {
    async fn check(&mut self) -> crbk::Result<()> {
        Ok(())
    }
    fn release(&mut self) -> crbk::Result<()> {
        Ok(())
    }
}

impl LibsqlStore {
    async fn exchange_with_guard<G: crbk::CommitGuard>(
        &self,
        expected: Option<u64>,
        next: &StoredPolicy,
        guard: &mut G,
    ) -> Result<()> {
        let mut tx = self.scope.tx().await?;
        let previous = read(&mut Reader::Writer(&mut tx), &self.name).await?;
        validate_transition(&self.name, previous.as_ref(), expected, next)?;
        let old_entries = entries(
            &previous
                .as_ref()
                .map(|p| p.revocations.clone())
                .unwrap_or_default(),
        )?;
        let new_entries = entries(&next.revocations)?;
        for entry in old_entries.difference(&new_entries) {
            tx.execute(RESTORE, [entry.as_str()]).await?;
        }
        for entry in new_entries.difference(&old_entries) {
            tx.execute(REVOKE, [entry.as_str()]).await?;
        }
        let mut document = next.clone();
        document.revocations = crate::Revocations::default();
        let document = serde_json::to_string(&document).map_err(|_| Error::Corrupt)?;
        let count = match expected {
            None => {
                tx.execute(INSERT, params![1i64, next.revision as i64, document])
                    .await
            }
            Some(revision) => {
                tx.execute(
                    UPDATE,
                    params![next.revision as i64, document, 1i64, revision as i64],
                )
                .await
            }
        }?;
        if count != 1 {
            return Err(Error::Conflict);
        }
        guard.check().await.map_err(Error::from)?;
        guard.release().map_err(Error::from)?;
        tx.commit().await.map_err(Error::from)?;
        guard.release().map_err(|_| Error::Storage)
    }
}
