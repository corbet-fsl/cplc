use crlt::{Community, Db, params};

use super::MAX_STORED_DOCUMENT_BYTES;
use super::{Storage, StoredPolicy, validate_transition};
use crate::{Error, Result, identifier};

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
        self.scope.explain(SELECT, [1i64]).await?.assert_indexed()?;
        self.scope
            .explain(INSERT, params![1i64, 1i64, "{}"])
            .await?
            .assert_indexed()?;
        self.scope
            .explain(UPDATE, params![2i64, "{}", 1i64, 1i64])
            .await?
            .assert_indexed()?;
        for sql in [REVOKED, REVOKE, RESTORE] {
            self.scope
                .explain(sql, ["member:example"])
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
    Ok(entries)
}

async fn read(tx: &mut crlt::Transaction, scope: &str) -> Result<Option<StoredPolicy>> {
    let mut state = decode(&tx.query(SELECT, [1i64]).await?, scope)?;
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
                } else {
                    return Err(Error::Corrupt);
                }
                after = entry.to_owned();
            }
        }
        state.validate()?;
    }
    Ok(state)
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
        let mut tx = self.scope.tx().await?;
        let state = read(&mut tx, &self.name).await?;
        tx.commit().await?;
        Ok(state)
    }
    async fn compare_exchange(&self, expected: Option<u64>, next: &StoredPolicy) -> Result<()> {
        let mut tx = self.scope.tx().await?;
        let previous = read(&mut tx, &self.name).await?;
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
        tx.commit().await.map_err(Error::from)
    }
}
