//! Stateful, exact-key grants. No signatures or quota reservations before M4.
use super::*;
use crate::security::http::CanonicalHttpRequest;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub enum GrantChange {
    Create {
        principal_id: String,
        key_id: String,
        policy_id: String,
        policy_version: u32,
        expiry: i64,
        max_uses: u32,
    },
    Revoke {
        grant_id: String,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub grant_id: String,
    pub principal_id: String,
    pub key_id: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub boot_epoch: i64,
    pub expiry: i64,
    pub max_uses: u32,
    pub used_uses: u32,
    pub state: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", deny_unknown_fields)]
pub(super) enum Effect {
    Create {
        grant: Grant,
        monotonic_deadline: i64,
    },
    Revoke {
        grant_id: String,
    },
}
fn refused(code: &str) -> KeydError {
    KeydError::Misuse(code.into())
}
fn principal(db: &Connection, id: &str) -> Result<()> {
    if !db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM principals WHERE principal_id=?1 AND state='enabled')",
            [id],
            |r| r.get::<_, bool>(0),
        )
        .map_err(db_error)?
    {
        return Err(refused("PRINCIPAL_DISABLED"));
    }
    Ok(())
}
fn hot_key(db: &Connection, root: &Path, id: &str) -> Result<catalog::KeyRecord> {
    let key = catalog::get_key(db, id).map_err(|_| refused("KEY_ROLE_FORBIDDEN"))?;
    if key.role != catalog::KeyRole::Hot || key.state != "active" {
        return Err(refused("KEY_ROLE_FORBIDDEN"));
    }
    catalog::check_key(db, root, &key.vault_id, &key.did, &key.kid)
        .map_err(|_| refused("KEY_ROLE_FORBIDDEN"))?;
    Ok(key)
}
fn policy(db: &Connection, id: &str, version: u32) -> Result<Value> {
    let content: String = db
        .query_row(
            "SELECT content FROM policies WHERE policy_id=?1 AND version=?2",
            params![id, version],
            |r| r.get(0),
        )
        .optional()
        .map_err(db_error)?
        .ok_or_else(|| refused("POLICY_DENIED"))?;
    serde_json::from_str(&content).map_err(|_| unavailable())
}
fn validate(db: &Connection, root: &Path, g: &Grant, now: Time) -> Result<()> {
    principal(db, &g.principal_id)?;
    hot_key(db, root, &g.key_id)?;
    let p = super::policy::parse(policy(db, &g.policy_id, g.policy_version)?)?;
    let duration = g
        .expiry
        .checked_sub(now.wall)
        .filter(|v| *v > 0)
        .ok_or_else(|| refused("GRANT_EXPIRED"))?;
    if duration > i64::from(p.grant_limits.max_duration_seconds)
        || g.max_uses == 0
        || g.max_uses > p.grant_limits.max_uses
    {
        return Err(refused("GRANT_INVALID"));
    }
    Ok(())
}
pub(super) fn resolve(
    db: &Connection,
    root: &Path,
    change: GrantChange,
    boot: i64,
    now: Time,
) -> Result<Effect> {
    match change {
        GrantChange::Create {
            principal_id,
            key_id,
            policy_id,
            policy_version,
            expiry,
            max_uses,
        } => {
            let mut bytes = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut bytes);
            let grant = Grant {
                grant_id: hex(&bytes),
                principal_id,
                key_id,
                policy_id,
                policy_version,
                boot_epoch: boot,
                expiry,
                max_uses,
                used_uses: 0,
                state: "active".into(),
            };
            validate(db, root, &grant, now)?;
            let monotonic_deadline = expiry
                .checked_sub(now.wall)
                .and_then(|s| s.checked_mul(1000))
                .and_then(|ms| now.monotonic_ms.checked_add(ms))
                .ok_or_else(invalid)?;
            Ok(Effect::Create {
                grant,
                monotonic_deadline,
            })
        }
        GrantChange::Revoke { grant_id } => {
            if get(db, &grant_id)?.is_none() {
                return Err(refused("GRANT_INVALID"));
            }
            Ok(Effect::Revoke { grant_id })
        }
    }
}
pub(super) fn apply(
    tx: &Transaction<'_>,
    root: &Path,
    effect: Effect,
    boot: i64,
    now: Time,
) -> Result<()> {
    match effect {
        Effect::Create {
            grant: g,
            monotonic_deadline,
        } => {
            validate(tx, root, &g, now)?;
            if g.boot_epoch != boot || now.monotonic_ms >= monotonic_deadline {
                return Err(refused("GRANT_EXPIRED"));
            }
            tx.execute(
                "INSERT INTO grants VALUES(?1,?2,?3,?4,?5,?6,?7,?8,0,'active')",
                params![
                    g.grant_id,
                    g.principal_id,
                    g.key_id,
                    g.policy_id,
                    g.policy_version,
                    boot,
                    g.expiry,
                    g.max_uses
                ],
            )
            .map_err(db_error)?;
            tx.execute(
                "INSERT INTO grant_deadlines VALUES(?1,?2)",
                params![g.grant_id, monotonic_deadline],
            )
            .map_err(db_error)?;
        }
        Effect::Revoke { grant_id } => {
            tx.execute(
                "UPDATE grants SET state='revoked' WHERE grant_id=?1 AND state='active'",
                [grant_id],
            )
            .map_err(db_error)?;
        }
    }
    Ok(())
}
fn get(db: &Connection, id: &str) -> Result<Option<Grant>> {
    db.query_row("SELECT grant_id,principal_id,key_id,policy_id,policy_version,boot_epoch,expiry,max_uses,used_uses,state FROM grants WHERE grant_id=?1",[id],|r|Ok(Grant{grant_id:r.get(0)?,principal_id:r.get(1)?,key_id:r.get(2)?,policy_id:r.get(3)?,policy_version:r.get(4)?,boot_epoch:r.get(5)?,expiry:r.get(6)?,max_uses:r.get(7)?,used_uses:r.get(8)?,state:r.get(9)?})).optional().map_err(db_error)
}
impl Database {
    fn refresh_grants(&mut self, now: Time) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        if tx.query_row("SELECT EXISTS(SELECT 1 FROM grants g LEFT JOIN grant_deadlines d USING(grant_id) WHERE g.state='active' AND g.boot_epoch=?1 AND d.grant_id IS NULL)",[self.boot_epoch],|r|r.get::<_,bool>(0)).map_err(db_error)? {
            return Err(unavailable());
        }
        let exhausted = tx
            .execute(
                "UPDATE grants SET state='exhausted' WHERE state='active' AND used_uses>=max_uses",
                [],
            )
            .map_err(db_error)?;
        if exhausted > 0 {
            append(
                &tx,
                &json!({"event":"GRANTS_EXHAUSTED","count":exhausted,"at":now.wall}),
            )?;
        }
        let changed=tx.execute("UPDATE grants SET state='expired' WHERE state='active' AND (expiry<=?1 OR grant_id IN (SELECT grant_id FROM grant_deadlines WHERE monotonic_deadline<=?2))",params![now.wall,now.monotonic_ms]).map_err(db_error)?;
        if changed > 0 {
            append(
                &tx,
                &json!({"event":"GRANTS_EXPIRED","count":changed,"at":now.wall}),
            )?;
        }
        tx.commit().map_err(db_error)
    }
    pub fn grant_status(&mut self, principal_id: &str, id: &str, now: Time) -> Result<Grant> {
        self.refresh_grants(now)?;
        principal(&self.connection, principal_id)?;
        get(&self.connection, id)?
            .filter(|g| g.principal_id == principal_id)
            .ok_or_else(|| refused("GRANT_INVALID"))
    }
    pub fn authorized_keys(
        &mut self,
        principal_id: &str,
        now: Time,
    ) -> Result<Vec<catalog::KeyRecord>> {
        self.refresh_grants(now)?;
        principal(&self.connection, principal_id)?;
        let ids = {
            let mut s=self.connection.prepare("SELECT DISTINCT key_id FROM grants WHERE principal_id=?1 AND state='active' AND boot_epoch=?2 AND used_uses<max_uses").map_err(db_error)?;
            let ids = s
                .query_map(params![principal_id, self.boot_epoch], |r| {
                    r.get::<_, String>(0)
                })
                .map_err(db_error)?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(db_error)?;
            ids
        };
        ids.iter()
            .map(|id| hot_key(&self.connection, &self.root, id))
            .collect()
    }
    pub fn authorize_http(
        &mut self,
        principal_id: &str,
        id: &str,
        request: &CanonicalHttpRequest,
        now: Time,
    ) -> Result<(Grant, catalog::KeyRecord)> {
        let g = self.grant_status(principal_id, id, now)?;
        match g.state.as_str() {
            "expired" => return Err(refused("GRANT_EXPIRED")),
            "exhausted" => return Err(refused("GRANT_EXHAUSTED")),
            "active" => {}
            _ => return Err(refused("GRANT_INVALID")),
        }
        if g.boot_epoch != self.boot_epoch {
            return Err(refused("GRANT_INVALID"));
        }
        if g.used_uses >= g.max_uses {
            return Err(refused("GRANT_EXHAUSTED"));
        }
        let key = hot_key(&self.connection, &self.root, &g.key_id)?;
        super::policy::evaluate(
            policy(&self.connection, &g.policy_id, g.policy_version)?,
            request,
        )?;
        Ok((g, key))
    }
}
