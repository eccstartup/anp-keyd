use super::*;

struct Fixture {
    db: Database,
    config: ServiceConfig,
    dir: std::path::PathBuf,
}
impl Fixture {
    fn new() -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("keyd-db-test-{}", uuid()));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.join("state.sqlite");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let config:ServiceConfig=serde_json::from_value(json!({
            "schema_version":1,"mode":"linux-boundary-preview","instance_id":uuid(),
            "service_uid":1001,"admin_uids":[1002],"agent_gid":1003,"admin_gid":1004,
            "state_dir":"/var/lib/anp-keyd","sign_socket":"/run/anp-keyd/sign/sign.sock","admin_socket":"/run/anp-keyd/admin/admin.sock",
            "principals":[{"principal_id":uuid(),"uid":1005,"generation":1,"enabled":true}],"vault_ids":[]
        })).unwrap();
        config.validate().unwrap();
        let mut connection = open_new(&path).unwrap();
        Database::create(&mut connection, &config, now()).unwrap();
        let mut db = Database {
            connection,
            boot_epoch: 0,
        };
        db.recovery(&config, now()).unwrap();
        Self { db, config, dir }
    }
    fn disable(&mut self) -> Prepared {
        self.db
            .prepare(
                1002,
                Change::DisablePrincipal {
                    principal_id: self.config.principals[0].principal_id.clone(),
                },
                now(),
            )
            .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn now() -> Time {
    Time {
        wall: 1_000,
        monotonic_ms: 10_000,
    }
}

#[test]
fn prepared_operations_bind_actor_digest_epoch_and_single_use() {
    let mut f = Fixture::new();
    let p = f.disable();
    assert!(f.db.commit(999, &p.operation_id, &p.digest, now()).is_err());
    assert!(f.db.commit(1002, &p.operation_id, "wrong", now()).is_err());
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    assert!(f.db.principal(1005).unwrap().is_none());
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    let fresh =
        f.db.prepare(1002, Change::RegisterPrincipal { uid: 1005 }, now())
            .unwrap();
    assert_ne!(
        fresh.effect["principal_id"],
        f.config.principals[0].principal_id
    );
    assert_eq!(fresh.effect["generation"], 2);
    f.db.commit(1002, &fresh.operation_id, &fresh.digest, now())
        .unwrap();
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(f.db.principal(1005).unwrap().unwrap().generation, 2);
}

#[test]
fn stale_approvals_and_payload_replacement_cannot_mutate_state() {
    let mut f = Fixture::new();
    let stale = f.disable();
    let another =
        f.db.prepare(1002, Change::RegisterPrincipal { uid: 1006 }, now())
            .unwrap();
    f.db.commit(1002, &another.operation_id, &another.digest, now())
        .unwrap();
    assert!(f
        .db
        .commit(1002, &stale.operation_id, &stale.digest, now())
        .is_err());
    let p = f.disable();
    f.db.connection.execute("UPDATE admin_operations SET payload=?1 WHERE operation_id=?2",params![r#"{"kind":"RegisterPrincipal","uid":1007,"principal_id":"replaced","generation":1}"#,p.operation_id]).unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.principal(1007).unwrap().is_none());
    assert!(f.db.principal(1005).unwrap().is_some());
}

#[test]
fn deadline_checks_include_monotonic_time_and_restart_invalidates_approval() {
    let mut f = Fixture::new();
    let p = f.disable();
    assert!(f
        .db
        .commit(
            1002,
            &p.operation_id,
            &p.digest,
            Time {
                wall: 999,
                monotonic_ms: 130_001
            }
        )
        .is_err());
    assert!(f
        .db
        .commit(
            1002,
            &p.operation_id,
            &p.digest,
            Time {
                wall: 1_121,
                monotonic_ms: 10_001
            }
        )
        .is_err());
    let boot = f.db.boot_epoch;
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(f.db.boot_epoch, boot + 1);
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.principal(1005).unwrap().is_some());
}

#[test]
fn audit_failure_rolls_back_both_preparation_and_commit() {
    let mut f = Fixture::new();
    f.db.connection.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    assert!(f
        .db
        .prepare(1002, Change::RegisterPrincipal { uid: 1007 }, now())
        .is_err());
    assert_eq!(
        f.db.connection
            .query_row("SELECT count(*) FROM admin_operations", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
    f.db.connection
        .execute_batch("DROP TRIGGER fail_audit")
        .unwrap();
    let p = f.disable();
    f.db.connection.execute_batch("CREATE TRIGGER fail_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.principal(1005).unwrap().is_some());
    let state: String =
        f.db.connection
            .query_row(
                "SELECT state FROM admin_operations WHERE operation_id=?1",
                [p.operation_id],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(state, "prepared");
}

#[test]
fn recovery_preserves_consumption_and_marks_incomplete_requests_unknown() {
    let mut f = Fixture::new();
    let principal = &f.config.principals[0].principal_id;
    f.db.connection.execute_batch("INSERT INTO vaults VALUES('vault','vaults/vault','active'); INSERT INTO keys VALUES('key','vault','did','did#hot','hot','digest','active',0,0); INSERT INTO policies VALUES('policy',1,'{}','digest');").unwrap();
    f.db.connection
        .execute(
            "INSERT INTO grants VALUES('grant',?1,'key','policy',1,1,9999,2,1,'active')",
            [principal],
        )
        .unwrap();
    f.db.connection
        .execute(
            "INSERT INTO requests VALUES(?1,'request','grant','digest','reserved',NULL,NULL)",
            [principal],
        )
        .unwrap();
    assert!(f
        .db
        .connection
        .execute("UPDATE grants SET used_uses=3", [])
        .is_err());
    assert!(f
        .db
        .connection
        .execute("UPDATE policies SET content='changed'", [])
        .is_err());
    f.db.recovery(&f.config, now()).unwrap();
    let (state, uses): (String, i64) =
        f.db.connection
            .query_row("SELECT state,used_uses FROM grants", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
    assert_eq!((state.as_str(), uses), ("revoked_restart", 1));
    let state: String =
        f.db.connection
            .query_row("SELECT state FROM requests", [], |r| r.get(0))
            .unwrap();
    assert_eq!(state, "outcome_unknown");
}

#[test]
fn missing_future_corrupt_and_foreign_instance_databases_are_refused() {
    let mut f = Fixture::new();
    let missing = f.dir.join("missing.sqlite");
    assert!(open(&missing).is_err());
    assert!(!missing.exists());
    let mut foreign = f.config.clone();
    foreign.instance_id = uuid();
    assert!(f.db.recovery(&foreign, now()).is_err());
    f.db.connection
        .pragma_update(None, "user_version", SCHEMA + 1)
        .unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
    f.db.connection
        .pragma_update(None, "user_version", SCHEMA)
        .unwrap();
    f.db.connection
        .execute("UPDATE audit_events SET event_data=x'00' WHERE seq=1", [])
        .unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
}

#[test]
fn opening_newer_schema_does_not_rewrite_its_journal_mode() {
    let f = Fixture::new();
    f.db.connection
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=2;")
        .unwrap();
    assert!(open(&f.dir.join("state.sqlite")).is_err());
    let mode: String =
        f.db.connection
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
    assert_eq!(mode, "wal");
}
