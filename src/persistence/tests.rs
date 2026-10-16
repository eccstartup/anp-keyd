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
            root: dir.clone(),
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
    f.db.connection.execute_batch("INSERT INTO vaults VALUES('vault','vaults/vault','active'); INSERT INTO keys VALUES('key','vault','did','did#hot','hot','digest','active',0,0,''); INSERT INTO policies VALUES('policy',1,'{}','digest');").unwrap();
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
        .execute_batch("PRAGMA journal_mode=WAL; PRAGMA user_version=3;")
        .unwrap();
    assert!(open(&f.dir.join("state.sqlite")).is_err());
    let mode: String =
        f.db.connection
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
    assert_eq!(mode, "wal");
}

fn policy_value() -> Value {
    json!({"schema_version":1,"name":"read-orders","purpose":"http-authentication","origin":"https://service.example.com","methods":["GET"],"paths":["/v1/orders"],"query":{"mode":"none"},"body":{"mode":"empty","max_bytes":0},"signature_profile":"anp-http-v2","grant_limits":{"max_duration_seconds":900,"max_uses":100}})
}
fn apply_change(f: &mut Fixture, change: catalog::CatalogChange) -> Prepared {
    let p =
        f.db.prepare(1002, Change::Catalog { change }, now())
            .unwrap();
    f.db.commit(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    p
}
fn vault_fixture(f: &mut Fixture) -> (String, String, Value) {
    use crate::keystore::{create, hardware::HardwareChoice, layout::KeydLayout};
    let vault = uuid();
    let layout = KeydLayout::at(f.dir.join("vaults").join(&vault));
    layout.ensure().unwrap();
    let spec = crate::did::DidDocumentSpec::new("example.com", vec!["test".into()]);
    let created = create::create(
        &layout,
        &spec,
        "test",
        b"test-pass",
        crate::crypto::kdf::Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        HardwareChoice::None,
    )
    .unwrap();
    let secret = crate::keystore::device::load(&layout).unwrap();
    let key = crate::keystore::unwrap::unlock(&created.wrapped, b"test-pass", &secret).unwrap();
    let doc = crate::did::document::publishable(&spec, &created.did, &key).unwrap();
    crate::keystore::store::write_did_document(&layout, &created.did, &doc).unwrap();
    f.db.connection
        .execute(
            "INSERT INTO vaults VALUES(?1,?2,'active')",
            params![vault, format!("vaults/{vault}")],
        )
        .unwrap();
    (vault, created.did, doc)
}
#[test]
fn catalog_enrollment_never_infers_role_and_root_cannot_become_hot() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, _) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let key = f.db.catalog().unwrap().keys.remove(0);
    assert_eq!(key.role, KeyRole::Unclassified);
    assert!(f.db.check_key(&vault, &did, &key.kid).is_err());
    assert!(f
        .db
        .prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::ConfirmRole {
                    key_id: key.key_id.clone(),
                    role: KeyRole::Hot
                }
            },
            now()
        )
        .is_err());
    apply_change(
        &mut f,
        CatalogChange::ConfirmRole {
            key_id: key.key_id.clone(),
            role: KeyRole::Root,
        },
    );
    f.db.check_key(&vault, &did, &key.kid).unwrap();
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let migrated = f.db.catalog().unwrap().keys.remove(0);
    assert_eq!(migrated.key_id, key.key_id);
    assert_eq!(migrated.role, KeyRole::Unclassified);
    assert!(f.db.check_key(&vault, &did, &key.kid).is_err());
}
#[test]
fn policy_versions_are_immutable_and_unknown_fields_are_rejected() {
    use catalog::*;
    let mut f = Fixture::new();
    let id = uuid();
    apply_change(
        &mut f,
        CatalogChange::PublishPolicy {
            policy_id: id.clone(),
            version: 1,
            content: policy_value(),
        },
    );
    assert!(f
        .db
        .prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::PublishPolicy {
                    policy_id: id.clone(),
                    version: 1,
                    content: policy_value()
                }
            },
            now()
        )
        .is_err());
    let mut unknown = policy_value();
    unknown["unexpected"] = json!(true);
    let mut bad_origin = policy_value();
    bad_origin["origin"] = json!("https://example.com@evil.com");
    let mut query = policy_value();
    query["query"] = json!({"mode":"exact","value":"a=1&a=2"});
    for content in [unknown, bad_origin, query] {
        assert!(f
            .db
            .prepare(
                1002,
                Change::Catalog {
                    change: CatalogChange::PublishPolicy {
                        policy_id: id.clone(),
                        version: 2,
                        content
                    }
                },
                now()
            )
            .is_err());
    }
    apply_change(
        &mut f,
        CatalogChange::PublishPolicy {
            policy_id: id,
            version: 2,
            content: policy_value(),
        },
    );
    assert_eq!(f.db.catalog().unwrap().policies.len(), 2);
    assert!(f.db.connection.execute("DELETE FROM policies", []).is_err());
}
#[test]
fn enrollment_approval_binds_inventory_envelope_and_document() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, _, _) = vault_fixture(&mut f);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::EnrollVault {
                    vault_id: vault.clone(),
                },
            },
            now(),
        )
        .unwrap();
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    let path = layout.list_key_paths().unwrap().remove(0);
    let mut wrapped: crate::keystore::record::WrappedKey =
        serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    wrapped.label = "changed after approval".into();
    crate::keystore::store::write(&layout, &wrapped).unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    assert!(f.db.catalog().unwrap().keys.is_empty());
}
#[test]
fn journal_recovers_after_file_install_and_refuses_unknown_disk_state() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    // Inject failure after installing a different, valid signed document.
    let updated = changed_document(&f, &vault, &did, &doc);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: updated.clone(),
                },
            },
            now(),
        )
        .unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_completion BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%FILE_OPERATION_COMPLETED%' BEGIN SELECT RAISE(ABORT,'crash after rename'); END;").unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    let state: String =
        f.db.connection
            .query_row(
                "SELECT state FROM vaults WHERE vault_id=?1",
                [&vault],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(state, "maintenance");
    f.db.connection
        .execute_batch("DROP TRIGGER fail_completion")
        .unwrap();
    f.db.recovery(&f.config, now()).unwrap();
    let state: String =
        f.db.connection
            .query_row("SELECT state FROM file_operations", [], |r| r.get(0))
            .unwrap();
    assert_eq!(state, "complete");
    // An unknown document is never overwritten to manufacture successful recovery.
    f.db.connection
        .execute("UPDATE file_operations SET state='pending'", [])
        .unwrap();
    let path =
        crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault)).did_path(&did);
    std::fs::write(&path, b"{}").unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"{}");
}
#[test]
fn legacy_commands_reject_managed_vault_even_through_symlink() {
    let f = Fixture::new();
    let nested = f.dir.join("vaults").join(uuid());
    std::fs::create_dir_all(&nested).unwrap();
    assert!(crate::security::paths::deny_managed_directory(&nested).is_err());
    let alias = f.dir.with_extension("alias");
    std::os::unix::fs::symlink(&nested, &alias).unwrap();
    assert!(crate::security::paths::deny_managed_directory(&alias).is_err());
    std::fs::remove_file(alias).unwrap();
}

#[test]
fn v1_migration_is_transactional_and_bound_to_instance_and_audit() {
    let mut f = Fixture::new();
    f.db.connection.execute_batch("DROP TABLE file_operations; ALTER TABLE keys DROP COLUMN document_digest; ALTER TABLE service_meta RENAME TO meta_old; CREATE TABLE service_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL CHECK(schema_version=1),instance_id TEXT NOT NULL,boot_epoch INTEGER NOT NULL,mutation_epoch INTEGER NOT NULL) STRICT; INSERT INTO service_meta SELECT singleton,1,instance_id,boot_epoch,mutation_epoch FROM meta_old; DROP TABLE meta_old; PRAGMA user_version=1;").unwrap();
    let mut foreign = f.config.clone();
    foreign.instance_id = uuid();
    assert!(f.db.recovery(&foreign, now()).is_err());
    let version: i64 =
        f.db.connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
    assert_eq!(version, 1);
    f.db.connection.execute_batch("CREATE TRIGGER fail_migration BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%SCHEMA_MIGRATED%' BEGIN SELECT RAISE(ABORT,'injected migration failure'); END;").unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
    let version: i64 =
        f.db.connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
    assert_eq!(version, 1);
    f.db.connection
        .execute_batch("DROP TRIGGER fail_migration")
        .unwrap();
    f.db.recovery(&f.config, now()).unwrap();
    let version: i64 =
        f.db.connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
    assert_eq!(version, 2);
    verify_audit(&f.db.connection).unwrap();
}

fn changed_document(f: &Fixture, vault: &str, did: &str, doc: &Value) -> Value {
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(vault));
    let wrapped = crate::keystore::store::resolve(&layout, did, None).unwrap();
    let secret = crate::keystore::device::load(&layout).unwrap();
    let key = crate::keystore::unwrap::unlock(&wrapped, b"test-pass", &secret).unwrap();
    let mut unsigned = crate::did::lifecycle::strip_proof(doc).unwrap();
    unsigned["service"] = json!([{"id":format!("{did}#test"),"type":"TestService","serviceEndpoint":"https://example.com/updated"}]);
    let signed = crate::did::document::sign_document(&unsigned, &key, &wrapped.id.kid).unwrap();
    crate::did::document::verify_path_binding(did, &signed).unwrap();
    signed
}
#[test]
fn restart_rolls_forward_durable_intent_before_any_file_write() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, old) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let updated = changed_document(&f, &vault, &did, &old);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: updated.clone(),
                },
            },
            now(),
        )
        .unwrap();
    f.db.commit_intent(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        old
    );
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        updated
    );
    f.db.recovery(&f.config, now()).unwrap();
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        updated
    );
}
#[test]
fn pending_file_journal_cannot_substitute_an_unapproved_signed_document() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, old) = vault_fixture(&mut f);
    let updated = changed_document(&f, &vault, &did, &old);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: old.clone(),
                },
            },
            now(),
        )
        .unwrap();
    f.db.commit_intent(1002, &p.operation_id, &p.digest, now())
        .unwrap();
    let hash = hex(&Sha256::digest(
        serde_json_canonicalizer::to_vec(&updated).unwrap(),
    ));
    f.db.connection
        .execute(
            "UPDATE file_operations SET document=?1,after_digest=?2",
            params![serde_json::to_vec(&updated).unwrap(), hash],
        )
        .unwrap();
    assert!(f.db.recovery(&f.config, now()).is_err());
}

#[test]
fn hot_and_recovery_roles_require_verified_document_relationships() {
    use anp::authentication::DidVerificationRelationship::{AssertionMethod, Authentication};
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    let mut extras = Vec::new();
    for (fragment, relationship) in [
        ("not-a-role-name", Authentication),
        ("arbitrary-fragment", AssertionMethod),
    ] {
        let (_, extra) = crate::keystore::create::create_extra(
            &layout,
            &did,
            fragment,
            vec![relationship],
            "test",
            b"test-pass",
            crate::crypto::kdf::Argon2Config {
                m_cost: 1024,
                t_cost: 1,
                p_cost: 1,
            },
            crate::keystore::hardware::HardwareChoice::None,
        )
        .unwrap();
        extras.push(extra);
    }
    let root = crate::keystore::store::resolve(&layout, &did, None).unwrap();
    let secret = crate::keystore::device::load(&layout).unwrap();
    let key = crate::keystore::unwrap::unlock(&root, b"test-pass", &secret).unwrap();
    // Use the document's original subject/spec; only add explicit public keys.
    let mut unsigned = crate::did::lifecycle::strip_proof(&doc).unwrap();
    for extra in &extras {
        unsigned = crate::did::lifecycle::with_extra_key(
            &unsigned,
            &did,
            &key.verifying_key(),
            extra.clone(),
        )
        .unwrap();
    }
    let signed = crate::did::document::sign_document(&unsigned, &key, &root.id.kid).unwrap();
    crate::keystore::store::write_did_document(&layout, &did, &signed).unwrap();
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    for (fragment, role, wrong) in [
        ("not-a-role-name", KeyRole::Hot, KeyRole::Recovery),
        ("arbitrary-fragment", KeyRole::Recovery, KeyRole::Hot),
    ] {
        let record =
            f.db.catalog()
                .unwrap()
                .keys
                .into_iter()
                .find(|k| k.kid == format!("{did}#{fragment}"))
                .unwrap();
        assert!(f
            .db
            .prepare(
                1002,
                Change::Catalog {
                    change: CatalogChange::ConfirmRole {
                        key_id: record.key_id.clone(),
                        role: wrong
                    }
                },
                now()
            )
            .is_err());
        apply_change(
            &mut f,
            CatalogChange::ConfirmRole {
                key_id: record.key_id,
                role,
            },
        );
        f.db.check_key(&vault, &did, &record.kid).unwrap();
    }
}

#[test]
fn audit_failure_cannot_publish_a_file_or_leave_a_partial_catalog() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, doc) = vault_fixture(&mut f);
    let updated = changed_document(&f, &vault, &did, &doc);
    let p =
        f.db.prepare(
            1002,
            Change::Catalog {
                change: CatalogChange::InstallDocument {
                    vault_id: vault.clone(),
                    document: updated,
                },
            },
            now(),
        )
        .unwrap();
    f.db.connection.execute_batch("CREATE TRIGGER fail_commit BEFORE INSERT ON audit_events WHEN CAST(NEW.event_data AS TEXT) LIKE '%OPERATION_COMMITTED%' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END;").unwrap();
    assert!(f
        .db
        .commit(1002, &p.operation_id, &p.digest, now())
        .is_err());
    let layout = crate::keystore::layout::KeydLayout::at(f.dir.join("vaults").join(&vault));
    assert_eq!(
        crate::keystore::store::read_did_document(&layout, &did).unwrap(),
        doc
    );
    let count: i64 =
        f.db.connection
            .query_row("SELECT count(*) FROM file_operations", [], |r| r.get(0))
            .unwrap();
    assert_eq!(count, 0);
    let state: String =
        f.db.connection
            .query_row("SELECT state FROM vaults WHERE vault_id=?1", [vault], |r| {
                r.get(0)
            })
            .unwrap();
    assert_eq!(state, "active");
}

#[test]
fn unknown_persisted_role_is_refused_even_if_constraints_were_bypassed() {
    use catalog::*;
    let mut f = Fixture::new();
    let (vault, did, _) = vault_fixture(&mut f);
    apply_change(
        &mut f,
        CatalogChange::EnrollVault {
            vault_id: vault.clone(),
        },
    );
    let record = f.db.catalog().unwrap().keys.remove(0);
    f.db.connection
        .execute_batch(
            "PRAGMA ignore_check_constraints=ON; UPDATE keys SET role='future_unknown_role';",
        )
        .unwrap();
    assert!(f.db.check_key(&vault, &did, &record.kid).is_err());
    assert!(f.db.catalog().is_err());
}
