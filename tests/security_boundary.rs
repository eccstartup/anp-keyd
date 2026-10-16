//! Explicit fixture generator for the disposable Linux multi-UID harness.
//! Never runs in the normal test suite or against real user identities.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "run only inside deploy/linux/test-container.sh"]
fn disposable_linux_fixture() {
    use anp_keyd::crypto::kdf::Argon2Config;
    use anp_keyd::did::document::{self, DidDocumentSpec};
    use anp_keyd::keystore::hardware::HardwareChoice;
    use anp_keyd::keystore::layout::KeydLayout;
    use anp_keyd::keystore::{create, device, store, unwrap};
    assert_eq!(
        std::env::var("ANP_KEYD_DISPOSABLE_LINUX_TEST").as_deref(),
        Ok("1")
    );
    assert_eq!(nix::unistd::geteuid().as_raw(), 0);
    let path = std::path::PathBuf::from("/tmp/keyd-boundary-fixture");
    assert!(!path.exists(), "fixture must be newly generated");
    let layout = KeydLayout::at(path);
    layout.ensure().unwrap();
    let spec = DidDocumentSpec::new("example.com", vec!["boundary-test".into()]);
    let pass = b"temporary-boundary-test-secret";
    let created = create::create(
        &layout,
        &spec,
        "disposable",
        pass,
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        HardwareChoice::None,
    )
    .unwrap();
    let wrapped = store::load(&layout, &created.wrapped.id.thumbprint).unwrap();
    let key = unwrap::unlock(&wrapped, pass, &device::load(&layout).unwrap()).unwrap();
    let doc = document::publishable(&spec, &created.did, &key).unwrap();
    let (_, extra) = create::create_extra(
        &layout,
        &created.did,
        "http-hot",
        vec![anp::authentication::DidVerificationRelationship::Authentication],
        "disposable-hot",
        pass,
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        HardwareChoice::None,
    )
    .unwrap();
    let mut unsigned = anp_keyd::did::lifecycle::strip_proof(&doc).unwrap();
    unsigned["service"] = serde_json::json!([{"id":format!("{}#anp",created.did),"type":"ANPMessageService","serviceEndpoint":"https://example.com/anp-im/rpc","serviceDid":"did:wba:example.com"}]);
    let unsigned = anp_keyd::did::lifecycle::with_extra_key(
        &unsigned,
        &created.did,
        &key.verifying_key(),
        extra,
    )
    .unwrap();
    let (_, next) = create::create_extra(
        &layout,
        &created.did,
        "http-next",
        vec![anp::authentication::DidVerificationRelationship::Authentication],
        "disposable-next",
        pass,
        Argon2Config {
            m_cost: 1024,
            t_cost: 1,
            p_cost: 1,
        },
        HardwareChoice::None,
    )
    .unwrap();
    let unsigned = anp_keyd::did::lifecycle::with_extra_key(
        &unsigned,
        &created.did,
        &key.verifying_key(),
        next,
    )
    .unwrap();
    let doc = document::sign_document(&unsigned, &key, &wrapped.id.kid).unwrap();
    store::write_did_document(&layout, &created.did, &doc).unwrap();
    std::fs::write(
        "/tmp/keyd-boundary-fixture-info.json",
        serde_json::to_vec(&serde_json::json!({
            "did": created.did, "kid": wrapped.id.kid,
        }))
        .unwrap(),
    )
    .unwrap();
}
