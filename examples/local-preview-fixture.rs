//! Disposable fixture / independent upstream verifier for local acceptance only.
//! Fixed public test password and reduced KDF parameters: NEVER use real identities.
use std::path::PathBuf;
fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("generate") => {
            let path = PathBuf::from(args.next().expect("new fixture directory"));
            assert!(args.next().is_none());
            generate(path);
        }
        Some("verify") => {
            use std::collections::BTreeMap;
            use std::io::Read;
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(65_537)
                .read_to_end(&mut bytes)
                .unwrap();
            assert!(bytes.len() <= 65_536);
            let input: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let headers: BTreeMap<String, String> =
                serde_json::from_value(input["headers"].clone()).unwrap();
            anp::authentication::verify_http_message_signature(
                &input["document"],
                "GET",
                input["url"].as_str().unwrap(),
                &headers,
                None,
            )
            .expect("independent upstream verification failed");
            println!("VERIFIED");
        }
        _ => panic!("expected generate NEW_DIRECTORY or verify with public JSON stdin"),
    }
}
fn generate(path: PathBuf) {
    use anp_keyd::crypto::kdf::Argon2Config;
    use anp_keyd::did::document::{self, DidDocumentSpec};
    use anp_keyd::keystore::hardware::HardwareChoice;
    use anp_keyd::keystore::layout::KeydLayout;
    use anp_keyd::keystore::{create, device, store, unwrap};
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
    println!(
        "{}",
        serde_json::json!({"did":created.did,"kid":wrapped.id.kid,"document":doc})
    );
}
