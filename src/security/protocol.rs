//! Versioned, bounded JSON protocol. Data requests have no password operation.
use crate::error::{KeydError, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use zeroize::Zeroizing;

pub const VERSION: u32 = 2;
pub const MAX_FRAME: usize = 65_536;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    pub version: u32,
    pub request: T,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum DataRequest {
    #[serde(rename = "GET_CAPABILITIES")]
    Capabilities {},
    #[serde(rename = "LIST_AUTHORIZED_KEYS")]
    ListAuthorizedKeys {},
    #[serde(rename = "GET_GRANT_STATUS")]
    GrantStatus { grant_id: String },
    #[serde(rename = "GET_DOCUMENT")]
    Document { key_id: String },
    #[serde(rename = "SIGN_HTTP")]
    SignHttp {
        grant_id: String,
        request_id: String,
        http: super::http::HttpRequest,
    },
    #[serde(rename = "GET_REQUEST_STATUS")]
    RequestStatus { request_id: String },
}

// Deliberately no Debug implementation: even malformed admin inputs are secret.
#[derive(Deserialize, Serialize)]
#[serde(tag = "operation", deny_unknown_fields)]
pub enum AdminRequest {
    #[serde(rename = "COMPLETE_SECRET_OPERATION")]
    CompleteSecretOperation {
        operation_id: String,
        digest: String,
    },
    #[serde(rename = "GET_CAPABILITIES")]
    Capabilities {},
    #[serde(rename = "LIST_PRINCIPALS")]
    ListPrincipals {},
    #[serde(rename = "GET_CATALOG")]
    Catalog {},
    #[serde(rename = "PREPARE_OPERATION")]
    Prepare { change: crate::persistence::Change },
    #[serde(rename = "COMMIT_OPERATION")]
    Commit {
        operation_id: String,
        digest: String,
    },
    #[serde(rename = "LOCK_ALL")]
    LockAll {},
    #[serde(rename = "UNLOCK_KEY")]
    Unlock {
        vault_id: String,
        did: String,
        kid: String,
    },
}

// Passwords occupy a separate bounded binary frame, only after an authenticated
// management UNLOCK_KEY header. JSON escape/parser scratch buffers never see them.
pub fn read_secret<R: Read>(reader: &mut R) -> Result<Zeroizing<String>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(KeydError::Protocol("invalid credential frame size".into()));
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut bytes)?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| KeydError::Protocol("invalid credential encoding".into()))?;
    Ok(Zeroizing::new(text.to_owned()))
}

pub fn write_secret<W: Write>(writer: &mut W, secret: &str) -> Result<()> {
    if secret.is_empty() || secret.len() > MAX_FRAME {
        return Err(KeydError::Protocol("invalid credential frame size".into()));
    }
    writer.write_all(&(secret.len() as u32).to_be_bytes())?;
    writer.write_all(secret.as_bytes())?;
    writer.flush()?;
    Ok(())
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub version: u32,
    pub code: String,
    pub instance_id: Option<String>,
    pub principal_id: Option<String>,
    pub signing_available: bool,
    pub protected_supported: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared: Option<crate::persistence::Prepared>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_epoch: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principals: Option<Vec<crate::principal::Principal>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<crate::persistence::catalog::Catalog>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}
impl Reply {
    pub fn code(code: &str) -> Self {
        Self {
            version: VERSION,
            code: code.into(),
            instance_id: None,
            principal_id: None,
            signing_available: false,
            protected_supported: false,
            prepared: None,
            boot_epoch: None,
            principals: None,
            catalog: None,
            data: None,
        }
    }
}

pub fn read<R: Read, T: serde::de::DeserializeOwned>(reader: &mut R) -> Result<T> {
    let mut header = [0; 4];
    reader.read_exact(&mut header)?;
    let len = u32::from_be_bytes(header) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(KeydError::Protocol("invalid protected frame size".into()));
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    reader.read_exact(&mut bytes)?;
    // serde error messages can contain attacker supplied values, including passwords.
    super::json::decode(&bytes)
}

pub fn write<W: Write, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    // Fixed capacity avoids leaving prior allocations of plaintext after realloc.
    let mut bytes = Zeroizing::new(vec![0; MAX_FRAME]);
    let mut buffer = std::io::Cursor::new(&mut bytes[..]);
    serde_json::to_writer(&mut buffer, value).map_err(|_| {
        KeydError::Protocol("protected frame exceeds limit or cannot be encoded".into())
    })?;
    let len = buffer.position() as usize;
    writer.write_all(&(len as u32).to_be_bytes())?;
    writer.write_all(&bytes[..len])?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse<T: serde::de::DeserializeOwned>(text: &str) -> Result<T> {
        let mut frame = (text.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(text.as_bytes());
        read(&mut &frame[..])
    }
    #[test]
    fn binary_secret_round_trips_arbitrary_utf8_without_json_escaping() {
        let password = Zeroizing::new("spaces \" \\ \n \0 密码".to_string());
        let mut frame = Zeroizing::new(Vec::new());
        write_secret(&mut *frame, &password).unwrap();
        assert_eq!(*read_secret(&mut &frame[..]).unwrap(), *password);
        assert!(read_secret(&mut &[0, 0, 0, 0][..]).is_err());
        assert!(read_secret(&mut &[0, 0, 0, 2, 0xff, 0xff][..]).is_err());
        assert!(read::<_, Envelope<DataRequest>>(&mut &(u32::MAX.to_be_bytes())[..]).is_err());
    }

    #[test]
    fn data_rejects_password_operations_duplicates_unknown_fields_and_v1() {
        for request in [
            r#"{"version":2,"request":{"operation":"UNLOCK_KEY","passphrase":"secret"}}"#,
            r#"{"version":2,"version":2,"request":{"operation":"GET_CAPABILITIES"}}"#,
            r#"{"version":2,"request":{"operation":"GET_CAPABILITIES","passphrase":"secret"}}"#,
            r#"{"version":4294967296,"request":{"operation":"GET_CAPABILITIES"}}"#,
        ] {
            let error = parse::<Envelope<DataRequest>>(request).unwrap_err();
            assert!(!error.to_string().contains("secret"));
        }
        assert!(read::<_, Envelope<DataRequest>>(&mut &[0, 0, 0, 1, 3][..]).is_err());
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;
    #[test]
    fn structured_data_requires_body_state_and_forbids_key_or_profile_override() {
        let base = serde_json::json!({"version":2,"request":{"operation":"SIGN_HTTP","grant_id":"g","request_id":"r","http":{"method":"POST","url":"https://example.com/x","headers":{},"body":{"state":"present","bytes":[]},"nonce":null}}});
        let decode = |v: &serde_json::Value| {
            let payload = serde_json::to_vec(v).unwrap();
            let mut frame = (payload.len() as u32).to_be_bytes().to_vec();
            frame.extend(payload);
            read::<_, Envelope<DataRequest>>(&mut &frame[..])
        };
        assert!(decode(&base).is_ok());
        for field in [
            "did",
            "kid",
            "key_id",
            "covered",
            "passphrase",
            "signature_profile",
        ] {
            let mut bad = base.clone();
            bad["request"][field] = serde_json::json!("override");
            assert!(decode(&bad).is_err(), "{field}");
        }
        let mut bad = base.clone();
        bad["request"]["http"]
            .as_object_mut()
            .unwrap()
            .remove("body");
        assert!(decode(&bad).is_err());
        let mut bad = base.clone();
        bad["request"]["http"]["body"] = serde_json::json!({"state":"absent","bytes":[]});
        assert!(decode(&bad).is_err());
        let mut bad = base.clone();
        bad["request"]["http"]["body"]["bytes"] = serde_json::json!([256]);
        assert!(decode(&bad).is_err());
    }
}
