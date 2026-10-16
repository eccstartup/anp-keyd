//! Kernel UIDs map to installation-local principals, never caller-supplied labels.
use serde::{Deserialize, Serialize};

use crate::error::{KeydError, Result};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub principal_id: String,
    pub uid: u32,
    pub generation: u32,
    pub enabled: bool,
}

pub fn validate_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(&c)
            }
        })
}

/// Resolve an initialization snapshot only. Protected request admission uses SQLite.
pub fn resolve(principals: &[Principal], uid: u32) -> Result<&Principal> {
    principals
        .iter()
        .find(|p| p.uid == uid && p.enabled)
        .ok_or_else(|| KeydError::Permission("principal disabled or unregistered".into()))
}
