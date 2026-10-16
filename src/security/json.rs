//! Reject duplicate members even inside dynamically typed public documents.
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::Value;
use std::fmt;
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        d.deserialize_any(JsonVisitor).map(Unique)
    }
}
struct JsonVisitor;
impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unambiguous JSON")
    }
    fn visit_unit<E: de::Error>(self) -> std::result::Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Value, E> {
        Ok(v.into())
    }
    fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Value, E> {
        Ok(Value::String(v.into()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = Vec::new();
        while let Some(Unique(v)) = a.next_element()? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> std::result::Result<Value, A::Error> {
        let mut out = serde_json::Map::new();
        while let Some((key, Unique(v))) = a.next_entry::<String, Unique>()? {
            if out.insert(key, v).is_some() {
                return Err(de::Error::custom("duplicate member"));
            }
        }
        Ok(Value::Object(out))
    }
}
pub fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> crate::Result<T> {
    let value: Unique = serde_json::from_slice(bytes)
        .map_err(|_| crate::KeydError::Protocol("malformed protected request".into()))?;
    serde_json::from_value(value.0)
        .map_err(|_| crate::KeydError::Protocol("malformed protected request".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_members_are_rejected_at_every_depth() {
        for bytes in [
            br#"{"a":1,"a":2}"#.as_slice(),
            br#"{"document":{"proof":{"created":"a","created":"b"}}}"#.as_slice(),
            br#"[{"role":"root","role":"hot"}]"#.as_slice(),
        ] {
            assert!(decode::<Value>(bytes).is_err());
        }
        let value: Value =
            decode(br#"{"policy":{"schema_version":1},"keys":[true,null,2,"x"]}"#).unwrap();
        assert_eq!(value["policy"]["schema_version"], 1);
    }
}
