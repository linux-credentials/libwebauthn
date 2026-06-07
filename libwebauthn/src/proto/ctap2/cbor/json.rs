//! JSON-safe conversion of arbitrary CBOR values.
//!
//! Used to surface authenticator-provided maps that have no typed model, such
//! as the getAssertion `unsignedExtensionOutputs` map (response member 0x08),
//! into WebAuthn client extension results. Per the WebAuthn JSON convention,
//! binary (CBOR byte string) values are encoded as base64url.

use std::collections::BTreeMap;

use serde_json::{Map, Number, Value as Json};

use super::Value;

/// Converts a CBOR map into a JSON object, dropping entries whose key cannot be
/// represented as a JSON string.
pub(crate) fn map_to_json_object(map: &BTreeMap<Value, Value>) -> Map<String, Json> {
    map.iter()
        .filter_map(|(k, v)| key_to_string(k).map(|k| (k, value_to_json(v))))
        .collect()
}

/// Converts an arbitrary CBOR value into a JSON-safe value.
fn value_to_json(value: &Value) -> Json {
    match value {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Integer(i) => integer_to_json(*i),
        Value::Float(f) => Number::from_f64(*f).map(Json::Number).unwrap_or(Json::Null),
        Value::Bytes(b) => Json::String(base64_url::encode(b)),
        Value::Text(s) => Json::String(s.clone()),
        Value::Array(items) => Json::Array(items.iter().map(value_to_json).collect()),
        Value::Map(m) => Json::Object(map_to_json_object(m)),
        // Tags carry no WebAuthn meaning here; surface the tagged value itself.
        Value::Tag(_, inner) => value_to_json(inner),
        // Non-exhaustive enum: anything else has no JSON representation.
        _ => Json::Null,
    }
}

/// CBOR integers span -2^64..2^64-1, wider than any single JSON number type.
/// Map what fits into `i64`/`u64`; fall back to a decimal string otherwise.
fn integer_to_json(i: i128) -> Json {
    if let Ok(n) = i64::try_from(i) {
        Json::Number(n.into())
    } else if let Ok(n) = u64::try_from(i) {
        Json::Number(n.into())
    } else {
        Json::String(i.to_string())
    }
}

/// JSON object keys must be strings. Extension output maps use text keys; other
/// scalar key types are stringified best-effort, and unsupported keys are
/// dropped by the caller.
fn key_to_string(key: &Value) -> Option<String> {
    match key {
        Value::Text(s) => Some(s.clone()),
        Value::Integer(i) => Some(i.to_string()),
        Value::Bytes(b) => Some(base64_url::encode(b)),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_round_trip() {
        assert_eq!(value_to_json(&Value::Bool(true)), Json::Bool(true));
        assert_eq!(value_to_json(&Value::Null), Json::Null);
        assert_eq!(value_to_json(&Value::Text("hi".into())), Json::from("hi"));
        assert_eq!(value_to_json(&Value::Integer(42)), Json::from(42));
        assert_eq!(value_to_json(&Value::Integer(-7)), Json::from(-7));
    }

    #[test]
    fn bytes_become_base64url() {
        let value = Value::Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            value_to_json(&value),
            Json::from(base64_url::encode(&[0xDE, 0xAD, 0xBE, 0xEF]))
        );
    }

    #[test]
    fn nested_array_and_map() {
        let mut inner = BTreeMap::new();
        inner.insert(Value::Text("blob".into()), Value::Bytes(vec![0x01, 0x02]));
        let value = Value::Array(vec![Value::Integer(1), Value::Map(inner)]);

        let json = value_to_json(&value);
        let arr = json.as_array().unwrap();
        assert_eq!(arr[0], Json::from(1));
        assert_eq!(
            arr[1]["blob"],
            Json::from(base64_url::encode(&[0x01, 0x02]))
        );
    }

    #[test]
    fn tag_surfaces_inner_value() {
        let value = Value::Tag(42, Box::new(Value::Text("tagged".into())));
        assert_eq!(value_to_json(&value), Json::from("tagged"));
    }

    #[test]
    fn out_of_range_integer_becomes_string() {
        let big = i128::from(u64::MAX) + 1;
        assert_eq!(
            value_to_json(&Value::Integer(big)),
            Json::from(big.to_string())
        );
    }

    #[test]
    fn non_finite_float_becomes_null() {
        assert_eq!(value_to_json(&Value::Float(f64::NAN)), Json::Null);
        assert_eq!(value_to_json(&Value::Float(1.5)), Json::from(1.5));
    }

    #[test]
    fn non_string_keys_are_dropped() {
        let mut map = BTreeMap::new();
        map.insert(Value::Text("ok".into()), Value::Bool(true));
        map.insert(Value::Array(vec![Value::Integer(1)]), Value::Bool(false));

        let object = map_to_json_object(&map);
        assert_eq!(object.len(), 1);
        assert_eq!(object["ok"], Json::Bool(true));
    }
}
