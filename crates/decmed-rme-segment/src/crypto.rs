use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::SegmentValidationError;

pub fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("string serialization failed"),
        Value::Array(values) => {
            let values = values.iter().map(canonical_json).collect::<Vec<_>>();
            format!("[{}]", values.join(","))
        }
        Value::Object(map) => {
            let mut entries = map.iter().collect::<Vec<_>>();
            entries.sort_by(|(left, _), (right, _)| left.cmp(right));

            let entries = entries
                .into_iter()
                .map(|(key, value)| {
                    let key = serde_json::to_string(key).expect("object key serialization failed");
                    format!("{key}:{}", canonical_json(value))
                })
                .collect::<Vec<_>>();

            format!("{{{}}}", entries.join(","))
        }
    }
}

pub fn payload_hash(payload: &Value) -> String {
    sha256_hex(canonical_json(payload).as_bytes())
}

pub fn sha256_hex(data: impl AsRef<[u8]>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_ref());
    hex_lower(&hasher.finalize())
}

pub fn ciphertext_integrity_hash_from_base64(
    enc_data: &str,
) -> Result<String, SegmentValidationError> {
    let ciphertext = STANDARD
        .decode(enc_data)
        .map_err(|_| SegmentValidationError::InvalidCiphertext)?;

    Ok(sha256_hex(ciphertext))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}
