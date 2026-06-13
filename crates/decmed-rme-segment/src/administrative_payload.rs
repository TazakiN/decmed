use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::SegmentValidationError;

/// Off-chain payload for `ADMINISTRATIVE_GENERAL` segments (snake_case JSON).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AdministrativeGeneralPayload {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub birth_place: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_of_birth: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub religion: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub education: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub occupation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub marital_status: Option<String>,
}

impl AdministrativeGeneralPayload {
    pub fn validate(&self) -> Result<(), SegmentValidationError> {
        if self.id.trim().is_empty() {
            return Err(SegmentValidationError::InvalidAdministrativePayload(
                "id must not be empty".into(),
            ));
        }
        Ok(())
    }

    pub fn to_payload_value(&self) -> Value {
        serde_json::to_value(self).expect("AdministrativeGeneralPayload serializes to JSON")
    }
}

pub fn administrative_general_payload_from_value(
    value: &Value,
) -> Result<AdministrativeGeneralPayload, SegmentValidationError> {
    let payload: AdministrativeGeneralPayload =
        serde_json::from_value(value.clone()).map_err(|e| {
            SegmentValidationError::InvalidAdministrativePayload(e.to_string())
        })?;
    payload.validate()?;
    Ok(payload)
}

pub fn administrative_general_payload_from_fields(
    id: String,
    name: Option<String>,
    birth_place: Option<String>,
    date_of_birth: Option<String>,
    gender: Option<String>,
    religion: Option<String>,
    education: Option<String>,
    occupation: Option<String>,
    marital_status: Option<String>,
) -> Result<Value, SegmentValidationError> {
    let payload = AdministrativeGeneralPayload {
        id,
        name,
        birth_place,
        date_of_birth,
        gender,
        religion,
        education,
        occupation,
        marital_status,
    };
    payload.validate()?;
    Ok(payload.to_payload_value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rejects_empty_id() {
        let value = json!({ "id": "  " });
        assert!(administrative_general_payload_from_value(&value).is_err());
    }

    #[test]
    fn round_trips_payload() {
        let value = json!({
            "id": "3201010101010001",
            "name": "Pasien Test"
        });
        let parsed = administrative_general_payload_from_value(&value).unwrap();
        assert_eq!(parsed.id, "3201010101010001");
        assert_eq!(parsed.name.as_deref(), Some("Pasien Test"));
    }
}
