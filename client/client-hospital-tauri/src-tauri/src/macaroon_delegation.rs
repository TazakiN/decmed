use decmed_macaroon_auth::{attenuate_macaroon, DelegationAttenuationParams};
use serde::{Deserialize, Serialize};
use tauri::command;

use crate::hospital_error::HospitalError;

#[derive(Debug, Deserialize, Serialize)]
pub struct DelegateMacaroonPayload {
    pub parent_token: String,
    pub delegated_by: String,
    pub delegated_to: String,
    pub read_datasets: Vec<String>,
    pub write_datasets: Vec<String>,
    pub read_functions: Vec<String>,
    pub write_functions: Vec<String>,
    pub expires_before: String,
    pub max_delegation_depth: u32,
    #[serde(default)]
    pub related_rme_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DelegateMacaroonResponse {
    pub delegated_token: String,
}

/// Locally attenuate a parent macaroon for delegation (no PRE root key required).
#[command]
pub fn delegate_macaroon(
    payload: DelegateMacaroonPayload,
) -> Result<DelegateMacaroonResponse, HospitalError> {
    use decmed_rme_segment::{DatasetCategory, FunctionCategory};

    let parse_datasets = |values: &[String]| -> Result<Vec<DatasetCategory>, HospitalError> {
        values
            .iter()
            .map(|v| {
                serde_json::from_str(&format!("\"{v}\""))
                    .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e)))
            })
            .collect()
    };
    let parse_functions = |values: &[String]| -> Result<Vec<FunctionCategory>, HospitalError> {
        values
            .iter()
            .map(|v| {
                serde_json::from_str(&format!("\"{v}\""))
                    .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e)))
            })
            .collect()
    };

    let expires_before = chrono::DateTime::parse_from_rfc3339(&payload.expires_before)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_timezone(&chrono::Utc);
    if expires_before <= chrono::Utc::now() {
        return Err(HospitalError::Anyhow(anyhow::anyhow!(
            "Delegation expiry must be in the future"
        )));
    }
    let write_functions = parse_functions(&payload.write_functions)?;
    if write_functions.contains(&FunctionCategory::ADMINISTRATIVE_GENERAL) {
        return Err(HospitalError::Anyhow(anyhow::anyhow!(
            "ADMINISTRATIVE_GENERAL cannot be delegated with write/update access"
        )));
    }

    let params = DelegationAttenuationParams {
        delegated_by: payload.delegated_by,
        delegated_to: payload.delegated_to,
        read_datasets: parse_datasets(&payload.read_datasets)?,
        write_datasets: parse_datasets(&payload.write_datasets)?,
        read_functions: parse_functions(&payload.read_functions)?,
        write_functions,
        expires_before,
        max_delegation_depth: payload.max_delegation_depth,
        related_rme_id: payload.related_rme_id,
    };

    let delegated_token = attenuate_macaroon(&payload.parent_token, &params)
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(DelegateMacaroonResponse { delegated_token })
}
