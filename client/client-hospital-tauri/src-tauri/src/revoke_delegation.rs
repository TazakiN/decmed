use std::str::FromStr;

use anyhow::Context;
use iota_types::base_types::IotaAddress;
use serde::{Deserialize, Serialize};
use tauri::{async_runtime::Mutex, command, State};
use tauri_plugin_http::reqwest;

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    hospital_error::HospitalError,
    types::{
        AppState, MoveHospitalPersonnelAccessType, PatientDelegationAuditInput, ResponseStatus,
        SuccessResponse,
    },
    utils::{
        encode_activation_key_from_keys_entry, get_iota_address_from_keys_entry,
        get_iota_key_pair_from_keys_entry, parse_keys_entry,
    },
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeDelegatedAccessPayload {
    pub access_token: String,
    pub delegatee_iota_address: String,
    pub patient_iota_address: String,
    pub purpose: String,
    pub delegated_by: String,
    pub delegated_to: String,
    pub access_type: String,
    #[serde(default)]
    pub related_rme_id: Option<String>,
    #[serde(default)]
    pub token_hash: Option<String>,
    #[serde(default)]
    pub expires_before: Option<String>,
    #[serde(default)]
    pub root_subject: Option<String>,
    #[serde(default)]
    pub parent_token_hash: Option<String>,
    #[serde(default)]
    pub delegation_depth: Option<u8>,
}

fn parse_expires_at_ms(value: Option<&str>) -> Result<Option<u64>, HospitalError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e).context(current_fn!())))?
        .with_timezone(&chrono::Utc);
    let millis = parsed.timestamp_millis();
    if millis < 0 {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("Delegation expiry is before Unix epoch").context(current_fn!()),
        ));
    }
    Ok(Some(millis as u64))
}

fn build_audit_input(
    payload: &RevokeDelegatedAccessPayload,
    access_type: MoveHospitalPersonnelAccessType,
) -> Result<PatientDelegationAuditInput, HospitalError> {
    let root_subject = payload
        .root_subject
        .as_deref()
        .unwrap_or(&payload.delegated_by);
    Ok(PatientDelegationAuditInput {
        root_subject: IotaAddress::from_str(root_subject).context(current_fn!())?,
        access_type,
        related_rme_id: payload.related_rme_id.clone(),
        delegation_depth: payload.delegation_depth.unwrap_or(1),
        token_hash: payload.token_hash.clone(),
        parent_token_hash: payload.parent_token_hash.clone(),
        expires_at_ms: parse_expires_at_ms(payload.expires_before.as_deref())?,
    })
}

#[command]
pub async fn revoke_delegated_access(
    state: State<'_, Mutex<AppState>>,
    payload: RevokeDelegatedAccessPayload,
) -> Result<SuccessResponse<()>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let pin = state.auth_state.session_pin.clone().ok_or_else(|| {
        HospitalError::Anyhow(anyhow::anyhow!("Session PIN not found").context(current_fn!()))
    })?;

    let activation_key =
        encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
    let delegator_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
    let delegator_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;

    let delegatee_address =
        IotaAddress::from_str(&payload.delegatee_iota_address).context(current_fn!())?;
    let patient_address =
        IotaAddress::from_str(&payload.patient_iota_address).context(current_fn!())?;
    let audit_metadata = match payload.access_type.as_str() {
        "Read" => vec![build_audit_input(
            &payload,
            MoveHospitalPersonnelAccessType::Read,
        )?],
        "Update" => vec![build_audit_input(
            &payload,
            MoveHospitalPersonnelAccessType::Update,
        )?],
        "Read,Update" => vec![
            build_audit_input(&payload, MoveHospitalPersonnelAccessType::Read)?,
            build_audit_input(&payload, MoveHospitalPersonnelAccessType::Update)?,
        ],
        _ => {
            return Err(HospitalError::Anyhow(
                anyhow::anyhow!("Invalid access type").context(current_fn!()),
            ))
        }
    };

    // Step 1: Execute Move revoke_delegated_access
    let tx_digest = state
        .move_call
        .revoke_delegated_access(
            activation_key,
            delegatee_address,
            patient_address,
            payload.access_type,
            payload.related_rme_id.clone(),
            audit_metadata,
            delegator_iota_address,
            delegator_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    // Step 2: Notify proxy about the revocation
    let req_client = reqwest::Client::new();
    let proxy_url = format!("{}/revocations/delegation", PROXY_BASE_URL);
    let proxy_body = serde_json::json!({
        "patient_address": payload.patient_iota_address,
        "purpose": payload.purpose,
        "delegated_by": payload.delegated_by,
        "delegated_to": payload.delegated_to,
        "related_rme_id": payload.related_rme_id,
        "token_hash": payload.token_hash,
        "expires_before": payload.expires_before,
        "tx_digest": tx_digest,
    });

    let proxy_resp = req_client
        .post(&proxy_url)
        .bearer_auth(&payload.access_token)
        .json(&proxy_body)
        .send()
        .await
        .context(current_fn!())?;

    let proxy_status = proxy_resp.status();
    if !proxy_status.is_success() {
        let err_text = proxy_resp.text().await.unwrap_or_default();
        eprintln!("Proxy revocation warning: {proxy_status} {err_text}");
        // Non-fatal - on-chain revoke already succeeded
    }

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}
