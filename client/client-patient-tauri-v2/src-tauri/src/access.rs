use std::str::FromStr;

use anyhow::{anyhow, Context};
use iota_types::{
    base_types::IotaAddress,
    crypto::{EncodeDecodeBase64, Signature},
};
use serde::Serialize;
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, State};
use tauri_plugin_http::reqwest;

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    patient_error::PatientError,
    types::{
        AppState, CommandGetAccessLogResponse, HospitalPersonnelPublicAdministrativeData,
        MovePatientAccessLog, ResponseStatus, SuccessResponse,
    },
    utils::{
        get_iota_address_from_keys_entry, get_iota_key_pair_from_keys_entry, parse_keys_entry,
        serde_deserialize_from_base64,
    },
};

#[derive(Serialize)]
struct PatientRevocationSignedPayload {
    patient_address: String,
    purpose: String,
    root_subject: String,
    token_hash: Option<String>,
    expires_before: Option<String>,
    tx_digest: String,
}

#[tauri::command]
pub async fn get_access_log(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<CommandGetAccessLogResponse>>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let patient_iota_address = {
        let patient_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;

        patient_iota_address
    };

    let access_log: Vec<MovePatientAccessLog> = state
        .move_call
        .get_access_log(0, 10, patient_iota_address)
        .await
        .context(current_fn!())?;

    let access_log = access_log
        .into_iter()
        .map(|metadata| {
            let hospital_personnel_metadata: HospitalPersonnelPublicAdministrativeData =
                serde_deserialize_from_base64(metadata.hospital_personnel_metadata)
                    .context(current_fn!())?;

            Ok(CommandGetAccessLogResponse {
                access_data_type: metadata.access_data_type,
                access_type: metadata.access_type,
                date: metadata.date,
                exp_dur: metadata.exp_dur,
                hospital_metadata: metadata.hospital_metadata,
                hospital_personnel_address: metadata.hospital_personnel_address.to_string(),
                hospital_personnel_metadata,
                index: metadata.index,
                is_revoked: metadata.is_revoked,
                is_delegated: metadata.is_delegated,
                delegated_by_address: metadata
                    .delegated_by_address
                    .map(|address| address.to_string()),
                token_hash: metadata.token_hash,
            })
        })
        .collect::<Result<Vec<CommandGetAccessLogResponse>, PatientError>>()?;

    Ok(SuccessResponse {
        data: access_log,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn revoke_access(
    state: State<'_, Mutex<AppState>>,
    hospital_personnel_address: String,
    index: u64,
    purpose: String,
    root_subject: String,
    token_hash: Option<String>,
    expires_before: Option<String>,
) -> Result<SuccessResponse<()>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let pin = state
        .auth_state
        .session_pin
        .clone()
        .ok_or(anyhow!("Session PIN Not found"))
        .context(current_fn!())?;
    let patient_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
    let patient_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
    let hospital_personnel_address =
        IotaAddress::from_str(&hospital_personnel_address).context(current_fn!())?;

    // Execute the Move revoke
    let tx_digest = state
        .move_call
        .revoke_access(
            hospital_personnel_address,
            index,
            patient_iota_address,
            patient_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    // Call proxy revocation endpoint after successful Move transaction
    let req_client = reqwest::Client::new();
    let proxy_url = format!("{}/revocations/patient", PROXY_BASE_URL);

    // Re-read key pair to sign the tx_digest for proxy
    let patient_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

    let signed_payload = PatientRevocationSignedPayload {
        patient_address: patient_iota_address.to_string(),
        purpose,
        root_subject,
        token_hash,
        expires_before,
        tx_digest,
    };
    let canonical = serde_json::to_string(&signed_payload).context(current_fn!())?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let signature = Signature::new_secure(&intent_message, &patient_iota_key_pair);
    let signature_b64 = signature.encode_base64();

    let proxy_body = serde_json::json!({
        "patient_address": signed_payload.patient_address,
        "purpose": signed_payload.purpose,
        "root_subject": signed_payload.root_subject,
        "token_hash": signed_payload.token_hash,
        "expires_before": signed_payload.expires_before,
        "tx_digest": signed_payload.tx_digest,
        "signature": signature_b64,
    });

    let proxy_resp = req_client
        .post(&proxy_url)
        .json(&proxy_body)
        .send()
        .await
        .context(current_fn!())?;

    let proxy_status = proxy_resp.status();
    if !proxy_status.is_success() {
        let err_text = proxy_resp.text().await.unwrap_or_default();
        eprintln!("Proxy revocation warning: {proxy_status} {err_text}");
    }

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}
