use anyhow::{anyhow, Context};
use serde_json::{json, Value};
use tauri::{async_runtime::Mutex, State};
use tauri_plugin_http::reqwest;
use umbral_pre::decrypt_original;

use crate::{
    administrative_fetch::fetch_patient_administrative_data,
    current_fn,
    hospital_error::HospitalError,
    types::{
        AccessData, AccessMetadata, AccessMetadataEncrypted, AppState, ResponseStatus,
        SuccessResponse,
    },
    utils::{
        encode_activation_key_from_keys_entry, get_iota_address_from_keys_entry,
        get_iota_key_pair_from_keys_entry, get_pre_keys_from_keys_entry, parse_keys_entry,
        serde_deserialize_from_base64,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[tauri::command]
pub async fn get_administrative_data(
    state: State<'_, Mutex<AppState>>,
    access_token: String,
    patient_iota_address: String,
) -> Result<SuccessResponse<Value>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;
    let req_client = reqwest::Client::new();

    let pin = state
        .auth_state
        .session_pin
        .clone()
        .ok_or(anyhow!("Session PIN not found"))?;

    let administrative_data = fetch_patient_administrative_data(
        &access_token,
        &patient_iota_address,
        &keys_entry,
        &pin,
        &req_client,
    )
    .await
    .context(current_fn!())?;

    let res_data = json!({
        "administrativeData": administrative_data
    });

    Ok(SuccessResponse {
        data: res_data,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn get_read_access_administrative_personnel(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<AccessData>>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (
        activation_key,
        administrative_personnel_iota_address,
        administrative_personnel_iota_key_pair,
        administrative_personnel_pre_secret_key,
    ) = {
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found on auth state").context(current_fn!()))?;
        let activation_key =
            encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
        let administrative_personnel_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let administrative_personnel_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let (administrative_personnel_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (
            activation_key,
            administrative_personnel_iota_address,
            administrative_personnel_iota_key_pair,
            administrative_personnel_pre_secret_key,
        )
    };

    // do cleanup
    let _ = state
        .move_call
        .cleanup_read_access(
            activation_key.clone(),
            administrative_personnel_iota_address,
            administrative_personnel_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    // get the data
    let access = state
        .move_call
        .get_read_access(activation_key, administrative_personnel_iota_address)
        .await
        .context(current_fn!())?;

    let access = access
        .into_iter()
        .map(|access| {
            let access_metadata: AccessMetadataEncrypted =
                serde_deserialize_from_base64(access.metadata).context(current_fn!())?;
            let access_metadata = decrypt_original(
                &administrative_personnel_pre_secret_key,
                &serde_deserialize_from_base64(access_metadata.capsule).context(current_fn!())?,
                &STANDARD
                    .decode(access_metadata.enc_data)
                    .context(current_fn!())?,
            )
            .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
            let access_metadata: AccessMetadata =
                serde_json::from_slice(&access_metadata).context(current_fn!())?;

            let access = AccessData {
                access_data_types: access.access_data_types,
                access_token: access_metadata.access_token,
                token_hash: access_metadata.token_hash,
                enc_data_pre_secret_key_seed: access_metadata.enc_data_pre_secret_key_seed,
                data_pre_secret_key_seed_capsule: access_metadata.data_pre_secret_key_seed_capsule,
                exp: access.exp,
                medical_metadata_index: access.medical_metadata_index,
                patient_iota_address: access_metadata.patient_iota_address,
                patient_name: access_metadata.patient_name,
                patient_pre_public_key: access_metadata.patient_pre_public_key,
                related_rme_id: access_metadata.related_rme_id,
                delegated_by: access_metadata
                    .delegated_by
                    .or_else(|| access.delegated_by.map(|a| a.to_string())),
                delegated_to: access_metadata.delegated_to,
                expires_before: access_metadata.expires_before,
                delegation_signature: access_metadata.delegation_signature,
                delegation_depth: Some(access.delegation_depth),
            };

            Ok(access)
        })
        .collect::<Result<Vec<AccessData>, HospitalError>>()?;

    Ok(SuccessResponse {
        data: access,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn get_update_access_administrative_personnel(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<AccessData>>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (
        activation_key,
        administrative_personnel_iota_address,
        administrative_personnel_iota_key_pair,
        administrative_personnel_pre_secret_key,
    ) = {
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found on auth state").context(current_fn!()))?;
        let activation_key =
            encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
        let administrative_personnel_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let administrative_personnel_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let (administrative_personnel_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (
            activation_key,
            administrative_personnel_iota_address,
            administrative_personnel_iota_key_pair,
            administrative_personnel_pre_secret_key,
        )
    };

    let _ = state
        .move_call
        .cleanup_update_access(
            activation_key.clone(),
            administrative_personnel_iota_address,
            administrative_personnel_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    let access = state
        .move_call
        .get_update_access(activation_key, administrative_personnel_iota_address)
        .await
        .context(current_fn!())?;

    let access = access
        .into_iter()
        .map(|access| {
            let access_metadata: AccessMetadataEncrypted =
                serde_deserialize_from_base64(access.metadata).context(current_fn!())?;
            let access_metadata = decrypt_original(
                &administrative_personnel_pre_secret_key,
                &serde_deserialize_from_base64(access_metadata.capsule).context(current_fn!())?,
                &STANDARD
                    .decode(access_metadata.enc_data)
                    .context(current_fn!())?,
            )
            .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
            let access_metadata: AccessMetadata =
                serde_json::from_slice(&access_metadata).context(current_fn!())?;

            let access = AccessData {
                access_data_types: access.access_data_types,
                access_token: access_metadata.access_token,
                token_hash: access_metadata.token_hash,
                enc_data_pre_secret_key_seed: access_metadata.enc_data_pre_secret_key_seed,
                data_pre_secret_key_seed_capsule: access_metadata.data_pre_secret_key_seed_capsule,
                exp: access.exp,
                medical_metadata_index: access.medical_metadata_index,
                patient_iota_address: access_metadata.patient_iota_address,
                patient_name: access_metadata.patient_name,
                patient_pre_public_key: access_metadata.patient_pre_public_key,
                related_rme_id: access_metadata.related_rme_id,
                delegated_by: access_metadata
                    .delegated_by
                    .or_else(|| access.delegated_by.map(|a| a.to_string())),
                delegated_to: access_metadata.delegated_to,
                expires_before: access_metadata.expires_before,
                delegation_signature: access_metadata.delegation_signature,
                delegation_depth: Some(access.delegation_depth),
            };

            Ok(access)
        })
        .collect::<Result<Vec<AccessData>, HospitalError>>()?;

    Ok(SuccessResponse {
        data: access,
        status: ResponseStatus::Success,
    })
}
