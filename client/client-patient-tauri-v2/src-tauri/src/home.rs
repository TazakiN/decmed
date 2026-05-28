use anyhow::{anyhow, Context};
use serde_json::{json, Value};
use tauri::{async_runtime::Mutex, State};
use umbral_pre::decrypt_original;

use crate::{
    current_fn,
    patient_error::PatientError,
    types::{
        AppState, CommandGetMedicalRecordsResponseData, KeyNonce, MovePatientMedicalMetadata,
        ResponseStatus, RmeSegmentData, RmeSegmentMetadata, SuccessResponse,
    },
    utils::{
        aes_decrypt, get_data_ipfs, get_iota_address_from_keys_entry, get_pre_keys_from_keys_entry,
        parse_keys_entry, serde_deserialize_from_base64,
    },
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

struct StoredRmeSegmentMetadata {
    author_address: String,
    capsule: String,
    cid: String,
    created_at: String,
    dataset_category: crate::types::DatasetCategory,
    enc_key_and_nonce: String,
    function_category: crate::types::FunctionCategory,
    related_rme_id: String,
}

fn deserialize_stored_rme_segment_metadata(
    metadata: String,
) -> Result<Option<StoredRmeSegmentMetadata>, PatientError> {
    let metadata_value: serde_json::Value =
        serde_deserialize_from_base64(metadata).context(current_fn!())?;

    if metadata_value.get("ipfs_cid").is_none() {
        return Ok(None);
    }

    let segment_metadata: RmeSegmentMetadata = serde_json::from_value(metadata_value)
        .map_err(|_| anyhow!("Invalid stored RME segment metadata"))
        .context(current_fn!())?;

    Ok(Some(StoredRmeSegmentMetadata {
        author_address: segment_metadata.author_address,
        capsule: segment_metadata.capsule,
        cid: segment_metadata.ipfs_cid,
        created_at: segment_metadata.created_at,
        dataset_category: segment_metadata.dataset_category,
        enc_key_and_nonce: segment_metadata.enc_key_and_nonce,
        function_category: segment_metadata.function_category,
        related_rme_id: segment_metadata.related_rme_id,
    }))
}

fn require_stored_rme_segment_metadata(
    metadata: String,
) -> Result<StoredRmeSegmentMetadata, PatientError> {
    deserialize_stored_rme_segment_metadata(metadata)?.ok_or(
        anyhow!("Legacy EMR metadata is no longer supported")
            .context(current_fn!())
            .into(),
    )
}

#[tauri::command]
pub async fn get_medical_records(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<CommandGetMedicalRecordsResponseData>>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let patient_iota_address = {
        let patient_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;

        patient_iota_address
    };

    let medical_records: Vec<MovePatientMedicalMetadata> = state
        .move_call
        .get_medical_records(0, 100, patient_iota_address)
        .await
        .context(current_fn!())?;

    let medical_records = medical_records
        .into_iter()
        .map(|metadata| {
            deserialize_stored_rme_segment_metadata(metadata.metadata).map(|medical_metadata| {
                medical_metadata.map(|medical_metadata| CommandGetMedicalRecordsResponseData {
                    author_address: medical_metadata.author_address,
                    cid: medical_metadata.cid,
                    index: metadata.index,
                    created_at: medical_metadata.created_at,
                    dataset_category: medical_metadata.dataset_category,
                    function_category: medical_metadata.function_category,
                    related_rme_id: medical_metadata.related_rme_id,
                })
            })
        })
        .collect::<Result<Vec<Option<CommandGetMedicalRecordsResponseData>>, PatientError>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<CommandGetMedicalRecordsResponseData>>();

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: medical_records,
    })
}

#[tauri::command]
pub async fn get_medical_record(
    state: State<'_, Mutex<AppState>>,
    index: u64,
) -> Result<SuccessResponse<Value>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (patient_iota_address, patient_pre_secret_key) = {
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found"))
            .context(current_fn!())?;
        let patient_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let (patient_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (patient_iota_address, patient_pre_secret_key)
    };

    let medical_metadata = state
        .move_call
        .get_medical_record(index, patient_iota_address)
        .await
        .context(current_fn!())?;

    let medical_metadata = require_stored_rme_segment_metadata(medical_metadata.metadata)?;

    let medical_record_key_nonce = decrypt_original(
        &patient_pre_secret_key,
        &serde_deserialize_from_base64(medical_metadata.capsule).context(current_fn!())?,
        &STANDARD
            .decode(medical_metadata.enc_key_and_nonce)
            .context(current_fn!())?,
    )
    .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
    let medical_record_key_nonce: KeyNonce =
        serde_json::from_slice(&medical_record_key_nonce).context(current_fn!())?;

    let medical_record_content = get_data_ipfs(medical_metadata.cid)
        .await
        .context(current_fn!())?;
    let medical_record_content = aes_decrypt(
        &STANDARD
            .decode(medical_record_content)
            .context(current_fn!())?,
        &STANDARD
            .decode(medical_record_key_nonce.key)
            .context(current_fn!())?,
        &STANDARD
            .decode(medical_record_key_nonce.nonce)
            .context(current_fn!())?,
    )
    .context(current_fn!())?;
    let segment_data: RmeSegmentData =
        serde_json::from_slice(&medical_record_content).context(current_fn!())?;

    let res_data = json!({
        "createdAt": medical_metadata.created_at,
        "segmentData": segment_data,
    });

    Ok(SuccessResponse {
        data: res_data,
        status: ResponseStatus::Success,
    })
}
