use anyhow::{anyhow, Context};
use iota_types::base_types::IotaAddress;
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

const MEDICAL_RECORDS_PAGE_SIZE: u64 = 10;

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

async fn fetch_all_medical_records_metadata(
    move_call: &crate::move_call::MoveCall,
    patient_iota_address: IotaAddress,
) -> Result<Vec<MovePatientMedicalMetadata>, PatientError> {
    let mut cursor = 0u64;
    let mut page_number = 0u64;
    let mut all_records = Vec::new();

    loop {
        let page = move_call
            .get_medical_records(cursor, MEDICAL_RECORDS_PAGE_SIZE, patient_iota_address.clone())
            .await
            .context(current_fn!())?;

        let raw_count = page.len();
        println!(
            "get_medical_records page={} cursor={} raw_count={}",
            page_number, cursor, raw_count
        );

        if raw_count == 0 {
            break;
        }

        all_records.extend(page);
        cursor += raw_count as u64;
        page_number += 1;
    }

    println!("get_medical_records total_raw={}", all_records.len());

    Ok(all_records)
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

    let raw_medical_records =
        fetch_all_medical_records_metadata(&state.move_call, patient_iota_address)
            .await
            .context(current_fn!())?;

    let mut medical_records = Vec::new();
    let mut skipped_legacy = 0u64;
    let mut skipped_invalid = 0u64;

    for metadata in raw_medical_records {
        let index = metadata.index;

        match deserialize_stored_rme_segment_metadata(metadata.metadata) {
            Ok(Some(medical_metadata)) => {
                medical_records.push(CommandGetMedicalRecordsResponseData {
                    author_address: medical_metadata.author_address,
                    cid: medical_metadata.cid,
                    index,
                    created_at: medical_metadata.created_at,
                    dataset_category: medical_metadata.dataset_category,
                    function_category: medical_metadata.function_category,
                    related_rme_id: medical_metadata.related_rme_id,
                });
            }
            Ok(None) => skipped_legacy += 1,
            Err(err) => {
                skipped_invalid += 1;
                println!(
                    "Skipping invalid RME metadata at index={}: {:?}",
                    index, err
                );
            }
        }
    }

    println!(
        "get_medical_records decoded={} skipped_legacy={} skipped_invalid={}",
        medical_records.len(),
        skipped_legacy,
        skipped_invalid
    );

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
