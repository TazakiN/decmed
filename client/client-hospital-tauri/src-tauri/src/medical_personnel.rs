use std::str::FromStr;

use anyhow::{anyhow, Context};
use iota_types::base_types::IotaAddress;
use tauri::{async_runtime::Mutex, State};
use umbral_pre::{decrypt_original, encrypt, PublicKey};

use crate::{
    current_fn,
    hospital_error::HospitalError,
    types::{
        AccessData, AccessMetadata, AccessMetadataEncrypted, AppState, KeyNonce, MedicalData,
        MedicalDataMainCategory, MedicalDataSubCategory, MedicalMetadata, ResponseStatus,
        SuccessResponse,
    },
    utils::{
        add_and_pin_to_ipfs, aes_encrypt, encode_activation_key_from_keys_entry,
        get_iota_address_from_keys_entry, get_iota_key_pair_from_keys_entry,
        get_pre_keys_from_keys_entry, parse_keys_entry, serde_deserialize_from_base64,
        serde_serialize_to_base64, sys_time_to_iso,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[tauri::command]
pub async fn new_medical_record(
    state: State<'_, Mutex<AppState>>,
    patient_iota_address: String,
    patient_pre_public_key: String,
    pin: String,
) -> Result<SuccessResponse<()>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (activation_key, hospital_personnel_iota_address, hospital_personnel_iota_key_pair) = {
        let activation_key =
            encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
        let hospital_personnel_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let hospital_personnel_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (
            activation_key,
            hospital_personnel_iota_address,
            hospital_personnel_iota_key_pair,
        )
    };

    let (medical_metadata, patient_iota_address) = {
        let patient_iota_address =
            IotaAddress::from_str(&patient_iota_address).context(current_fn!())?;
        let patient_pre_public_key: PublicKey =
            serde_deserialize_from_base64(patient_pre_public_key).context(current_fn!())?;

        let medical_data = MedicalData {
            main_category: MedicalDataMainCategory::Category1,
            sub_category: MedicalDataSubCategory::SubCategory1,
        };
        let (enc_medical_data, medical_data_key, medical_data_nonce) =
            aes_encrypt(&serde_json::to_vec(&medical_data).context(current_fn!())?)
                .context(current_fn!())?;

        let enc_medical_data_cid = add_and_pin_to_ipfs(STANDARD.encode(enc_medical_data))
            .await
            .context(current_fn!())?;

        let medical_data_key_nonce = KeyNonce {
            key: STANDARD.encode(medical_data_key),
            nonce: STANDARD.encode(medical_data_nonce),
        };
        let (medical_data_key_nonce_capsule, enc_medical_data_key_nonce) = encrypt(
            &patient_pre_public_key,
            &serde_json::to_vec(&medical_data_key_nonce).context(current_fn!())?,
        )
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;

        let created_at = sys_time_to_iso(std::time::SystemTime::now());

        let medical_metadata = MedicalMetadata {
            capsule: serde_serialize_to_base64(&medical_data_key_nonce_capsule)
                .context(current_fn!())?,
            enc_key_and_nonce: STANDARD.encode(enc_medical_data_key_nonce),
            cid: enc_medical_data_cid,
            created_at,
        };

        (medical_metadata, patient_iota_address)
    };

    let _ = state
        .move_call
        .create_medical_record(
            activation_key,
            serde_serialize_to_base64(&medical_metadata)?,
            &patient_iota_address,
            hospital_personnel_iota_address,
            hospital_personnel_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}

#[tauri::command]
pub async fn get_read_access_medical_personnel(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<AccessData>>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (
        activation_key,
        medical_personnel_iota_address,
        medical_personnel_iota_key_pair,
        medical_personnel_pre_secret_key,
    ) = {
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found on auth state").context(current_fn!()))?;
        let activation_key =
            encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
        let medical_personnel_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let medical_personnel_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let (medical_personnel_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (
            activation_key,
            medical_personnel_iota_address,
            medical_personnel_iota_key_pair,
            medical_personnel_pre_secret_key,
        )
    };

    // do cleanup
    let _ = state
        .move_call
        .cleanup_read_access(
            activation_key.clone(),
            medical_personnel_iota_address,
            medical_personnel_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    // get the data
    let access = state
        .move_call
        .get_read_access(activation_key, medical_personnel_iota_address)
        .await
        .context(current_fn!())?;

    let access = access
        .into_iter()
        .map(|access| {
            let access_metadata: AccessMetadataEncrypted =
                serde_deserialize_from_base64(access.metadata).context(current_fn!())?;
            let access_metadata = decrypt_original(
                &medical_personnel_pre_secret_key,
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
                patient_iota_address: access_metadata.patient_iota_address,
                patient_name: access_metadata.patient_name,
                exp: access.exp,
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
pub async fn get_update_access_medical_personnel(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<AccessData>>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (
        activation_key,
        medical_personnel_iota_address,
        medical_personnel_iota_key_pair,
        medical_personnel_pre_secret_key,
    ) = {
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found on auth state").context(current_fn!()))?;
        let activation_key =
            encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
        let medical_personnel_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let medical_personnel_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let (medical_personnel_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (
            activation_key,
            medical_personnel_iota_address,
            medical_personnel_iota_key_pair,
            medical_personnel_pre_secret_key,
        )
    };

    // do cleanup
    let _ = state
        .move_call
        .cleanup_update_access(
            activation_key.clone(),
            medical_personnel_iota_address,
            medical_personnel_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    // get the data
    let access = state
        .move_call
        .get_update_access(activation_key, medical_personnel_iota_address)
        .await
        .context(current_fn!())?;

    let access = access
        .into_iter()
        .map(|access| {
            let access_metadata: AccessMetadataEncrypted =
                serde_deserialize_from_base64(access.metadata).context(current_fn!())?;
            let access_metadata = decrypt_original(
                &medical_personnel_pre_secret_key,
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
                patient_iota_address: access_metadata.patient_iota_address,
                patient_name: access_metadata.patient_name,
                exp: access.exp,
            };

            Ok(access)
        })
        .collect::<Result<Vec<AccessData>, HospitalError>>()?;

    Ok(SuccessResponse {
        data: access,
        status: ResponseStatus::Success,
    })
}
