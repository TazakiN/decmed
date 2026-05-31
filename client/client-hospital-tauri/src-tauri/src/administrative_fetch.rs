use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use tauri_plugin_http::reqwest;
use umbral_pre::{
    decrypt_original, decrypt_reencrypted, Capsule, CapsuleFrag, PublicKey, SecretKey,
};

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    hospital_error::HospitalError,
    types::{
        KeyNonce, KeysEntry, PatientPrivateAdministrativeData, ProxyReencryptionErrorResponse,
        ProxyReencryptionGetPatientAdministrativeDataResponseData,
        ProxyReencryptionSuccessResponse,
    },
    utils::{
        aes_decrypt, compute_pre_keys, do_http_get_request_json, get_pre_keys_from_keys_entry,
        serde_deserialize_from_base64,
    },
};
use tauri::http::StatusCode;

pub async fn fetch_patient_administrative_data(
    access_token: &str,
    patient_iota_address: &str,
    keys_entry: &KeysEntry,
    session_pin: &str,
    req_client: &reqwest::Client,
) -> Result<PatientPrivateAdministrativeData, HospitalError> {
    let (hospital_personnel_pre_secret_key, _) =
        get_pre_keys_from_keys_entry(keys_entry, session_pin.to_string()).context(current_fn!())?;

    let res = do_http_get_request_json::<
        ProxyReencryptionSuccessResponse<ProxyReencryptionGetPatientAdministrativeDataResponseData>,
        ProxyReencryptionErrorResponse,
        _,
    >(
        Some(access_token.to_string()),
        None,
        None,
        req_client,
        StatusCode::OK,
        format!(
            "{}/administrative?patient_iota_address={}",
            PROXY_BASE_URL, patient_iota_address
        ),
    )
    .await
    .context(current_fn!())?;

    decrypt_administrative_response(&hospital_personnel_pre_secret_key, res.data)
}

pub fn decrypt_administrative_response(
    hospital_personnel_pre_secret_key: &SecretKey,
    res: ProxyReencryptionGetPatientAdministrativeDataResponseData,
) -> Result<PatientPrivateAdministrativeData, HospitalError> {
    let patient_pre_public_key: PublicKey =
        serde_deserialize_from_base64(res.patient_pre_public_key).context(current_fn!())?;
    let data_pre_secret_key_seed_capsule: Capsule =
        serde_deserialize_from_base64(res.data_pre_secret_key_seed_capsule)
            .context(current_fn!())?;
    let data_pre_secret_key_seed = decrypt_original(
        hospital_personnel_pre_secret_key,
        &data_pre_secret_key_seed_capsule,
        STANDARD
            .decode(res.enc_data_pre_secret_key_seed)
            .context(current_fn!())?,
    )
    .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
    let (data_pre_secret_key, data_pre_public_key) =
        compute_pre_keys(&data_pre_secret_key_seed).context(current_fn!())?;
    let signer_pre_public_key: PublicKey =
        serde_deserialize_from_base64(res.signer_pre_public_key).context(current_fn!())?;
    let c_frag: CapsuleFrag = serde_deserialize_from_base64(res.c_frag).context(current_fn!())?;
    let administrative_data_capsule: Capsule =
        serde_deserialize_from_base64(res.patient_private_adm_data_capsule)
            .context(current_fn!())?;
    let verified_cfrag = c_frag
        .verify(
            &administrative_data_capsule,
            &signer_pre_public_key,
            &patient_pre_public_key,
            &data_pre_public_key,
        )
        .map_err(|e| anyhow!(e.0.to_string()).context(current_fn!()))?;
    let administrative_data_key_nonce = decrypt_reencrypted(
        &data_pre_secret_key,
        &patient_pre_public_key,
        &administrative_data_capsule,
        [verified_cfrag],
        STANDARD
            .decode(res.enc_patient_private_adm_data_key_nonce)
            .context(current_fn!())?,
    )
    .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
    let administrative_data_key_nonce: KeyNonce =
        serde_json::from_slice(&administrative_data_key_nonce).context(current_fn!())?;
    let administrative_data = aes_decrypt(
        &STANDARD
            .decode(res.enc_patient_private_adm_data)
            .context(current_fn!())?,
        &STANDARD
            .decode(administrative_data_key_nonce.key)
            .context(current_fn!())?,
        &STANDARD
            .decode(administrative_data_key_nonce.nonce)
            .context(current_fn!())?,
    )
    .context(current_fn!())?;
    let data: PatientPrivateAdministrativeData =
        serde_json::from_slice(&administrative_data).context(current_fn!())?;
    Ok(data)
}
