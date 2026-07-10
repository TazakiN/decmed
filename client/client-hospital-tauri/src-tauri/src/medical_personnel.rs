use std::str::FromStr;

use anyhow::{anyhow, Context};
use decmed_rme_segment::RmeSegmentData;
use iota_types::{
    base_types::IotaAddress,
    crypto::{EncodeDecodeBase64, IotaKeyPair, Signature},
};
use serde_json::{json, Value};
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, http::StatusCode, State};
use tauri_plugin_http::reqwest;
use umbral_pre::{decrypt_original, decrypt_reencrypted, encrypt, Capsule, CapsuleFrag, PublicKey};

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    hospital_error::HospitalError,
    types::{
        AccessData, AccessMetadata, AccessMetadataEncrypted, AppState,
        CommandNewMedicalRecordPayload, CommandUpdateMedicalRecordPayload, KeyNonce, MedicalData,
        MedicalMetadata, PatientPrivateAdministrativeData, ProxyReencryptionErrorResponse,
        ProxyReencryptionGetMedicalRecordResponseData, ProxyReencryptionSuccessResponse,
        ResponseStatus, SuccessResponse,
    },
    utils::{
        aes_decrypt, aes_encrypt, compute_pre_keys, do_http_post_request_json,
        do_http_put_request_json, encode_activation_key_from_keys_entry,
        get_iota_address_from_keys_entry, get_iota_key_pair_from_keys_entry,
        get_pre_keys_from_keys_entry, parse_keys_entry, serde_deserialize_from_base64,
        serde_serialize_to_base64,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[tauri::command]
pub async fn new_medical_record(
    _state: State<'_, Mutex<AppState>>,
    access_token: String,
    data: CommandNewMedicalRecordPayload,
    patient_iota_address: String,
    patient_pre_public_key: String,
) -> Result<SuccessResponse<()>, HospitalError> {
    let req_client = reqwest::Client::new();

    let (medical_metadata, patient_iota_address) = {
        let patient_iota_address =
            IotaAddress::from_str(&patient_iota_address).context(current_fn!())?;
        let patient_pre_public_key: PublicKey =
            serde_deserialize_from_base64(patient_pre_public_key).context(current_fn!())?;

        let medical_data = MedicalData {
            anamnesis: data.anamnesis,
            diagnose: data.diagnose,
            physical_check: data.physical_check,
            psychological_check: data.psychological_check,
            therapy: data.therapy,
        };
        let (enc_medical_data, medical_data_key, medical_data_nonce) =
            aes_encrypt(&serde_json::to_vec(&medical_data).context(current_fn!())?)
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

        let medical_metadata = MedicalMetadata {
            capsule: serde_serialize_to_base64(&medical_data_key_nonce_capsule)
                .context(current_fn!())?,
            enc_data: STANDARD.encode(enc_medical_data),
            enc_key_and_nonce: STANDARD.encode(enc_medical_data_key_nonce),
        };

        (medical_metadata, patient_iota_address)
    };

    let _ = do_http_post_request_json::<
        _,
        ProxyReencryptionSuccessResponse<()>,
        ProxyReencryptionErrorResponse,
    >(
        Some(access_token),
        None,
        None,
        None,
        &format!("{}/medical-record", PROXY_BASE_URL),
        &json!({
            "medical_metadata": serde_serialize_to_base64(&medical_metadata).context(current_fn!())?,
            "patient_iota_address": patient_iota_address.to_string(),
        }),
        &req_client,
        StatusCode::OK,
    )
    .await
    .context(current_fn!())?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}

pub(crate) fn proxy_error_to_hospital(error: ProxyReencryptionErrorResponse) -> HospitalError {
    HospitalError::Anyhow(anyhow!(format!("{:#?}", error)).context(current_fn!()))
}

pub(crate) fn sign_wallet_proof_context(
    context: &decmed_macaroon_auth::WalletProofContext,
    iota_key_pair: &IotaKeyPair,
) -> Result<String, HospitalError> {
    let canonical = context
        .canonical_message()
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);

    Ok(Signature::new_secure(&intent_message, iota_key_pair).encode_base64())
}

async fn request_medical_record_from_proxy(
    req_client: &reqwest::Client,
    access_token: &str,
    index: u64,
    patient_iota_address: &str,
    include_administrative: bool,
    wallet_signature: Option<&str>,
    wallet_timestamp: Option<&str>,
    delegation_signature: Option<&str>,
) -> Result<
    Result<
        ProxyReencryptionSuccessResponse<ProxyReencryptionGetMedicalRecordResponseData>,
        ProxyReencryptionErrorResponse,
    >,
    HospitalError,
> {
    let mut request = req_client
        .get(format!(
            "{}/medical-record?index={}&patient_iota_address={}&include_administrative={}",
            PROXY_BASE_URL, index, patient_iota_address, include_administrative
        ))
        .bearer_auth(access_token);

    if let Some(signature) = wallet_signature {
        request = request.header("x-decmed-wallet-signature", signature);
    }
    if let Some(timestamp) = wallet_timestamp {
        request = request.header("x-decmed-wallet-timestamp", timestamp);
    }
    if let Some(signature) = delegation_signature {
        request = request.header("x-decmed-delegation-signature", signature);
    }

    let response = request.send().await.context(current_fn!())?;
    let status = response.status();
    let body = response.bytes().await.context(current_fn!())?;

    if status != StatusCode::OK {
        let error = serde_json::from_slice::<ProxyReencryptionErrorResponse>(&body)
            .context(current_fn!())?;
        return Ok(Err(error));
    }

    let data = serde_json::from_slice::<
        ProxyReencryptionSuccessResponse<ProxyReencryptionGetMedicalRecordResponseData>,
    >(&body)
    .context(current_fn!())?;
    Ok(Ok(data))
}

#[tauri::command]
pub async fn get_medical_record(
    state: State<'_, Mutex<AppState>>,
    access_token: String,
    index: Option<u64>,
    patient_iota_address: String,
    enc_data_pre_secret_key_seed: Option<String>,
    data_pre_secret_key_seed_capsule: Option<String>,
    delegation_signature: Option<String>,
) -> Result<SuccessResponse<Value>, HospitalError> {
    get_medical_record_impl(
        state,
        access_token,
        index,
        patient_iota_address,
        enc_data_pre_secret_key_seed,
        data_pre_secret_key_seed_capsule,
        delegation_signature,
        true,
    )
    .await
}

#[tauri::command]
pub async fn get_medical_record_payload(
    state: State<'_, Mutex<AppState>>,
    access_token: String,
    index: Option<u64>,
    patient_iota_address: String,
    enc_data_pre_secret_key_seed: Option<String>,
    data_pre_secret_key_seed_capsule: Option<String>,
    delegation_signature: Option<String>,
) -> Result<SuccessResponse<Value>, HospitalError> {
    get_medical_record_impl(
        state,
        access_token,
        index,
        patient_iota_address,
        enc_data_pre_secret_key_seed,
        data_pre_secret_key_seed_capsule,
        delegation_signature,
        false,
    )
    .await
}

async fn get_medical_record_impl(
    state: State<'_, Mutex<AppState>>,
    access_token: String,
    index: Option<u64>,
    patient_iota_address: String,
    enc_data_pre_secret_key_seed: Option<String>,
    data_pre_secret_key_seed_capsule: Option<String>,
    delegation_signature: Option<String>,
    include_administrative: bool,
) -> Result<SuccessResponse<Value>, HospitalError> {
    let (keys_entry_secret, pin) = {
        let state = state.lock().await;
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found"))?;
        (state.keys_entry.get_secret().context(current_fn!())?, pin)
    };
    let keys_entry = parse_keys_entry(&keys_entry_secret).context(current_fn!())?;
    let req_client = reqwest::Client::new();

    let (hospital_personnel_pre_secret_key, hospital_personnel_iota_key_pair) = {
        let iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let (hospital_personnel_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (hospital_personnel_pre_secret_key, iota_key_pair)
    };

    let request_index = index.unwrap_or(0);
    let res = match request_medical_record_from_proxy(
        &req_client,
        &access_token,
        request_index,
        &patient_iota_address,
        include_administrative,
        None,
        None,
        delegation_signature.as_deref(),
    )
    .await
    .context(current_fn!())?
    {
        Ok(response) => response,
        Err(error_response) => {
            if error_response.status_code == StatusCode::UNAUTHORIZED.as_u16() {
                if let Some(proof_context) = error_response.proof_context.clone() {
                    let wallet_signature = sign_wallet_proof_context(
                        &proof_context,
                        &hospital_personnel_iota_key_pair,
                    )
                    .context(current_fn!())?;
                    match request_medical_record_from_proxy(
                        &req_client,
                        &access_token,
                        request_index,
                        &patient_iota_address,
                        include_administrative,
                        Some(&wallet_signature),
                        Some(&proof_context.timestamp),
                        delegation_signature.as_deref(),
                    )
                    .await
                    .context(current_fn!())?
                    {
                        Ok(response) => response,
                        Err(error_response) => return Err(proxy_error_to_hospital(error_response)),
                    }
                } else {
                    return Err(proxy_error_to_hospital(error_response));
                }
            } else {
                return Err(proxy_error_to_hospital(error_response));
            }
        }
    };

    let (medical_data, administrative_data) = {
        let patient_pre_public_key: PublicKey =
            serde_deserialize_from_base64(res.data.patient_pre_public_key)
                .context(current_fn!())?;
        let medical_record_pre_secret_key_seed_capsule: Capsule = serde_deserialize_from_base64(
            data_pre_secret_key_seed_capsule
                .unwrap_or_else(|| res.data.data_pre_secret_key_seed_capsule.clone()),
        )
        .context(current_fn!())?;
        let medical_record_pre_secret_key_seed = decrypt_original(
            &hospital_personnel_pre_secret_key,
            &medical_record_pre_secret_key_seed_capsule,
            STANDARD
                .decode(
                    enc_data_pre_secret_key_seed
                        .unwrap_or_else(|| res.data.enc_data_pre_secret_key_seed.clone()),
                )
                .context(current_fn!())?,
        )
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
        let (medical_record_pre_secret_key, medical_record_pre_public_key) =
            compute_pre_keys(&medical_record_pre_secret_key_seed).context(current_fn!())?;
        let signer_pre_public_key: PublicKey =
            serde_deserialize_from_base64(res.data.signer_pre_public_key).context(current_fn!())?;
        let c_frag_medical: CapsuleFrag =
            serde_deserialize_from_base64(res.data.c_frag_medical).context(current_fn!())?;
        let medical_data_capsule: Capsule =
            serde_deserialize_from_base64(res.data.medical_data_capsule).context(current_fn!())?;
        let verified_cfrag_medical = c_frag_medical
            .verify(
                &medical_data_capsule,
                &signer_pre_public_key,
                &patient_pre_public_key,
                &medical_record_pre_public_key,
            )
            .map_err(|e| anyhow!(e.0.to_string()).context(current_fn!()))?;
        let medical_data_key_nonce = decrypt_reencrypted(
            &medical_record_pre_secret_key,
            &patient_pre_public_key,
            &medical_data_capsule,
            [verified_cfrag_medical],
            STANDARD
                .decode(res.data.enc_medical_data_key_nonce)
                .context(current_fn!())?,
        )
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
        let medical_data_key_nonce: KeyNonce =
            serde_json::from_slice(&medical_data_key_nonce).context(current_fn!())?;
        let medical_data = aes_decrypt(
            &STANDARD
                .decode(res.data.enc_medical_data)
                .context(current_fn!())?,
            &STANDARD
                .decode(medical_data_key_nonce.key)
                .context(current_fn!())?,
            &STANDARD
                .decode(medical_data_key_nonce.nonce)
                .context(current_fn!())?,
        )
        .context(current_fn!())?;
        let medical_data_value = match serde_json::from_slice::<RmeSegmentData>(&medical_data) {
            Ok(segment) => {
                segment
                    .validate()
                    .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
                json!({
                    "recordKind": "segment",
                    "segment": segment,
                })
            }
            Err(_) => {
                let medical_data: MedicalData =
                    serde_json::from_slice(&medical_data).context(current_fn!())?;
                json!({
                    "recordKind": "legacy",
                    "medicalData": medical_data,
                })
            }
        };

        let administrative_data = if include_administrative {
            let c_frag_administrative: CapsuleFrag = serde_deserialize_from_base64(
                res.data
                    .c_frag_administrative
                    .clone()
                    .ok_or_else(|| anyhow!("Missing administrative cfrag"))?,
            )
            .context(current_fn!())?;
            let administrative_data_capsule: Capsule = serde_deserialize_from_base64(
                res.data
                    .administrative_data_capsule
                    .clone()
                    .ok_or_else(|| anyhow!("Missing administrative capsule"))?,
            )
            .context(current_fn!())?;
            let verified_cfrag_administrative = c_frag_administrative
                .verify(
                    &administrative_data_capsule,
                    &signer_pre_public_key,
                    &patient_pre_public_key,
                    &medical_record_pre_public_key,
                )
                .map_err(|e| anyhow!(e.0.to_string()).context(current_fn!()))?;
            let administrative_data_key_nonce = decrypt_reencrypted(
                &medical_record_pre_secret_key,
                &patient_pre_public_key,
                &administrative_data_capsule,
                [verified_cfrag_administrative],
                STANDARD
                    .decode(
                        res.data
                            .enc_administrative_data_key_nonce
                            .clone()
                            .ok_or_else(|| anyhow!("Missing administrative key nonce"))?,
                    )
                    .context(current_fn!())?,
            )
            .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
            let administrative_data_key_nonce: KeyNonce =
                serde_json::from_slice(&administrative_data_key_nonce).context(current_fn!())?;
            let administrative_data = aes_decrypt(
                &STANDARD
                    .decode(
                        res.data
                            .enc_administrative_data
                            .clone()
                            .ok_or_else(|| anyhow!("Missing administrative payload"))?,
                    )
                    .context(current_fn!())?,
                &STANDARD
                    .decode(administrative_data_key_nonce.key)
                    .context(current_fn!())?,
                &STANDARD
                    .decode(administrative_data_key_nonce.nonce)
                    .context(current_fn!())?,
            )
            .context(current_fn!())?;
            Some(
                serde_json::from_slice::<PatientPrivateAdministrativeData>(&administrative_data)
                    .context(current_fn!())?,
            )
        } else {
            None
        };

        (medical_data_value, administrative_data)
    };

    let mut res_data = json!({
        "createdAt": res.data.medical_data_created_at,
        "currentIndex": res.data.current_index,
        "medicalData": medical_data.get("medicalData").cloned().unwrap_or(serde_json::Value::Null),
        "recordKind": medical_data.get("recordKind").cloned().unwrap_or(json!("legacy")),
        "segment": medical_data.get("segment").cloned(),
        "nextIndex": res.data.next_index,
        "prevIndex": res.data.prev_index,
    });

    if let Some(administrative_data) = administrative_data {
        if let Value::Object(map) = &mut res_data {
            map.insert("administrativeData".to_string(), json!(administrative_data));
        }
    }

    Ok(SuccessResponse {
        data: res_data,
        status: ResponseStatus::Success,
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
pub async fn update_medical_record(
    _state: State<'_, Mutex<AppState>>,
    access_token: String,
    data: CommandUpdateMedicalRecordPayload,
    patient_iota_address: String,
    patient_pre_public_key: String,
) -> Result<SuccessResponse<()>, HospitalError> {
    let req_client = reqwest::Client::new();

    let (medical_metadata, patient_iota_address) = {
        let patient_iota_address =
            IotaAddress::from_str(&patient_iota_address).context(current_fn!())?;
        let patient_pre_public_key: PublicKey =
            serde_deserialize_from_base64(patient_pre_public_key).context(current_fn!())?;

        let medical_data = MedicalData {
            anamnesis: data.anamnesis,
            diagnose: data.diagnose,
            physical_check: data.physical_check,
            psychological_check: data.psychological_check,
            therapy: data.therapy,
        };
        let (enc_medical_data, medical_data_key, medical_data_nonce) =
            aes_encrypt(&serde_json::to_vec(&medical_data).context(current_fn!())?)
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

        let medical_metadata = MedicalMetadata {
            capsule: serde_serialize_to_base64(&medical_data_key_nonce_capsule)
                .context(current_fn!())?,
            enc_data: STANDARD.encode(enc_medical_data),
            enc_key_and_nonce: STANDARD.encode(enc_medical_data_key_nonce),
        };

        (medical_metadata, patient_iota_address)
    };

    let _ = do_http_put_request_json::<
        _,
        ProxyReencryptionSuccessResponse<()>,
        ProxyReencryptionErrorResponse,
    >(
        Some(access_token),
        &format!("{}/medical-record", PROXY_BASE_URL),
        &json!({
            "medical_metadata": serde_serialize_to_base64(&medical_metadata).context(current_fn!())?,
            "patient_iota_address": patient_iota_address.to_string(),
        }),
        &req_client,
        StatusCode::OK,
    )
    .await
    .context(current_fn!())?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}
