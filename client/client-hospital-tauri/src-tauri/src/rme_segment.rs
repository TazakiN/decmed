use std::str::FromStr;

use anyhow::{anyhow, Context};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use decmed_rme_segment::{
    sha256_hex, ClientEncryptedRmeSegment, CreateRmeSegmentRequest, CreateRmeSegmentResponse,
    EncryptionAlgorithm, RmeSegmentData,
};
use iota_types::base_types::IotaAddress;
use iota_types::crypto::{EncodeDecodeBase64, IotaKeyPair, Signature};
use serde::Serialize;
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, http::StatusCode, State};
use tauri_plugin_http::reqwest;
use umbral_pre::{encrypt, PublicKey};
use uuid::Uuid;

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    hospital_error::HospitalError,
    types::{
        AppState, KeyNonce, ProxyReencryptionErrorResponse, ProxyReencryptionSuccessResponse,
        ResponseStatus, SuccessResponse,
    },
    utils::{
        aes_encrypt, do_http_post_request_json, get_iota_key_pair_from_keys_entry,
        parse_keys_entry, serde_deserialize_from_base64, serde_serialize_to_base64,
    },
};

#[derive(Debug, Serialize)]
struct ProxyCreateRmeSegmentPayload {
    encrypted_segment: String,
    patient_iota_address: String,
}

pub fn build_encrypted_rme_segment(
    request: CreateRmeSegmentRequest,
    patient_pre_public_key: PublicKey,
) -> Result<(RmeSegmentData, ClientEncryptedRmeSegment), HospitalError> {
    let patient_address = request.patient_address.clone();
    let fasyankes_id = request.fasyankes_id.clone();
    let author_address = request.author_address.clone();
    let segment_id = Uuid::new_v4();
    let off_chain_segment = RmeSegmentData::new(segment_id, request)
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;

    let off_chain_segment_json = serde_json::to_vec(&off_chain_segment).context(current_fn!())?;
    let (encrypted_segment, segment_key, segment_nonce) =
        aes_encrypt(&off_chain_segment_json).context(current_fn!())?;

    let segment_key_nonce = KeyNonce {
        key: STANDARD.encode(segment_key),
        nonce: STANDARD.encode(segment_nonce),
    };
    let (segment_key_nonce_capsule, enc_segment_key_nonce) = encrypt(
        &patient_pre_public_key,
        &serde_json::to_vec(&segment_key_nonce).context(current_fn!())?,
    )
    .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;

    let encrypted_segment_metadata = ClientEncryptedRmeSegment {
        segment_id: off_chain_segment.segment_id.clone(),
        related_rme_id: off_chain_segment.related_rme_id.clone(),
        patient_address,
        fasyankes_id,
        dataset_category: off_chain_segment.dataset_category,
        function_category: off_chain_segment.function_category,
        integrity_hash: sha256_hex(&encrypted_segment),
        capsule: serde_serialize_to_base64(&segment_key_nonce_capsule).context(current_fn!())?,
        enc_data: STANDARD.encode(encrypted_segment),
        enc_key_and_nonce: STANDARD.encode(enc_segment_key_nonce),
        encryption_algo: EncryptionAlgorithm::Aes256Gcm,
        author_address,
    };

    encrypted_segment_metadata
        .validate()
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
    off_chain_segment
        .validate()
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;

    Ok((off_chain_segment, encrypted_segment_metadata))
}

pub async fn post_encrypted_rme_segment(
    access_token: &str,
    encrypted_segment: &ClientEncryptedRmeSegment,
    patient_iota_address: &str,
    iota_key_pair: &IotaKeyPair,
    delegation_signature: Option<String>,
    req_client: &reqwest::Client,
) -> Result<CreateRmeSegmentResponse, HospitalError> {
    use decmed_macaroon_auth::AccessMode;

    let mac = macaroon::Macaroon::deserialize(access_token)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    let wallet_timestamp = chrono::Utc::now().to_rfc3339();
    let wallet_ctx = decmed_macaroon_auth::WalletProofContext {
        token_id: mac.identifier().to_string(),
        patient_address: encrypted_segment.patient_address.clone(),
        related_rme_id: encrypted_segment.related_rme_id.clone(),
        operation: AccessMode::Write,
        segment_id: encrypted_segment.segment_id.clone(),
        dataset_category: encrypted_segment.dataset_category,
        function_category: encrypted_segment.function_category,
        timestamp: wallet_timestamp.clone(),
    };
    let canonical = wallet_ctx
        .canonical_message()
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let wallet_signature = Signature::new_secure(&intent_message, iota_key_pair).encode_base64();

    let res = do_http_post_request_json::<
        _,
        ProxyReencryptionSuccessResponse<CreateRmeSegmentResponse>,
        ProxyReencryptionErrorResponse,
    >(
        Some(access_token.to_string()),
        Some(wallet_signature),
        Some(wallet_timestamp),
        delegation_signature,
        &format!("{}/medical-record-segment", PROXY_BASE_URL),
        &ProxyCreateRmeSegmentPayload {
            encrypted_segment: serde_serialize_to_base64(encrypted_segment)
                .context(current_fn!())?,
            patient_iota_address: patient_iota_address.to_string(),
        },
        req_client,
        StatusCode::OK,
    )
    .await
    .context(current_fn!())?;

    Ok(res.data)
}

#[tauri::command]
pub async fn new_medical_record_segment(
    state: State<'_, Mutex<AppState>>,
    access_token: String,
    data: CreateRmeSegmentRequest,
    patient_pre_public_key: String,
    pin: Option<String>,
    delegation_signature: Option<String>,
) -> Result<SuccessResponse<CreateRmeSegmentResponse>, HospitalError> {
    use anyhow::anyhow;

    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)?;
    let req_client = reqwest::Client::new();
    let patient_iota_address =
        IotaAddress::from_str(&data.patient_address).context(current_fn!())?;
    let patient_pre_public_key: PublicKey =
        serde_deserialize_from_base64(patient_pre_public_key).context(current_fn!())?;

    let pin = pin
        .or_else(|| state.auth_state.session_pin.clone())
        .ok_or_else(|| {
            HospitalError::Anyhow(anyhow!("Session PIN not found").context(current_fn!()))
        })?;
    let iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;
    let author_address = crate::utils::get_iota_address_from_keys_entry(&keys_entry)?.to_string();
    let mut segment_request = data;
    segment_request.author_address = author_address;

    let (_, encrypted_segment) =
        build_encrypted_rme_segment(segment_request, patient_pre_public_key)
            .context(current_fn!())?;

    let data = post_encrypted_rme_segment(
        &access_token,
        &encrypted_segment,
        &patient_iota_address.to_string(),
        &iota_key_pair,
        delegation_signature,
        &req_client,
    )
    .await
    .context(current_fn!())?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data,
    })
}

#[tauri::command]
pub async fn get_medical_record_segment(
    state: State<'_, Mutex<AppState>>,
    access_token: String,
    patient_iota_address: String,
    index: Option<u64>,
    enc_data_pre_secret_key_seed: Option<String>,
    data_pre_secret_key_seed_capsule: Option<String>,
) -> Result<SuccessResponse<serde_json::Value>, HospitalError> {
    crate::medical_personnel::get_medical_record(
        state,
        access_token,
        index,
        patient_iota_address,
        enc_data_pre_secret_key_seed,
        data_pre_secret_key_seed_capsule,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use decmed_rme_segment::{DatasetCategory, FunctionCategory};
    use serde_json::json;
    use umbral_pre::SecretKeyFactory;

    #[test]
    fn builds_off_chain_segment_and_client_metadata() {
        let seed = [7u8; 32];
        let patient_secret_key = SecretKeyFactory::from_secure_randomness(&seed)
            .unwrap()
            .make_key(&seed);
        let patient_pre_public_key = patient_secret_key.public_key();
        let request = CreateRmeSegmentRequest {
            related_rme_id: "rme-2026-0001".to_string(),
            patient_address: "0x1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            patient_ref: "patient-001".to_string(),
            fasyankes_id: "rs-001".to_string(),
            encounter_id: "enc-rawat-jalan-001".to_string(),
            service_date: "2026-05-18".to_string(),
            author_address: "0x2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            dataset_category: DatasetCategory::RAWAT_JALAN,
            function_category: FunctionCategory::ANAMNESIS,
            payload: json!({
                "keluhan_utama": "Demam dan batuk sejak 3 hari"
            }),
        };

        let (off_chain, encrypted_segment) =
            build_encrypted_rme_segment(request, patient_pre_public_key).unwrap();

        assert_eq!(off_chain.segment_id, encrypted_segment.segment_id);
        assert_eq!(off_chain.related_rme_id, encrypted_segment.related_rme_id);
        assert_eq!(
            off_chain.dataset_category,
            encrypted_segment.dataset_category
        );
        assert_eq!(
            off_chain.function_category,
            encrypted_segment.function_category
        );
        assert_eq!(
            off_chain.payload_hash,
            decmed_rme_segment::payload_hash(&off_chain.payload)
        );
        assert_ne!(
            encrypted_segment.integrity_hash,
            decmed_rme_segment::payload_hash(&off_chain.payload)
        );
    }
}
