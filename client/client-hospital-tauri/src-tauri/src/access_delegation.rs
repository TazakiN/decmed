use std::str::FromStr;

use anyhow::Context;
use chrono::{DateTime, Utc};
use decmed_macaroon_auth::{
    hash_macaroon_token, CaveatKey, CaveatValue, DelegationAttenuationParams, DelegationChain,
    DelegationProofContext, DelegationRequestProofContext, EffectiveCapability, Macaroon,
    ParsedCaveats,
};
use decmed_rme_segment::{
    DatasetCategory, FunctionCategory, ALL_DATASET_CATEGORIES, ALL_FUNCTION_CATEGORIES,
};
use iota_types::{
    base_types::IotaAddress,
    crypto::{EncodeDecodeBase64, Signature},
};
use serde::{Deserialize, Serialize};
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, command, http::StatusCode, State};
use tauri_plugin_http::reqwest;
use umbral_pre::{decrypt_original, encrypt, Capsule, PublicKey, SecretKey};

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    hospital_error::HospitalError,
    types::{
        AccessData, AccessMetadata, AccessMetadataEncrypted, AppState, HospitalPersonnelRole,
        MoveHospitalPersonnelAccessData, MoveHospitalPersonnelAccessType,
        PatientDelegationAuditInput, ProxyReencryptionErrorResponse,
        ProxyReencryptionSuccessResponse, ResponseStatus, SuccessResponse,
    },
    utils::{
        do_http_post_request_json, encode_activation_key_from_keys_entry,
        get_iota_address_from_keys_entry, get_iota_key_pair_from_keys_entry,
        get_pre_keys_from_keys_entry, parse_keys_entry, serde_deserialize_from_base64,
        serde_serialize_to_base64,
    },
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

fn default_preset() -> String {
    "doctor".to_string()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessCapabilityData {
    pub access: AccessData,
    pub purpose: String,
    pub read_datasets: Vec<DatasetCategory>,
    pub write_datasets: Vec<DatasetCategory>,
    pub read_functions: Vec<FunctionCategory>,
    pub write_functions: Vec<FunctionCategory>,
    pub expires_before: Option<String>,
    pub related_rme_id: Option<String>,
    pub delegation_depth: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessCapabilitiesResponse {
    pub read: Vec<AccessCapabilityData>,
    pub write: Vec<AccessCapabilityData>,
}

fn sort_datasets(mut values: Vec<DatasetCategory>) -> Vec<DatasetCategory> {
    values.sort_by_key(|value| {
        ALL_DATASET_CATEGORIES
            .iter()
            .position(|candidate| candidate == value)
            .unwrap_or(usize::MAX)
    });
    values
}

fn sort_functions(mut values: Vec<FunctionCategory>) -> Vec<FunctionCategory> {
    values.sort_by_key(|value| {
        ALL_FUNCTION_CATEGORIES
            .iter()
            .position(|candidate| candidate == value)
            .unwrap_or(usize::MAX)
    });
    values
}

fn parse_dataset_values(values: &[String]) -> Result<Vec<DatasetCategory>, HospitalError> {
    values
        .iter()
        .map(|value| {
            serde_json::from_str(&format!("\"{value}\""))
                .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e).context(current_fn!())))
        })
        .collect()
}

fn parse_function_values(values: &[String]) -> Result<Vec<FunctionCategory>, HospitalError> {
    values
        .iter()
        .map(|value| {
            serde_json::from_str(&format!("\"{value}\""))
                .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e).context(current_fn!())))
        })
        .collect()
}

fn purpose_from_parsed(parsed: &ParsedCaveats, fallback: &str) -> String {
    parsed
        .all(CaveatKey::Purpose)
        .first()
        .and_then(|entry| match &entry.value {
            CaveatValue::Text(value) => Some(value.clone()),
            _ => None,
        })
        .unwrap_or_else(|| fallback.to_string())
}

fn decrypt_access_data(
    access: MoveHospitalPersonnelAccessData,
    personnel_pre_secret_key: &SecretKey,
) -> Result<AccessData, HospitalError> {
    let access_metadata: AccessMetadataEncrypted =
        serde_deserialize_from_base64(access.metadata).context(current_fn!())?;
    let access_metadata = decrypt_original(
        personnel_pre_secret_key,
        &serde_deserialize_from_base64(access_metadata.capsule).context(current_fn!())?,
        &STANDARD
            .decode(access_metadata.enc_data)
            .context(current_fn!())?,
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()).context(current_fn!()))?;
    let access_metadata: AccessMetadata =
        serde_json::from_slice(&access_metadata).context(current_fn!())?;

    Ok(AccessData {
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
            .or_else(|| access.delegated_by.map(|address| address.to_string())),
        delegated_to: access_metadata.delegated_to,
        expires_before: access_metadata.expires_before,
        delegation_signature: access_metadata.delegation_signature,
        delegation_depth: Some(access.delegation_depth),
    })
}

fn token_effective_capability(
    access: &AccessData,
    fallback_purpose: &str,
) -> Result<AccessCapabilityData, HospitalError> {
    let mac = Macaroon::deserialize(&access.access_token).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;

    let purpose = purpose_from_parsed(&parsed, fallback_purpose);
    let (
        read_datasets,
        write_datasets,
        read_functions,
        write_functions,
        expires_before,
        related_rme_id,
        delegation_depth,
    ) = {
        let effective = EffectiveCapability::from_parsed(&parsed).map_err(|e| {
            HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
        })?;
        (
            sort_datasets(effective.read_datasets.iter().copied().collect()),
            sort_datasets(effective.write_datasets.iter().copied().collect()),
            sort_functions(effective.read_functions.iter().copied().collect()),
            sort_functions(effective.write_functions.iter().copied().collect()),
            effective
                .expires_before
                .map(|value| value.format("%Y-%m-%dT%H:%M:%S").to_string()),
            effective
                .related_rme_id
                .or_else(|| access.related_rme_id.clone()),
            effective.remaining_max_delegation_depth,
        )
    };

    Ok(AccessCapabilityData {
        access: access.clone(),
        purpose,
        read_datasets,
        write_datasets,
        read_functions,
        write_functions,
        expires_before,
        related_rme_id,
        delegation_depth,
    })
}

fn related_rme_from_token(token: &str) -> Result<Option<String>, HospitalError> {
    let mac = Macaroon::deserialize(token).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let effective = EffectiveCapability::from_parsed(&parsed).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    Ok(effective.related_rme_id)
}

fn build_delegation_params(
    delegated_by: &str,
    delegated_to: &str,
    read_datasets: Vec<DatasetCategory>,
    write_datasets: Vec<DatasetCategory>,
    read_functions: Vec<FunctionCategory>,
    write_functions: Vec<FunctionCategory>,
    expires_before: DateTime<Utc>,
    related_rme_id: Option<String>,
) -> DelegationAttenuationParams {
    DelegationAttenuationParams {
        delegated_by: delegated_by.to_string(),
        delegated_to: delegated_to.to_string(),
        read_datasets,
        write_datasets,
        read_functions,
        write_functions,
        expires_before,
        max_delegation_depth: 0,
        related_rme_id,
    }
}

fn ensure_no_administrative_general_write(
    write_functions: &[FunctionCategory],
) -> Result<(), HospitalError> {
    if write_functions.contains(&FunctionCategory::ADMINISTRATIVE_GENERAL) {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("ADMINISTRATIVE_GENERAL cannot be delegated with write/update access")
                .context(current_fn!()),
        ));
    }
    Ok(())
}

#[command]
pub async fn get_current_access_capabilities(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<AccessCapabilitiesResponse>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let role = state.auth_state.role.ok_or_else(|| {
        HospitalError::Anyhow(
            anyhow::anyhow!("Role not found on auth state").context(current_fn!()),
        )
    })?;

    if matches!(role, HospitalPersonnelRole::Admin) {
        return Ok(SuccessResponse {
            status: ResponseStatus::Success,
            data: AccessCapabilitiesResponse {
                read: Vec::new(),
                write: Vec::new(),
            },
        });
    }

    let pin = state.auth_state.session_pin.clone().ok_or_else(|| {
        HospitalError::Anyhow(anyhow::anyhow!("Session PIN not found").context(current_fn!()))
    })?;
    let activation_key =
        encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
    let personnel_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
    let personnel_iota_key_pair_read =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
    let personnel_iota_key_pair_update =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
    let (personnel_pre_secret_key, _) =
        get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

    let _ = state
        .move_call
        .cleanup_read_access(
            activation_key.clone(),
            personnel_iota_address,
            personnel_iota_key_pair_read,
        )
        .await
        .context(current_fn!())?;
    let _ = state
        .move_call
        .cleanup_update_access(
            activation_key.clone(),
            personnel_iota_address,
            personnel_iota_key_pair_update,
        )
        .await
        .context(current_fn!())?;

    let read = state
        .move_call
        .get_read_access(activation_key.clone(), personnel_iota_address)
        .await
        .context(current_fn!())?
        .into_iter()
        .map(|access| {
            decrypt_access_data(access, &personnel_pre_secret_key)
                .and_then(|access| token_effective_capability(&access, "Read"))
        })
        .collect::<Result<Vec<_>, HospitalError>>()?;

    let write = state
        .move_call
        .get_update_access(activation_key, personnel_iota_address)
        .await
        .context(current_fn!())?
        .into_iter()
        .map(|access| {
            decrypt_access_data(access, &personnel_pre_secret_key)
                .and_then(|access| token_effective_capability(&access, "Update"))
        })
        .collect::<Result<Vec<_>, HospitalError>>()?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: AccessCapabilitiesResponse { read, write },
    })
}

fn build_encrypted_metadata(
    metadata: &AccessMetadata,
    delegatee_pre_public_key: &PublicKey,
) -> Result<AccessMetadataEncrypted, HospitalError> {
    let (capsule, enc_data) = encrypt(
        delegatee_pre_public_key,
        &serde_json::to_vec(metadata).context(current_fn!())?,
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    Ok(AccessMetadataEncrypted {
        capsule: serde_serialize_to_base64(&capsule).context(current_fn!())?,
        enc_data: STANDARD.encode(enc_data),
    })
}

pub(crate) fn sign_delegation_proof(
    token: &str,
    _related_rme_id: &str,
    _params: &DelegationAttenuationParams,
    delegator_iota_key_pair: &iota_types::crypto::IotaKeyPair,
) -> Result<String, HospitalError> {
    let proof_ctx = DelegationProofContext::from_token(token).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let canonical = proof_ctx.canonical_message().map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let signature = Signature::new_secure(&intent_message, delegator_iota_key_pair);
    Ok(signature.encode_base64())
}

fn sign_delegation_request_context(
    context: &DelegationRequestProofContext,
    delegator_iota_key_pair: &iota_types::crypto::IotaKeyPair,
) -> Result<String, HospitalError> {
    let canonical = context.canonical_message().map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let signature = Signature::new_secure(&intent_message, delegator_iota_key_pair);
    Ok(signature.encode_base64())
}

fn datetime_to_epoch_ms(value: DateTime<Utc>) -> Result<u64, HospitalError> {
    let millis = value.timestamp_millis();
    if millis < 0 {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("Delegation expiry is before Unix epoch").context(current_fn!()),
        ));
    }
    Ok(millis as u64)
}

fn parse_future_expires_before(value: &str) -> Result<DateTime<Utc>, HospitalError> {
    let expires_before = DateTime::parse_from_rfc3339(value)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_timezone(&Utc);
    if expires_before <= Utc::now() {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("Delegation expiry must be in the future").context(current_fn!()),
        ));
    }
    Ok(expires_before)
}

fn build_delegation_audit_input(
    token: &str,
    parent_token: &str,
    access_type: MoveHospitalPersonnelAccessType,
    fallback_related_rme_id: Option<String>,
    fallback_expires_before: DateTime<Utc>,
) -> Result<PatientDelegationAuditInput, HospitalError> {
    let mac = Macaroon::deserialize(token).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let delegation = DelegationChain::from_parsed(&parsed).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let effective = EffectiveCapability::from_parsed(&parsed).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let delegation_depth = delegation.delegation_depth();
    if delegation_depth > u8::MAX as usize {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("Delegation depth exceeds u8").context(current_fn!()),
        ));
    }
    let root_subject = IotaAddress::from_str(&delegation.root_subject).context(current_fn!())?;
    let expires_at = effective.expires_before.unwrap_or(fallback_expires_before);

    Ok(PatientDelegationAuditInput {
        root_subject,
        access_type,
        related_rme_id: effective.related_rme_id.or(fallback_related_rme_id),
        delegation_depth: delegation_depth as u8,
        token_hash: Some(hash_macaroon_token(token)),
        parent_token_hash: Some(hash_macaroon_token(parent_token)),
        expires_at_ms: Some(datetime_to_epoch_ms(expires_at)?),
    })
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct DelegatedAccessMetadataInput {
    patient_iota_address: String,
    patient_name: String,
    patient_pre_public_key: Option<String>,
    related_rme_id: Option<String>,
}

fn build_delegated_access_metadata(
    access_token: String,
    payload: &DelegatedAccessMetadataInput,
    params: &DelegationAttenuationParams,
    delegation_signature: Option<String>,
    enc_seed: Option<String>,
    capsule: Option<String>,
) -> AccessMetadata {
    AccessMetadata {
        access_token: access_token.clone(),
        token_hash: Some(hash_macaroon_token(&access_token)),
        patient_iota_address: payload.patient_iota_address.clone(),
        patient_name: payload.patient_name.clone(),
        patient_pre_public_key: payload.patient_pre_public_key.clone(),
        enc_data_pre_secret_key_seed: enc_seed,
        data_pre_secret_key_seed_capsule: capsule,
        related_rme_id: payload.related_rme_id.clone(),
        delegated_by: Some(params.delegated_by.clone()),
        delegated_to: Some(params.delegated_to.clone()),
        expires_before: Some(
            params
                .expires_before
                .format("%Y-%m-%dT%H:%M:%S")
                .to_string(),
        ),
        delegation_signature,
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminDelegatedAccessPayload {
    pub parent_write_token: String,
    #[serde(default)]
    pub parent_read_token: Option<String>,
    #[serde(default)]
    pub parent_read_delegation_signature: Option<String>,
    #[serde(default)]
    pub parent_write_delegation_signature: Option<String>,
    pub delegatee_iota_address: String,
    pub delegatee_pre_public_key: String,
    pub patient_iota_address: String,
    pub patient_name: String,
    pub patient_pre_public_key: Option<String>,
    pub parent_enc_data_pre_secret_key_seed: String,
    pub parent_data_pre_secret_key_seed_capsule: String,
    pub expires_before: String,
    #[serde(default = "default_preset")]
    pub preset: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminDelegatedAccessResponse {
    pub related_rme_id: String,
    pub delegated_read_token: String,
    pub delegated_update_token: String,
    pub administrative_segments_seeded: u32,
    pub seed_warnings: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDelegatedAccessPayload {
    pub mode: String,
    pub parent_read_token: Option<String>,
    pub parent_write_token: Option<String>,
    #[serde(default)]
    pub parent_read_delegation_signature: Option<String>,
    #[serde(default)]
    pub parent_write_delegation_signature: Option<String>,
    pub delegatee_iota_address: String,
    pub delegatee_pre_public_key: String,
    pub patient_iota_address: String,
    pub patient_name: String,
    pub patient_pre_public_key: Option<String>,
    pub parent_enc_data_pre_secret_key_seed: String,
    pub parent_data_pre_secret_key_seed_capsule: String,
    pub expires_before: String,
    #[serde(default)]
    pub related_rme_id: Option<String>,
    #[serde(default)]
    pub read_datasets: Vec<String>,
    #[serde(default)]
    pub write_datasets: Vec<String>,
    #[serde(default)]
    pub read_functions: Vec<String>,
    #[serde(default)]
    pub write_functions: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDelegatedAccessResponse {
    pub related_rme_id: Option<String>,
    pub delegated_read_token: Option<String>,
    pub delegated_update_token: Option<String>,
    pub administrative_segments_seeded: u32,
    pub seed_warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyAttenuateDelegationPayload {
    mode: String,
    parent_read_token: Option<String>,
    parent_write_token: Option<String>,
    parent_read_delegation_signature: Option<String>,
    parent_write_delegation_signature: Option<String>,
    delegator_iota_address: String,
    delegatee_iota_address: String,
    patient_iota_address: String,
    expires_before: String,
    related_rme_id: Option<String>,
    read_datasets: Vec<DatasetCategory>,
    write_datasets: Vec<DatasetCategory>,
    read_functions: Vec<FunctionCategory>,
    write_functions: Vec<FunctionCategory>,
    preset: Option<String>,
    delegation_request_signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyDelegationEffectivePreview {
    read_datasets: Vec<DatasetCategory>,
    write_datasets: Vec<DatasetCategory>,
    read_functions: Vec<FunctionCategory>,
    write_functions: Vec<FunctionCategory>,
    expires_before: Option<String>,
    related_rme_id: Option<String>,
    remaining_max_delegation_depth: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyDelegatedTokenPreview {
    token_hash: String,
    parent_token_hash: String,
    expires_at_ms: Option<u64>,
    delegation_depth: u8,
    proof_context: DelegationProofContext,
    effective: ProxyDelegationEffectivePreview,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProxyDelegationAttenuationResponse {
    related_rme_id: Option<String>,
    delegated_read_token: Option<String>,
    delegated_update_token: Option<String>,
    read_preview: Option<ProxyDelegatedTokenPreview>,
    update_preview: Option<ProxyDelegatedTokenPreview>,
}

async fn request_delegation_attenuation_from_proxy(
    mut payload: ProxyAttenuateDelegationPayload,
    delegator_iota_key_pair: &iota_types::crypto::IotaKeyPair,
) -> Result<ProxyDelegationAttenuationResponse, HospitalError> {
    let uses_preset = payload
        .preset
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false);
    let context = DelegationRequestProofContext {
        request_kind: if uses_preset { "admin" } else { "custom" }.to_string(),
        mode: payload.mode.clone(),
        delegator_iota_address: payload.delegator_iota_address.clone(),
        delegatee_iota_address: payload.delegatee_iota_address.clone(),
        patient_iota_address: payload.patient_iota_address.clone(),
        parent_read_token_hash: payload
            .parent_read_token
            .as_deref()
            .map(hash_macaroon_token),
        parent_write_token_hash: payload
            .parent_write_token
            .as_deref()
            .map(hash_macaroon_token),
        expires_before: payload.expires_before.clone(),
        related_rme_id: if uses_preset {
            None
        } else {
            payload.related_rme_id.clone()
        },
        preset: payload.preset.clone(),
        read_datasets: if uses_preset {
            Vec::new()
        } else {
            payload.read_datasets.clone()
        },
        write_datasets: if uses_preset {
            Vec::new()
        } else {
            payload.write_datasets.clone()
        },
        read_functions: if uses_preset {
            Vec::new()
        } else {
            payload.read_functions.clone()
        },
        write_functions: if uses_preset {
            Vec::new()
        } else {
            payload.write_functions.clone()
        },
    };
    payload.delegation_request_signature =
        sign_delegation_request_context(&context, delegator_iota_key_pair)?;

    let req_client = reqwest::Client::new();
    let res = do_http_post_request_json::<
        ProxyAttenuateDelegationPayload,
        ProxyReencryptionSuccessResponse<ProxyDelegationAttenuationResponse>,
        ProxyReencryptionErrorResponse,
    >(
        None,
        None,
        None,
        None,
        &format!("{}/delegations/attenuate", PROXY_BASE_URL),
        &payload,
        &req_client,
        StatusCode::OK,
    )
    .await?;

    Ok(res.data)
}

async fn request_admin_delegation_attenuation_from_proxy(
    payload: ProxyAttenuateDelegationPayload,
    delegator_iota_key_pair: &iota_types::crypto::IotaKeyPair,
) -> Result<ProxyDelegationAttenuationResponse, HospitalError> {
    request_delegation_attenuation_from_proxy(payload, delegator_iota_key_pair).await
}

#[command]
pub async fn create_delegated_access(
    state: State<'_, Mutex<AppState>>,
    payload: CreateDelegatedAccessPayload,
) -> Result<SuccessResponse<CreateDelegatedAccessResponse>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)?;

    let pin = state.auth_state.session_pin.clone().ok_or_else(|| {
        HospitalError::Anyhow(anyhow::anyhow!("Session PIN not found").context(current_fn!()))
    })?;

    let (delegator_pre_secret_key, delegator_iota_address, delegator_iota_key_pair) = {
        let (delegator_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let delegator_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let delegator_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        (
            delegator_pre_secret_key,
            delegator_iota_address,
            delegator_iota_key_pair,
        )
    };

    let delegatee_pre_public_key: PublicKey =
        serde_deserialize_from_base64(payload.delegatee_pre_public_key.clone())
            .context(current_fn!())?;
    let delegatee_iota_address =
        IotaAddress::from_str(&payload.delegatee_iota_address).context(current_fn!())?;
    let patient_iota_address =
        IotaAddress::from_str(&payload.patient_iota_address).context(current_fn!())?;

    let parent_capsule: Capsule =
        serde_deserialize_from_base64(payload.parent_data_pre_secret_key_seed_capsule.clone())
            .context(current_fn!())?;
    let data_pre_secret_key_seed = decrypt_original(
        &delegator_pre_secret_key,
        &parent_capsule,
        STANDARD
            .decode(&payload.parent_enc_data_pre_secret_key_seed)
            .context(current_fn!())?,
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()).context(current_fn!()))?;

    let (rewrap_capsule, rewrap_enc) =
        encrypt(&delegatee_pre_public_key, &data_pre_secret_key_seed)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let rewrap_enc_b64 = STANDARD.encode(rewrap_enc);
    let rewrap_capsule_b64 = serde_serialize_to_base64(&rewrap_capsule).context(current_fn!())?;

    let expires_before = parse_future_expires_before(&payload.expires_before)?;
    let read_datasets = parse_dataset_values(&payload.read_datasets)?;
    let write_datasets = parse_dataset_values(&payload.write_datasets)?;
    let read_functions = parse_function_values(&payload.read_functions)?;
    let write_functions = parse_function_values(&payload.write_functions)?;
    ensure_no_administrative_general_write(&write_functions)?;

    let mode = payload.mode.as_str();
    if !matches!(mode, "read" | "write" | "read_write") {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("Invalid delegation mode").context(current_fn!()),
        ));
    }

    let write_parent_related = payload
        .parent_write_token
        .as_deref()
        .map(related_rme_from_token)
        .transpose()?
        .flatten();
    let generated_write_related_rme_id = matches!(mode, "write" | "read_write")
        && payload.related_rme_id.is_none()
        && write_parent_related.is_none();

    let pre_attenuation = request_delegation_attenuation_from_proxy(
        ProxyAttenuateDelegationPayload {
            mode: payload.mode.clone(),
            parent_read_token: payload.parent_read_token.clone(),
            parent_write_token: payload.parent_write_token.clone(),
            parent_read_delegation_signature: payload.parent_read_delegation_signature.clone(),
            parent_write_delegation_signature: payload.parent_write_delegation_signature.clone(),
            delegator_iota_address: delegator_iota_address.to_string(),
            delegatee_iota_address: delegatee_iota_address.to_string(),
            patient_iota_address: payload.patient_iota_address.clone(),
            expires_before: payload.expires_before.clone(),
            related_rme_id: payload.related_rme_id.clone(),
            read_datasets: read_datasets.clone(),
            write_datasets: write_datasets.clone(),
            read_functions: read_functions.clone(),
            write_functions: write_functions.clone(),
            preset: None,
            delegation_request_signature: String::new(),
        },
        &delegator_iota_key_pair,
    )
    .await?;

    let read_effective_related_rme_id: Option<String> = None;
    let write_effective_related_rme_id = pre_attenuation.related_rme_id.clone();
    let response_related_rme_id = if matches!(mode, "write" | "read_write") {
        write_effective_related_rme_id.clone()
    } else {
        read_effective_related_rme_id.clone()
    };

    let delegator = delegator_iota_address.to_string();
    let delegatee = delegatee_iota_address.to_string();
    let mut on_chain_metadata = Vec::new();
    let mut on_chain_audit_metadata = Vec::new();
    let mut delegated_read_token = None;
    let mut delegated_update_token = None;

    if matches!(mode, "read" | "read_write") {
        let parent_read_token = payload.parent_read_token.as_ref().ok_or_else(|| {
            HospitalError::Anyhow(
                anyhow::anyhow!("Parent read token is required").context(current_fn!()),
            )
        })?;
        let read_params = build_delegation_params(
            &delegator,
            &delegatee,
            read_datasets.clone(),
            Vec::new(),
            read_functions.clone(),
            Vec::new(),
            expires_before,
            None,
        );
        let token = pre_attenuation
            .delegated_read_token
            .clone()
            .ok_or_else(|| {
                HospitalError::Anyhow(
                    anyhow::anyhow!("PRE did not return delegated read token")
                        .context(current_fn!()),
                )
            })?;
        let signature = sign_delegation_proof(
            &token,
            read_effective_related_rme_id.as_deref().unwrap_or_default(),
            &read_params,
            &delegator_iota_key_pair,
        )?;
        let metadata_input = DelegatedAccessMetadataInput {
            patient_iota_address: payload.patient_iota_address.clone(),
            patient_name: payload.patient_name.clone(),
            patient_pre_public_key: payload.patient_pre_public_key.clone(),
            related_rme_id: read_effective_related_rme_id.clone(),
        };
        let metadata = build_delegated_access_metadata(
            token.clone(),
            &metadata_input,
            &read_params,
            Some(signature),
            Some(rewrap_enc_b64.clone()),
            Some(rewrap_capsule_b64.clone()),
        );
        on_chain_metadata.push(
            serde_serialize_to_base64(&build_encrypted_metadata(
                &metadata,
                &delegatee_pre_public_key,
            )?)
            .context(current_fn!())?,
        );
        on_chain_audit_metadata.push(build_delegation_audit_input(
            &token,
            parent_read_token,
            MoveHospitalPersonnelAccessType::Read,
            read_effective_related_rme_id.clone(),
            expires_before,
        )?);
        delegated_read_token = Some(token);
    }

    if matches!(mode, "write" | "read_write") {
        let parent_write_token = payload.parent_write_token.as_ref().ok_or_else(|| {
            HospitalError::Anyhow(
                anyhow::anyhow!("Parent write token is required").context(current_fn!()),
            )
        })?;
        let update_params = build_delegation_params(
            &delegator,
            &delegatee,
            Vec::new(),
            write_datasets.clone(),
            Vec::new(),
            write_functions.clone(),
            expires_before,
            if write_parent_related.is_some() {
                None
            } else {
                write_effective_related_rme_id.clone()
            },
        );
        let token = pre_attenuation
            .delegated_update_token
            .clone()
            .ok_or_else(|| {
                HospitalError::Anyhow(
                    anyhow::anyhow!("PRE did not return delegated update token")
                        .context(current_fn!()),
                )
            })?;
        let signature = sign_delegation_proof(
            &token,
            write_effective_related_rme_id
                .as_deref()
                .unwrap_or_default(),
            &update_params,
            &delegator_iota_key_pair,
        )?;
        let metadata_input = DelegatedAccessMetadataInput {
            patient_iota_address: payload.patient_iota_address.clone(),
            patient_name: payload.patient_name.clone(),
            patient_pre_public_key: payload.patient_pre_public_key.clone(),
            related_rme_id: write_effective_related_rme_id.clone(),
        };
        let metadata = build_delegated_access_metadata(
            token.clone(),
            &metadata_input,
            &update_params,
            Some(signature),
            Some(rewrap_enc_b64.clone()),
            Some(rewrap_capsule_b64.clone()),
        );
        let encrypted = serde_serialize_to_base64(&build_encrypted_metadata(
            &metadata,
            &delegatee_pre_public_key,
        )?)
        .context(current_fn!())?;
        on_chain_metadata.push(encrypted);
        on_chain_audit_metadata.push(build_delegation_audit_input(
            &token,
            parent_write_token,
            MoveHospitalPersonnelAccessType::Update,
            write_effective_related_rme_id.clone(),
            expires_before,
        )?);
        delegated_update_token = Some(token);
    }

    let seed_outcome = if generated_write_related_rme_id {
        if let Some(parent_write_token) = payload.parent_write_token.as_deref() {
            match payload.patient_pre_public_key.as_deref() {
                Some(patient_pre_public_key) => {
                    let Some(new_rme_id) = response_related_rme_id.as_deref() else {
                        return Err(HospitalError::Anyhow(
                            anyhow::anyhow!("PRE did not return generated related_rme_id")
                                .context(current_fn!()),
                        ));
                    };
                    crate::rme_admin_seed::seed_administrative_general_segments(
                        parent_write_token,
                        payload.parent_read_token.as_deref(),
                        new_rme_id,
                        &payload.patient_iota_address,
                        patient_pre_public_key,
                        &delegator_iota_address.to_string(),
                        &keys_entry,
                        &pin,
                        &delegator_iota_key_pair,
                        expires_before,
                    )
                    .await
                    .unwrap_or_else(|e| {
                        crate::rme_admin_seed::SeedAdministrativeGeneralResult {
                            seeded: 0,
                            warnings: vec![format!("Administrative segment seed failed: {e}")],
                        }
                    })
                }
                None => crate::rme_admin_seed::SeedAdministrativeGeneralResult {
                    seeded: 0,
                    warnings: vec![
                        "Administrative segment seed skipped: patient_pre_public_key missing."
                            .into(),
                    ],
                },
            }
        } else {
            crate::rme_admin_seed::SeedAdministrativeGeneralResult::default()
        }
    } else {
        crate::rme_admin_seed::SeedAdministrativeGeneralResult::default()
    };

    let activation_key =
        encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;

    state
        .move_call
        .create_delegated_access(
            activation_key,
            delegatee_iota_address,
            patient_iota_address,
            on_chain_metadata,
            on_chain_audit_metadata,
            delegator_iota_address,
            delegator_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: CreateDelegatedAccessResponse {
            related_rme_id: response_related_rme_id,
            delegated_read_token,
            delegated_update_token,
            administrative_segments_seeded: seed_outcome.seeded,
            seed_warnings: seed_outcome.warnings,
        },
    })
}

#[command]
pub async fn create_admin_delegated_access(
    state: State<'_, Mutex<AppState>>,
    payload: CreateAdminDelegatedAccessPayload,
) -> Result<SuccessResponse<CreateAdminDelegatedAccessResponse>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)?;

    let pin = state.auth_state.session_pin.clone().ok_or_else(|| {
        HospitalError::Anyhow(anyhow::anyhow!("Session PIN not found").context(current_fn!()))
    })?;

    let (delegator_pre_secret_key, delegator_iota_address, delegator_iota_key_pair) = {
        let (delegator_pre_secret_key, _) =
            get_pre_keys_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let delegator_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let delegator_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        (
            delegator_pre_secret_key,
            delegator_iota_address,
            delegator_iota_key_pair,
        )
    };

    let delegatee_pre_public_key: PublicKey =
        serde_deserialize_from_base64(payload.delegatee_pre_public_key.clone())
            .context(current_fn!())?;
    let delegatee_iota_address =
        IotaAddress::from_str(&payload.delegatee_iota_address).context(current_fn!())?;
    let patient_iota_address =
        IotaAddress::from_str(&payload.patient_iota_address).context(current_fn!())?;

    let parent_capsule: Capsule =
        serde_deserialize_from_base64(payload.parent_data_pre_secret_key_seed_capsule.clone())
            .context(current_fn!())?;
    let data_pre_secret_key_seed = decrypt_original(
        &delegator_pre_secret_key,
        &parent_capsule,
        STANDARD
            .decode(&payload.parent_enc_data_pre_secret_key_seed)
            .context(current_fn!())?,
    )
    .map_err(|e| anyhow::anyhow!(e.to_string()).context(current_fn!()))?;

    let (rewrap_capsule, rewrap_enc) =
        encrypt(&delegatee_pre_public_key, &data_pre_secret_key_seed)
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;
    let rewrap_enc_b64 = STANDARD.encode(rewrap_enc);
    let rewrap_capsule_b64 = serde_serialize_to_base64(&rewrap_capsule).context(current_fn!())?;

    let parent_write_related_rme_id = related_rme_from_token(&payload.parent_write_token)?;
    let expires_before = parse_future_expires_before(&payload.expires_before)?;
    let parent_read_token = payload.parent_read_token.as_ref().ok_or_else(|| {
        HospitalError::Anyhow(
            anyhow::anyhow!("Parent read token is required for admin delegation")
                .context(current_fn!()),
        )
    })?;

    let pre_attenuation = request_admin_delegation_attenuation_from_proxy(
        ProxyAttenuateDelegationPayload {
            mode: "read_write".to_string(),
            parent_write_token: Some(payload.parent_write_token.clone()),
            parent_read_token: Some(parent_read_token.clone()),
            parent_read_delegation_signature: payload.parent_read_delegation_signature.clone(),
            parent_write_delegation_signature: payload.parent_write_delegation_signature.clone(),
            delegator_iota_address: delegator_iota_address.to_string(),
            delegatee_iota_address: delegatee_iota_address.to_string(),
            patient_iota_address: payload.patient_iota_address.clone(),
            expires_before: payload.expires_before.clone(),
            related_rme_id: None,
            read_datasets: Vec::new(),
            write_datasets: Vec::new(),
            read_functions: Vec::new(),
            write_functions: Vec::new(),
            preset: Some(payload.preset.clone()),
            delegation_request_signature: String::new(),
        },
        &delegator_iota_key_pair,
    )
    .await?;
    let related_rme_id = pre_attenuation.related_rme_id.clone().ok_or_else(|| {
        HospitalError::Anyhow(
            anyhow::anyhow!("PRE did not return related_rme_id for admin delegation")
                .context(current_fn!()),
        )
    })?;
    let delegated_read_token = pre_attenuation
        .delegated_read_token
        .clone()
        .ok_or_else(|| {
            HospitalError::Anyhow(
                anyhow::anyhow!("PRE did not return delegated read token").context(current_fn!()),
            )
        })?;
    let delegated_update_token =
        pre_attenuation
            .delegated_update_token
            .clone()
            .ok_or_else(|| {
                HospitalError::Anyhow(
                    anyhow::anyhow!("PRE did not return delegated update token")
                        .context(current_fn!()),
                )
            })?;

    let read_params = build_delegation_params(
        &delegator_iota_address.to_string(),
        &delegatee_iota_address.to_string(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        expires_before,
        None,
    );
    let update_params = build_delegation_params(
        &delegator_iota_address.to_string(),
        &delegatee_iota_address.to_string(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        expires_before,
        if parent_write_related_rme_id.is_some() {
            None
        } else {
            Some(related_rme_id.clone())
        },
    );

    let read_delegation_signature = sign_delegation_proof(
        &delegated_read_token,
        &related_rme_id,
        &read_params,
        &delegator_iota_key_pair,
    )?;
    let update_delegation_signature = sign_delegation_proof(
        &delegated_update_token,
        &related_rme_id,
        &update_params,
        &delegator_iota_key_pair,
    )?;

    let patient_iota_address_for_seed = payload.patient_iota_address.clone();
    let patient_pre_public_key_for_seed = payload.patient_pre_public_key.clone();

    let read_metadata_input = DelegatedAccessMetadataInput {
        patient_iota_address: payload.patient_iota_address.clone(),
        patient_name: payload.patient_name.clone(),
        patient_pre_public_key: payload.patient_pre_public_key.clone(),
        related_rme_id: None,
    };
    let update_metadata_input = DelegatedAccessMetadataInput {
        patient_iota_address: payload.patient_iota_address,
        patient_name: payload.patient_name,
        patient_pre_public_key: payload.patient_pre_public_key,
        related_rme_id: Some(related_rme_id.clone()),
    };

    let read_metadata = build_delegated_access_metadata(
        delegated_read_token.clone(),
        &read_metadata_input,
        &read_params,
        Some(read_delegation_signature),
        Some(rewrap_enc_b64.clone()),
        Some(rewrap_capsule_b64.clone()),
    );
    let enc_read = build_encrypted_metadata(&read_metadata, &delegatee_pre_public_key)?;

    let update_metadata = build_delegated_access_metadata(
        delegated_update_token.clone(),
        &update_metadata_input,
        &update_params,
        Some(update_delegation_signature),
        Some(rewrap_enc_b64),
        Some(rewrap_capsule_b64),
    );
    let enc_update = build_encrypted_metadata(&update_metadata, &delegatee_pre_public_key)?;

    let on_chain_metadata = vec![
        serde_serialize_to_base64(&enc_read).context(current_fn!())?,
        serde_serialize_to_base64(&enc_update).context(current_fn!())?,
    ];
    let on_chain_audit_metadata = vec![
        build_delegation_audit_input(
            &delegated_read_token,
            parent_read_token,
            MoveHospitalPersonnelAccessType::Read,
            None,
            expires_before,
        )?,
        build_delegation_audit_input(
            &delegated_update_token,
            &payload.parent_write_token,
            MoveHospitalPersonnelAccessType::Update,
            Some(related_rme_id.clone()),
            expires_before,
        )?,
    ];

    let seed_outcome = match patient_pre_public_key_for_seed.as_deref() {
        Some(patient_pre_public_key) => {
            crate::rme_admin_seed::seed_administrative_general_segments(
                &payload.parent_write_token,
                payload.parent_read_token.as_deref(),
                &related_rme_id,
                &patient_iota_address_for_seed,
                patient_pre_public_key,
                &delegator_iota_address.to_string(),
                &keys_entry,
                &pin,
                &delegator_iota_key_pair,
                expires_before,
            )
            .await
            .unwrap_or_else(|e| {
                crate::rme_admin_seed::SeedAdministrativeGeneralResult {
                    seeded: 0,
                    warnings: vec![format!("Administrative segment seed failed: {e}")],
                }
            })
        }
        None => crate::rme_admin_seed::SeedAdministrativeGeneralResult {
            seeded: 0,
            warnings: vec![
                "Administrative segment seed skipped: patient_pre_public_key missing.".into(),
            ],
        },
    };

    let activation_key =
        encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;

    state
        .move_call
        .create_delegated_access(
            activation_key,
            delegatee_iota_address,
            patient_iota_address,
            on_chain_metadata,
            on_chain_audit_metadata,
            delegator_iota_address,
            delegator_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: CreateAdminDelegatedAccessResponse {
            related_rme_id,
            delegated_read_token,
            delegated_update_token,
            administrative_segments_seeded: seed_outcome.seeded,
            seed_warnings: seed_outcome.warnings,
        },
    })
}
