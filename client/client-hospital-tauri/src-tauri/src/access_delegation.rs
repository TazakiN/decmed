use std::str::FromStr;

use anyhow::Context;
use chrono::{DateTime, Utc};
use decmed_macaroon_auth::{
    attenuate_macaroon, generate_related_rme_id, hash_macaroon_token, CaveatKey, CaveatValue,
    DelegationAttenuationParams, DelegationProofContext, EffectiveCapability, ParsedCaveats,
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
use tauri::{async_runtime::Mutex, command, State};
use umbral_pre::{decrypt_original, encrypt, Capsule, PublicKey, SecretKey};

use crate::{
    current_fn,
    hospital_error::HospitalError,
    types::{
        AccessData, AccessMetadata, AccessMetadataEncrypted, AppState, HospitalPersonnelRole,
        MoveHospitalPersonnelAccessData, ResponseStatus, SuccessResponse,
    },
    utils::{
        encode_activation_key_from_keys_entry, get_iota_address_from_keys_entry,
        get_iota_key_pair_from_keys_entry, get_pre_keys_from_keys_entry, parse_keys_entry,
        serde_deserialize_from_base64, serde_serialize_to_base64,
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
    let mac = macaroon::Macaroon::deserialize(&access.access_token).map_err(|e| {
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
    ) = if parsed.is_decmed_token() {
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
    } else {
        let all_datasets = sort_datasets(ALL_DATASET_CATEGORIES.to_vec());
        let all_functions = sort_functions(ALL_FUNCTION_CATEGORIES.to_vec());
        let (read_datasets, write_datasets, read_functions, write_functions) =
            match fallback_purpose {
                "Update" => (Vec::new(), all_datasets, Vec::new(), all_functions),
                _ => (all_datasets, Vec::new(), all_functions, Vec::new()),
            };
        (
            read_datasets,
            write_datasets,
            read_functions,
            write_functions,
            access.expires_before.clone(),
            access.related_rme_id.clone(),
            access.delegation_depth.map(u32::from),
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
    let mac = macaroon::Macaroon::deserialize(token).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    if !parsed.is_decmed_token() {
        return Ok(None);
    }
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
        require_wallet_proof: true,
        related_rme_id,
    }
}

fn normalize_scope_pair<T: Clone>(primary: &[T], fallback: &[T]) -> Vec<T> {
    if primary.is_empty() {
        fallback.to_vec()
    } else {
        primary.to_vec()
    }
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

fn sign_delegation_proof(
    token: &str,
    related_rme_id: &str,
    params: &DelegationAttenuationParams,
    delegator_iota_key_pair: &iota_types::crypto::IotaKeyPair,
) -> Result<String, HospitalError> {
    let proof_ctx = DelegationProofContext::from_delegation(token, related_rme_id, params);
    let canonical = proof_ctx.canonical_message().map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let signature = Signature::new_secure(&intent_message, delegator_iota_key_pair);
    Ok(signature.encode_base64())
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

fn encounter_from_write_token(token: &str) -> Result<DatasetCategory, HospitalError> {
    let mac = macaroon::Macaroon::deserialize(token).map_err(|e| {
        HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
    })?;
    let effective =
        EffectiveCapability::from_parsed(&ParsedCaveats::from_macaroon(&mac).map_err(|e| {
            HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
        })?)
        .map_err(|e| {
            HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
        })?;
    effective
        .write_datasets
        .iter()
        .find(|d| {
            matches!(
                d,
                DatasetCategory::RAWAT_JALAN | DatasetCategory::RAWAT_INAP
            )
        })
        .copied()
        .ok_or_else(|| {
            HospitalError::Anyhow(
                anyhow::anyhow!("write parent missing RAWAT encounter dataset")
                    .context(current_fn!()),
            )
        })
}

fn admin_delegation_params(
    preset: &str,
    encounter: DatasetCategory,
    delegator: &str,
    delegatee: &str,
    related_rme_id: &str,
    expires_before: DateTime<Utc>,
) -> Result<DelegationAttenuationParams, HospitalError> {
    let mut params = match preset {
        "doctor" => DelegationAttenuationParams::example_admin_delegate_to_doctor(
            delegator,
            delegatee,
            related_rme_id,
            encounter,
        ),
        "nurse" => {
            let mut p = DelegationAttenuationParams::example_nurse_delegation(delegator, delegatee);
            p.read_datasets = vec![encounter];
            p.write_datasets = vec![encounter];
            p.related_rme_id = Some(related_rme_id.to_string());
            p
        }
        "lab" => {
            let mut p = DelegationAttenuationParams::example_lab_delegation(delegator, delegatee);
            p.related_rme_id = Some(related_rme_id.to_string());
            p
        }
        "apotek" => {
            let mut p =
                DelegationAttenuationParams::example_apotek_delegation(delegator, delegatee);
            p.related_rme_id = Some(related_rme_id.to_string());
            p
        }
        _ => {
            return Err(HospitalError::Anyhow(
                anyhow::anyhow!("Unknown preset: {preset}").context(current_fn!()),
            ))
        }
    };
    params.expires_before = expires_before;
    params.require_wallet_proof = true;
    Ok(params)
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminDelegatedAccessPayload {
    pub parent_write_token: String,
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
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDelegatedAccessPayload {
    pub mode: String,
    pub parent_read_token: Option<String>,
    pub parent_write_token: Option<String>,
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
            get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;
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

    let expires_before = DateTime::parse_from_rfc3339(&payload.expires_before)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_timezone(&Utc);
    let read_datasets = parse_dataset_values(&payload.read_datasets)?;
    let write_datasets = parse_dataset_values(&payload.write_datasets)?;
    let read_functions = parse_function_values(&payload.read_functions)?;
    let write_functions = parse_function_values(&payload.write_functions)?;

    let mode = payload.mode.as_str();
    if !matches!(mode, "read" | "write" | "read_write") {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("Invalid delegation mode").context(current_fn!()),
        ));
    }

    let read_parent_related = payload
        .parent_read_token
        .as_deref()
        .map(related_rme_from_token)
        .transpose()?
        .flatten();
    let write_parent_related = payload
        .parent_write_token
        .as_deref()
        .map(related_rme_from_token)
        .transpose()?
        .flatten();
    let final_related_rme_id = payload
        .related_rme_id
        .clone()
        .or_else(|| write_parent_related.clone())
        .or_else(|| read_parent_related.clone())
        .or_else(|| {
            if matches!(mode, "write" | "read_write") {
                Some(generate_related_rme_id(Utc::now()))
            } else {
                None
            }
        });

    let metadata_input = DelegatedAccessMetadataInput {
        patient_iota_address: payload.patient_iota_address,
        patient_name: payload.patient_name,
        patient_pre_public_key: payload.patient_pre_public_key,
        related_rme_id: final_related_rme_id.clone(),
    };

    let delegator = delegator_iota_address.to_string();
    let delegatee = delegatee_iota_address.to_string();
    let mut on_chain_metadata = Vec::new();
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
            normalize_scope_pair(&write_datasets, &read_datasets),
            read_functions.clone(),
            normalize_scope_pair(&write_functions, &read_functions),
            expires_before,
            if read_parent_related.is_some() {
                None
            } else {
                final_related_rme_id.clone()
            },
        );
        let token = attenuate_macaroon(parent_read_token, &read_params).map_err(|e| {
            HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
        })?;
        let signature = sign_delegation_proof(
            &token,
            final_related_rme_id.as_deref().unwrap_or_default(),
            &read_params,
            &delegator_iota_key_pair,
        )?;
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
            normalize_scope_pair(&read_datasets, &write_datasets),
            write_datasets.clone(),
            normalize_scope_pair(&read_functions, &write_functions),
            write_functions.clone(),
            expires_before,
            if write_parent_related.is_some() {
                None
            } else {
                final_related_rme_id.clone()
            },
        );
        let token = attenuate_macaroon(parent_write_token, &update_params).map_err(|e| {
            HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
        })?;
        let signature = sign_delegation_proof(
            &token,
            final_related_rme_id.as_deref().unwrap_or_default(),
            &update_params,
            &delegator_iota_key_pair,
        )?;
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
        if mode == "write" {
            on_chain_metadata.push(encrypted.clone());
        }
        on_chain_metadata.push(encrypted);
        delegated_update_token = Some(token);
    }

    let activation_key =
        encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;

    state
        .move_call
        .create_delegated_access(
            activation_key,
            delegatee_iota_address,
            patient_iota_address,
            on_chain_metadata,
            delegator_iota_address,
            delegator_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: CreateDelegatedAccessResponse {
            related_rme_id: final_related_rme_id,
            delegated_read_token,
            delegated_update_token,
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
            get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;
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

    let encounter = encounter_from_write_token(&payload.parent_write_token)?;
    let related_rme_id = generate_related_rme_id(Utc::now());
    let expires_before = DateTime::parse_from_rfc3339(&payload.expires_before)
        .map_err(|e| anyhow::anyhow!(e))?
        .with_timezone(&Utc);
    let params = admin_delegation_params(
        &payload.preset,
        encounter,
        &delegator_iota_address.to_string(),
        &delegatee_iota_address.to_string(),
        &related_rme_id,
        expires_before,
    )?;

    let delegated_read_token =
        attenuate_macaroon(&payload.parent_write_token, &params).map_err(|e| {
            HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
        })?;
    let delegated_update_token =
        attenuate_macaroon(&payload.parent_write_token, &params).map_err(|e| {
            HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!()))
        })?;

    let read_delegation_signature = sign_delegation_proof(
        &delegated_read_token,
        &related_rme_id,
        &params,
        &delegator_iota_key_pair,
    )?;
    let update_delegation_signature = sign_delegation_proof(
        &delegated_update_token,
        &related_rme_id,
        &params,
        &delegator_iota_key_pair,
    )?;

    let metadata_input = DelegatedAccessMetadataInput {
        patient_iota_address: payload.patient_iota_address,
        patient_name: payload.patient_name,
        patient_pre_public_key: payload.patient_pre_public_key,
        related_rme_id: Some(related_rme_id.clone()),
    };

    let read_metadata = build_delegated_access_metadata(
        delegated_read_token.clone(),
        &metadata_input,
        &params,
        Some(read_delegation_signature),
        Some(rewrap_enc_b64.clone()),
        Some(rewrap_capsule_b64.clone()),
    );
    let enc_read = build_encrypted_metadata(&read_metadata, &delegatee_pre_public_key)?;

    let update_metadata = build_delegated_access_metadata(
        delegated_update_token.clone(),
        &metadata_input,
        &params,
        Some(update_delegation_signature),
        Some(rewrap_enc_b64),
        Some(rewrap_capsule_b64),
    );
    let enc_update = build_encrypted_metadata(&update_metadata, &delegatee_pre_public_key)?;

    let on_chain_metadata = vec![
        serde_serialize_to_base64(&enc_read).context(current_fn!())?,
        serde_serialize_to_base64(&enc_update).context(current_fn!())?,
    ];

    let activation_key =
        encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;

    state
        .move_call
        .create_delegated_access(
            activation_key,
            delegatee_iota_address,
            patient_iota_address,
            on_chain_metadata,
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
        },
    })
}
