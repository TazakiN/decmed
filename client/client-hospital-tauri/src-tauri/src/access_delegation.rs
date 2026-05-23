use std::str::FromStr;

use anyhow::Context;
use chrono::{DateTime, Utc};
use decmed_macaroon_auth::{
    attenuate_macaroon, generate_related_rme_id, hash_macaroon_token, DelegationAttenuationParams,
    DelegationProofContext, EffectiveCapability, ParsedCaveats,
};
use decmed_rme_segment::DatasetCategory;
use iota_types::{
    base_types::IotaAddress,
    crypto::{EncodeDecodeBase64, Signature},
};
use serde::{Deserialize, Serialize};
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, command, State};
use umbral_pre::{decrypt_original, encrypt, Capsule, PublicKey};

use crate::{
    current_fn,
    hospital_error::HospitalError,
    types::{AccessMetadata, AccessMetadataEncrypted, AppState, ResponseStatus, SuccessResponse},
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
    let canonical = proof_ctx
        .canonical_message()
        .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!())))?;
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
    related_rme_id: String,
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
        related_rme_id: Some(payload.related_rme_id.clone()),
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
    let mac = macaroon::Macaroon::deserialize(token)
        .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!())))?;
    let effective = EffectiveCapability::from_parsed(
        &ParsedCaveats::from_macaroon(&mac)
            .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!())))?,
    )
    .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!())))?;
    effective
        .write_datasets
        .iter()
        .find(|d| matches!(d, DatasetCategory::RAWAT_JALAN | DatasetCategory::RAWAT_INAP))
        .copied()
        .ok_or_else(|| {
            HospitalError::Anyhow(
                anyhow::anyhow!("write parent missing RAWAT encounter dataset").context(current_fn!()),
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
            let mut p = DelegationAttenuationParams::example_apotek_delegation(delegator, delegatee);
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

#[command]
pub async fn create_admin_delegated_access(
    state: State<'_, Mutex<AppState>>,
    payload: CreateAdminDelegatedAccessPayload,
) -> Result<SuccessResponse<CreateAdminDelegatedAccessResponse>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)?;

    let pin = state
        .auth_state
        .session_pin
        .clone()
        .ok_or_else(|| HospitalError::Anyhow(anyhow::anyhow!("Session PIN not found").context(current_fn!())))?;

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

    let (rewrap_capsule, rewrap_enc) = encrypt(&delegatee_pre_public_key, &data_pre_secret_key_seed)
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
        related_rme_id: related_rme_id.clone(),
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
