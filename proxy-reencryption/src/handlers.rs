use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::{Extension, Json};
use decmed_rme_segment::{
    ClientEncryptedRmeSegment, CreateRmeSegmentResponse, DatasetCategory, FunctionCategory,
    RmeSegmentMetadata, ALL_DATASET_CATEGORIES, ALL_FUNCTION_CATEGORIES,
};
use iota_types::base_types::IotaAddress;
use iota_types::crypto::{
    EncodeDecodeBase64, IotaKeyPair, IotaSignature, Signature, SignatureScheme,
};

use redis::{Commands, SetExpiry, SetOptions};
use serde_json::{json, Value};
use shared_crypto::intent::{Intent, IntentMessage};
use umbral_pre::{reencrypt, Capsule, KeyFrag, PublicKey};

use crate::constants::{
    ADMINISTRATIVE_RAWAT_INAP_KEYS_DUR, ADMINISTRATIVE_RAWAT_JALAN_KEYS_DUR, MEDICAL_KEYS_READ_DUR,
    MEDICAL_KEYS_UPDATE_DUR, NONCE_EXP_DUR,
};
use crate::current_fn;
use crate::macaroon_auth::{map_caveat_error, IotaWalletVerifier};
use crate::middlewares::{
    ensure_token_not_revoked, WALLET_SIGNATURE_HEADER, WALLET_TIMESTAMP_HEADER,
};
use crate::proxy_error::{ProxyError, ResultExt};
use crate::segment_authorization::{authorize_create_rme_segment, authorize_segment_hospital};
use crate::types::{
    AccessKeys, AppState, AuthRole, ClientMedicalMetadata, CurrentUser, DelegatedTokenPreview,
    DelegationAttenuationHandlerResponse, DelegationEffectivePreview,
    GenerateMacaroonKeyHandlerResponse, GenerateRelatedRmeIdResponse,
    GenerateSignatureHandlerPayload, GetNonceHandlerPayload, HandlerAttenuateDelegationPayload,
    HandlerCreateMedicalRecordPayload, HandlerCreateMedicalRecordSegmentPayload,
    HandlerGetAdministrativeDataQueryParams, HandlerGetMedicalRecordQueryParams,
    HandlerGetMedicalRecordUpdateQueryParams, HandlerListMedicalRecordsQueryParams,
    HandlerStoreKeysPayload, HandlerUpdateMedicalRecordPayload, MedicalMetadata,
    MedicalRecordMetadataItem, MoveDelegationAccessSnapshot, MoveHospitalPersonnelRole,
    PatientPrivateAdministrativeMetadata, PatientRevocationSignedPayload, ReencryptionPurposeType,
};
use crate::utils::Utils;
use decmed_macaroon_auth::{
    admin_all_datasets, admin_all_functions, admin_write_datasets, admin_write_functions,
    attenuate_macaroon, format_related_rme_id, hash_token, issue_admin_personnel_token,
    verify_macaroon_signature, AccessMode, AdminTokenKind, DelegationAttenuationParams,
    DelegationChain, DelegationProofContext, DelegationRequestProofContext, EffectiveCapability,
    InitialAdminPersonnelTokenParams, Macaroon, MacaroonKey, ParsedCaveats,
};
use decmed_macaroon_auth::{
    verify_decmed_token, CaveatVerificationError, SegmentAccessContext, TokenVerificationContext,
    WalletProofContext,
};

const RME_COUNTER_KEY: &str = "rme:encounter-counter";

pub struct Handlers {}

#[derive(Debug)]
struct StoredMedicalMetadata {
    capsule: String,
    cid: String,
    created_at: String,
    enc_key_and_nonce: String,
}

fn deserialize_stored_medical_metadata(
    metadata: String,
) -> Result<StoredMedicalMetadata, ProxyError> {
    let metadata_value: Value = Utils::serde_deserialize_from_base64(metadata)
        .map_err(|_| anyhow!("Invalid stored medical metadata"))
        .code(StatusCode::BAD_REQUEST)?;

    if let Ok(metadata) = serde_json::from_value::<MedicalMetadata>(metadata_value.clone()) {
        return Ok(StoredMedicalMetadata {
            capsule: metadata.capsule,
            cid: metadata.cid,
            created_at: metadata.created_at,
            enc_key_and_nonce: metadata.enc_key_and_nonce,
        });
    }

    let segment_metadata: RmeSegmentMetadata = serde_json::from_value(metadata_value)
        .map_err(|_| anyhow!("Invalid stored RME segment metadata"))
        .code(StatusCode::BAD_REQUEST)?;
    segment_metadata
        .validate()
        .map_err(|e| anyhow!(e.to_string()))
        .code(StatusCode::BAD_REQUEST)?;

    Ok(StoredMedicalMetadata {
        capsule: segment_metadata.capsule,
        cid: segment_metadata.ipfs_cid,
        created_at: segment_metadata.created_at,
        enc_key_and_nonce: segment_metadata.enc_key_and_nonce,
    })
}

fn access_key_subject_candidates(current_user: &CurrentUser) -> Vec<String> {
    let mut candidates = vec![current_user.iota_address.clone()];

    if let Some(verified) = current_user.decmed_token.as_ref() {
        for step in verified.delegation.steps.iter().rev() {
            candidates.push(step.delegated_by.clone());
        }
        candidates.push(verified.delegation.root_subject.clone());
    }

    let mut unique = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if !unique.iter().any(|seen| seen == &candidate) {
            unique.push(candidate);
        }
    }
    unique
}

fn administrative_keys_duration(encounter_dataset: DatasetCategory) -> u64 {
    match encounter_dataset {
        DatasetCategory::RAWAT_JALAN => ADMINISTRATIVE_RAWAT_JALAN_KEYS_DUR,
        DatasetCategory::RAWAT_INAP => ADMINISTRATIVE_RAWAT_INAP_KEYS_DUR,
        _ => 0,
    }
}

fn parse_requested_expiry(
    expires_before: Option<&str>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, ProxyError> {
    let Some(expires_before) = expires_before.filter(|value| !value.trim().is_empty()) else {
        return Ok(None);
    };
    let expiry = chrono::DateTime::parse_from_rfc3339(expires_before)
        .map_err(|e| ProxyError::Anyhow {
            source: anyhow!("Invalid expires_before; expected RFC3339: {e}"),
            code: StatusCode::BAD_REQUEST,
        })?
        .with_timezone(&chrono::Utc);
    if expiry <= now {
        return Err(ProxyError::Anyhow {
            source: anyhow!("expires_before must be in the future"),
            code: StatusCode::BAD_REQUEST,
        });
    }
    Ok(Some(expiry))
}

fn expiry_ttl_secs(
    expires_before: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<u64, ProxyError> {
    let remaining_ms = expires_before.signed_duration_since(now).num_milliseconds();
    if remaining_ms <= 0 {
        return Err(ProxyError::Anyhow {
            source: anyhow!("expires_before must be in the future"),
            code: StatusCode::BAD_REQUEST,
        });
    }
    Ok(((remaining_ms as u64) + 999) / 1000)
}

fn max_revocation_ttl_secs() -> u64 {
    [
        ADMINISTRATIVE_RAWAT_JALAN_KEYS_DUR,
        ADMINISTRATIVE_RAWAT_INAP_KEYS_DUR,
        MEDICAL_KEYS_READ_DUR,
        MEDICAL_KEYS_UPDATE_DUR,
    ]
    .into_iter()
    .max()
    .unwrap_or(24 * 60 * 60)
}

fn revocation_ttl(expires_before: Option<&str>) -> Result<u64, ProxyError> {
    let Some(expires_before) = expires_before.filter(|v| !v.trim().is_empty()) else {
        return Ok(max_revocation_ttl_secs());
    };

    let expiry = if let Ok(epoch_secs) = expires_before.parse::<i64>() {
        chrono::DateTime::<chrono::Utc>::from_timestamp(epoch_secs, 0).ok_or_else(|| {
            ProxyError::Anyhow {
                source: anyhow!("Invalid expires_before epoch seconds"),
                code: StatusCode::BAD_REQUEST,
            }
        })?
    } else {
        chrono::DateTime::parse_from_rfc3339(expires_before)
            .map_err(|_| ProxyError::Anyhow {
                source: anyhow!("Invalid expires_before; expected RFC3339 or epoch seconds"),
                code: StatusCode::BAD_REQUEST,
            })?
            .with_timezone(&chrono::Utc)
    };

    let remaining = expiry
        .signed_duration_since(chrono::Utc::now())
        .num_seconds();
    if remaining <= 0 {
        return Err(ProxyError::Anyhow {
            source: anyhow!("expires_before is already expired"),
            code: StatusCode::BAD_REQUEST,
        });
    }
    Ok(remaining as u64)
}

fn reserve_related_rme_id(conn: &mut redis::Connection) -> Result<String, ProxyError> {
    let sequence: u64 = conn.incr(RME_COUNTER_KEY, 1).context(current_fn!())?;

    // related_rme_id is the encounter/RME id. Do not derive it from
    // metadata.index; that index identifies individual segment metadata.
    Ok(format_related_rme_id(sequence))
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

fn datetime_to_epoch_ms(value: chrono::DateTime<chrono::Utc>) -> Result<u64, ProxyError> {
    let millis = value.timestamp_millis();
    if millis < 0 {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Delegation expiry is before Unix epoch"),
            code: StatusCode::BAD_REQUEST,
        });
    }
    Ok(millis as u64)
}

fn parse_future_delegation_expiry(
    value: &str,
) -> Result<chrono::DateTime<chrono::Utc>, ProxyError> {
    let expires_before = chrono::DateTime::parse_from_rfc3339(value)
        .map_err(|e| ProxyError::Anyhow {
            source: anyhow!("Invalid expires_before; expected RFC3339: {e}"),
            code: StatusCode::BAD_REQUEST,
        })?
        .with_timezone(&chrono::Utc);
    if expires_before <= chrono::Utc::now() {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Delegation expiry must be in the future"),
            code: StatusCode::BAD_REQUEST,
        });
    }
    Ok(expires_before)
}

fn ensure_scope_requested(
    mode: &str,
    datasets_empty: bool,
    functions_empty: bool,
) -> Result<(), ProxyError> {
    if datasets_empty || functions_empty {
        return Err(ProxyError::Anyhow {
            source: anyhow!("{mode} delegation requires non-empty dataset and function scope"),
            code: StatusCode::BAD_REQUEST,
        });
    }
    Ok(())
}

fn ensure_no_administrative_general_write(
    write_functions: &[FunctionCategory],
) -> Result<(), ProxyError> {
    if write_functions.contains(&FunctionCategory::ADMINISTRATIVE_GENERAL) {
        return Err(ProxyError::Anyhow {
            source: anyhow!("ADMINISTRATIVE_GENERAL cannot be delegated with write/update access"),
            code: StatusCode::BAD_REQUEST,
        });
    }
    Ok(())
}

fn verify_delegation_request_signature(
    context: &DelegationRequestProofContext,
    signature_b64: &str,
    delegator_iota_address: &str,
) -> Result<(), ProxyError> {
    let signature =
        Utils::construct_signature_from_str(signature_b64).map_err(|_| ProxyError::Anyhow {
            source: anyhow!("Invalid delegation request signature format"),
            code: StatusCode::UNAUTHORIZED,
        })?;
    let address =
        IotaAddress::from_str(delegator_iota_address).map_err(|_| ProxyError::Anyhow {
            source: anyhow!("Invalid delegator address"),
            code: StatusCode::BAD_REQUEST,
        })?;
    let message = context.canonical_message().map_err(map_caveat_error)?;
    let intent_message = IntentMessage::new(Intent::personal_message(), message);
    signature
        .verify_secure(&intent_message, address, SignatureScheme::ED25519)
        .map_err(|_| ProxyError::Anyhow {
            source: anyhow!("Delegation request signature mismatch"),
            code: StatusCode::UNAUTHORIZED,
        })?;
    Ok(())
}

#[derive(Clone, Debug)]
struct VerifiedParentDelegationToken {
    effective: EffectiveCapability,
}

fn verify_parent_token_for_delegation(
    conn: &mut redis::Connection,
    root_key: &MacaroonKey,
    parent_token: &str,
    parent_delegation_signature: Option<&str>,
    delegator_iota_address: &str,
    patient_iota_address: &str,
) -> Result<VerifiedParentDelegationToken, ProxyError> {
    let mac = Macaroon::deserialize(parent_token).map_err(|e| ProxyError::Anyhow {
        source: anyhow!("Invalid parent token format: {e}"),
        code: StatusCode::UNAUTHORIZED,
    })?;
    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(map_caveat_error)?;
    if !parsed.is_decmed_token() {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Parent token is not a valid DecMed token"),
            code: StatusCode::UNAUTHORIZED,
        });
    }
    verify_macaroon_signature(&mac, root_key).map_err(map_caveat_error)?;

    let effective = EffectiveCapability::from_parsed(&parsed).map_err(map_caveat_error)?;
    if effective.patient_address.as_deref() != Some(patient_iota_address) {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Parent token patient does not match request"),
            code: StatusCode::FORBIDDEN,
        });
    }
    if effective.is_expired(chrono::Utc::now()) {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Parent token has expired"),
            code: StatusCode::UNAUTHORIZED,
        });
    }

    let delegation = DelegationChain::from_parsed(&parsed).map_err(map_caveat_error)?;
    if delegation.active_subject != delegator_iota_address {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Parent token active subject is not the requested delegator"),
            code: StatusCode::FORBIDDEN,
        });
    }
    if let Some(root_budget) = effective.root_max_delegation_depth {
        if delegation.delegation_depth() as u32 > root_budget {
            return Err(map_caveat_error(
                CaveatVerificationError::DelegationDepthExceeded,
            ));
        }
    }

    ensure_token_not_revoked(&parsed, &delegation, parent_token, |key| {
        conn.exists(key).map_err(|e| ProxyError::Anyhow {
            source: anyhow!("Revocation check failed: {e}"),
            code: StatusCode::SERVICE_UNAVAILABLE,
        })
    })?;

    if let Some(last) = delegation.steps.last() {
        if last.delegated_by != last.delegated_to {
            let signature = parent_delegation_signature.ok_or_else(|| ProxyError::Anyhow {
                source: anyhow!("Parent delegated token requires delegation signature"),
                code: StatusCode::UNAUTHORIZED,
            })?;
            crate::macaroon_auth::verify_delegation_proof(parent_token, signature)?;
        }
    }

    Ok(VerifiedParentDelegationToken { effective })
}

fn effective_preview(effective: &EffectiveCapability) -> DelegationEffectivePreview {
    DelegationEffectivePreview {
        read_datasets: sort_datasets(effective.read_datasets.iter().copied().collect()),
        write_datasets: sort_datasets(effective.write_datasets.iter().copied().collect()),
        read_functions: sort_functions(effective.read_functions.iter().copied().collect()),
        write_functions: sort_functions(effective.write_functions.iter().copied().collect()),
        expires_before: effective
            .expires_before
            .map(|value| value.format("%Y-%m-%dT%H:%M:%S").to_string()),
        related_rme_id: effective.related_rme_id.clone(),
        remaining_max_delegation_depth: effective.remaining_max_delegation_depth,
    }
}

fn build_delegated_token_preview(
    token: &str,
    parent_token: &str,
    expected_delegation_depth: u8,
) -> Result<DelegatedTokenPreview, ProxyError> {
    let mac = Macaroon::deserialize(token).map_err(|e| ProxyError::Anyhow {
        source: anyhow!("Invalid delegated token format: {e}"),
        code: StatusCode::INTERNAL_SERVER_ERROR,
    })?;
    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(map_caveat_error)?;
    let effective = EffectiveCapability::from_parsed(&parsed).map_err(map_caveat_error)?;
    let delegation = DelegationChain::from_parsed(&parsed).map_err(map_caveat_error)?;
    let delegation_depth =
        u8::try_from(delegation.delegation_depth()).map_err(|_| ProxyError::Anyhow {
            source: anyhow!("Delegation depth exceeds u8"),
            code: StatusCode::BAD_REQUEST,
        })?;
    if delegation_depth != expected_delegation_depth {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Delegated token depth does not match on-chain access depth"),
            code: StatusCode::FORBIDDEN,
        });
    }
    let expires_at_ms = effective
        .expires_before
        .map(datetime_to_epoch_ms)
        .transpose()?;
    let proof_context = DelegationProofContext::from_token(token).map_err(map_caveat_error)?;

    Ok(DelegatedTokenPreview {
        token_hash: hash_token(token),
        parent_token_hash: hash_token(parent_token),
        expires_at_ms,
        delegation_depth,
        proof_context,
        effective: effective_preview(&effective),
    })
}

fn ensure_effective_mode_scope(
    preview: &DelegatedTokenPreview,
    mode: AccessMode,
) -> Result<(), ProxyError> {
    let allowed = match mode {
        AccessMode::Read => {
            !preview.effective.read_datasets.is_empty()
                && !preview.effective.read_functions.is_empty()
        }
        AccessMode::Write => {
            !preview.effective.write_datasets.is_empty()
                && !preview.effective.write_functions.is_empty()
        }
    };
    if !allowed {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Delegated token has empty effective scope"),
            code: StatusCode::FORBIDDEN,
        });
    }
    Ok(())
}

fn ensure_requested_expiry_within_snapshot(
    expires_at_ms: u64,
    snapshot: &MoveDelegationAccessSnapshot,
    requires_read: bool,
    requires_update: bool,
) -> Result<(), ProxyError> {
    if requires_read && expires_at_ms > snapshot.read_exp {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Delegation expiry exceeds delegator read access expiry"),
            code: StatusCode::FORBIDDEN,
        });
    }
    if requires_update && expires_at_ms > snapshot.update_exp {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Delegation expiry exceeds delegator update access expiry"),
            code: StatusCode::FORBIDDEN,
        });
    }
    Ok(())
}

fn ensure_snapshot_depths_compatible(
    snapshot: &MoveDelegationAccessSnapshot,
    requires_read: bool,
    requires_update: bool,
) -> Result<(), ProxyError> {
    if requires_read
        && requires_update
        && snapshot.read_delegation_depth != snapshot.update_delegation_depth
    {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Read and update delegation depths differ on-chain"),
            code: StatusCode::FORBIDDEN,
        });
    }
    Ok(())
}

fn encounter_from_write_parent(
    effective: &EffectiveCapability,
) -> Result<DatasetCategory, ProxyError> {
    effective
        .write_datasets
        .iter()
        .find(|dataset| {
            matches!(
                dataset,
                DatasetCategory::RAWAT_JALAN | DatasetCategory::RAWAT_INAP
            )
        })
        .copied()
        .ok_or_else(|| ProxyError::Anyhow {
            source: anyhow!("write parent missing RAWAT encounter dataset"),
            code: StatusCode::BAD_REQUEST,
        })
}

fn build_admin_delegation_params(
    preset: &str,
    encounter: DatasetCategory,
    delegator: &str,
    delegatee: &str,
    related_rme_id: &str,
    expires_before: chrono::DateTime<chrono::Utc>,
) -> Result<DelegationAttenuationParams, ProxyError> {
    let max_depth = match preset {
        "doctor" => 1,
        _ => 0,
    };
    let (read_datasets, write_datasets, read_functions, write_functions) = match preset {
        "doctor" => {
            let read_datasets = admin_all_datasets();
            let read_functions = admin_all_functions();
            let write_datasets = admin_write_datasets(encounter);
            let mut write_functions = admin_write_functions(encounter);
            write_functions.retain(|f| *f != FunctionCategory::ADMINISTRATIVE_GENERAL);
            (
                read_datasets,
                write_datasets,
                read_functions,
                write_functions,
            )
        }
        "nurse" => (
            vec![encounter],
            vec![encounter],
            vec![
                FunctionCategory::ADMINISTRATIVE_GENERAL,
                FunctionCategory::ANAMNESIS,
                FunctionCategory::PEMERIKSAAN_FISIK,
            ],
            vec![
                FunctionCategory::ANAMNESIS,
                FunctionCategory::PEMERIKSAAN_FISIK,
            ],
        ),
        "lab" => (
            vec![DatasetCategory::LABORATORIUM],
            vec![DatasetCategory::LABORATORIUM],
            vec![
                FunctionCategory::ADMINISTRATIVE_GENERAL,
                FunctionCategory::PEMERIKSAAN_PENUNJANG,
                FunctionCategory::LABORATORIUM,
            ],
            vec![FunctionCategory::LABORATORIUM],
        ),
        "apotek" => (
            vec![encounter, DatasetCategory::APOTEK],
            vec![DatasetCategory::APOTEK],
            vec![
                FunctionCategory::ADMINISTRATIVE_GENERAL,
                FunctionCategory::RIWAYAT_PENGGUNAAN_OBAT,
                FunctionCategory::TERAPI,
                FunctionCategory::PERESEPAN,
                FunctionCategory::DISPENSING,
            ],
            vec![FunctionCategory::PERESEPAN, FunctionCategory::DISPENSING],
        ),
        _ => {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Unknown preset: {preset}"),
                code: StatusCode::BAD_REQUEST,
            });
        }
    };

    Ok(DelegationAttenuationParams {
        delegated_by: delegator.to_string(),
        delegated_to: delegatee.to_string(),
        read_datasets,
        write_datasets,
        read_functions,
        write_functions,
        expires_before,
        max_delegation_depth: max_depth,
        related_rme_id: Some(related_rme_id.to_string()),
    })
}

fn get_access_keys_for_current_user(
    conn: &mut redis::Connection,
    current_user: &CurrentUser,
    patient_iota_address: &str,
) -> Result<AccessKeys, ProxyError> {
    for subject in access_key_subject_candidates(current_user) {
        let stored_access_keys: redis::RedisResult<String> =
            conn.get(format!("keys:{}@{}", subject, patient_iota_address));

        if let Ok(stored_access_keys) = stored_access_keys {
            let access_keys =
                Utils::serde_deserialize_from_base64(stored_access_keys).context(current_fn!())?;
            return Ok(access_keys);
        }
    }

    Err(ProxyError::Anyhow {
        source: anyhow!("Keys not found"),
        code: StatusCode::BAD_REQUEST,
    })
}

impl Handlers {
    pub async fn attenuate_delegation(
        State(state): State<Arc<AppState>>,
        Json(payload): Json<HandlerAttenuateDelegationPayload>,
    ) -> Result<Response, ProxyError> {
        let mode = payload.mode.as_str();
        if !matches!(mode, "read" | "write" | "read_write") {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Invalid delegation mode"),
                code: StatusCode::BAD_REQUEST,
            });
        }
        let preset = payload
            .preset
            .as_deref()
            .filter(|value| !value.trim().is_empty());
        let uses_preset = preset.is_some();
        if uses_preset && mode != "read_write" {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Preset delegation requires read_write mode"),
                code: StatusCode::BAD_REQUEST,
            });
        }
        let requires_read = matches!(mode, "read" | "read_write");
        let requires_update = matches!(mode, "write" | "read_write");

        if uses_preset {
            if payload.related_rme_id.is_some() {
                return Err(ProxyError::Anyhow {
                    source: anyhow!("related_rme_id is managed by PRE for preset delegation"),
                    code: StatusCode::BAD_REQUEST,
                });
            }
        } else if requires_read {
            ensure_scope_requested(
                "read",
                payload.read_datasets.is_empty(),
                payload.read_functions.is_empty(),
            )?;
        }
        if !uses_preset && requires_update {
            ensure_scope_requested(
                "write",
                payload.write_datasets.is_empty(),
                payload.write_functions.is_empty(),
            )?;
            ensure_no_administrative_general_write(&payload.write_functions)?;
        } else if payload.related_rme_id.is_some() {
            return Err(ProxyError::Anyhow {
                source: anyhow!("related_rme_id is only allowed for write delegation"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        let parent_read_token = if requires_read {
            Some(
                payload
                    .parent_read_token
                    .as_deref()
                    .ok_or_else(|| ProxyError::Anyhow {
                        source: anyhow!("Parent read token is required"),
                        code: StatusCode::BAD_REQUEST,
                    })?,
            )
        } else {
            None
        };
        let parent_write_token = if requires_update {
            Some(
                payload
                    .parent_write_token
                    .as_deref()
                    .ok_or_else(|| ProxyError::Anyhow {
                        source: anyhow!("Parent write token is required"),
                        code: StatusCode::BAD_REQUEST,
                    })?,
            )
        } else {
            None
        };

        let request_context = DelegationRequestProofContext {
            request_kind: if uses_preset { "admin" } else { "custom" }.to_string(),
            mode: payload.mode.clone(),
            delegator_iota_address: payload.delegator_iota_address.clone(),
            delegatee_iota_address: payload.delegatee_iota_address.clone(),
            patient_iota_address: payload.patient_iota_address.clone(),
            parent_read_token_hash: parent_read_token.map(hash_token),
            parent_write_token_hash: parent_write_token.map(hash_token),
            expires_before: payload.expires_before.clone(),
            related_rme_id: if uses_preset {
                None
            } else {
                payload.related_rme_id.clone()
            },
            preset: preset.map(str::to_string),
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
        verify_delegation_request_signature(
            &request_context,
            &payload.delegation_request_signature,
            &payload.delegator_iota_address,
        )?;

        let expires_before = parse_future_delegation_expiry(&payload.expires_before)?;
        let expires_at_ms = datetime_to_epoch_ms(expires_before)?;
        let delegator_iota_address = IotaAddress::from_str(&payload.delegator_iota_address)
            .map_err(|_| anyhow!("Invalid delegator IOTA address"))
            .code(StatusCode::BAD_REQUEST)?;
        let delegatee_iota_address = IotaAddress::from_str(&payload.delegatee_iota_address)
            .map_err(|_| anyhow!("Invalid delegatee IOTA address"))
            .code(StatusCode::BAD_REQUEST)?;
        let patient_iota_address = IotaAddress::from_str(&payload.patient_iota_address)
            .map_err(|_| anyhow!("Invalid patient IOTA address"))
            .code(StatusCode::BAD_REQUEST)?;
        let proxy_iota_address =
            IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

        let root_key = MacaroonKey::generate(&state.macaroon_root_key);
        let (write_effective_related_rme_id, write_parent_has_related_rme_id, preset_encounter) = {
            let mut conn = state.redis_pool.get().context(current_fn!())?;

            if let Some(parent_token) = parent_read_token {
                let _ = verify_parent_token_for_delegation(
                    &mut conn,
                    &root_key,
                    parent_token,
                    payload.parent_read_delegation_signature.as_deref(),
                    &payload.delegator_iota_address,
                    &payload.patient_iota_address,
                )?;
            }

            if let Some(parent_token) = parent_write_token {
                let verified = verify_parent_token_for_delegation(
                    &mut conn,
                    &root_key,
                    parent_token,
                    payload.parent_write_delegation_signature.as_deref(),
                    &payload.delegator_iota_address,
                    &payload.patient_iota_address,
                )?;
                let encounter = if uses_preset {
                    Some(encounter_from_write_parent(&verified.effective)?)
                } else {
                    None
                };
                let parent_related = verified.effective.related_rme_id.clone();
                let parent_has_related = parent_related.is_some();
                if let (Some(parent_related), Some(requested_related)) =
                    (&parent_related, &payload.related_rme_id)
                {
                    if parent_related != requested_related {
                        return Err(ProxyError::Anyhow {
                            source: anyhow!("requested related_rme_id differs from parent token"),
                            code: StatusCode::FORBIDDEN,
                        });
                    }
                }
                if parent_related.is_none() && payload.related_rme_id.is_none() {
                    (
                        Some(reserve_related_rme_id(&mut conn)?),
                        parent_has_related,
                        encounter,
                    )
                } else {
                    (
                        parent_related.or_else(|| payload.related_rme_id.clone()),
                        parent_has_related,
                        encounter,
                    )
                }
            } else {
                (None, false, None)
            }
        };

        let snapshot = state
            .move_call
            .get_delegation_access_snapshot(
                &delegator_iota_address,
                &delegatee_iota_address,
                &patient_iota_address,
                requires_read,
                requires_update,
                proxy_iota_address,
            )
            .await?;
        ensure_snapshot_depths_compatible(&snapshot, requires_read, requires_update)?;
        ensure_requested_expiry_within_snapshot(
            expires_at_ms,
            &snapshot,
            requires_read,
            requires_update,
        )?;

        let mut parent_token_hashes = Vec::new();
        if let Some(parent_token) = parent_read_token {
            parent_token_hashes.push(hash_token(parent_token));
        }
        if let Some(parent_token) = parent_write_token {
            let parent_token_hash = hash_token(parent_token);
            if !parent_token_hashes.contains(&parent_token_hash) {
                parent_token_hashes.push(parent_token_hash);
            }
        }

        let mut delegatee_role = None;
        for parent_token_hash in &parent_token_hashes {
            let role_slot = state
                .move_call
                .get_delegation_role_slot_snapshot(
                    &delegatee_iota_address,
                    parent_token_hash,
                    &patient_iota_address,
                    proxy_iota_address,
                )
                .await?;
            delegatee_role = role_slot.delegatee_role;
            if role_slot.role_slot_used {
                return Err(ProxyError::Anyhow {
                    source: anyhow!(
                        "Delegator already has an active delegation for this role from the same parent token"
                    ),
                    code: StatusCode::CONFLICT,
                });
            }
        }

        let mut delegated_read_token = None;
        let mut delegated_update_token = None;
        let mut read_preview = None;
        let mut update_preview = None;

        if uses_preset {
            let related_rme_id =
                write_effective_related_rme_id
                    .clone()
                    .ok_or_else(|| ProxyError::Anyhow {
                        source: anyhow!("PRE did not resolve related_rme_id for preset delegation"),
                        code: StatusCode::BAD_REQUEST,
                    })?;
            let encounter = preset_encounter.ok_or_else(|| ProxyError::Anyhow {
                source: anyhow!("PRE could not infer encounter for preset delegation"),
                code: StatusCode::BAD_REQUEST,
            })?;
            let params = build_admin_delegation_params(
                preset.unwrap(),
                encounter,
                &payload.delegator_iota_address,
                &payload.delegatee_iota_address,
                &related_rme_id,
                expires_before,
            )?;

            let mut read_params = params.clone();
            read_params.write_datasets.clear();
            read_params.write_functions.clear();
            read_params.related_rme_id = None;
            let mut update_params = params;
            update_params.read_datasets.clear();
            update_params.read_functions.clear();
            if write_parent_has_related_rme_id {
                update_params.related_rme_id = None;
            }
            ensure_no_administrative_general_write(&update_params.write_functions)?;

            let parent_read = payload.parent_read_token.as_deref().unwrap();
            let token = attenuate_macaroon(parent_read, &read_params).map_err(map_caveat_error)?;
            let preview =
                build_delegated_token_preview(&token, parent_read, snapshot.read_delegation_depth)?;
            ensure_effective_mode_scope(&preview, AccessMode::Read)?;
            delegated_read_token = Some(token);
            read_preview = Some(preview);

            let parent_write = payload.parent_write_token.as_deref().unwrap();
            let token =
                attenuate_macaroon(parent_write, &update_params).map_err(map_caveat_error)?;
            let preview = build_delegated_token_preview(
                &token,
                parent_write,
                snapshot.update_delegation_depth,
            )?;
            ensure_effective_mode_scope(&preview, AccessMode::Write)?;
            delegated_update_token = Some(token);
            update_preview = Some(preview);
        } else if requires_read {
            let parent_token = payload.parent_read_token.as_deref().unwrap();
            let params = DelegationAttenuationParams {
                delegated_by: payload.delegator_iota_address.clone(),
                delegated_to: payload.delegatee_iota_address.clone(),
                read_datasets: payload.read_datasets.clone(),
                write_datasets: Vec::new(),
                read_functions: payload.read_functions.clone(),
                write_functions: Vec::new(),
                expires_before,
                max_delegation_depth: 0,
                related_rme_id: None,
            };
            let token = attenuate_macaroon(parent_token, &params).map_err(map_caveat_error)?;
            let preview = build_delegated_token_preview(
                &token,
                parent_token,
                snapshot.read_delegation_depth,
            )?;
            ensure_effective_mode_scope(&preview, AccessMode::Read)?;
            delegated_read_token = Some(token);
            read_preview = Some(preview);
        }

        if !uses_preset && requires_update {
            let parent_token = payload.parent_write_token.as_deref().unwrap();
            let params = DelegationAttenuationParams {
                delegated_by: payload.delegator_iota_address.clone(),
                delegated_to: payload.delegatee_iota_address.clone(),
                read_datasets: Vec::new(),
                write_datasets: payload.write_datasets.clone(),
                read_functions: Vec::new(),
                write_functions: payload.write_functions.clone(),
                expires_before,
                max_delegation_depth: 0,
                related_rme_id: if write_parent_has_related_rme_id {
                    None
                } else {
                    write_effective_related_rme_id.clone()
                },
            };
            let token = attenuate_macaroon(parent_token, &params).map_err(map_caveat_error)?;
            let preview = build_delegated_token_preview(
                &token,
                parent_token,
                snapshot.update_delegation_depth,
            )?;
            ensure_effective_mode_scope(&preview, AccessMode::Write)?;
            delegated_update_token = Some(token);
            update_preview = Some(preview);
        }

        Ok(Utils::build_success_response(
            DelegationAttenuationHandlerResponse {
                related_rme_id: if requires_update {
                    write_effective_related_rme_id
                } else {
                    None
                },
                delegated_read_token,
                delegated_update_token,
                read_preview,
                update_preview,
                delegatee_role,
                role_slot_available: true,
            },
            StatusCode::OK,
        ))
    }

    pub async fn reserve_related_rme_id_handler(
        State(state): State<Arc<AppState>>,
    ) -> Result<Response, ProxyError> {
        let mut conn = state.redis_pool.get().context(current_fn!())?;
        let related_rme_id = reserve_related_rme_id(&mut conn)?;

        Ok(Utils::build_success_response(
            GenerateRelatedRmeIdResponse { related_rme_id },
            StatusCode::OK,
        ))
    }

    pub async fn create_medical_record(
        State(state): State<Arc<AppState>>,
        Extension(current_user): Extension<CurrentUser>,
        Json(payload): Json<HandlerCreateMedicalRecordPayload>,
    ) -> Result<Response, ProxyError> {
        if current_user.role != AuthRole::MedicalPersonnel {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid role"),
                code: StatusCode::UNAUTHORIZED,
            });
        }

        if current_user.purpose != ReencryptionPurposeType::Update {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid purpose"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        let (
            medical_metadata,
            hospital_personnel_iota_address,
            proxy_iota_address,
            proxy_iota_key_pair,
            patient_iota_address,
        ) = {
            let patient_iota_address = IotaAddress::from_str(&payload.patient_iota_address)
                .map_err(|_| anyhow!("Invalid patient IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
            let medical_metadata: ClientMedicalMetadata =
                Utils::serde_deserialize_from_base64(payload.medical_metadata)
                    .map_err(|_| anyhow!("Invalid medical metadata"))
                    .code(StatusCode::BAD_REQUEST)?;
            let hospital_personnel_iota_address = IotaAddress::from_str(&current_user.iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))?;
            let proxy_iota_address =
                IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;
            let proxy_iota_key_pair = IotaKeyPair::decode(&state.proxy_iota_key_pair)
                .map_err(|e| anyhow!(e.to_string()))
                .context(current_fn!())?;

            (
                medical_metadata,
                hospital_personnel_iota_address,
                proxy_iota_address,
                proxy_iota_key_pair,
                patient_iota_address,
            )
        };

        let cid = Utils::add_and_pin_to_ipfs(medical_metadata.enc_data)
            .await
            .context(current_fn!())?;
        let created_at = Utils::sys_time_to_iso(std::time::SystemTime::now());

        let medical_metadata = MedicalMetadata {
            capsule: medical_metadata.capsule,
            cid,
            created_at,
            enc_key_and_nonce: medical_metadata.enc_key_and_nonce,
        };

        let _ = state
            .move_call
            .create_medical_record(
                &hospital_personnel_iota_address,
                Utils::serde_serialize_to_base64(&medical_metadata).context(current_fn!())?,
                &patient_iota_address,
                proxy_iota_address,
                proxy_iota_key_pair,
            )
            .await
            .context(current_fn!())?;

        Ok(Utils::build_success_response((), StatusCode::OK))
    }

    pub async fn create_medical_record_segment(
        State(state): State<Arc<AppState>>,
        Extension(current_user): Extension<CurrentUser>,
        headers: HeaderMap,
        Json(payload): Json<HandlerCreateMedicalRecordSegmentPayload>,
    ) -> Result<Response, ProxyError> {
        let (
            encrypted_segment,
            hospital_personnel_iota_address,
            proxy_iota_address,
            proxy_iota_key_pair,
            patient_iota_address,
        ) = {
            let patient_iota_address = IotaAddress::from_str(&payload.patient_iota_address)
                .map_err(|_| anyhow!("Invalid patient IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
            let encrypted_segment: ClientEncryptedRmeSegment =
                Utils::serde_deserialize_from_base64(payload.encrypted_segment)
                    .map_err(|_| anyhow!("Invalid encrypted segment metadata"))
                    .code(StatusCode::BAD_REQUEST)?;
            encrypted_segment
                .validate()
                .map_err(|e| anyhow!(e.to_string()))
                .code(StatusCode::BAD_REQUEST)?;

            if encrypted_segment.patient_address != patient_iota_address.to_string() {
                return Err(ProxyError::Anyhow {
                    source: anyhow!(
                        "Segment patient_address does not match request patient_iota_address"
                    ),
                    code: StatusCode::BAD_REQUEST,
                });
            }

            let hospital_personnel_iota_address = IotaAddress::from_str(&current_user.iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))?;

            if encrypted_segment.author_address != hospital_personnel_iota_address.to_string() {
                return Err(ProxyError::Anyhow {
                    source: anyhow!("Segment author_address does not match authenticated subject"),
                    code: StatusCode::BAD_REQUEST,
                });
            }

            let proxy_iota_address =
                IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;
            let proxy_iota_key_pair = IotaKeyPair::decode(&state.proxy_iota_key_pair)
                .map_err(|e| anyhow!(e.to_string()))
                .context(current_fn!())?;

            (
                encrypted_segment,
                hospital_personnel_iota_address,
                proxy_iota_address,
                proxy_iota_key_pair,
                patient_iota_address,
            )
        };

        authorize_create_rme_segment(
            current_user.role,
            current_user.sub_role,
            current_user.purpose,
            encrypted_segment.dataset_category,
            encrypted_segment.function_category,
        )?;
        authorize_segment_hospital(
            current_user.hospital_cid.as_deref(),
            &encrypted_segment.hospital_cid,
        )?;

        let created_at = Utils::sys_time_to_iso(std::time::SystemTime::now());
        let segment_metadata_preview = encrypted_segment
            .clone()
            .into_metadata(String::new(), created_at.clone());
        if current_user.decmed_token.is_some() {
            let wallet_sig = headers
                .get(WALLET_SIGNATURE_HEADER)
                .and_then(|v| v.to_str().ok());
            let wallet_timestamp = headers
                .get(WALLET_TIMESTAMP_HEADER)
                .and_then(|v| v.to_str().ok());
            let mac = Macaroon::deserialize(&current_user.bearer_token).map_err(|_| {
                ProxyError::Anyhow {
                    source: anyhow!("Invalid access token"),
                    code: StatusCode::UNAUTHORIZED,
                }
            })?;
            let root_key = MacaroonKey::generate(&state.macaroon_root_key);
            let segment = SegmentAccessContext {
                segment_id: segment_metadata_preview.segment_id.clone(),
                patient_address: segment_metadata_preview.patient_address.clone(),
                related_rme_id: segment_metadata_preview.related_rme_id.clone(),
                dataset_category: segment_metadata_preview.dataset_category,
                function_category: segment_metadata_preview.function_category,
            };
            let verifier: Option<&dyn decmed_macaroon_auth::WalletSignatureVerifier> =
                Some(&IotaWalletVerifier);
            verify_decmed_token(
                &mac,
                &root_key,
                &(TokenVerificationContext {
                    operation: AccessMode::Write,
                    segment,
                    wallet_signature_b64: wallet_sig.map(|s| s.to_string()),
                    wallet_timestamp: wallet_timestamp.map(|s| s.to_string()),
                    now: chrono::Utc::now(),
                }),
                verifier,
            )
            .map_err(map_caveat_error)?;
        }

        let cid = Utils::add_and_pin_to_ipfs(encrypted_segment.enc_data.clone())
            .await
            .context(current_fn!())?;
        let segment_metadata = encrypted_segment.into_metadata(cid, created_at);
        segment_metadata
            .validate()
            .map_err(|e| anyhow!(e.to_string()))
            .code(StatusCode::BAD_REQUEST)?;

        let response_data = CreateRmeSegmentResponse::from(&segment_metadata);

        let _ = state
            .move_call
            .create_medical_record_segment(
                &hospital_personnel_iota_address,
                Utils::serde_serialize_to_base64(&segment_metadata).context(current_fn!())?,
                &patient_iota_address,
                proxy_iota_address,
                proxy_iota_key_pair,
            )
            .await
            .context(current_fn!())?;

        Ok(Utils::build_success_response(response_data, StatusCode::OK))
    }

    /**
     * This is just helper function
     */
    pub async fn generate_and_register_proxy_address(
        State(state): State<Arc<AppState>>,
    ) -> Result<Response, ProxyError> {
        let mnemonic = Utils::generate_mnemonic(12).context(current_fn!())?;

        let seed_words: Vec<&str> = mnemonic.words().collect();
        let seed_words = seed_words.join(" ");
        let seed = mnemonic.to_seed_normalized("proxy");

        let (proxy_iota_address, proxy_iota_keypair) =
            Utils::generate_iota_keys_ed(&seed).context(current_fn!())?;

        let _ = state
            .move_call
            .create_capability(
                &proxy_iota_address,
                IotaAddress::from_str(&state.global_admin_iota_address).context(current_fn!())?,
                IotaKeyPair::decode(&state.global_admin_iota_key_pair.clone())
                    .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?,
            )
            .await
            .context(current_fn!())?;

        let res_data = json!({
            "iota_address": proxy_iota_address.to_string(),
            "iota_key_pair": proxy_iota_keypair.encode().map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?,
            "seed_words": seed_words,
        });

        Ok(Utils::build_success_response(res_data, StatusCode::OK))
    }

    pub async fn generate_macaroon_key_handler() -> Result<Response, ProxyError> {
        let res_data = GenerateMacaroonKeyHandlerResponse {
            macaroon_root_key: Utils::generate_macaroon_root_key(),
        };

        Ok(Utils::build_success_response(res_data, StatusCode::OK))
    }

    /**
     * This is just helper function
     */
    pub async fn generate_signature(
        Json(payload): Json<GenerateSignatureHandlerPayload>,
    ) -> Result<Response, ProxyError> {
        let iota_keypair = IotaKeyPair::decode(&payload.iota_keypair)
            .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))
            .code(StatusCode::BAD_REQUEST)?;

        let intent_message = IntentMessage::new(Intent::personal_message(), payload.nonce);
        let signature = Signature::new_secure(&intent_message, &iota_keypair);
        let signature_string = signature.encode_base64();

        Ok(Utils::build_success_response(
            signature_string,
            StatusCode::OK,
        ))
    }

    pub async fn get_administrative_data(
        State(state): State<Arc<AppState>>,
        Extension(current_user): Extension<CurrentUser>,
        Query(query): Query<HandlerGetAdministrativeDataQueryParams>,
    ) -> Result<Response, ProxyError> {
        if current_user.role != AuthRole::AdministrativePersonnel
            && current_user.role != AuthRole::MedicalPersonnel
        {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid role"),
                code: StatusCode::UNAUTHORIZED,
            });
        }

        if current_user.purpose != ReencryptionPurposeType::Read
            && !(current_user.role == AuthRole::MedicalPersonnel
                && current_user.purpose == ReencryptionPurposeType::Update)
        {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid purpose"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        let (hospital_personnel_iota_address, patient_iota_address, proxy_iota_address) = {
            let hospital_personnel_iota_address = IotaAddress::from_str(&current_user.iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
            let patient_iota_address = IotaAddress::from_str(&query.patient_iota_address)
                .map_err(|_| anyhow!("Invalid patient IOTA address"))
                .code(StatusCode::UNAUTHORIZED)?;
            let proxy_iota_address =
                IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

            (
                hospital_personnel_iota_address,
                patient_iota_address,
                proxy_iota_address,
            )
        };

        let (
            enc_patient_private_adm_data,
            access_keys,
            c_frag,
            enc_patient_private_adm_data_key_nonce,
            patient_private_adm_data_capsule,
        ) = {
            let mut conn = state.redis_pool.get().context(current_fn!())?;

            let access_keys = get_access_keys_for_current_user(
                &mut conn,
                &current_user,
                &query.patient_iota_address,
            )?;

            let patient_administrative_metadata = state
                .move_call
                .get_administrative_data(
                    &hospital_personnel_iota_address,
                    &patient_iota_address,
                    proxy_iota_address,
                )
                .await
                .context(current_fn!())?;

            let patient_private_adm_metadata: PatientPrivateAdministrativeMetadata =
                Utils::serde_deserialize_from_base64(
                    patient_administrative_metadata.private_metadata,
                )
                .context(current_fn!())?;

            let k_frag: KeyFrag = Utils::serde_deserialize_from_base64(access_keys.k_frag.clone())
                .context(current_fn!())?;
            let signer_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.signer_pre_public_key.clone())
                    .context(current_fn!())?;
            let patient_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.patient_pre_public_key.clone())
                    .context(current_fn!())?;
            let data_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.data_pre_public_key.clone())
                    .context(current_fn!())?;
            let patient_private_adm_metadata_key_nonce_capsule: Capsule =
                Utils::serde_deserialize_from_base64(patient_private_adm_metadata.capsule.clone())
                    .context(current_fn!())?;

            let verified_kfrag = k_frag
                .verify(
                    &signer_pre_public_key,
                    Some(&patient_pre_public_key),
                    Some(&data_pre_public_key),
                )
                .map_err(|e| anyhow!(e.0.to_string()).context(current_fn!()))?;
            let verified_cfrag = reencrypt(
                &patient_private_adm_metadata_key_nonce_capsule,
                verified_kfrag,
            );
            let c_frag = verified_cfrag.unverify();

            (
                patient_private_adm_metadata.enc_data,
                access_keys,
                c_frag,
                patient_private_adm_metadata.enc_key_nonce,
                patient_private_adm_metadata.capsule,
            )
        };

        let res_data = json!({
            "c_frag": Utils::serde_serialize_to_base64(&c_frag).context(current_fn!())?,
            "data_pre_public_key": access_keys.data_pre_public_key,
            "data_pre_secret_key_seed_capsule": access_keys.data_pre_secret_key_seed_capsule,
            "enc_data_pre_secret_key_seed": access_keys.enc_data_pre_secret_key_seed,
            "enc_patient_private_adm_data": enc_patient_private_adm_data,
            "enc_patient_private_adm_data_key_nonce": enc_patient_private_adm_data_key_nonce,
            "patient_pre_public_key": access_keys.patient_pre_public_key,
            "patient_private_adm_data_capsule": patient_private_adm_data_capsule,
            "signer_pre_public_key": access_keys.signer_pre_public_key,
        });

        Ok(Utils::build_success_response(res_data, StatusCode::OK))
    }

    pub async fn get_medical_record(
        State(state): State<Arc<AppState>>,
        Extension(current_user): Extension<CurrentUser>,
        headers: HeaderMap,
        Query(query): Query<HandlerGetMedicalRecordQueryParams>,
    ) -> Result<Response, ProxyError> {
        if current_user.role != AuthRole::MedicalPersonnel {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid role"),
                code: StatusCode::UNAUTHORIZED,
            });
        }

        if current_user.purpose != ReencryptionPurposeType::Read {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid purpose"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        let (hospital_personnel_iota_address, patient_iota_address, proxy_iota_address) = {
            let hospital_personnel_iota_address = IotaAddress::from_str(&current_user.iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
            let patient_iota_address = IotaAddress::from_str(&query.patient_iota_address)
                .map_err(|_| anyhow!("Invalid patient IOTA address"))
                .code(StatusCode::UNAUTHORIZED)?;
            let proxy_iota_address =
                IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

            (
                hospital_personnel_iota_address,
                patient_iota_address,
                proxy_iota_address,
            )
        };

        let include_administrative = query.include_administrative.unwrap_or(true);

        let (
            enc_administrative_data,
            enc_medical_data,
            access_keys,
            c_frag_administrative,
            c_frag_medical,
            current_index,
            prev_index,
            next_index,
            enc_medical_data_key_nonce,
            medical_data_capsule,
            medical_data_created_at,
            enc_administrative_data_key_nonce,
            administrative_data_capsule,
        ) = {
            let mut conn = state.redis_pool.get().context(current_fn!())?;

            let access_keys = get_access_keys_for_current_user(
                &mut conn,
                &current_user,
                &query.patient_iota_address,
            )?;

            let mut scan_index = query.index.unwrap_or(0);
            let (medical_metadata, administrative_metadata, current_index, prev_index, next_index) = loop {
                let record = state
                    .move_call
                    .get_medical_record(
                        &hospital_personnel_iota_address,
                        scan_index,
                        &patient_iota_address,
                        proxy_iota_address,
                    )
                    .await
                    .context(current_fn!())?;

                if current_user.decmed_token.is_some() {
                    if let Ok(segment_meta) = Utils::serde_deserialize_from_base64::<
                        RmeSegmentMetadata,
                    >(record.0.metadata.clone())
                    {
                        let wallet_sig = headers
                            .get(WALLET_SIGNATURE_HEADER)
                            .and_then(|v| v.to_str().ok());
                        let wallet_timestamp = headers
                            .get(WALLET_TIMESTAMP_HEADER)
                            .and_then(|v| v.to_str().ok());
                        let mac =
                            Macaroon::deserialize(&current_user.bearer_token).map_err(|_| {
                                ProxyError::Anyhow {
                                    source: anyhow!("Invalid access token"),
                                    code: StatusCode::UNAUTHORIZED,
                                }
                            })?;
                        let root_key = MacaroonKey::generate(&state.macaroon_root_key);
                        let segment = SegmentAccessContext {
                            segment_id: segment_meta.segment_id.clone(),
                            patient_address: segment_meta.patient_address.clone(),
                            related_rme_id: segment_meta.related_rme_id.clone(),
                            dataset_category: segment_meta.dataset_category,
                            function_category: segment_meta.function_category,
                        };
                        let verifier: Option<&dyn decmed_macaroon_auth::WalletSignatureVerifier> =
                            Some(&IotaWalletVerifier);
                        let now = chrono::Utc::now();
                        let proof_timestamp = wallet_timestamp
                            .map(|s| s.to_string())
                            .unwrap_or_else(|| now.to_rfc3339());
                        match verify_decmed_token(
                            &mac,
                            &root_key,
                            &(TokenVerificationContext {
                                operation: AccessMode::Read,
                                segment: segment.clone(),
                                wallet_signature_b64: wallet_sig.map(|s| s.to_string()),
                                wallet_timestamp: Some(proof_timestamp.clone()),
                                now,
                            }),
                            verifier,
                        ) {
                            Ok(_) => {
                                break record;
                            }
                            Err(
                                CaveatVerificationError::DatasetCategoryNotAllowed
                                | CaveatVerificationError::FunctionCategoryNotAllowed
                                | CaveatVerificationError::RmeMismatch,
                            ) => {
                                if let Some(next_scan_index) = record.4 {
                                    scan_index = next_scan_index;
                                    continue;
                                }
                                return Err(ProxyError::Anyhow {
                                    source: anyhow!("No accessible medical record found"),
                                    code: StatusCode::NOT_FOUND,
                                });
                            }
                            Err(CaveatVerificationError::WalletSignatureRequired) => {
                                return Err(ProxyError::WalletProofChallenge {
                                    code: StatusCode::UNAUTHORIZED.as_u16(),
                                    error: CaveatVerificationError::WalletSignatureRequired
                                        .to_string(),
                                    proof_context: WalletProofContext {
                                        token_id: mac.identifier().to_string(),
                                        patient_address: segment.patient_address.clone(),
                                        related_rme_id: segment.related_rme_id.clone(),
                                        operation: AccessMode::Read,
                                        segment_id: segment.segment_id.clone(),
                                        dataset_category: segment.dataset_category,
                                        function_category: segment.function_category,
                                        timestamp: proof_timestamp,
                                    },
                                });
                            }
                            Err(err) => {
                                return Err(map_caveat_error(err));
                            }
                        }
                    }
                }

                break record;
            };

            let medical_metadata = deserialize_stored_medical_metadata(medical_metadata.metadata)?;

            let enc_medical_data = Utils::get_data_ipfs(medical_metadata.cid)
                .await
                .context(current_fn!())?;

            let k_frag: KeyFrag = Utils::serde_deserialize_from_base64(access_keys.k_frag.clone())
                .context(current_fn!())?;
            let signer_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.signer_pre_public_key.clone())
                    .context(current_fn!())?;
            let patient_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.patient_pre_public_key.clone())
                    .context(current_fn!())?;
            let medical_record_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.data_pre_public_key.clone())
                    .context(current_fn!())?;
            let medical_metadata_key_nonce_capsule: Capsule =
                Utils::serde_deserialize_from_base64(medical_metadata.capsule.clone())
                    .context(current_fn!())?;

            let verified_kfrag = k_frag
                .verify(
                    &signer_pre_public_key,
                    Some(&patient_pre_public_key),
                    Some(&medical_record_pre_public_key),
                )
                .map_err(|e| anyhow!(e.0.to_string()).context(current_fn!()))?;
            let verified_cfrag_medical =
                reencrypt(&medical_metadata_key_nonce_capsule, verified_kfrag.clone());
            let c_frag_medical = verified_cfrag_medical.unverify();

            let administrative = if include_administrative {
                let patient_private_adm_metadata: PatientPrivateAdministrativeMetadata =
                    Utils::serde_deserialize_from_base64(administrative_metadata.private_metadata)
                        .context(current_fn!())?;
                let patient_private_adm_metadata_key_nonce_capsule: Capsule =
                    Utils::serde_deserialize_from_base64(
                        patient_private_adm_metadata.capsule.clone(),
                    )
                    .context(current_fn!())?;
                let verified_cfrag_administrative = reencrypt(
                    &patient_private_adm_metadata_key_nonce_capsule,
                    verified_kfrag,
                );
                let c_frag_administrative = verified_cfrag_administrative.unverify();
                Some((
                    patient_private_adm_metadata.enc_data,
                    c_frag_administrative,
                    patient_private_adm_metadata.enc_key_nonce,
                    patient_private_adm_metadata.capsule,
                ))
            } else {
                None
            };

            let (
                enc_administrative_data,
                c_frag_administrative,
                enc_administrative_data_key_nonce,
                administrative_data_capsule,
            ) = administrative
                .map(|(enc_data, c_frag, enc_key_nonce, capsule)| {
                    (
                        Some(enc_data),
                        Some(c_frag),
                        Some(enc_key_nonce),
                        Some(capsule),
                    )
                })
                .unwrap_or((None, None, None, None));

            (
                enc_administrative_data,
                enc_medical_data,
                access_keys,
                c_frag_administrative,
                c_frag_medical,
                current_index,
                prev_index,
                next_index,
                medical_metadata.enc_key_and_nonce,
                medical_metadata.capsule,
                medical_metadata.created_at,
                enc_administrative_data_key_nonce,
                administrative_data_capsule,
            )
        };

        let mut res_data = json!({
            "c_frag_medical": Utils::serde_serialize_to_base64(&c_frag_medical).context(current_fn!())?,
            "current_index": current_index,
            "data_pre_public_key": access_keys.data_pre_public_key,
            "data_pre_secret_key_seed_capsule": access_keys.data_pre_secret_key_seed_capsule,
            "enc_data_pre_secret_key_seed": access_keys.enc_data_pre_secret_key_seed,
            "enc_medical_data": enc_medical_data,
            "enc_medical_data_key_nonce": enc_medical_data_key_nonce,
            "medical_data_capsule": medical_data_capsule,
            "medical_data_created_at": medical_data_created_at,
            "next_index": next_index,
            "patient_pre_public_key": access_keys.patient_pre_public_key,
            "prev_index": prev_index,
            "signer_pre_public_key": access_keys.signer_pre_public_key,
        });

        if include_administrative {
            let administrative_data_capsule = administrative_data_capsule
                .ok_or_else(|| anyhow!("Missing administrative data"))?;
            let c_frag_administrative =
                c_frag_administrative.ok_or_else(|| anyhow!("Missing administrative cfrag"))?;
            let enc_administrative_data =
                enc_administrative_data.ok_or_else(|| anyhow!("Missing administrative payload"))?;
            let enc_administrative_data_key_nonce = enc_administrative_data_key_nonce
                .ok_or_else(|| anyhow!("Missing administrative key nonce"))?;

            if let Value::Object(map) = &mut res_data {
                map.insert(
                    "administrative_data_capsule".to_string(),
                    json!(administrative_data_capsule),
                );
                map.insert(
                    "c_frag_administrative".to_string(),
                    json!(Utils::serde_serialize_to_base64(&c_frag_administrative)
                        .context(current_fn!())?),
                );
                map.insert(
                    "enc_administrative_data".to_string(),
                    json!(enc_administrative_data),
                );
                map.insert(
                    "enc_administrative_data_key_nonce".to_string(),
                    json!(enc_administrative_data_key_nonce),
                );
            }
        }

        Ok(Utils::build_success_response(res_data, StatusCode::OK))
    }

    pub async fn list_medical_records(
        State(state): State<Arc<AppState>>,
        Extension(current_user): Extension<CurrentUser>,
        headers: HeaderMap,
        Query(query): Query<HandlerListMedicalRecordsQueryParams>,
    ) -> Result<Response, ProxyError> {
        if current_user.role != AuthRole::MedicalPersonnel {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid role"),
                code: StatusCode::UNAUTHORIZED,
            });
        }

        if current_user.purpose != ReencryptionPurposeType::Read {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid purpose"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        const DEFAULT_LIMIT: u64 = 50;
        const MAX_LIMIT: u64 = 100;
        const CHAIN_PAGE_SIZE: u64 = 50;

        let cursor = query.cursor.unwrap_or(0);
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);

        let (hospital_personnel_iota_address, patient_iota_address, proxy_iota_address) = {
            let hospital_personnel_iota_address = IotaAddress::from_str(&current_user.iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
            let patient_iota_address = IotaAddress::from_str(&query.patient_iota_address)
                .map_err(|_| anyhow!("Invalid patient IOTA address"))
                .code(StatusCode::UNAUTHORIZED)?;
            let proxy_iota_address =
                IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

            (
                hospital_personnel_iota_address,
                patient_iota_address,
                proxy_iota_address,
            )
        };

        if let Some(verified) = current_user.decmed_token.as_ref() {
            crate::metadata_list::verify_decmed_token_patient_for_list(
                verified,
                &query.patient_iota_address,
            )?;
            crate::metadata_list::verify_list_wallet_proof(
                verified,
                &query.patient_iota_address,
                &headers,
            )?;
        }

        let mut filtered: Vec<MedicalRecordMetadataItem> = Vec::new();
        let mut chain_cursor = 0u64;

        loop {
            let page = state
                .move_call
                .get_medical_records(
                    &hospital_personnel_iota_address,
                    &patient_iota_address,
                    chain_cursor,
                    CHAIN_PAGE_SIZE,
                    proxy_iota_address,
                )
                .await
                .context(current_fn!())?;

            if page.is_empty() {
                break;
            }

            let page_start_cursor = chain_cursor;
            let page_len = page.len() as u64;

            for (offset, record) in page.into_iter().enumerate() {
                let Some(segment) =
                    crate::metadata_list::decode_rme_segment_metadata(&record.metadata)
                else {
                    continue;
                };

                if segment.patient_address != query.patient_iota_address {
                    continue;
                }
                if let Some(related_rme_id) = query.related_rme_id.as_deref() {
                    if segment.related_rme_id != related_rme_id {
                        continue;
                    }
                }

                let include = if let Some(verified) = current_user.decmed_token.as_ref() {
                    crate::metadata_list::segment_allowed_for_list(
                        verified,
                        &segment,
                        &query.patient_iota_address,
                    )
                } else {
                    true
                };

                if include {
                    filtered.push(crate::metadata_list::to_metadata_item(
                        record.index,
                        page_start_cursor + (offset as u64),
                        &segment,
                    ));
                }
            }

            chain_cursor += page_len;
        }

        let res_data = crate::metadata_list::active_metadata_page(filtered, cursor, limit);

        Ok(Utils::build_success_response(res_data, StatusCode::OK))
    }

    pub async fn get_medical_record_update(
        State(state): State<Arc<AppState>>,
        Extension(current_user): Extension<CurrentUser>,
        Query(query): Query<HandlerGetMedicalRecordUpdateQueryParams>,
    ) -> Result<Response, ProxyError> {
        if current_user.role != AuthRole::MedicalPersonnel {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid role"),
                code: StatusCode::UNAUTHORIZED,
            });
        }

        if current_user.purpose != ReencryptionPurposeType::Update {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid purpose"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        let (hospital_personnel_iota_address, patient_iota_address, proxy_iota_address) = {
            let hospital_personnel_iota_address = IotaAddress::from_str(&current_user.iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
            let patient_iota_address = IotaAddress::from_str(&query.patient_iota_address)
                .map_err(|_| anyhow!("Invalid patient IOTA address"))
                .code(StatusCode::UNAUTHORIZED)?;
            let proxy_iota_address =
                IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

            (
                hospital_personnel_iota_address,
                patient_iota_address,
                proxy_iota_address,
            )
        };

        let (
            enc_administrative_data,
            enc_medical_data,
            access_keys,
            c_frag_administrative,
            c_frag_medical,
            enc_medical_data_key_nonce,
            medical_data_capsule,
            medical_data_created_at,
            enc_administrative_data_key_nonce,
            administrative_data_capsule,
        ) = {
            let mut conn = state.redis_pool.get().context(current_fn!())?;

            let access_keys = get_access_keys_for_current_user(
                &mut conn,
                &current_user,
                &query.patient_iota_address,
            )?;

            let (medical_metadata, administrative_metadata) = state
                .move_call
                .get_medical_record_update(
                    &hospital_personnel_iota_address,
                    query.index.unwrap_or(0),
                    &patient_iota_address,
                    proxy_iota_address,
                )
                .await
                .context(current_fn!())?;

            let medical_metadata = deserialize_stored_medical_metadata(medical_metadata.metadata)?;

            let patient_private_adm_metadata: PatientPrivateAdministrativeMetadata =
                Utils::serde_deserialize_from_base64(administrative_metadata.private_metadata)
                    .context(current_fn!())?;

            let enc_medical_data = Utils::get_data_ipfs(medical_metadata.cid)
                .await
                .context(current_fn!())?;

            let k_frag: KeyFrag = Utils::serde_deserialize_from_base64(access_keys.k_frag.clone())
                .context(current_fn!())?;
            let signer_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.signer_pre_public_key.clone())
                    .context(current_fn!())?;
            let patient_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.patient_pre_public_key.clone())
                    .context(current_fn!())?;
            let data_pre_public_key: PublicKey =
                Utils::serde_deserialize_from_base64(access_keys.data_pre_public_key.clone())
                    .context(current_fn!())?;
            let medical_metadata_key_nonce_capsule: Capsule =
                Utils::serde_deserialize_from_base64(medical_metadata.capsule.clone())
                    .context(current_fn!())?;
            let patient_private_adm_metadata_key_nonce_capsule: Capsule =
                Utils::serde_deserialize_from_base64(patient_private_adm_metadata.capsule.clone())
                    .context(current_fn!())?;

            let verified_kfrag = k_frag
                .verify(
                    &signer_pre_public_key,
                    Some(&patient_pre_public_key),
                    Some(&data_pre_public_key),
                )
                .map_err(|e| anyhow!(e.0.to_string()).context(current_fn!()))?;
            let verified_cfrag_medical =
                reencrypt(&medical_metadata_key_nonce_capsule, verified_kfrag.clone());
            let c_frag_medical = verified_cfrag_medical.unverify();

            let verified_cfrag_administrative = reencrypt(
                &patient_private_adm_metadata_key_nonce_capsule,
                verified_kfrag,
            );
            let c_frag_administrative = verified_cfrag_administrative.unverify();

            (
                patient_private_adm_metadata.enc_data,
                enc_medical_data,
                access_keys,
                c_frag_administrative,
                c_frag_medical,
                medical_metadata.enc_key_and_nonce,
                medical_metadata.capsule,
                medical_metadata.created_at,
                patient_private_adm_metadata.enc_key_nonce,
                patient_private_adm_metadata.capsule,
            )
        };

        let res_data = json!({
            "administrative_data_capsule": administrative_data_capsule,
            "c_frag_administrative": Utils::serde_serialize_to_base64(&c_frag_administrative).context(current_fn!())?,
            "c_frag_medical": Utils::serde_serialize_to_base64(&c_frag_medical).context(current_fn!())?,
            "data_pre_public_key": access_keys.data_pre_public_key,
            "data_pre_secret_key_seed_capsule": access_keys.data_pre_secret_key_seed_capsule,
            "enc_administrative_data": enc_administrative_data,
            "enc_administrative_data_key_nonce": enc_administrative_data_key_nonce,
            "enc_data_pre_secret_key_seed": access_keys.enc_data_pre_secret_key_seed,
            "enc_medical_data": enc_medical_data,
            "enc_medical_data_key_nonce": enc_medical_data_key_nonce,
            "medical_data_capsule": medical_data_capsule,
            "medical_data_created_at": medical_data_created_at,
            "patient_pre_public_key": access_keys.patient_pre_public_key,
            "signer_pre_public_key": access_keys.signer_pre_public_key,
        });

        Ok(Utils::build_success_response(res_data, StatusCode::OK))
    }

    pub async fn get_nonce_handler(
        State(state): State<Arc<AppState>>,
        Json(payload): Json<GetNonceHandlerPayload>,
    ) -> Result<Response, ProxyError> {
        let patient_iota_address = IotaAddress::from_str(&payload.iota_address)
            .map_err(|_| anyhow!("Invalid patient IOTA address"))
            .code(StatusCode::BAD_REQUEST)?;
        let proxy_iota_address =
            IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

        let _ = state
            .move_call
            .is_patient_registered(&patient_iota_address, proxy_iota_address)
            .await
            .context(current_fn!())?;

        let nonce = Utils::generate_64_bytes_seed();
        let nonce = hex::encode(&nonce);

        let mut conn = state.redis_pool.get().context(current_fn!())?;

        let _: () = conn
            .set_options(
                format!("nonce:{}", patient_iota_address.to_string()),
                nonce.clone(),
                SetOptions::default().with_expiration(SetExpiry::EX(NONCE_EXP_DUR)),
            )
            .context(current_fn!())?;

        Ok(Utils::build_success_response(nonce, StatusCode::OK))
    }

    pub async fn store_keys(
        State(state): State<Arc<AppState>>,
        Json(payload): Json<HandlerStoreKeysPayload>,
    ) -> Result<Response, ProxyError> {
        let patient_iota_address = IotaAddress::from_str(&payload.patient_iota_address)
            .map_err(|_| anyhow!("Invalid patient IOTA address"))
            .code(StatusCode::BAD_REQUEST)?;
        let hospital_personnel_iota_address =
            IotaAddress::from_str(&payload.hospital_personnel_iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
        let signature = Utils::construct_signature_from_str(&payload.signature)
            .map_err(|_| anyhow!("Invalid signature"))
            .code(StatusCode::BAD_REQUEST)?;
        let proxy_iota_address =
            IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

        let mut conn = state.redis_pool.get().context(current_fn!())?;

        let nonce: String = conn
            .get(format!("nonce:{}", patient_iota_address.to_string()))
            .map_err(|_| anyhow!("Nonce not found"))
            .code(StatusCode::BAD_REQUEST)?;

        let intent_message = IntentMessage::new(Intent::personal_message(), nonce);

        let _ = signature
            .verify_secure(
                &intent_message,
                patient_iota_address,
                SignatureScheme::ED25519,
            )
            .map_err(|_| anyhow!("Failed to verify signature"))
            .code(StatusCode::UNAUTHORIZED)?;

        let _: () = conn
            .del(format!("nonce:{}", patient_iota_address.to_string()))
            .map_err(|_| anyhow!("Nonce expired"))
            .code(StatusCode::UNAUTHORIZED)?;

        // Get the role of hospital personnel
        let role = state
            .move_call
            .get_hospital_personnel_role(&hospital_personnel_iota_address, proxy_iota_address)
            .await
            .context(current_fn!())?;

        let hospital_personnel_role = match role {
            MoveHospitalPersonnelRole::AdministrativePersonnel => AuthRole::AdministrativePersonnel,
            MoveHospitalPersonnelRole::MedicalPersonnel => AuthRole::MedicalPersonnel,
            _ => {
                return Err(ProxyError::Anyhow {
                    source: anyhow!("Invalid personnel account"),
                    code: StatusCode::BAD_REQUEST,
                });
            }
        };

        // Create access token for hospital personnel
        let root_key = MacaroonKey::generate(&state.macaroon_root_key);

        let root_subject = payload
            .root_subject
            .clone()
            .unwrap_or_else(|| hospital_personnel_iota_address.to_string());

        let hospital_cid = payload.hospital_cid.trim();
        if hospital_cid.is_empty() {
            return Err(ProxyError::Anyhow {
                source: anyhow!("hospital_cid is required"),
                code: StatusCode::BAD_REQUEST,
            });
        }
        let now = chrono::Utc::now();
        let requested_expiry = parse_requested_expiry(payload.expires_before.as_deref(), now)?;
        let access_mode = payload.access_mode;
        let mut issued_expiries = Vec::new();

        let mut response_related_rme_id: Option<String> = None;
        let (hospital_personnel_access_token_read, hospital_personnel_access_token_update) =
            match hospital_personnel_role {
                AuthRole::AdministrativePersonnel => {
                    if payload.related_rme_id.is_some() {
                        return Err(ProxyError::Anyhow {
                            source: anyhow!(
                            "related_rme_id must not be sent for administrative personnel grant"
                        ),
                            code: StatusCode::BAD_REQUEST,
                        });
                    }
                    if let Some(encounter_dataset) = payload.encounter_dataset {
                        let keys_duration = administrative_keys_duration(encounter_dataset);
                        if keys_duration == 0 {
                            return Err(ProxyError::Anyhow {
                            source: anyhow!(
                                "encounter_dataset (RAWAT_JALAN or RAWAT_INAP) is required for administrative personnel access grant"
                            ),
                            code: StatusCode::BAD_REQUEST,
                        });
                        }
                        let expires_before = requested_expiry.clone().unwrap_or_else(|| {
                            now + chrono::Duration::seconds(keys_duration as i64)
                        });
                        let related_rme_id = if access_mode.includes_update() {
                            let related_rme_id = reserve_related_rme_id(&mut conn)?;
                            response_related_rme_id = Some(related_rme_id.clone());
                            Some(related_rme_id)
                        } else {
                            None
                        };

                        let read_token = if access_mode.includes_read() {
                            let mut read_params = InitialAdminPersonnelTokenParams::for_grant(
                                &patient_iota_address.to_string(),
                                &root_subject,
                                encounter_dataset,
                                AdminTokenKind::Read,
                                expires_before,
                            )
                            .map_err(|e| ProxyError::Caveat {
                                code: StatusCode::BAD_REQUEST.as_u16(),
                                error: e.to_string(),
                            })?;
                            read_params.hospital_cid = Some(hospital_cid.to_string());
                            issued_expiries.push(expires_before);
                            Some(
                                issue_admin_personnel_token(&root_key, &read_params).map_err(
                                    |e| ProxyError::Caveat {
                                        code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                        error: e.to_string(),
                                    },
                                )?,
                            )
                        } else {
                            None
                        };

                        let update_token = if access_mode.includes_update() {
                            let mut write_params = InitialAdminPersonnelTokenParams::for_grant(
                                &patient_iota_address.to_string(),
                                &root_subject,
                                encounter_dataset,
                                AdminTokenKind::Update,
                                expires_before,
                            )
                            .map_err(|e| ProxyError::Caveat {
                                code: StatusCode::BAD_REQUEST.as_u16(),
                                error: e.to_string(),
                            })?;
                            write_params.hospital_cid = Some(hospital_cid.to_string());
                            write_params.related_rme_id = related_rme_id;
                            issued_expiries.push(expires_before);
                            Some(
                                issue_admin_personnel_token(&root_key, &write_params).map_err(
                                    |e| ProxyError::Caveat {
                                        code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                        error: e.to_string(),
                                    },
                                )?,
                            )
                        } else {
                            None
                        };
                        (read_token, update_token)
                    } else {
                        return Err(ProxyError::Anyhow {
                        source: anyhow!(
                            "encounter_dataset (RAWAT_JALAN or RAWAT_INAP) is required for administrative personnel access grant"
                        ),
                        code: StatusCode::BAD_REQUEST,
                    });
                    }
                }
                AuthRole::MedicalPersonnel => {
                    return Err(ProxyError::Anyhow {
                        source: anyhow!(
                            "Initial patient grants are only issued to AdministrativePersonnel"
                        ),
                        code: StatusCode::BAD_REQUEST,
                    });
                }
                AuthRole::Patient => {
                    return Err(ProxyError::Anyhow {
                        source: anyhow!("Invalid personnel account"),
                        code: StatusCode::BAD_REQUEST,
                    });
                }
            };

        let access_keys_duration = issued_expiries
            .into_iter()
            .map(|expiry| expiry_ttl_secs(expiry, now))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .max()
            .ok_or_else(|| ProxyError::Anyhow {
                source: anyhow!("No access token was issued"),
                code: StatusCode::BAD_REQUEST,
            })?;

        let access_keys = AccessKeys {
            enc_data_pre_secret_key_seed: payload.enc_data_pre_secret_key_seed,
            k_frag: payload.k_frag,
            data_pre_public_key: payload.data_pre_public_key,
            data_pre_secret_key_seed_capsule: payload.data_pre_secret_key_seed_capsule,
            patient_pre_public_key: payload.patient_pre_public_key,
            signer_pre_public_key: payload.signer_pre_public_key,
        };

        let _: () = conn
            .set_options(
                format!(
                    "keys:{}@{}",
                    hospital_personnel_iota_address.to_string(),
                    patient_iota_address.to_string()
                ),
                Utils::serde_serialize_to_base64(&access_keys).context(current_fn!())?,
                SetOptions::default().with_expiration(SetExpiry::EX(access_keys_duration)),
            )
            .context(current_fn!())?;

        let access_token_read_hash = hospital_personnel_access_token_read
            .as_ref()
            .map(|token| decmed_macaroon_auth::hash_token(token));
        let access_token_update_hash = hospital_personnel_access_token_update
            .as_ref()
            .map(|token| decmed_macaroon_auth::hash_token(token));
        let res_data = json!({
            "access_token_read": hospital_personnel_access_token_read,
            "access_token_update": hospital_personnel_access_token_update,
            "access_token_read_hash": access_token_read_hash,
            "access_token_update_hash": access_token_update_hash,
            "related_rme_id": response_related_rme_id,
        });

        Ok(Utils::build_success_response(res_data, StatusCode::OK))
    }

    pub async fn update_medical_record(
        State(state): State<Arc<AppState>>,
        Extension(current_user): Extension<CurrentUser>,
        Json(payload): Json<HandlerUpdateMedicalRecordPayload>,
    ) -> Result<Response, ProxyError> {
        if current_user.role != AuthRole::MedicalPersonnel {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid role"),
                code: StatusCode::UNAUTHORIZED,
            });
        }

        if current_user.purpose != ReencryptionPurposeType::Update {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Illegal action. Invalid purpose"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        let (
            medical_metadata,
            hospital_personnel_iota_address,
            proxy_iota_address,
            proxy_iota_key_pair,
            patient_iota_address,
        ) = {
            let patient_iota_address = IotaAddress::from_str(&payload.patient_iota_address)
                .map_err(|_| anyhow!("Invalid patient IOTA address"))
                .code(StatusCode::BAD_REQUEST)?;
            let medical_metadata: ClientMedicalMetadata =
                Utils::serde_deserialize_from_base64(payload.medical_metadata)
                    .map_err(|_| anyhow!("Invalid medical metadata"))
                    .code(StatusCode::BAD_REQUEST)?;
            let hospital_personnel_iota_address = IotaAddress::from_str(&current_user.iota_address)
                .map_err(|_| anyhow!("Invalid hospital personnel IOTA address"))?;
            let proxy_iota_address =
                IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;
            let proxy_iota_key_pair = IotaKeyPair::decode(&state.proxy_iota_key_pair)
                .map_err(|e| anyhow!(e.to_string()))
                .context(current_fn!())?;

            (
                medical_metadata,
                hospital_personnel_iota_address,
                proxy_iota_address,
                proxy_iota_key_pair,
                patient_iota_address,
            )
        };

        let cid = Utils::add_and_pin_to_ipfs(medical_metadata.enc_data)
            .await
            .context(current_fn!())?;
        let created_at = Utils::sys_time_to_iso(std::time::SystemTime::now());

        let medical_metadata = MedicalMetadata {
            capsule: medical_metadata.capsule,
            cid,
            created_at,
            enc_key_and_nonce: medical_metadata.enc_key_and_nonce,
        };

        let _ = state
            .move_call
            .update_medical_record(
                &hospital_personnel_iota_address,
                Utils::serde_serialize_to_base64(&medical_metadata).context(current_fn!())?,
                &patient_iota_address,
                proxy_iota_address,
                proxy_iota_key_pair,
            )
            .await
            .context(current_fn!())?;

        Ok(Utils::build_success_response((), StatusCode::OK))
    }

    pub async fn revoke_patient_access(
        State(state): State<Arc<AppState>>,
        Json(payload): Json<crate::types::PatientRevocationPayload>,
    ) -> Result<Response, ProxyError> {
        let patient_iota_address = IotaAddress::from_str(&payload.patient_address)
            .map_err(|_| anyhow!("Invalid patient IOTA address"))
            .code(StatusCode::BAD_REQUEST)?;
        let _proxy_iota_address =
            IotaAddress::from_str(&state.proxy_iota_address).context(current_fn!())?;

        // Verify patient signature against the full canonical revocation payload.
        let signature = Utils::construct_signature_from_str(&payload.signature)
            .map_err(|_| anyhow!("Invalid signature"))
            .code(StatusCode::BAD_REQUEST)?;
        let canonical = serde_json::to_string(&PatientRevocationSignedPayload::from(&payload))
            .map_err(|e| anyhow!(e.to_string()))
            .code(StatusCode::BAD_REQUEST)?;
        let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
        signature
            .verify_secure(
                &intent_message,
                patient_iota_address,
                SignatureScheme::ED25519,
            )
            .map_err(|_| anyhow!("Invalid patient signature"))
            .code(StatusCode::UNAUTHORIZED)?;

        let mut conn = state.redis_pool.get().context(current_fn!())?;
        let ttl = revocation_ttl(payload.expires_before.as_deref())?;

        if payload.delegated_by.is_some() != payload.delegated_to.is_some() {
            return Err(ProxyError::Anyhow {
                source: anyhow!("delegated_by and delegated_to must be provided together"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        let token_hash = payload
            .token_hash
            .as_ref()
            .ok_or_else(|| ProxyError::Anyhow {
                source: anyhow!("token_hash is required for token revocation"),
                code: StatusCode::BAD_REQUEST,
            })?;
        let token_key = decmed_macaroon_auth::token_revocation_key(token_hash);
        let _: () = conn
            .set_options(
                token_key,
                payload.tx_digest.clone(),
                SetOptions::default().with_expiration(SetExpiry::EX(ttl)),
            )
            .context(current_fn!())?;

        let _: usize = conn
            .del(format!(
                "keys:{}@{}",
                payload.root_subject, payload.patient_address
            ))
            .context(current_fn!())?;
        if let Some(delegated_to) = &payload.delegated_to {
            let _: usize = conn
                .del(format!("keys:{}@{}", delegated_to, payload.patient_address))
                .context(current_fn!())?;
        }

        Ok(Utils::build_success_response(
            json!({ "revoked": true }),
            StatusCode::OK,
        ))
    }
}

#[cfg(test)]
mod delegation_attenuation_tests {
    use super::*;

    fn request_context(address: String) -> DelegationRequestProofContext {
        DelegationRequestProofContext {
            request_kind: "custom".to_string(),
            mode: "read".to_string(),
            delegator_iota_address: address,
            delegatee_iota_address:
                "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
            patient_iota_address:
                "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            parent_read_token_hash: Some("parent-read".to_string()),
            parent_write_token_hash: None,
            expires_before: "2030-05-16T18:00:00+00:00".to_string(),
            related_rme_id: None,
            preset: None,
            read_datasets: vec![DatasetCategory::LABORATORIUM],
            write_datasets: Vec::new(),
            read_functions: vec![FunctionCategory::LABORATORIUM],
            write_functions: Vec::new(),
        }
    }

    #[test]
    fn delegation_request_signature_must_match_canonical_context() {
        let seed = [7u8; 64];
        let (address, keypair) = Utils::generate_iota_keys_ed(&seed).unwrap();
        let context = request_context(address.to_string());
        let canonical = context.canonical_message().unwrap();
        let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
        let signature = Signature::new_secure(&intent_message, &keypair).encode_base64();

        verify_delegation_request_signature(&context, &signature, &address.to_string()).unwrap();

        let mut tampered = context;
        tampered.read_datasets = vec![DatasetCategory::APOTEK];
        assert!(
            verify_delegation_request_signature(&tampered, &signature, &address.to_string())
                .is_err()
        );
    }

    #[test]
    fn write_scope_rejects_administrative_general() {
        let err =
            ensure_no_administrative_general_write(&[FunctionCategory::ADMINISTRATIVE_GENERAL])
                .unwrap_err();

        match err {
            ProxyError::Anyhow { code, .. } => assert_eq!(code, StatusCode::BAD_REQUEST),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn doctor_admin_preset_does_not_delegate_administrative_general_write() {
        let params = build_admin_delegation_params(
            "doctor",
            DatasetCategory::RAWAT_JALAN,
            "0x2222222222222222222222222222222222222222222222222222222222222222",
            "0x3333333333333333333333333333333333333333333333333333333333333333",
            "RME-001",
            chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
                .unwrap()
                .with_timezone(&chrono::Utc),
        )
        .unwrap();

        assert!(!params
            .write_functions
            .contains(&FunctionCategory::ADMINISTRATIVE_GENERAL));
    }
}
