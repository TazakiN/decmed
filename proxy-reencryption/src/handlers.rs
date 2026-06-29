use std::str::FromStr;
use std::sync::Arc;

use anyhow::{anyhow, Context};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use axum::{Extension, Json};
use decmed_rme_segment::{
    ClientEncryptedRmeSegment, CreateRmeSegmentResponse, DatasetCategory, RmeSegmentMetadata,
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
use crate::middlewares::{WALLET_SIGNATURE_HEADER, WALLET_TIMESTAMP_HEADER};
use crate::proxy_error::{ProxyError, ResultExt};
use crate::segment_authorization::{authorize_create_rme_segment, authorize_segment_hospital};
use crate::types::{
    AccessKeys, AppState, AuthRole, ClientMedicalMetadata, CurrentUser,
    GenerateMacaroonKeyHandlerResponse, GenerateRelatedRmeIdResponse,
    GenerateSignatureHandlerPayload, GetNonceHandlerPayload, HandlerCreateMedicalRecordPayload,
    HandlerCreateMedicalRecordSegmentPayload, HandlerGetAdministrativeDataQueryParams,
    HandlerGetMedicalRecordQueryParams, HandlerGetMedicalRecordUpdateQueryParams,
    HandlerListMedicalRecordsQueryParams, HandlerStoreKeysPayload,
    HandlerUpdateMedicalRecordPayload, MedicalMetadata, MedicalRecordMetadataItem,
    MoveHospitalPersonnelRole, PatientPrivateAdministrativeMetadata,
    PatientRevocationSignedPayload, ReencryptionPurposeType,
};
use crate::utils::Utils;
use decmed_macaroon_auth::{
    edge_revocation_key,
    format_related_rme_id, issue_admin_personnel_token, issue_initial_token, AccessMode,
    AdminTokenKind, InitialAdminPersonnelTokenParams, InitialDoctorTokenParams, Macaroon,
    MacaroonKey,
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
        let segment_metadata_preview =
            encrypted_segment
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

        let (hospital_personnel_role, read_keys_duration, update_keys_duration): (
            AuthRole,
            u64,
            Option<u64>,
        ) = match role {
            MoveHospitalPersonnelRole::AdministrativePersonnel => {
                (AuthRole::AdministrativePersonnel, 0, None)
            }
            MoveHospitalPersonnelRole::MedicalPersonnel => (
                AuthRole::MedicalPersonnel,
                MEDICAL_KEYS_READ_DUR,
                Some(MEDICAL_KEYS_UPDATE_DUR),
            ),
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
                            Some(issue_admin_personnel_token(&root_key, &read_params).map_err(
                                |e| ProxyError::Caveat {
                                    code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                    error: e.to_string(),
                                },
                            )?)
                        } else {
                            None
                        };

                        let update_token = if access_mode.includes_update() {
                            let mut write_params = InitialAdminPersonnelTokenParams::for_grant(
                                &patient_iota_address.to_string(),
                                &root_subject,
                                encounter_dataset,
                                AdminTokenKind::Write,
                                expires_before,
                            )
                            .map_err(|e| ProxyError::Caveat {
                                code: StatusCode::BAD_REQUEST.as_u16(),
                                error: e.to_string(),
                            })?;
                            write_params.hospital_cid = Some(hospital_cid.to_string());
                            write_params.related_rme_id = related_rme_id;
                            issued_expiries.push(expires_before);
                            Some(issue_admin_personnel_token(&root_key, &write_params).map_err(
                                |e| ProxyError::Caveat {
                                    code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                    error: e.to_string(),
                                },
                            )?)
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
                    if payload.encounter_dataset.is_some() && payload.related_rme_id.is_none() {
                        return Err(ProxyError::Anyhow {
                        source: anyhow!(
                            "Scanned personnel is registered as MedicalPersonnel; use the Administrative Personnel QR from the hospital profile"
                        ),
                        code: StatusCode::BAD_REQUEST,
                    });
                    }
                    let related_rme_id = payload.related_rme_id.clone();
                    if access_mode.includes_update() && related_rme_id.is_none() {
                        return Err(ProxyError::Anyhow {
                            source: anyhow!(
                                "related_rme_id is required for MedicalPersonnel update grant"
                            ),
                            code: StatusCode::BAD_REQUEST,
                        });
                    }
                    if access_mode.includes_update() {
                        let related_rme_id = related_rme_id.as_ref().ok_or_else(|| {
                            ProxyError::Anyhow {
                                source: anyhow!(
                                    "related_rme_id is required for MedicalPersonnel update grant"
                                ),
                                code: StatusCode::BAD_REQUEST,
                            }
                        })?;
                        response_related_rme_id = Some(related_rme_id.clone());
                    }
                    let read_token = if access_mode.includes_read() {
                        let expires_before = requested_expiry.clone().unwrap_or_else(|| {
                            now + chrono::Duration::seconds(read_keys_duration as i64)
                        });
                        let mut read_params =
                            InitialDoctorTokenParams::example_rm_initial_token(
                                &patient_iota_address.to_string(),
                                related_rme_id.as_deref().unwrap_or_default(),
                                &root_subject,
                            )
                            .into_read_only();
                        read_params.expires_before = expires_before;
                        read_params.hospital_cid = Some(hospital_cid.to_string());
                        issued_expiries.push(expires_before);
                        Some(issue_initial_token(&root_key, &read_params).map_err(|e| {
                            ProxyError::Caveat {
                                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                error: e.to_string(),
                            }
                        })?)
                    } else {
                        None
                    };

                    let update_token = if access_mode.includes_update() {
                        let update_keys_duration = update_keys_duration.ok_or_else(|| {
                            ProxyError::Anyhow {
                                source: anyhow!("Update access is not available"),
                                code: StatusCode::BAD_REQUEST,
                            }
                        })?;
                        let update_expires = requested_expiry.clone().unwrap_or_else(|| {
                            now + chrono::Duration::seconds(update_keys_duration as i64)
                        });
                        let related_rme_id = related_rme_id.as_deref().ok_or_else(|| {
                            ProxyError::Anyhow {
                                source: anyhow!(
                                    "related_rme_id is required for MedicalPersonnel update grant"
                                ),
                                code: StatusCode::BAD_REQUEST,
                            }
                        })?;
                        let mut update_params =
                            InitialDoctorTokenParams::example_rm_initial_token(
                                &patient_iota_address.to_string(),
                                related_rme_id,
                                &root_subject,
                            )
                            .into_update_only();
                        update_params.expires_before = update_expires;
                        update_params.hospital_cid = Some(hospital_cid.to_string());
                        issued_expiries.push(update_expires);
                        Some(issue_initial_token(&root_key, &update_params).map_err(|e| {
                            ProxyError::Caveat {
                                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                error: e.to_string(),
                            }
                        })?)
                    } else {
                        None
                    };
                    (read_token, update_token)
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

        let is_edge_revocation = payload.delegated_by.is_some() || payload.delegated_to.is_some();
        if payload.delegated_by.is_some() != payload.delegated_to.is_some() {
            return Err(ProxyError::Anyhow {
                source: anyhow!("delegated_by and delegated_to must be provided together"),
                code: StatusCode::BAD_REQUEST,
            });
        }

        // Set exact token revocation key if token_hash is provided. Delegated edge
        // revocations also set an edge key so descendants that include this edge
        // in their delegation chain are blocked without revoking the root grant.
        if let Some(token_hash) = &payload.token_hash {
            let token_key = decmed_macaroon_auth::token_revocation_key(token_hash);
            let _: () = conn
                .set_options(
                    token_key,
                    payload.tx_digest.clone(),
                    SetOptions::default().with_expiration(SetExpiry::EX(ttl)),
                )
                .context(current_fn!())?;
        }

        if let (Some(delegated_by), Some(delegated_to)) =
            (&payload.delegated_by, &payload.delegated_to)
        {
            let edge_key = edge_revocation_key(
                &payload.patient_address,
                &payload.purpose,
                delegated_by,
                delegated_to,
                payload.related_rme_id.as_deref(),
            );
            let _: () = conn
                .set_options(
                    edge_key,
                    payload.tx_digest.clone(),
                    SetOptions::default().with_expiration(SetExpiry::EX(ttl)),
                )
                .context(current_fn!())?;
        } else if !is_edge_revocation {
            let root_key = decmed_macaroon_auth::root_revocation_key(
                &payload.patient_address,
                &payload.purpose,
                &payload.root_subject,
            );
            let _: () = conn
                .set_options(
                    root_key,
                    payload.tx_digest.clone(),
                    SetOptions::default().with_expiration(SetExpiry::EX(ttl)),
                )
            .context(current_fn!())?;
        }

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

    pub async fn revoke_delegation_access(
        State(_state): State<Arc<AppState>>,
        Extension(_current_user): Extension<CurrentUser>,
        Json(_payload): Json<crate::types::DelegationRevocationPayload>,
    ) -> Result<Response, ProxyError> {
        Err(ProxyError::Anyhow {
            source: anyhow!("Delegation revoke is disabled; only patients can revoke access"),
            code: StatusCode::FORBIDDEN,
        })
    }
}
