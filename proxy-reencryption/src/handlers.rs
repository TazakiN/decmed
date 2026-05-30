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
use crate::types::{
    AccessKeys, AppState, AuthRole, ClientMedicalMetadata, CurrentUser,
    GenerateMacaroonKeyHandlerResponse, GenerateSignatureHandlerPayload, GetNonceHandlerPayload,
    HandlerCreateMedicalRecordPayload, HandlerCreateMedicalRecordSegmentPayload,
    HandlerGetAdministrativeDataQueryParams, HandlerGetMedicalRecordQueryParams,
    HandlerGetMedicalRecordUpdateQueryParams, HandlerStoreKeysPayload,
    HandlerUpdateMedicalRecordPayload, MedicalMetadata, MoveHospitalPersonnelRole,
    PatientPrivateAdministrativeMetadata, ReencryptionPurposeType,
};
use crate::utils::Utils;
use decmed_macaroon_auth::{
    issue_admin_personnel_token, issue_initial_token, AccessMode, AdminTokenKind,
    InitialAdminPersonnelTokenParams, InitialDoctorTokenParams,
};
use decmed_macaroon_auth::{
    verify_decmed_token, CaveatVerificationError, SegmentAccessContext, TokenVerificationContext,
    WalletProofContext,
};

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

fn issue_legacy_role_macaroons(
    root_key: &macaroon::MacaroonKey,
    role_str: &str,
    subject: &str,
    hospital_id: Option<&str>,
    read_keys_duration: u64,
    update_keys_duration: Option<u64>,
) -> Result<(String, Option<String>), ProxyError> {
    let read_exp = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + read_keys_duration;

    let mut read_macaroon =
        macaroon::Macaroon::create(Some("proxy-reencryption".into()), root_key, subject.into())
            .map_err(|_| anyhow!("Failed to create macaroon"))
            .code(StatusCode::INTERNAL_SERVER_ERROR)?;

    read_macaroon.add_first_party_caveat(format!("role = {}", role_str).into());
    read_macaroon.add_first_party_caveat("purpose = Read".into());
    read_macaroon.add_first_party_caveat(format!("subject = {}", subject).into());
    if let Some(hospital_id) = hospital_id.filter(|id| !id.is_empty()) {
        read_macaroon.add_first_party_caveat(format!("hospital_id = {}", hospital_id).into());
    }
    read_macaroon.add_first_party_caveat(format!("time < {}", read_exp).into());

    let read_token = read_macaroon
        .serialize(macaroon::Format::V2)
        .map_err(|_| anyhow!("Failed to serialize macaroon"))
        .code(StatusCode::INTERNAL_SERVER_ERROR)?;

    let update_token = if let Some(update_keys_duration) = update_keys_duration {
        let update_exp = std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + update_keys_duration;

        let mut update_macaroon =
            macaroon::Macaroon::create(Some("proxy-reencryption".into()), root_key, subject.into())
                .map_err(|_| anyhow!("Failed to create macaroon"))
                .code(StatusCode::INTERNAL_SERVER_ERROR)?;

        update_macaroon.add_first_party_caveat(format!("role = {}", role_str).into());
        update_macaroon.add_first_party_caveat("purpose = Update".into());
        update_macaroon.add_first_party_caveat(format!("subject = {}", subject).into());
        if let Some(hospital_id) = hospital_id.filter(|id| !id.is_empty()) {
            update_macaroon.add_first_party_caveat(format!("hospital_id = {}", hospital_id).into());
        }
        update_macaroon.add_first_party_caveat(format!("time < {}", update_exp).into());

        Some(
            update_macaroon
                .serialize(macaroon::Format::V2)
                .map_err(|_| anyhow!("Failed to serialize macaroon"))
                .code(StatusCode::INTERNAL_SERVER_ERROR)?,
        )
    } else {
        None
    };

    Ok((read_token, update_token))
}

impl Handlers {
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
            let mac =
                macaroon::Macaroon::deserialize(&current_user.bearer_token).map_err(|_| {
                    ProxyError::Anyhow {
                        source: anyhow!("Invalid access token"),
                        code: StatusCode::UNAUTHORIZED,
                    }
                })?;
            let root_key = macaroon::MacaroonKey::generate(&state.macaroon_root_key);
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
                &TokenVerificationContext {
                    operation: AccessMode::Write,
                    segment,
                    wallet_signature_b64: wallet_sig.map(|s| s.to_string()),
                    wallet_timestamp: wallet_timestamp.map(|s| s.to_string()),
                    now: chrono::Utc::now(),
                },
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
                        let mac = macaroon::Macaroon::deserialize(&current_user.bearer_token)
                            .map_err(|_| ProxyError::Anyhow {
                                source: anyhow!("Invalid access token"),
                                code: StatusCode::UNAUTHORIZED,
                            })?;
                        let root_key = macaroon::MacaroonKey::generate(&state.macaroon_root_key);
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
                            &TokenVerificationContext {
                                operation: AccessMode::Read,
                                segment: segment.clone(),
                                wallet_signature_b64: wallet_sig.map(|s| s.to_string()),
                                wallet_timestamp: Some(proof_timestamp.clone()),
                                now,
                            },
                            verifier,
                        ) {
                            Ok(_) => break record,
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
                            Err(err) => return Err(map_caveat_error(err)),
                        }
                    }
                }

                break record;
            };

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
            let medical_record_pre_public_key: PublicKey =
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
                    Some(&medical_record_pre_public_key),
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
                current_index,
                prev_index,
                next_index,
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
            "current_index": current_index,
            "data_pre_public_key": access_keys.data_pre_public_key,
            "data_pre_secret_key_seed_capsule": access_keys.data_pre_secret_key_seed_capsule,
            "enc_administrative_data": enc_administrative_data,
            "enc_administrative_data_key_nonce": enc_administrative_data_key_nonce,
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
            .del(patient_iota_address.to_string())
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
                })
            }
        };

        // Create access token for hospital personnel
        let root_key = macaroon::MacaroonKey::generate(&state.macaroon_root_key);

        let role_str = match hospital_personnel_role {
            AuthRole::AdministrativePersonnel => "AdministrativePersonnel",
            AuthRole::MedicalPersonnel => "MedicalPersonnel",
            AuthRole::Patient => "Patient",
        };

        let root_subject = payload
            .root_subject
            .clone()
            .unwrap_or_else(|| hospital_personnel_iota_address.to_string());

        let hospital_id_opt = payload.hospital_id.as_deref().filter(|id| !id.is_empty());
        let mut access_keys_duration = update_keys_duration.unwrap_or(read_keys_duration);

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
                        access_keys_duration = keys_duration;
                        let expires_before =
                            chrono::Utc::now() + chrono::Duration::seconds(keys_duration as i64);

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
                        read_params.require_wallet_proof = true;
                        if let Some(hospital_id) = payload.hospital_id.clone() {
                            read_params.hospital_id = Some(hospital_id);
                        }

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
                        write_params.require_wallet_proof = true;
                        if let Some(hospital_id) = payload.hospital_id.clone() {
                            write_params.hospital_id = Some(hospital_id);
                        }

                        let read_token = issue_admin_personnel_token(&root_key, &read_params)
                            .map_err(|e| ProxyError::Caveat {
                                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                error: e.to_string(),
                            })?;
                        let update_token = issue_admin_personnel_token(&root_key, &write_params)
                            .map_err(|e| ProxyError::Caveat {
                                code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                error: e.to_string(),
                            })?;
                        (read_token, Some(update_token))
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
                    if let Some(related_rme_id) = payload.related_rme_id.clone() {
                        let expires_before = chrono::Utc::now()
                            + chrono::Duration::seconds(read_keys_duration as i64);
                        let mut read_params = InitialDoctorTokenParams::example_rm_initial_token(
                            &patient_iota_address.to_string(),
                            &related_rme_id,
                            &root_subject,
                        );
                        read_params.expires_before = expires_before;
                        read_params.purpose = Some("Read".into());
                        read_params.role = Some(role_str.to_string());
                        read_params.require_wallet_proof = true;
                        if let Some(hospital_id) = payload.hospital_id.clone() {
                            read_params.hospital_id = Some(hospital_id);
                        }

                        let read_token =
                            issue_initial_token(&root_key, &read_params).map_err(|e| {
                                ProxyError::Caveat {
                                    code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                                    error: e.to_string(),
                                }
                            })?;

                        let update_token = if let Some(update_keys_duration) = update_keys_duration
                        {
                            let update_expires = chrono::Utc::now()
                                + chrono::Duration::seconds(update_keys_duration as i64);
                            let mut update_params = read_params.clone();
                            update_params.expires_before = update_expires;
                            update_params.purpose = Some("Update".into());
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
                    } else {
                        issue_legacy_role_macaroons(
                            &root_key,
                            role_str,
                            &root_subject,
                            hospital_id_opt,
                            read_keys_duration,
                            update_keys_duration,
                        )?
                    }
                }
                AuthRole::Patient => {
                    return Err(ProxyError::Anyhow {
                        source: anyhow!("Invalid personnel account"),
                        code: StatusCode::BAD_REQUEST,
                    })
                }
            };

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

        let res_data = json!({
            "access_token_read": hospital_personnel_access_token_read,
            "access_token_update": hospital_personnel_access_token_update,
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
}
