use anyhow::{anyhow, Context};
use iota_types::crypto::{EncodeDecodeBase64, Signature};
use serde_json::json;
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, http::StatusCode, State};
use tauri_plugin_http::reqwest;
use umbral_pre::{encrypt, generate_kfrags, SecretKey, Signer};

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    patient_error::PatientError,
    types::{
        AppState, CommandProcessQrResponse, HospitalPersonnelPublicAdministrativeData,
        MoveCreateAccessData, MoveCreateAccessMetadata, ProxyReencryptionErrorResponse,
        ProxyReencryptionNoncePayload, ProxyReencryptionPostKeysResponseData,
        ProxyReencryptionSuccessResponse, ResponseStatus, SuccessResponse,
    },
    utils::{
        compute_pre_keys, decode_hospital_grant_qr, do_http_post_json_request,
        generate_64_bytes_seed, get_iota_address_from_keys_entry,
        get_iota_key_pair_from_keys_entry, get_pre_keys_from_keys_entry, parse_keys_entry,
        process_qr_image, serde_deserialize_from_base64, serde_serialize_to_base64,
        sys_time_to_iso,
    },
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use decmed_rme_segment::DatasetCategory;

#[tauri::command]
pub async fn create_access(
    state: State<'_, Mutex<AppState>>,
    pin: String,
    encounter_dataset: Option<String>,
) -> Result<SuccessResponse<()>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;
    let req_client = reqwest::Client::new();

    let (
        patient_iota_address,
        patient_iota_key_pair,
        patient_pre_secret_key,
        patient_pre_public_key,
    ) = {
        let patient_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let patient_iota_key_pair =
            get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
        let (patient_pre_secret_key, patient_pre_public_key) =
            get_pre_keys_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

        (
            patient_iota_address,
            patient_iota_key_pair,
            patient_pre_secret_key,
            patient_pre_public_key,
        )
    };

    let nonce = {
        let payload = ProxyReencryptionNoncePayload {
            iota_address: patient_iota_address.to_string(),
        };
        do_http_post_json_request::<
            _,
            ProxyReencryptionSuccessResponse<String>,
            ProxyReencryptionErrorResponse,
        >(
            None,
            &format!("{}/nonce", PROXY_BASE_URL),
            &payload,
            &req_client,
            StatusCode::OK,
        )
        .await
        .context(current_fn!())?
        .data
    };

    let (
        hospital_id,
        hospital_personnel_iota_address,
        hospital_personnel_pre_public_key,
        data_pre_secret_key_seed_capsule,
        enc_data_pre_secret_key_seed,
        data_pre_public_key,
    ) = {
        let grant = decode_hospital_grant_qr(
            state
                .scan_state
                .hospital_personnel_qr_content
                .clone()
                .context(current_fn!())?,
        )
        .context(current_fn!())?;

        let hospital_personnel_iota_address = grant.personnel_iota_address;
        let hospital_personnel_pre_public_key = grant.personnel_pre_public_key;
        let hospital_id = grant.hospital_id;

        let data_pre_secret_key_seed = generate_64_bytes_seed();
        let (data_pre_secret_key_seed_capsule, enc_data_pre_secret_key_seed) = encrypt(
            &hospital_personnel_pre_public_key,
            &data_pre_secret_key_seed[0..32],
        )
        .map_err(|e| anyhow!(e.to_string()))?;

        let (_, data_pre_public_key) =
            compute_pre_keys(&data_pre_secret_key_seed[0..32]).context(current_fn!())?;

        (
            hospital_id,
            hospital_personnel_iota_address,
            hospital_personnel_pre_public_key,
            data_pre_secret_key_seed_capsule,
            enc_data_pre_secret_key_seed,
            data_pre_public_key,
        )
    };

    let (signer_secret_key, signer_public_key) = {
        let signer_secret_key = Signer::new(SecretKey::random());
        let signer_public_key = signer_secret_key.verifying_key();

        (signer_secret_key, signer_public_key)
    };

    let k_frag = {
        let k_frags = generate_kfrags(
            &patient_pre_secret_key,
            &data_pre_public_key,
            &signer_secret_key,
            1,
            1,
            true,
            true,
        );
        k_frags[0].clone().unverify()
    };

    let signature = {
        let intent_message = IntentMessage::new(Intent::personal_message(), nonce);
        Signature::new_secure(&intent_message, &patient_iota_key_pair)
    };

    let raw = encounter_dataset
        .or_else(|| {
            state
                .scan_state
                .encounter_dataset
                .map(|ds| serde_json::to_string(&ds).unwrap_or_default())
        })
        .context(current_fn!())?;
    let json = format!("\"{}\"", raw.trim_matches('"'));
    let encounter_dataset =
        serde_json::from_str::<DatasetCategory>(&json).context(current_fn!())?;
    let administrative_access_exp_dur_minutes = match encounter_dataset {
        DatasetCategory::RAWAT_JALAN => 24 * 60,
        DatasetCategory::RAWAT_INAP => 3 * 24 * 60,
        _ => {
            return Err(anyhow!(
                "encounter_dataset must be RAWAT_JALAN or RAWAT_INAP for administrative access"
            )
            .context(current_fn!())
            .into())
        }
    };

    let enc_data_pre_secret_key_seed_b64 = STANDARD.encode(enc_data_pre_secret_key_seed);
    let data_pre_secret_key_seed_capsule_b64 =
        serde_serialize_to_base64(&data_pre_secret_key_seed_capsule).context(current_fn!())?;
    let patient_pre_public_key_b64 =
        serde_serialize_to_base64(&patient_pre_public_key).context(current_fn!())?;

    let mut payload = json!({
        "enc_data_pre_secret_key_seed": enc_data_pre_secret_key_seed_b64,
        "hospital_personnel_iota_address": hospital_personnel_iota_address.to_string(),
        "k_frag": serde_serialize_to_base64(&k_frag).context(current_fn!())?,
        "data_pre_public_key": serde_serialize_to_base64(&data_pre_public_key).context(current_fn!())?,
        "data_pre_secret_key_seed_capsule": data_pre_secret_key_seed_capsule_b64,
        "patient_iota_address": patient_iota_address.to_string(),
        "patient_pre_public_key": patient_pre_public_key_b64,
        "signature": signature.encode_base64(),
        "signer_pre_public_key": serde_serialize_to_base64(&signer_public_key)
            .context(current_fn!())?,
        "root_subject": hospital_personnel_iota_address.to_string(),
    });
    if !hospital_id.is_empty() {
        payload["hospital_id"] = json!(hospital_id);
    }
    payload["encounter_dataset"] = json!(encounter_dataset);

    let access_token = do_http_post_json_request::<
        _,
        ProxyReencryptionSuccessResponse<ProxyReencryptionPostKeysResponseData>,
        ProxyReencryptionErrorResponse,
    >(
        None,
        &format!("{}/keys", PROXY_BASE_URL),
        &payload,
        &req_client,
        StatusCode::OK,
    )
    .await
    .context(current_fn!())?
    .data;

    let access_token_update = access_token.access_token_update.ok_or_else(|| {
        anyhow!(
            "Proxy did not issue write access token (read-only). \
             Restart proxy-reencryption to the latest version and scan the Administrative Personnel QR."
        )
        .context(current_fn!())
    })?;
    let access_token_read_hash = access_token.access_token_read_hash.clone();
    let access_token_update_hash =
        access_token
            .access_token_update_hash
            .clone()
            .ok_or_else(|| {
                anyhow!("Proxy did not return write access token hash").context(current_fn!())
            })?;
    let related_rme_id = access_token.related_rme_id.clone();

    let (metadata_read, metadata_update, date) = {
        let patient_name = state
            .administrative_data
            .as_ref()
            .ok_or(anyhow!("Administrative data not found on state").context(current_fn!()))?
            .private
            .name
            .clone()
            .context(current_fn!())?;

        let data_read = MoveCreateAccessData {
            patient_name: patient_name.clone(),
            patient_iota_address: patient_iota_address.to_string(),
            access_token: access_token.access_token_read,
            patient_pre_public_key: None,
            enc_data_pre_secret_key_seed: Some(enc_data_pre_secret_key_seed_b64.clone()),
            data_pre_secret_key_seed_capsule: Some(data_pre_secret_key_seed_capsule_b64.clone()),
            related_rme_id: None,
        };
        let (data_capsule_read, enc_data_read) = encrypt(
            &hospital_personnel_pre_public_key,
            &serde_json::to_vec(&data_read).context(current_fn!())?,
        )
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
        let metadata_read = MoveCreateAccessMetadata {
            capsule: serde_serialize_to_base64(&data_capsule_read).context(current_fn!())?,
            enc_data: STANDARD.encode(enc_data_read),
        };

        let data_update = MoveCreateAccessData {
            access_token: access_token_update,
            patient_name,
            patient_iota_address: patient_iota_address.to_string(),
            patient_pre_public_key: Some(patient_pre_public_key_b64),
            enc_data_pre_secret_key_seed: Some(enc_data_pre_secret_key_seed_b64),
            data_pre_secret_key_seed_capsule: Some(data_pre_secret_key_seed_capsule_b64),
            related_rme_id,
        };

        let (data_capsule_update, enc_data_update) = encrypt(
            &hospital_personnel_pre_public_key,
            &serde_json::to_vec(&data_update).context(current_fn!())?,
        )
        .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
        let metadata_update = MoveCreateAccessMetadata {
            capsule: serde_serialize_to_base64(&data_capsule_update).context(current_fn!())?,
            enc_data: STANDARD.encode(enc_data_update),
        };

        let date = sys_time_to_iso(std::time::SystemTime::now());

        (metadata_read, metadata_update, date)
    };

    let metadata = vec![
        serde_serialize_to_base64(&metadata_read).context(current_fn!())?,
        serde_serialize_to_base64(&metadata_update).context(current_fn!())?,
    ];

    let _ = state
        .move_call
        .create_access(
            date,
            &hospital_personnel_iota_address,
            metadata,
            vec![access_token_read_hash, access_token_update_hash],
            administrative_access_exp_dur_minutes,
            patient_iota_address,
            patient_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn process_qr(
    state: State<'_, Mutex<AppState>>,
    qr_bytes: Vec<u8>,
) -> Result<SuccessResponse<CommandProcessQrResponse>, PatientError> {
    let mut state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;
    let patient_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;

    let (_meta, hp_addr_pub_key) = process_qr_image(&qr_bytes).context(current_fn!())?;
    let grant = decode_hospital_grant_qr(hp_addr_pub_key.clone()).context(current_fn!())?;
    state.scan_state.hospital_personnel_qr_content = Some(hp_addr_pub_key.clone());
    let hospital_personnel_iota_address = grant.personnel_iota_address;

    let (hospital_personnel_public_administrative_data, hospital_name) = state
        .move_call
        .get_hospital_personnel_info(&hospital_personnel_iota_address, patient_iota_address)
        .await
        .context(current_fn!())?;

    let hospital_personnel_public_administrative_data: HospitalPersonnelPublicAdministrativeData =
        serde_deserialize_from_base64(hospital_personnel_public_administrative_data)
            .context(current_fn!())?;

    let res_data = CommandProcessQrResponse {
        hospital_personnel_hospital_name: hospital_name,
        hospital_personnel_name: hospital_personnel_public_administrative_data.name.unwrap(),
    };

    Ok(SuccessResponse {
        data: res_data,
        status: ResponseStatus::Success,
    })
}
