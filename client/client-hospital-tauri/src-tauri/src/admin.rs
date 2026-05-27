use anyhow::{anyhow, Context};
use tauri::{async_runtime::Mutex, State};
use umbral_pre::{decrypt_original, Capsule};

use crate::{
    current_fn,
    hospital_error::HospitalError,
    types::{
        AppState, CommandGetDelegateeCandidatesResponseData,
        CommandGetHospitalPersonnelsResponseData, DelegateeCandidate, HospitalPersonnelMetadata,
        MoveCallHospitalAdminAddActivationKeyPayload, PublicAdministrativeData, ResponseStatus,
        SuccessResponse,
    },
    utils::{
        argon_hash, encode_activation_key_from_keys_entry, get_iota_address_from_keys_entry,
        get_pre_keys_from_keys_entry, parse_keys_entry, serde_deserialize_from_base64,
    },
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

#[tauri::command]
pub async fn get_hospital_personnels(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<CommandGetHospitalPersonnelsResponseData>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (hospital_admin_pre_secret_key, hospital_admin_iota_address, activation_key) = {
        let activation_key =
            encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
        let hospital_admin_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let (hospital_admin_pre_secret_key, _) = get_pre_keys_from_keys_entry(
            &keys_entry,
            state
                .auth_state
                .session_pin
                .clone()
                .ok_or(anyhow!("Session PIN not found").context(current_fn!()))?,
        )?;

        (
            hospital_admin_pre_secret_key,
            hospital_admin_iota_address,
            activation_key,
        )
    };

    let hospital_personnels_metadata = state
        .move_call
        .get_hospital_personnels(activation_key, hospital_admin_iota_address)
        .await
        .context(current_fn!())?;

    let hospital_personnels_metadata = hospital_personnels_metadata
        .iter()
        .map(|metadata| {
            let metadata: MoveCallHospitalAdminAddActivationKeyPayload = serde_json::from_slice(
                &(STANDARD
                    .decode(metadata.metadata.clone())
                    .context(current_fn!())?),
            )
            .context(current_fn!())?;
            let capsule: Capsule =
                serde_deserialize_from_base64(metadata.capsule).context(current_fn!())?;
            let ori = decrypt_original(
                &hospital_admin_pre_secret_key,
                &capsule,
                &STANDARD
                    .decode(metadata.enc_metadata)
                    .context(current_fn!())?,
            )
            .map_err(|e| anyhow!(e.to_string()).context(current_fn!()))?;
            Ok(
                serde_json::from_slice::<HospitalPersonnelMetadata>(&*ori)
                    .context(current_fn!())?,
            )
        })
        .collect::<Result<Vec<HospitalPersonnelMetadata>, HospitalError>>()
        .context(current_fn!())?;

    let data = CommandGetHospitalPersonnelsResponseData {
        personnels: hospital_personnels_metadata,
    };

    Ok(SuccessResponse {
        data,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn get_delegatee_candidates(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<CommandGetDelegateeCandidatesResponseData>, HospitalError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let activation_key =
        encode_activation_key_from_keys_entry(&keys_entry).context(current_fn!())?;
    let personnel_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
    let admin_personnel_id = argon_hash("admin".to_string()).context(current_fn!())?;

    let move_candidates = state
        .move_call
        .get_delegatee_candidates(activation_key, admin_personnel_id, personnel_iota_address)
        .await
        .context(current_fn!())?;

    let mut candidates = Vec::new();
    for candidate in move_candidates {
        let public_metadata: PublicAdministrativeData =
            serde_deserialize_from_base64(candidate.public_metadata).context(current_fn!())?;
        if let Some(pre_public_key) = public_metadata.pre_public_key {
            candidates.push(DelegateeCandidate {
                personnel_id_hash: candidate.personnel_id_hash,
                name: public_metadata.name,
                role: candidate.role,
                sub_role: candidate.sub_role,
                iota_address: candidate.address.to_string(),
                pre_public_key,
            });
        }
    }

    Ok(SuccessResponse {
        data: CommandGetDelegateeCandidatesResponseData { candidates },
        status: ResponseStatus::Success,
    })
}
