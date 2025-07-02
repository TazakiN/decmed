use anyhow::Context;
use tauri::{async_runtime::Mutex, State};
use uuid::Uuid;

use crate::{
    client_error::ClientError,
    current_fn,
    types::{AppState, CommandCreateActivationKeyPayload, ResponseStatus, SuccessResponse},
    utils::{
        get_global_admin_iota_address_from_keys_entry,
        get_global_admin_iota_key_pair_from_keys_entry, parse_keys_entry,
    },
};

#[tauri::command]
pub async fn create_activation_key(
    state: State<'_, Mutex<AppState>>,
    payload: CommandCreateActivationKeyPayload,
) -> Result<SuccessResponse<()>, ClientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let (admin_iota_address, admin_iota_key_pair) = {
        let admin_iota_address =
            get_global_admin_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
        let admin_iota_key_pair =
            get_global_admin_iota_key_pair_from_keys_entry(&keys_entry).context(current_fn!())?;

        (admin_iota_address, admin_iota_key_pair)
    };

    let hospital_admin_id = "admin";
    let hospital_admin_cid = format!("{}@{}", hospital_admin_id, payload.hospital_id);
    let activation_key = Uuid::new_v4().to_string();
    let compound_activation_key = format!("{}@{}", activation_key, hospital_admin_cid);

    let _ = state.move_call.create_activation_key(
        compound_activation_key,
        hospital_admin_id.to_string(),
        payload.hospital_id,
        payload.hospital_name,
        admin_iota_address,
        admin_iota_key_pair,
    );

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}
