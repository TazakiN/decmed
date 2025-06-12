use tauri::{async_runtime::Mutex, State};

use crate::{
    types::{AppState, ResponseStatus, SuccessResponse},
    utils::parse_keys_entry,
};

#[tauri::command]
pub async fn signout(state: State<'_, Mutex<AppState>>) -> Result<SuccessResponse<()>, String> {
    let state = state.lock().await;

    let mut keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    keys_entry.iota_address = None;
    keys_entry.iota_key_pair = None;
    keys_entry.iota_nonce = None;
    keys_entry.pre_nonce = None;
    keys_entry.pre_secret_key = None;
    let keys_entry = serde_json::to_vec(&keys_entry).unwrap();
    state.keys_entry.set_secret(&keys_entry).unwrap();

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}

#[tauri::command]
pub async fn reset(state: State<'_, Mutex<AppState>>) -> Result<SuccessResponse<()>, String> {
    let mut state = state.lock().await;

    let mut keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    keys_entry.activation_key = None;
    keys_entry.iota_address = None;
    keys_entry.iota_key_pair = None;
    keys_entry.iota_nonce = None;
    keys_entry.pre_nonce = None;
    keys_entry.pre_secret_key = None;
    keys_entry.id = None;
    let keys_entry = serde_json::to_vec(&keys_entry).unwrap();
    state.keys_entry.set_secret(&keys_entry).unwrap();
    state.auth_state.role = None;
    state.auth_state.is_signed_up = false;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}
