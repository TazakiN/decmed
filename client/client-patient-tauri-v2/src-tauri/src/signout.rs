use tauri::{async_runtime::Mutex, State};

use crate::{types::AppState, utils::parse_keys_entry};

#[tauri::command]
pub async fn signout(state: State<'_, Mutex<AppState>>) -> Result<(), ()> {
    let state = state.lock().await;

    let mut keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    keys_entry.iota_address = None;
    keys_entry.iota_key_pair = None;
    keys_entry.iota_nonce = None;
    keys_entry.pre_nonce = None;
    keys_entry.pre_secret_key = None;
    keys_entry.pre_public_key = None;
    let keys_entry = serde_json::to_vec(&keys_entry).unwrap();
    state.keys_entry.set_secret(&keys_entry).unwrap();

    Ok(())
}
