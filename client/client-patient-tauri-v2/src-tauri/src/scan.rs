use tauri::{async_runtime::Mutex, State};

use crate::{
    types::{AppState, CommandProcessQrResponse, ResponseStatus, SuccessResponse},
    utils::{decode_hospital_personnel_id, get_iota_client, parse_keys_entry, process_qr_image},
};

#[tauri::command]
pub async fn process_qr(
    state: State<'_, Mutex<AppState>>,
    qr_bytes: Vec<u8>,
) -> Result<SuccessResponse<CommandProcessQrResponse>, String> {
    let state = state.lock().await;
    let iota_client = get_iota_client().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());

    // hospital_personnel_id = {id_part_hash}@{hospital_part_hash}
    let (_meta, hospital_personnel_id) = process_qr_image(&qr_bytes)?;

    let (id_part_hash, hospital_part_hash) = decode_hospital_personnel_id(hospital_personnel_id)?;

    let res = CommandProcessQrResponse {
        hospital: "a".to_string(),
        name: "a".to_string(),
    };

    Ok(SuccessResponse {
        data: res,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn stop_polling_request_access(state: State<'_, Mutex<AppState>>) -> Result<(), ()> {
    let mut state = state.lock().await;
    state.polling_state.request_access = false;

    Ok(())
}
