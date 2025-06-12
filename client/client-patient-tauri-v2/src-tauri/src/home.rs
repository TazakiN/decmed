use std::str::FromStr;

use iota_types::base_types::IotaAddress;
use tauri::{async_runtime::Mutex, State};

use crate::{
    types::{
        AppState, CommandGetMedicalRecordsResponse, MedicalMetadata, MoveMedicalMetadata,
        ResponseStatus, SuccessResponse,
    },
    utils::{
        construct_pt, construct_shared_object_call_arg, get_iota_client,
        handle_error_move_call_read_only, move_call_read_only, parse_keys_entry,
        parse_move_read_only_result,
    },
};

#[tauri::command]
pub async fn get_medical_records(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<CommandGetMedicalRecordsResponse>>, String> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    let iota_client = get_iota_client().await;

    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        false,
    );
    let id_medical_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_medical_table_id,
        state.account_package.id_medical_table_version,
        false,
    );

    let pt = construct_pt(
        "get_medical_records".to_string(),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![address_id_table_call_arg, id_medical_table_call_arg],
    );

    let sender = IotaAddress::from_str(keys_entry.iota_address.unwrap().as_str()).unwrap();
    let response = move_call_read_only(sender, &iota_client, pt).await;

    handle_error_move_call_read_only("get_medical_records".to_string(), response.clone())?;

    let medical_records: Vec<MoveMedicalMetadata> = parse_move_read_only_result(response, 0)?;
    let medical_records: Vec<CommandGetMedicalRecordsResponse> = medical_records
        .iter()
        .map(|val| {
            let medical_metadata = serde_json::from_slice::<MedicalMetadata>(&val.data).unwrap();
            CommandGetMedicalRecordsResponse {
                index: val.index,
                created_at: medical_metadata.created_at,
            }
        })
        .collect();

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: medical_records,
    })
}
