use std::str::FromStr;

use iota_types::{
    base_types::IotaAddress,
    crypto::IotaKeyPair,
    gas_coin::NANOS_PER_IOTA,
    transaction::{CallArg, Transaction},
};
use tauri::{async_runtime::Mutex, State};
use umbral_pre::{decrypt_original, Capsule, DefaultDeserialize};

use crate::{
    constants::GAS_BUDGET,
    types::{
        AppState, CommandGetHospitalPersonnelsResponse, HospitalPersonnelMetadata,
        MoveGetHospitalPersonnelsResponse, MoveHospitalAdminAddActivationKeyData, ResponseStatus,
        SuccessResponse,
    },
    utils::{
        aes_decrypt, compute_pre_keys, construct_pt, construct_shared_object_call_arg,
        construct_sponsored_tx_data, execute_tx, get_ref_gas_price, handle_error_execute_tx,
        handle_error_move_call_read_only, move_call_read_only, parse_keys_entry,
        parse_move_read_only_result, reserve_gas, sha_hash, validate_by_regex,
    },
};

#[tauri::command]
pub async fn get_hospital_personnels(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<CommandGetHospitalPersonnelsResponse>, String> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());

    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        false,
    );
    let id_hospital_personnel_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_hospital_personnel_table_id,
        state.account_package.id_hospital_personnel_table_version,
        false,
    );

    let pt = construct_pt(
        String::from("get_hospital_personnel"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            address_id_table_call_arg,
            id_hospital_personnel_table_call_arg,
        ],
    );

    let sender = IotaAddress::from_str(keys_entry.iota_address.unwrap().as_str()).unwrap();
    let iota_client = state.iota_client.clone();

    let response = move_call_read_only(sender, &iota_client, pt).await;

    handle_error_move_call_read_only("get_hospital_personnels".to_string(), response.clone())?;

    let hospital_personnels: Vec<MoveGetHospitalPersonnelsResponse> =
        parse_move_read_only_result(response, 0)?;
    let hospital_personnels: Vec<MoveHospitalAdminAddActivationKeyData> = hospital_personnels
        .iter()
        .map(|val| serde_json::from_slice(&val.data).unwrap())
        .collect();

    let pre_seed = aes_decrypt(
        keys_entry.pre_secret_key.unwrap().as_slice(),
        sha_hash(state.auth_state.session_pin.as_ref().unwrap().as_bytes()).as_slice(),
        keys_entry.pre_nonce.unwrap().as_slice(),
    )?;
    let (pre_secret_key, _pre_public_key) = compute_pre_keys(pre_seed.as_slice());

    let personnels: Vec<HospitalPersonnelMetadata> = hospital_personnels
        .iter()
        .map(|val| {
            let capsule = Capsule::from_bytes(val.capsule.as_slice()).unwrap();
            let ori = decrypt_original(&pre_secret_key, &capsule, val.metadata.as_slice()).unwrap();
            serde_json::from_slice::<HospitalPersonnelMetadata>(&*ori).unwrap()
        })
        .collect();
    let data = CommandGetHospitalPersonnelsResponse { personnels };

    Ok(SuccessResponse {
        data,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn update_registered_hospital_name(
    state: State<'_, Mutex<AppState>>,
    hospital_name: String,
) -> Result<SuccessResponse<()>, String> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    let iota_key_pair = aes_decrypt(
        &keys_entry.iota_key_pair.unwrap(),
        &sha_hash(state.auth_state.session_pin.as_ref().unwrap().as_bytes()),
        &keys_entry.iota_nonce.unwrap(),
    )?;
    let iota_key_pair = String::from_utf8(iota_key_pair).unwrap();
    let iota_key_pair = IotaKeyPair::decode(iota_key_pair.as_str()).unwrap();

    if !validate_by_regex(&hospital_name, "^[a-zA-Z0-9 ]{2, 100}$") {
        return Err("Invalid hospital name".to_string());
    }

    let activation_key_activation_key_metadata_table_call_arg = construct_shared_object_call_arg(
        state
            .account_package
            .activation_key_activation_key_metadata_table_id,
        state
            .account_package
            .activation_key_activation_key_metadata_table_version,
        false,
    );
    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        false,
    );
    let hospital_id_registered_hospital_table_call_arg = construct_shared_object_call_arg(
        state
            .account_package
            .hospital_id_registered_hospital_table_id,
        state
            .account_package
            .hospital_id_registered_hospital_table_version,
        true,
    );
    let hospital_name_call_arg = CallArg::Pure(bcs::to_bytes(hospital_name.as_str()).unwrap());
    let id_activation_key_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_activation_key_table_id,
        state.account_package.id_activation_key_table_version,
        false,
    );

    let pt = construct_pt(
        "update_registered_hospital_data".to_string(),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            activation_key_activation_key_metadata_table_call_arg,
            address_id_table_call_arg,
            hospital_id_registered_hospital_table_call_arg,
            hospital_name_call_arg,
            id_activation_key_table_call_arg,
        ],
    );

    let iota_address =
        IotaAddress::from_str(keys_entry.iota_address.as_ref().unwrap().as_str()).unwrap();
    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA * 2, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let tx_data = construct_sponsored_tx_data(
        iota_address,
        gas_coins,
        pt,
        GAS_BUDGET,
        ref_gas_price,
        sponsor_account,
    );

    let signer = iota_key_pair;
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

    let response = execute_tx(tx, reservation_id).await;

    handle_error_execute_tx("update_registered_hospital_name".to_string(), response)?;

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}
