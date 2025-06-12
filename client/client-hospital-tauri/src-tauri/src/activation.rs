use std::str::FromStr;

use iota_types::{
    base_types::IotaAddress,
    crypto::IotaKeyPair,
    gas_coin::NANOS_PER_IOTA,
    transaction::{CallArg, Transaction},
};
use tauri::{async_runtime::Mutex, State};
use umbral_pre::{encrypt, DefaultSerialize, PublicKey};

use crate::{
    constants::GAS_BUDGET,
    types::{
        AppState, CommandGlobalAdminAddActivationKeyResponse,
        CommandHospitalAdminAddActivationKeyResponse, HospitalPersonnelMetadata,
        HospitalPersonnelRole, MoveHospitalAdminAddActivationKeyData, ResponseStatus,
        SuccessResponse,
    },
    utils::{
        aes_decrypt, construct_capability_call_arg, construct_pt, construct_shared_object_call_arg,
        construct_sponsored_tx_data, decode_hospital_personnel_id,
        decode_hospital_personnel_id_to_argon, execute_tx, generate_64_bytes_seed,
        generate_iota_keys_ed, get_ref_gas_price, handle_error_execute_tx,
        handle_error_move_call_read_only, move_call_read_only, parse_keys_entry,
        parse_move_read_only_result, reserve_gas, sha_hash, sha_hash_to_hex,
    },
};

#[tauri::command]
pub async fn is_app_activated(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<()>, String> {
    let mut state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());

    if keys_entry.activation_key.is_none() || keys_entry.id.is_none() {
        return Err("Activation key and id not found".to_string());
    }

    let (id_part_hash, hospital_part_hash) =
        decode_hospital_personnel_id_to_argon(keys_entry.id.unwrap())?;

    let hospital_personnel_hospital_part_call_arg =
        CallArg::Pure(bcs::to_bytes(&hospital_part_hash).unwrap());
    let hospital_personnel_id_part_call_arg = CallArg::Pure(bcs::to_bytes(&id_part_hash).unwrap());
    let id_activation_key_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_activation_key_table_id,
        state.account_package.id_activation_key_table_version,
        false,
    );
    let id_address_table = construct_shared_object_call_arg(
        state.account_package.id_address_table_id,
        state.account_package.id_address_table_version,
        false,
    );

    let pt = construct_pt(
        String::from("is_activation_key_id_registered"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            hospital_personnel_hospital_part_call_arg,
            hospital_personnel_id_part_call_arg,
            id_activation_key_table_call_arg,
            id_address_table,
        ],
    );

    let random_seed = generate_64_bytes_seed();
    let (random_iota_address, _random_iota_keypair) = generate_iota_keys_ed(&random_seed);

    let iota_client = state.iota_client.clone();
    let response = move_call_read_only(random_iota_address, &iota_client, pt).await;

    handle_error_move_call_read_only("is_app_activated".to_string(), response.clone())?;

    let is_activation_key_exist: bool = parse_move_read_only_result(response.clone(), 0)?;
    let is_signed_up: bool = parse_move_read_only_result(response, 1)?;

    if !is_activation_key_exist {
        return Err("Activation key not found".to_string());
    }

    state.auth_state.is_signed_up = is_signed_up;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}

#[tauri::command]
pub async fn global_admin_add_activation_key(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<CommandGlobalAdminAddActivationKeyResponse>, String> {
    let state = state.lock().await;
    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let activation_key = uuid::Uuid::new_v4().to_string();
    let hospital_part = "hos_x";
    let id_part = "admin";
    let id = format!("{}@{}", id_part, hospital_part);

    let (id_part_hash, hospital_part_hash) = decode_hospital_personnel_id_to_argon(id.clone())?;

    let activation_key_id = format!("{};{}", activation_key, id);
    let activation_key_id_hash = sha_hash_to_hex(activation_key_id.as_bytes());

    let activation_key_call_arg =
        CallArg::Pure(bcs::to_bytes(activation_key_id_hash.as_str()).unwrap());
    let activation_key_activation_key_metadata_table_call_arg = construct_shared_object_call_arg(
        state
            .account_package
            .activation_key_activation_key_metadata_table_id,
        state
            .account_package
            .activation_key_activation_key_metadata_table_version,
        true,
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
    let hospital_part_call_arg = CallArg::Pure(bcs::to_bytes(hospital_part_hash.as_str()).unwrap());
    let id_activation_key_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_activation_key_table_id,
        state.account_package.id_activation_key_table_version,
        true,
    );
    let id_part_call_arg = CallArg::Pure(bcs::to_bytes(id_part_hash.as_str()).unwrap());
    let global_admin_add_key_cap_call_arg = construct_capability_call_arg(
        &state.iota_client,
        state.account_package.global_admin_add_key_cap_id,
    )
    .await;

    let pt = construct_pt(
        String::from("global_admin_add_activation_key"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            activation_key_call_arg,
            activation_key_activation_key_metadata_table_call_arg,
            hospital_id_registered_hospital_table_call_arg,
            hospital_part_call_arg,
            id_activation_key_table_call_arg,
            id_part_call_arg,
            global_admin_add_key_cap_call_arg,
        ],
    );

    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());

    let tx_data = construct_sponsored_tx_data(
        IotaAddress::from_str(keys_entry.admin_address.unwrap().as_str()).unwrap(),
        gas_coins.clone(),
        pt,
        GAS_BUDGET,
        ref_gas_price,
        sponsor_account,
    );

    let signer =
        IotaKeyPair::decode(keys_entry.admin_secret_key.as_ref().unwrap().as_str()).unwrap();
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);
    let response = execute_tx(tx, reservation_id).await;

    handle_error_execute_tx("global_admin_add_activation_key".to_string(), response)?;

    let res = CommandGlobalAdminAddActivationKeyResponse { activation_key, id };

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: res,
    })
}

#[tauri::command]
pub async fn hospital_admin_add_activation_key(
    state: State<'_, Mutex<AppState>>,
    personnel_id_part: String,
    role: String,
    pin: String,
) -> Result<SuccessResponse<CommandHospitalAdminAddActivationKeyResponse>, String> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(2 * NANOS_PER_IOTA, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let (_, hospital_part) = decode_hospital_personnel_id(keys_entry.id.unwrap())?;
    let id = format!("{}@{}", personnel_id_part, hospital_part);
    let (id_part_hash, hospital_part_hash) = decode_hospital_personnel_id_to_argon(id.clone())?;

    let activation_key = uuid::Uuid::new_v4().to_string();
    let activation_key_id = format!("{};{}", activation_key, id);
    let activation_key_id_hash_str = sha_hash_to_hex(activation_key_id.as_bytes());

    let mut role_type = HospitalPersonnelRole::MedicalPersonnel;
    if role.as_str() == "AdministrativePersonnel" {
        role_type = HospitalPersonnelRole::AdministrativePersonnel;
    } else if role.as_str() != "MedicalPersonnel" {
        return Err(String::from("Invalid role argument."));
    }

    let hospital_personnel_metadata = HospitalPersonnelMetadata {
        activation_key: activation_key.clone(),
        id: id.clone(),
        role: role_type,
    };
    let hospital_personnel_metadata_bytes =
        serde_json::to_vec(&hospital_personnel_metadata).unwrap();
    let pre_public_key = PublicKey::try_from_compressed_bytes(
        keys_entry.pre_public_key.as_ref().unwrap().as_slice(),
    )
    .unwrap();
    let (capsule_hospital_personnel_metadata, enc_hospital_personnel_metadata) = encrypt(
        &pre_public_key,
        hospital_personnel_metadata_bytes.as_slice(),
    )
    .unwrap();
    let capsule_hospital_personnel_metadata_bytes =
        capsule_hospital_personnel_metadata.to_bytes().unwrap();
    let data = MoveHospitalAdminAddActivationKeyData {
        capsule: capsule_hospital_personnel_metadata_bytes.to_vec(),
        metadata: enc_hospital_personnel_metadata.to_vec(),
    };
    let data_bytes = serde_json::to_vec(&data).unwrap();

    let role = match role_type {
        HospitalPersonnelRole::Admin => return Err(String::from("Invalid role argument")),
        HospitalPersonnelRole::MedicalPersonnel => "MedicalPersonnel",
        HospitalPersonnelRole::AdministrativePersonnel => "AdministrativePersonnel",
    };

    let activation_key_call_arg =
        CallArg::Pure(bcs::to_bytes(activation_key_id_hash_str.as_str()).unwrap());
    let activation_key_activation_key_metadata_table_call_arg = construct_shared_object_call_arg(
        state
            .account_package
            .activation_key_activation_key_metadata_table_id,
        state
            .account_package
            .activation_key_activation_key_metadata_table_version,
        true,
    );
    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        false,
    );
    let data_call_arg = CallArg::Pure(bcs::to_bytes(&data_bytes).unwrap());
    let hospital_id_registered_hospital_table_call_arg = construct_shared_object_call_arg(
        state
            .account_package
            .hospital_id_registered_hospital_table_id,
        state
            .account_package
            .hospital_id_registered_hospital_table_version,
        false,
    );
    let id_activation_key_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_activation_key_table_id,
        state.account_package.id_activation_key_table_version,
        true,
    );
    let id_hospital_personnel_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_hospital_personnel_table_id,
        state.account_package.id_hospital_personnel_table_version,
        true,
    );
    let personnel_hospital_part_call_arg =
        CallArg::Pure(bcs::to_bytes(hospital_part_hash.as_str()).unwrap());
    let personnel_id_part_call_arg = CallArg::Pure(bcs::to_bytes(id_part_hash.as_str()).unwrap());
    let role_call_arg = CallArg::Pure(bcs::to_bytes(role).unwrap());

    let pt = construct_pt(
        String::from("hospital_admin_add_activation_key"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            activation_key_call_arg,
            activation_key_activation_key_metadata_table_call_arg,
            address_id_table_call_arg,
            data_call_arg,
            hospital_id_registered_hospital_table_call_arg,
            id_activation_key_table_call_arg,
            id_hospital_personnel_table_call_arg,
            personnel_hospital_part_call_arg,
            personnel_id_part_call_arg,
            role_call_arg,
        ],
    );

    let tx_data = construct_sponsored_tx_data(
        IotaAddress::from_str(keys_entry.iota_address.unwrap().as_str()).unwrap(),
        gas_coins.clone(),
        pt,
        GAS_BUDGET,
        ref_gas_price,
        sponsor_account,
    );

    let iota_key_pair = aes_decrypt(
        keys_entry.iota_key_pair.unwrap().as_slice(),
        sha_hash(pin.as_bytes()).as_slice(),
        keys_entry.iota_nonce.unwrap().as_slice(),
    )?;
    let iota_key_pair = String::from_utf8(iota_key_pair).unwrap();

    let signer = IotaKeyPair::decode(iota_key_pair.as_str()).unwrap();
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);
    let response = execute_tx(tx, reservation_id).await;

    handle_error_execute_tx("hospital_admin_add_activatoin_key".to_string(), response)?;

    let data = CommandHospitalAdminAddActivationKeyResponse { activation_key, id };

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data,
    })
}

#[tauri::command]
pub async fn activate_app(
    state: State<'_, Mutex<AppState>>,
    activation_key: String,
    id: String,
) -> Result<SuccessResponse<()>, String> {
    let state = state.lock().await;
    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let activation_key_id = format!("{};{}", activation_key, id);
    let activation_key_id_hash_str = sha_hash_to_hex(activation_key_id.as_bytes());

    let activation_key_call_arg =
        CallArg::Pure(bcs::to_bytes(activation_key_id_hash_str.as_str()).unwrap());
    let activation_key_activation_key_metadata_table_call_arg = construct_shared_object_call_arg(
        state
            .account_package
            .activation_key_activation_key_metadata_table_id,
        state
            .account_package
            .activation_key_activation_key_metadata_table_version,
        true,
    );

    let pt = construct_pt(
        String::from("use_activation_key"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            activation_key_call_arg,
            activation_key_activation_key_metadata_table_call_arg,
        ],
    );

    let random_seed = generate_64_bytes_seed();
    let (random_iota_address, random_iota_keypair) = generate_iota_keys_ed(&random_seed);

    let tx_data = construct_sponsored_tx_data(
        random_iota_address,
        gas_coins,
        pt,
        GAS_BUDGET,
        ref_gas_price,
        sponsor_account,
    );

    let signer = random_iota_keypair;
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

    let response = execute_tx(tx, reservation_id).await;

    handle_error_execute_tx("activate_app".to_string(), response)?;

    let mut keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    keys_entry.activation_key = Some(activation_key_id_hash_str);
    keys_entry.id = Some(id);
    let keys_entry = serde_json::to_vec(&keys_entry).unwrap();
    state.keys_entry.set_secret(&keys_entry).unwrap();

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}
