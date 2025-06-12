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
        AdministrativeData, AppState, AuthType, CommandGetProfileResponse,
        CommandUpdateProfileDataInput, HospitalPersonnelRole, KeyNonce,
        PrivateAdministrativeMetadata, ResponseStatus, SuccessResponse,
    },
    utils::{
        aes_decrypt, aes_encrypt, construct_pt, construct_shared_object_call_arg,
        construct_sponsored_tx_data, decode_hospital_personnel_id_to_argon, execute_tx,
        get_ref_gas_price, handle_error_execute_tx, parse_keys_entry, reserve_gas, sha_hash,
        validate_by_regex, validate_pin_util,
    },
};

#[tauri::command]
pub async fn validate_pin(
    state: State<'_, Mutex<AppState>>,
    pin: String,
    auth_type: String,
) -> Result<SuccessResponse<()>, String> {
    let mut state = state.lock().await;

    if !validate_pin_util(pin.clone()) {
        return Err("Invalid PIN".to_string());
    }

    let mut auth_typ = AuthType::Signin;
    if auth_type.as_str() == "Signup" {
        auth_typ = AuthType::Signup;
    } else if auth_type.as_str() != "Signin" {
        return Err("Invalid arg auth_type".to_string());
    }

    match auth_typ {
        AuthType::Signin => {
            state.signin_state.pin = Some(pin);
        }
        AuthType::Signup => {
            state.signup_state.pin = Some(pin);
        }
    };

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}

#[tauri::command]
pub async fn validate_confirm_pin(
    state: State<'_, Mutex<AppState>>,
    confirm_pin: String,
    auth_type: String,
) -> Result<SuccessResponse<()>, String> {
    let state = state.lock().await;

    if !validate_pin_util(confirm_pin.clone()) {
        return Err("Invalid confirm PIN".to_string());
    }

    let mut auth_typ = AuthType::Signin;
    if auth_type.as_str() == "Signup" {
        auth_typ = AuthType::Signup;
    } else if auth_type.as_str() != "Signin" {
        return Err("Invalid arg auth_type".to_string());
    }

    match auth_typ {
        AuthType::Signin => {
            if *state.signin_state.pin.as_ref().unwrap() != confirm_pin {
                return Err("PIN and confirm PIN must be same".to_string());
            }
        }
        AuthType::Signup => {
            if *state.signup_state.pin.as_ref().unwrap() != confirm_pin {
                return Err("PIN and confirm PIN must be same".to_string());
            }
        }
    };

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}

#[tauri::command]
pub async fn get_role(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<HospitalPersonnelRole>, String> {
    let state = state.lock().await;

    if state.auth_state.role.is_none() {
        return Err(String::from("Role not found."));
    }

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: state.auth_state.role.unwrap(),
    })
}

#[tauri::command]
pub async fn is_session_pin_exist(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<()>, String> {
    let state = state.lock().await;

    match state.auth_state.session_pin {
        Some(_) => {
            return Ok(SuccessResponse {
                status: ResponseStatus::Success,
                data: (),
            })
        }
        None => return Err("Session PIN not found".to_string()),
    }
}

#[tauri::command]
pub async fn get_profile(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<CommandGetProfileResponse>, String> {
    let state = state.lock().await;
    let administrative_data = state.administrative_data.as_ref().unwrap();

    let (id_part_hash, hospital_part_hash) =
        decode_hospital_personnel_id_to_argon(administrative_data.private.id.clone())?;
    let id_hash = format!("{}@{}", id_part_hash, hospital_part_hash);

    let data = CommandGetProfileResponse {
        id: administrative_data.private.id.clone(),
        id_hash,
        name: administrative_data.public.name.clone(),
        hospital: administrative_data.public.hospital_name.clone(),
        role: state.auth_state.role.unwrap(),
    };

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data,
    })
}

#[tauri::command]
pub async fn update_profile(
    state: State<'_, Mutex<AppState>>,
    data: CommandUpdateProfileDataInput,
) -> Result<SuccessResponse<()>, String> {
    let mut state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());

    let pre_public_key =
        PublicKey::try_from_compressed_bytes(&keys_entry.pre_public_key.unwrap()).unwrap();

    let iota_key_pair = aes_decrypt(
        keys_entry.iota_key_pair.unwrap().as_slice(),
        sha_hash(state.auth_state.session_pin.as_ref().unwrap().as_bytes()).as_slice(),
        keys_entry.iota_nonce.unwrap().as_slice(),
    )?;
    let iota_key_pair = String::from_utf8(iota_key_pair).unwrap();

    // Validate data
    if !validate_by_regex(&data.name, "^[a-zA-Z ]{2,100}$") {
        return Err("Invalid args: data.name is invalid".to_string());
    }

    // Construct private administrative data
    let private_administrative_data = state.administrative_data.as_ref().unwrap().private.clone();
    let private_administrative_data_bytes =
        serde_json::to_vec(&private_administrative_data).unwrap();
    let (
        enc_private_administrative_data,
        key_private_administrative_data,
        nonce_private_administrative_data,
    ) = aes_encrypt(&private_administrative_data_bytes);
    let key_nonce_private_administrative_data = KeyNonce {
        key: key_private_administrative_data,
        nonce: nonce_private_administrative_data,
    };
    let key_nonce_private_administrative_data_bytes =
        serde_json::to_vec(&key_nonce_private_administrative_data).unwrap();
    let (capsule_key_nonce_private_administrative_data, enc_key_nonce_private_administrative_data) =
        encrypt(
            &pre_public_key,
            &key_nonce_private_administrative_data_bytes,
        )
        .unwrap();
    let private_administrative_metadata = PrivateAdministrativeMetadata {
        capsule: capsule_key_nonce_private_administrative_data
            .to_bytes()
            .unwrap()
            .to_vec(),
        enc_data: enc_private_administrative_data,
        enc_key_nonce: enc_key_nonce_private_administrative_data.to_vec(),
    };
    let private_administrative_metadata_bytes =
        serde_json::to_vec(&private_administrative_metadata).unwrap();

    // Construct public administrative data
    let mut public_administrative_data = state.administrative_data.as_ref().unwrap().public.clone();
    public_administrative_data.hospital_name = None;
    public_administrative_data.name = Some(data.name);
    let public_administrative_data_bytes = serde_json::to_vec(&public_administrative_data).unwrap();

    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        false,
    );
    let id_administrative_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_administrative_table_id,
        state.account_package.id_administrative_table_version,
        true,
    );
    let private_data_call_arg =
        CallArg::Pure(bcs::to_bytes(&private_administrative_metadata_bytes).unwrap());
    let public_data_call_arg =
        CallArg::Pure(bcs::to_bytes(&public_administrative_data_bytes).unwrap());

    let pt = construct_pt(
        "update_administrative_data".to_string(),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            address_id_table_call_arg,
            id_administrative_table_call_arg,
            private_data_call_arg,
            public_data_call_arg,
        ],
    );

    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let tx_data = construct_sponsored_tx_data(
        IotaAddress::from_str(keys_entry.iota_address.unwrap().as_str()).unwrap(),
        gas_coins.clone(),
        pt,
        GAS_BUDGET,
        ref_gas_price,
        sponsor_account,
    );

    let signer = IotaKeyPair::decode(iota_key_pair.as_str()).unwrap();
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);
    let response = execute_tx(tx, reservation_id).await;

    handle_error_execute_tx("update_profile".to_string(), response)?;

    state.administrative_data = Some(AdministrativeData {
        private: private_administrative_data,
        public: public_administrative_data,
    });

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}
