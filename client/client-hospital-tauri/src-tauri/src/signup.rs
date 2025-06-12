use std::str::FromStr;

use bip39::Mnemonic;
use iota_types::{
    gas_coin::NANOS_PER_IOTA,
    transaction::{CallArg, Transaction},
};
use tauri::{async_runtime::Mutex, State};
use umbral_pre::{encrypt, DefaultSerialize, SecretKeyFactory};

use crate::{
    constants::GAS_BUDGET,
    types::{
        AppState, KeyNonce, PrivateAdministrativeData, PrivateAdministrativeMetadata,
        PublicAdministrativeData, ResponseStatus, SuccessResponse,
    },
    utils::{
        aes_encrypt, aes_encrypt_custom_key, construct_pt, construct_shared_object_call_arg,
        construct_sponsored_tx_data, decode_hospital_personnel_id_to_argon, execute_tx,
        generate_iota_keys_ed, get_ref_gas_price, handle_error_execute_tx, parse_keys_entry,
        reserve_gas, sha_hash,
    },
};

#[tauri::command]
pub async fn generate_mnemonic(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<String>, String> {
    let mut state = state.lock().await;

    let mnemonic = match bip39::Mnemonic::generate(12) {
        Ok(val) => val,
        Err(err) => return Err(err.to_string()),
    };
    let words = mnemonic.words().collect::<Vec<&str>>().join(" ");

    state.signup_state.seed_words = Some(words.clone());

    Ok(SuccessResponse {
        data: words,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn is_signed_up(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<()>, String> {
    let state = state.lock().await;

    match state.auth_state.is_signed_up {
        true => {
            return Ok(SuccessResponse {
                status: ResponseStatus::Success,
                data: (),
            })
        }
        false => return Err("Not registered".to_string()),
    }
}

#[tauri::command]
pub async fn signup(
    state: State<'_, Mutex<AppState>>,
    seed_words: String,
) -> Result<SuccessResponse<()>, String> {
    let mut state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    let (id_part_hash, hospital_part_hash) =
        decode_hospital_personnel_id_to_argon(keys_entry.id.clone().unwrap())?;

    if *state.signup_state.seed_words.as_ref().unwrap() != seed_words {
        return Err("Invalid seedWords".to_string());
    }

    let mnemonic = match Mnemonic::from_str(state.signup_state.seed_words.as_ref().unwrap()) {
        Ok(m) => m,
        Err(_) => return Err("Invalid seedWords".to_string()),
    };
    let seed = mnemonic.to_seed_normalized(keys_entry.id.as_ref().unwrap());

    let (iota_address, iota_keypair) = generate_iota_keys_ed(&seed);
    let iota_keypair_string = iota_keypair.encode().unwrap();
    let iota_address_string = iota_address.to_string();

    let pre_secret_key = SecretKeyFactory::from_secure_randomness(&seed[0..32])
        .unwrap()
        .make_key(&seed[0..32]);
    let pre_public_key = pre_secret_key.public_key();
    let pre_public_key_bytes = pre_public_key.to_compressed_bytes();

    // Construct private administrative data
    let private_administrative_data = PrivateAdministrativeData {
        id: keys_entry.id.unwrap().clone(),
    };
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
    let public_administrative_data = PublicAdministrativeData {
        hospital_name: None,
        name: None,
    };
    let public_administrative_data_bytes = serde_json::to_vec(&public_administrative_data).unwrap();

    // Encrypt PRE secret key
    let (enc_pre_secret_key, nonce_pre_secret_key) = aes_encrypt_custom_key(
        sha_hash(state.signup_state.pin.as_ref().unwrap().as_bytes()).as_slice(),
        &seed[0..32],
    );

    // Encrypt IOTA keypair
    let (enc_iota_keypair, nonce_iota_keypair) = aes_encrypt_custom_key(
        sha_hash(state.signup_state.pin.as_ref().unwrap().as_bytes()).as_slice(),
        iota_keypair_string.as_bytes(),
    );

    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        true,
    );
    let hospital_personnel_hospital_part_call_arg =
        CallArg::Pure(bcs::to_bytes(&hospital_part_hash).unwrap());
    let hospital_personnel_id_part_call_arg = CallArg::Pure(bcs::to_bytes(&id_part_hash).unwrap());
    let id_activation_key_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_activation_key_table_id,
        state.account_package.id_activation_key_table_version,
        false,
    );
    let id_address_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_address_table_id,
        state.account_package.id_address_table_version,
        true,
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
        String::from("register_hospital_personnel"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            address_id_table_call_arg,
            hospital_personnel_hospital_part_call_arg,
            hospital_personnel_id_part_call_arg,
            id_activation_key_table_call_arg,
            id_address_table_call_arg,
            id_administrative_table_call_arg,
            private_data_call_arg,
            public_data_call_arg,
        ],
    );

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

    let signer = iota_keypair;
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

    let response = execute_tx(tx, reservation_id).await;

    handle_error_execute_tx("signup".to_string(), response)?;

    let mut keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    keys_entry.iota_address = Some(iota_address_string);
    keys_entry.iota_key_pair = Some(enc_iota_keypair);
    keys_entry.pre_secret_key = Some(enc_pre_secret_key);
    keys_entry.pre_public_key = Some(pre_public_key_bytes.to_vec());
    keys_entry.pre_nonce = Some(nonce_pre_secret_key);
    keys_entry.iota_nonce = Some(nonce_iota_keypair);
    let keys_entry = serde_json::to_vec(&keys_entry).unwrap();
    state.keys_entry.set_secret(&keys_entry).unwrap();

    // drop SignupState from state
    state.signup_state.seed_words = None;
    state.signup_state.pin = None;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}
