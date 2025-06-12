use std::str::FromStr;

use bip39::Mnemonic;
use iota_types::base_types::IotaAddress;
use tauri::{async_runtime::Mutex, State};
use umbral_pre::{decrypt_original, Capsule, DefaultDeserialize, SecretKeyFactory};

use crate::{
    types::{
        AdministrativeData, AppState, KeyNonce, MoveAdministrative, PrivateAdministrativeData,
        PrivateAdministrativeMetadata, PublicAdministrativeData, ResponseStatus, SuccessResponse,
    },
    utils::{
        aes_decrypt, aes_encrypt_custom_key, compute_pre_keys, construct_pt,
        construct_shared_object_call_arg, generate_iota_keys_ed, get_iota_client,
        handle_error_move_call_read_only, move_call_read_only, parse_keys_entry,
        parse_move_read_only_result, sha_hash,
    },
};

#[tauri::command]
pub async fn is_signed_in(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<()>, String> {
    let mut state = state.lock().await;
    let iota_client = get_iota_client().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());

    if keys_entry.iota_key_pair.is_none() || keys_entry.pre_secret_key.is_none() {
        return Err("Auth keys not found".to_string());
    }

    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        false,
    );
    let id_activation_key_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_activation_key_table_id,
        state.account_package.id_activation_key_table_version,
        false,
    );
    let id_administrative_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_administrative_table_id,
        state.account_package.id_administrative_table_version,
        false,
    );

    let pt = construct_pt(
        "get_administrative_data_patient".to_string(),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            address_id_table_call_arg,
            id_activation_key_table_call_arg,
            id_administrative_table_call_arg,
        ],
    );

    let sender = IotaAddress::from_str(keys_entry.iota_address.unwrap().as_str()).unwrap();
    let response = move_call_read_only(sender, &iota_client, pt).await;

    handle_error_move_call_read_only("is_signed_in".to_string(), response.clone())?;

    let administrative_data: MoveAdministrative = parse_move_read_only_result(response, 0)?;

    let private_administrative_metadata: PrivateAdministrativeMetadata =
        serde_json::from_slice(&administrative_data.private_data).unwrap();
    let public_administrative_data: PublicAdministrativeData =
        serde_json::from_slice(&administrative_data.public_data).unwrap();

    let pre_seed = aes_decrypt(
        keys_entry.pre_secret_key.as_ref().unwrap().as_slice(),
        sha_hash(state.auth_state.session_pin.as_ref().unwrap().as_bytes()).as_slice(),
        keys_entry.pre_nonce.as_ref().unwrap().as_slice(),
    )?;
    let (pre_secret_key, _pre_public_key) = compute_pre_keys(pre_seed.as_slice());

    let capsule_private_administrative_data =
        Capsule::from_bytes(&private_administrative_metadata.capsule).unwrap();
    let key_nonce_private_administrative_data = decrypt_original(
        &pre_secret_key,
        &capsule_private_administrative_data,
        &private_administrative_metadata.enc_key_nonce,
    )
    .unwrap();
    let key_nonce_private_administrative_data =
        serde_json::from_slice::<KeyNonce>(&key_nonce_private_administrative_data).unwrap();
    let private_administrative_data = aes_decrypt(
        &private_administrative_metadata.enc_data,
        &key_nonce_private_administrative_data.key,
        &key_nonce_private_administrative_data.nonce,
    )?;
    let private_administrative_data =
        serde_json::from_slice::<PrivateAdministrativeData>(&private_administrative_data).unwrap();

    state.administrative_data = Some(AdministrativeData {
        private: private_administrative_data,
        public: public_administrative_data,
    });

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}

#[tauri::command]
pub async fn signin(
    state: State<'_, Mutex<AppState>>,
    seed_words: String,
    id: String,
) -> Result<SuccessResponse<()>, String> {
    let mut state = state.lock().await;
    let mut keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    let iota_client = get_iota_client().await;

    let mnemonic = match Mnemonic::from_str(&seed_words) {
        Ok(m) => m,
        Err(_) => return Err("Failed to parse seedWords".to_string()),
    };
    let seed = mnemonic.to_seed_normalized(id.as_str());

    let (iota_address, iota_keypair) = generate_iota_keys_ed(&seed);
    let iota_keypair_string = iota_keypair.encode().unwrap();
    let iota_address_string = iota_address.to_string();

    let pre_secret_key = SecretKeyFactory::from_secure_randomness(&seed[0..32])
        .unwrap()
        .make_key(&seed[0..32]);
    let pre_public_key = pre_secret_key.public_key();
    let pre_public_key_bytes = pre_public_key.to_compressed_bytes();

    let (enc_pre_secret_key, pre_nonce) = aes_encrypt_custom_key(
        sha_hash(state.signin_state.pin.as_ref().unwrap().as_bytes()).as_slice(),
        &seed[0..32],
    );
    let (enc_iota_keypair, iota_nonce) = aes_encrypt_custom_key(
        sha_hash(state.signin_state.pin.as_ref().unwrap().as_bytes()).as_slice(),
        iota_keypair_string.as_bytes(),
    );

    let address_id_table_call_arg = construct_shared_object_call_arg(
        state.account_package.address_id_table_id,
        state.account_package.address_id_table_version,
        true,
    );

    let pt = construct_pt(
        String::from("is_account_registered"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![address_id_table_call_arg],
    );

    let response = move_call_read_only(iota_address, &iota_client, pt).await;

    handle_error_move_call_read_only("signin".to_string(), response.clone())?;

    let is_registered: bool = parse_move_read_only_result(response, 0)?;

    if !is_registered {
        return Err("Account not found".to_string());
    }

    keys_entry.id = Some(id);
    keys_entry.iota_address = Some(iota_address_string);
    keys_entry.iota_key_pair = Some(enc_iota_keypair);
    keys_entry.pre_secret_key = Some(enc_pre_secret_key);
    keys_entry.pre_public_key = Some(pre_public_key_bytes.to_vec());
    keys_entry.pre_nonce = Some(pre_nonce);
    keys_entry.iota_nonce = Some(iota_nonce);
    let keys_entry = serde_json::to_vec(&keys_entry).unwrap();
    state.keys_entry.set_secret(&keys_entry).unwrap();

    // drop SigninState form state
    state.signin_state.pin = None;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}
