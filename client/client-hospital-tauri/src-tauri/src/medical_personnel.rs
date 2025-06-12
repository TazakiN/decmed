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
        AppState, KeyNonce, MedicalData, MedicalDataMainCategory, MedicalDataSubCategory,
        MedicalMetadata, ResponseStatus, SuccessResponse,
    },
    utils::{
        add_and_pin_to_ipfs, aes_decrypt, aes_encrypt, argon_hash, construct_pt,
        construct_shared_object_call_arg, construct_sponsored_tx_data, execute_tx,
        get_ref_gas_price, handle_error_execute_tx, parse_keys_entry, reserve_gas, sha_hash,
        sys_time_to_iso,
    },
};

#[tauri::command]
pub async fn new_medical_record(
    state: State<'_, Mutex<AppState>>,
    patient_id: String,
    patient_pre_public_key: Vec<u8>,
    pin: String,
) -> Result<SuccessResponse<()>, String> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let iota_key_pair = aes_decrypt(
        keys_entry.iota_key_pair.unwrap().as_slice(),
        sha_hash(pin.as_bytes()).as_slice(),
        keys_entry.iota_nonce.unwrap().as_slice(),
    )?;
    let iota_key_pair = String::from_utf8(iota_key_pair).unwrap();

    let id_hash = argon_hash(patient_id);

    let medical_metadata_bytes = {
        let medical_data = MedicalData {
            main_category: MedicalDataMainCategory::Category1,
            sub_category: MedicalDataSubCategory::SubCategory1,
        };
        let medical_data_bytes = serde_json::to_vec(&medical_data).unwrap();
        let (enc_med, med_key, med_nonce) = aes_encrypt(medical_data_bytes.as_slice());

        let med_cid = add_and_pin_to_ipfs(enc_med).await;

        let med_key_and_nonce = KeyNonce {
            key: med_key,
            nonce: med_nonce,
        };
        let med_key_and_nonce = serde_json::to_vec(&med_key_and_nonce).unwrap();
        let patient_pre_public_key =
            PublicKey::try_from_compressed_bytes(patient_pre_public_key.as_slice()).unwrap();
        let (capsule_med_key_and_nonce, enc_med_key_and_nonce) =
            encrypt(&patient_pre_public_key, med_key_and_nonce.as_slice()).unwrap();
        let capsule_med_key_and_nonce_bytes: Vec<u8> =
            capsule_med_key_and_nonce.to_bytes().unwrap().into();

        let created_at = sys_time_to_iso(std::time::SystemTime::now());

        let medical_metadata = MedicalMetadata {
            capsule: capsule_med_key_and_nonce_bytes,
            enc_key_and_nonce: enc_med_key_and_nonce.to_vec(),
            cid: med_cid,
            created_at,
        };
        serde_json::to_vec(&medical_metadata).unwrap()
    };

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
    let data_call_arg = CallArg::Pure(bcs::to_bytes(&medical_metadata_bytes).unwrap());
    let patient_id_call_arg = CallArg::Pure(bcs::to_bytes(id_hash.as_str()).unwrap());
    let id_activation_key_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_activation_key_table_id,
        state.account_package.id_activation_key_table_version,
        false,
    );
    let id_medical_table_call_arg = construct_shared_object_call_arg(
        state.account_package.id_medical_table_id,
        state.account_package.id_medical_table_version,
        true,
    );

    let pt = construct_pt(
        String::from("create_new_medical_record"),
        state.account_package.package_id,
        state.account_package.module.clone(),
        vec![],
        vec![
            activation_key_activation_key_metadata_table_call_arg,
            address_id_table_call_arg,
            data_call_arg,
            patient_id_call_arg,
            id_activation_key_table_call_arg,
            id_medical_table_call_arg,
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

    let signer = IotaKeyPair::decode(iota_key_pair.as_str()).unwrap();
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);
    let response = execute_tx(tx, reservation_id).await;

    handle_error_execute_tx("new_medical_record".to_string(), response)?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: (),
    })
}
