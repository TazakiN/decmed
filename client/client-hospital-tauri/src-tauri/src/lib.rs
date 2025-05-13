mod constants;
mod types;
mod utils;

use constants::{
    GAS_BUDGET, HOSPITAL_ADMIN_CAP_ID, HOSPITAL_MODULE_NAME, HOSPITAL_PACKAGE_ID, HOSPITAL_TABLE_ID,
};
use iota_sdk::IotaClientBuilder;
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    crypto::IotaKeyPair,
    gas_coin::NANOS_PER_IOTA,
    transaction::{CallArg, Transaction},
    Identifier,
};
use keyring::Entry;
use std::str::FromStr;
use tauri::{async_runtime::Mutex, Manager, State};
use types::{AppState, HospitalPackage, KeysEntry};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use utils::{
    construct_admin_cap_call_arg, construct_pt, construct_shared_object_call_arg,
    construct_sponsored_tx_data, execute_tx, generate_64_bytes_seed, generate_iota_keys_ed,
    get_ref_gas_price, move_call_read_only, parse_keys_entry, reserve_gas,
};

#[tauri::command]
async fn is_app_activated(state: State<'_, Mutex<AppState>>) -> Result<bool, ()> {
    let state = state.lock().await;

    if let Ok(keys) = state.keys_entry.get_secret() {
        let keys = parse_keys_entry(&keys);
        if keys.activation_key.is_some() {
            return Ok(true);
        }
    }

    Ok(false)
}

#[tauri::command]
async fn add_activation_key(state: State<'_, Mutex<AppState>>) -> Result<Value, ()> {
    let state = state.lock().await;
    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let activation_key = uuid::Uuid::new_v4().to_string();
    let id = "HOS_123";
    let activation_key_id = format!("{activation_key};{id}");
    let activation_key_id_hash = Sha256::digest(activation_key_id.into_bytes());
    let activation_key_id_hash_str = format!("{:x}", activation_key_id_hash);

    let admin_cap_call_arg =
        construct_admin_cap_call_arg(&state.iota_client, state.hospital_package.admin_cap_id).await;
    let activation_key_table_call_arg = construct_shared_object_call_arg(
        state.hospital_package.activation_key_table_id,
        state.hospital_package.activation_key_table_version,
        true,
    );
    let activation_key_arg =
        CallArg::Pure(bcs::to_bytes(activation_key_id_hash_str.as_str()).unwrap());

    let pt = construct_pt(
        String::from("add_activation_key"),
        state.hospital_package.package_id,
        state.hospital_package.module.clone(),
        vec![],
        vec![
            admin_cap_call_arg,
            activation_key_table_call_arg,
            activation_key_arg,
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

    let signer = IotaKeyPair::decode(keys_entry.admin_secret_key.unwrap().as_str()).unwrap();
    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);
    execute_tx(tx, reservation_id).await;

    Ok(json!({
        "status": "Success",
        "activationKey": activation_key,
        "id": id
    }))
}

#[tauri::command]
async fn activate_app(
    state: State<'_, Mutex<AppState>>,
    activation_key: String,
    id: String,
) -> Result<Value, ()> {
    let state = state.lock().await;
    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10).await;
    let ref_gas_price = get_ref_gas_price(&state.iota_client).await;

    let activation_key_id = format!("{activation_key};{id}");
    let activation_key_id_hash = Sha256::digest(activation_key_id.into_bytes());
    let activation_key_id_hash_str = format!("{:x}", activation_key_id_hash);

    let activation_key_table_call_arg = construct_shared_object_call_arg(
        state.hospital_package.activation_key_table_id,
        state.hospital_package.activation_key_table_version,
        true,
    );
    let activation_key_arg =
        CallArg::Pure(bcs::to_bytes(activation_key_id_hash_str.as_str()).unwrap());

    let call_args = vec![activation_key_table_call_arg, activation_key_arg];
    let pt = construct_pt(
        String::from("use_activation_key"),
        state.hospital_package.package_id,
        state.hospital_package.module.clone(),
        vec![],
        call_args,
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

    execute_tx(tx, reservation_id).await;

    let mut keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    keys_entry.activation_key = Some(activation_key_id_hash_str);
    let keys_entry = serde_json::to_vec(&keys_entry).unwrap();
    state.keys_entry.set_secret(&keys_entry).unwrap();

    Ok(json!({
        "status": "Success",
    }))
}

#[tauri::command]
async fn is_logged_in(state: State<'_, Mutex<AppState>>) -> Result<bool, ()> {
    let state = state.lock().await;

    if let Ok(keys) = state.keys_entry.get_secret() {
        let keys = parse_keys_entry(&keys);
        if keys.iota_key_pair.is_some() && keys.pre_secret_key.is_some() {
            return Ok(true);
        }
    }

    Ok(false)
}

#[tauri::command]
async fn is_activation_key_used(state: State<'_, Mutex<AppState>>) -> Result<(), ()> {
    let state = state.lock().await;

    let activation_key = "act_key_1";
    let activation_key_arg = CallArg::Pure(bcs::to_bytes(activation_key).unwrap());
    let activation_key_table_call_arg = construct_shared_object_call_arg(
        state.hospital_package.activation_key_table_id,
        state.hospital_package.activation_key_table_version,
        true,
    );

    let pt = construct_pt(
        String::from("is_activation_key_used"),
        state.hospital_package.package_id,
        state.hospital_package.module.clone(),
        vec![],
        vec![activation_key_table_call_arg, activation_key_arg],
    );

    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().unwrap());
    let sender = IotaAddress::from_str(keys_entry.admin_address.unwrap().as_str()).unwrap();
    let response = move_call_read_only(sender, &state.iota_client, pt).await;

    println!("{:#?}", response.results.unwrap()[0].return_values[0].0[0]);

    Ok(())
}

fn setup(app: &mut tauri::App) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let keys_entry = Entry::new("decmed_service_keys", "decmed_user").unwrap();
    let iota_client = tauri::async_runtime::block_on(async {
        IotaClientBuilder::default().build_localnet().await.unwrap()
    });
    let hospital_package = HospitalPackage {
        package_id: ObjectID::from_str(HOSPITAL_PACKAGE_ID).unwrap(),
        module: Identifier::from_str(HOSPITAL_MODULE_NAME).unwrap(),
        activation_key_table_id: ObjectID::from_str(HOSPITAL_TABLE_ID).unwrap(),
        activation_key_table_version: 5,
        admin_cap_id: ObjectID::from_str(HOSPITAL_ADMIN_CAP_ID).unwrap(),
    };
    let new_keys_entry = KeysEntry {
        admin_address: Some(String::from(
            "0x7c228da2e5b99ed280a2a3b9214a70b09a9550b0d3e63a12aaac7b045d7ce5af",
        )),
        admin_secret_key: Some(String::from(
            "iotaprivkey1qzw992dxx6mtf7z9amphg3e5qldult6ea9d70hemepgt9rzznlf65jnxxnp",
        )),
        activation_key: None,
        iota_address: None,
        iota_key_pair: None,
        pre_secret_key: None,
    };

    match keys_entry.get_secret() {
        Ok(_) => {
            // let new_keys_entry = serde_json::to_vec(&new_keys_entry).unwrap();
            // keys_entry.set_secret(&new_keys_entry).unwrap();
        }
        Err(err @ keyring::Error::NoEntry) => {
            let new_keys_entry = serde_json::to_vec(&new_keys_entry).unwrap();
            keys_entry.set_secret(&new_keys_entry).unwrap();

            println!("{:#?}", err);
        }
        Err(err) => {
            println!("{:#?}", err);
        }
    }

    app.manage(Mutex::new(AppState {
        keys_entry,
        iota_client,
        hospital_package,
    }));

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(setup)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            is_app_activated,
            add_activation_key,
            activate_app,
            is_logged_in,
            is_activation_key_used
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
