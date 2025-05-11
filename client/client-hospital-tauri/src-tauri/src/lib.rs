mod constants;
mod types;
mod utils;

use constants::{
    HOSPITAL_ADMIN_CAP_ID, HOSPITAL_MODULE_NAME, HOSPITAL_PACKAGE_ID, HOSPITAL_TABLE_ID,
};
use iota_json_rpc_types::IotaObjectDataOptions;
use iota_sdk::IotaClientBuilder;
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    crypto::IotaKeyPair,
    gas_coin::NANOS_PER_IOTA,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{CallArg, ObjectArg, Transaction, TransactionData, TransactionDataAPI},
    Identifier,
};
use keyring::Entry;
use std::str::FromStr;

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use utils::{execute_tx, reserve_gas};

#[tauri::command]
fn is_app_activated() -> bool {
    let activation_key_entry =
        Entry::new_with_target("activation_key", "decmed_service", "decmed_user").unwrap();
    if let Ok(activation_key) = activation_key_entry.get_password() {
        if !activation_key.is_empty() {
            return true;
        }
    }

    false
}

#[tauri::command]
async fn add_activation_key() -> Value {
    let iota_client = IotaClientBuilder::default().build_localnet().await.unwrap();

    let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10).await;

    let ref_gas_price = iota_client
        .governance_api()
        .get_reference_gas_price()
        .await
        .unwrap();

    let activation_key = uuid::Uuid::new_v4().to_string();
    let id = "HOS_123";
    let activation_key_id = format!("{activation_key};{id}");
    let activation_key_id_hash = Sha256::digest(activation_key_id.into_bytes());
    let activation_key_id_hash_str = format!("{:x}", activation_key_id_hash);

    let pt = {
        let mut builder = ProgrammableTransactionBuilder::new();
        let package = ObjectID::from_str(HOSPITAL_PACKAGE_ID).unwrap();
        let module = Identifier::from_str(HOSPITAL_MODULE_NAME).unwrap();
        let function = Identifier::from_str("add_activation_key").unwrap();

        let admin_cap_object = iota_client
            .read_api()
            .get_object_with_options(
                ObjectID::from_str(HOSPITAL_ADMIN_CAP_ID).unwrap(),
                IotaObjectDataOptions {
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        let admin_cap_object_arg = ObjectArg::ImmOrOwnedObject((
            admin_cap_object.data.clone().unwrap().object_id,
            admin_cap_object.data.clone().unwrap().version,
            admin_cap_object.data.unwrap().digest,
        ));
        let admin_cap_call_arg = CallArg::Object(admin_cap_object_arg);

        let activation_key_table_arg = ObjectArg::SharedObject {
            id: ObjectID::from_str(HOSPITAL_TABLE_ID).unwrap(),
            initial_shared_version: 3.into(),
            mutable: true,
        };
        let activation_key_table_call_arg = CallArg::Object(activation_key_table_arg);

        let activation_key_arg =
            CallArg::Pure(bcs::to_bytes(activation_key_id_hash_str.as_str()).unwrap());

        builder
            .move_call(
                package,
                module,
                function,
                vec![],
                vec![
                    admin_cap_call_arg,
                    activation_key_table_call_arg,
                    activation_key_arg,
                ],
            )
            .unwrap();
        builder.finish()
    };

    let mut tx_data = TransactionData::new_programmable(
        IotaAddress::from_str("0x7c228da2e5b99ed280a2a3b9214a70b09a9550b0d3e63a12aaac7b045d7ce5af")
            .unwrap(),
        gas_coins.clone(),
        pt,
        10_000_000,
        ref_gas_price,
    );
    tx_data.gas_data_mut().payment = gas_coins;
    tx_data.gas_data_mut().owner = sponsor_account;

    let signer = IotaKeyPair::decode(
        "iotaprivkey1qzw992dxx6mtf7z9amphg3e5qldult6ea9d70hemepgt9rzznlf65jnxxnp",
    )
    .unwrap();

    let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);
    let (tx_base_64, signature_base_64) = tx.to_tx_bytes_and_signatures();

    execute_tx(
        reservation_id,
        tx_base_64.encoded(),
        signature_base_64[0].encoded(),
    )
    .await;

    json!({
        "status": "Success",
        "activationKey": activation_key,
        "id": id
    })
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            is_app_activated,
            add_activation_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
