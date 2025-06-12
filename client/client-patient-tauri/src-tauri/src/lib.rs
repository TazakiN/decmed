mod constant;
mod types;

use std::{str::FromStr, sync::Mutex};
use tauri::Manager;

use constant::{
    ACCOUNT_ACTIVATION_KEY_TABLE_ID, ACCOUNT_ACTIVATION_KEY_TABLE_VERSION,
    ACCOUNT_ADDRESS_ID_TABLE_ID, ACCOUNT_ADDRESS_ID_TABLE_VERSION, ACCOUNT_ADMINISTRATIVE_TABLE_ID,
    ACCOUNT_ADMINISTRATIVE_TABLE_VERSION, ACCOUNT_ADMIN_CAP_ID,
    ACCOUNT_GLOBAL_ADMIN_ADD_KEY_CAP_ID, ACCOUNT_ID_ACTIVATION_KEY_TABLE_ID,
    ACCOUNT_ID_ACTIVATION_KEY_TABLE_VERSION, ACCOUNT_ID_ADDRESS_TABLE_ID,
    ACCOUNT_ID_ADDRESS_TABLE_VERSION, ACCOUNT_ID_HOSPITAL_PERSONNEL_METADATA_TABLE_ID,
    ACCOUNT_ID_HOSPITAL_PERSONNEL_METADATA_TABLE_VERSION, ACCOUNT_MEDICAL_TABLE_ID,
    ACCOUNT_MEDICAL_TABLE_VERSION, ACCOUNT_MODULE_NAME, ACCOUNT_PACKAGE_ID,
};
use iota_sdk::IotaClientBuilder;
use iota_types::{base_types::ObjectID, Identifier};
use types::{AccountPackage, AppState, AuthState, KeysEntry, SignInState, SignUpState};

fn setup(app: &mut tauri::App) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // let keys_entry = Entry::new("decmed_service_keys", "decmed_user").unwrap();
    let iota_client = tauri::async_runtime::block_on(async {
        IotaClientBuilder::default().build_localnet().await.unwrap()
    });
    let account_package = AccountPackage {
        package_id: ObjectID::from_str(ACCOUNT_PACKAGE_ID).unwrap(),
        module: Identifier::from_str(ACCOUNT_MODULE_NAME).unwrap(),
        id_activation_key_table_id: ObjectID::from_str(ACCOUNT_ID_ACTIVATION_KEY_TABLE_ID).unwrap(),
        id_activation_key_table_version: ACCOUNT_ID_ACTIVATION_KEY_TABLE_VERSION,
        activation_key_table_id: ObjectID::from_str(ACCOUNT_ACTIVATION_KEY_TABLE_ID).unwrap(),
        activation_key_table_version: ACCOUNT_ACTIVATION_KEY_TABLE_VERSION,
        address_id_table_id: ObjectID::from_str(ACCOUNT_ADDRESS_ID_TABLE_ID).unwrap(),
        address_id_table_version: ACCOUNT_ADDRESS_ID_TABLE_VERSION,
        id_address_table_id: ObjectID::from_str(ACCOUNT_ID_ADDRESS_TABLE_ID).unwrap(),
        id_address_table_version: ACCOUNT_ID_ADDRESS_TABLE_VERSION,
        administrative_table_id: ObjectID::from_str(ACCOUNT_ADMINISTRATIVE_TABLE_ID).unwrap(),
        administrative_table_version: ACCOUNT_ADMINISTRATIVE_TABLE_VERSION,
        medical_table_id: ObjectID::from_str(ACCOUNT_MEDICAL_TABLE_ID).unwrap(),
        medical_table_version: ACCOUNT_MEDICAL_TABLE_VERSION,
        id_hospital_personnel_metadata_table_id: ObjectID::from_str(
            ACCOUNT_ID_HOSPITAL_PERSONNEL_METADATA_TABLE_ID,
        )
        .unwrap(),
        id_hospital_personnel_metadata_table_version:
            ACCOUNT_ID_HOSPITAL_PERSONNEL_METADATA_TABLE_VERSION,
        admin_cap_id: ObjectID::from_str(ACCOUNT_ADMIN_CAP_ID).unwrap(),
        global_admin_add_key_cap_id: ObjectID::from_str(ACCOUNT_GLOBAL_ADMIN_ADD_KEY_CAP_ID)
            .unwrap(),
    };
    let new_keys_entry = KeysEntry {
        id: None,
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
        iota_nonce: None,
        pre_nonce: None,
    };
    let signin_state = SignInState { pin: None };
    let signup_state = SignUpState {
        seed_words: None,
        pin: None,
    };
    let auth_state = AuthState {
        is_registered: false,
        role: None,
        session_pin: Some("123456".to_string()),
    };

    // match keys_entry.get_secret() {
    //     Ok(_) => {
    //         // let new_keys_entry = serde_json::to_vec(&new_keys_entry).unwrap();
    //         // keys_entry.set_secret(&new_keys_entry).unwrap();
    //     }
    //     Err(err @ keyring::Error::NoEntry) => {
    //         let new_keys_entry = serde_json::to_vec(&new_keys_entry).unwrap();
    //         keys_entry.set_secret(&new_keys_entry).unwrap();

    //         println!("{:#?}", err);
    //     }
    //     Err(err) => {
    //         println!("{:#?}", err);
    //     }
    // }

    app.manage(Mutex::new(AppState {
        // keys_entry,
        iota_client,
        account_package,
        signin_state,
        signup_state,
        auth_state,
    }));

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .setup(setup)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
