mod constants;
mod home;
mod scan;
mod shared_cmds;
mod signin;
mod signout;
mod signup;
mod types;
mod utils;

use constants::{
    ACCOUNT_ACTIVATION_KEY_ACTIVATION_KEY_METADATA_TABLE_ID,
    ACCOUNT_ACTIVATION_KEY_ACTIVATION_KEY_METADATA_TABLE_VERSION, ACCOUNT_ADDRESS_ID_TABLE_ID,
    ACCOUNT_ADDRESS_ID_TABLE_VERSION, ACCOUNT_ADMIN_CAP_ID, ACCOUNT_GLOBAL_ADMIN_ADD_KEY_CAP_ID,
    ACCOUNT_HOSPITAL_ID_REGISTERED_HOSPITAL_TABLE_ID,
    ACCOUNT_HOSPITAL_ID_REGISTERED_HOSPITAL_TABLE_VERSION, ACCOUNT_ID_ACCESS_QUEUE_TABLE_ID,
    ACCOUNT_ID_ACCESS_QUEUE_TABLE_VERSION, ACCOUNT_ID_ACTIVATION_KEY_TABLE_ID,
    ACCOUNT_ID_ACTIVATION_KEY_TABLE_VERSION, ACCOUNT_ID_ADDRESS_TABLE_ID,
    ACCOUNT_ID_ADDRESS_TABLE_VERSION, ACCOUNT_ID_ADMINISTRATIVE_TABLE_ID,
    ACCOUNT_ID_ADMINISTRATIVE_TABLE_VERSION, ACCOUNT_ID_EXPECTED_HOSPITAL_PERSONNEL_TABLE_ID,
    ACCOUNT_ID_EXPECTED_HOSPITAL_PERSONNEL_TABLE_VERSION,
    ACCOUNT_ID_HOSPITAL_PERSONNEL_ACCESS_TABLE_ID,
    ACCOUNT_ID_HOSPITAL_PERSONNEL_ACCESS_TABLE_VERSION, ACCOUNT_ID_HOSPITAL_PERSONNEL_TABLE_ID,
    ACCOUNT_ID_HOSPITAL_PERSONNEL_TABLE_VERSION, ACCOUNT_ID_MEDICAL_TABLE_ID,
    ACCOUNT_ID_MEDICAL_TABLE_VERSION, ACCOUNT_ID_PATIENT_ACCESS_LOG_TABLE_ID,
    ACCOUNT_ID_PATIENT_ACCESS_LOG_TABLE_VERSION, ACCOUNT_MODULE_NAME, ACCOUNT_PACKAGE_ID,
    ACCOUNT_PROXY_ADDRESS_TABLE_ID, ACCOUNT_PROXY_ADDRESS_TABLE_VERSION,
};
use iota_types::{base_types::ObjectID, Identifier};
use keyring::Entry;
use std::str::FromStr;
use tauri::{async_runtime::Mutex, Manager};
use types::{
    AccountPackage, AppState, AuthState, KeysEntry, PollingState, SignInState, SignUpState,
};

fn setup(app: &mut tauri::App) -> std::result::Result<(), Box<dyn std::error::Error>> {
    // #[cfg(target_os = "android")]
    // app.get_webview_window("main")
    //     .unwrap()
    //     .with_webview(|webview| {
    //         webview.jni_handle().exec(|env, context, _webview| {
    //             use tauri::wry::prelude::JObject;
    //             let loader = env
    //                 .call_method(
    //                     context,
    //                     "getClassLoader",
    //                     "()Ljava/lang/ClassLoader;",
    //                     &[],
    //                 )
    //                 .unwrap();

    //             rustls_platform_verifier::android::init_with_refs(
    //                 env.get_java_vm().unwrap(),
    //                 env.new_global_ref(context).unwrap(),
    //                 env.new_global_ref(JObject::try_from(loader).unwrap())
    //                     .unwrap(),
    //             );
    //         });
    //     })?;
    //
    //
    //

    let keys_entry = Entry::new("decmed_patient_service_keys", "decmed_patient").unwrap();

    let account_package = AccountPackage {
        package_id: ObjectID::from_str(ACCOUNT_PACKAGE_ID).unwrap(),
        module: Identifier::from_str(ACCOUNT_MODULE_NAME).unwrap(),

        activation_key_activation_key_metadata_table_id: ObjectID::from_str(
            ACCOUNT_ACTIVATION_KEY_ACTIVATION_KEY_METADATA_TABLE_ID,
        )
        .unwrap(),
        activation_key_activation_key_metadata_table_version:
            ACCOUNT_ACTIVATION_KEY_ACTIVATION_KEY_METADATA_TABLE_VERSION,
        address_id_table_id: ObjectID::from_str(ACCOUNT_ADDRESS_ID_TABLE_ID).unwrap(),
        address_id_table_version: ACCOUNT_ADDRESS_ID_TABLE_VERSION,
        id_access_queue_table_id: ObjectID::from_str(ACCOUNT_ID_ACCESS_QUEUE_TABLE_ID).unwrap(),
        id_access_queue_table_version: ACCOUNT_ID_ACCESS_QUEUE_TABLE_VERSION,
        id_activation_key_table_id: ObjectID::from_str(ACCOUNT_ID_ACTIVATION_KEY_TABLE_ID).unwrap(),
        id_activation_key_table_version: ACCOUNT_ID_ACTIVATION_KEY_TABLE_VERSION,
        id_address_table_id: ObjectID::from_str(ACCOUNT_ID_ADDRESS_TABLE_ID).unwrap(),
        id_address_table_version: ACCOUNT_ID_ADDRESS_TABLE_VERSION,
        id_administrative_table_id: ObjectID::from_str(ACCOUNT_ID_ADMINISTRATIVE_TABLE_ID).unwrap(),
        id_administrative_table_version: ACCOUNT_ID_ADMINISTRATIVE_TABLE_VERSION,
        id_expected_hospital_personnel_table_id: ObjectID::from_str(
            ACCOUNT_ID_EXPECTED_HOSPITAL_PERSONNEL_TABLE_ID,
        )
        .unwrap(),
        id_expected_hospital_personnel_table_version:
            ACCOUNT_ID_EXPECTED_HOSPITAL_PERSONNEL_TABLE_VERSION,
        id_hospital_personnel_access_table_id: ObjectID::from_str(
            ACCOUNT_ID_HOSPITAL_PERSONNEL_ACCESS_TABLE_ID,
        )
        .unwrap(),
        id_hospital_personnel_access_table_version:
            ACCOUNT_ID_HOSPITAL_PERSONNEL_ACCESS_TABLE_VERSION,
        id_hospital_personnel_table_id: ObjectID::from_str(ACCOUNT_ID_HOSPITAL_PERSONNEL_TABLE_ID)
            .unwrap(),
        id_hospital_personnel_table_version: ACCOUNT_ID_HOSPITAL_PERSONNEL_TABLE_VERSION,
        id_patient_access_log_table_id: ObjectID::from_str(ACCOUNT_ID_PATIENT_ACCESS_LOG_TABLE_ID)
            .unwrap(),
        id_patient_access_log_table_version: ACCOUNT_ID_PATIENT_ACCESS_LOG_TABLE_VERSION,
        id_medical_table_id: ObjectID::from_str(ACCOUNT_ID_MEDICAL_TABLE_ID).unwrap(),
        id_medical_table_version: ACCOUNT_ID_MEDICAL_TABLE_VERSION,
        hospital_id_registered_hospital_table_id: ObjectID::from_str(
            ACCOUNT_HOSPITAL_ID_REGISTERED_HOSPITAL_TABLE_ID,
        )
        .unwrap(),
        hospital_id_registered_hospital_table_version:
            ACCOUNT_HOSPITAL_ID_REGISTERED_HOSPITAL_TABLE_VERSION,
        proxy_address_table_id: ObjectID::from_str(ACCOUNT_PROXY_ADDRESS_TABLE_ID).unwrap(),
        proxy_address_table_version: ACCOUNT_PROXY_ADDRESS_TABLE_VERSION,

        admin_cap_id: ObjectID::from_str(ACCOUNT_ADMIN_CAP_ID).unwrap(),
        global_admin_add_key_cap_id: ObjectID::from_str(ACCOUNT_GLOBAL_ADMIN_ADD_KEY_CAP_ID)
            .unwrap(),
    };
    let new_keys_entry = KeysEntry {
        id: None,
        admin_address: Some(String::from(
            "0x52a65ae806223e49aaff1cf7f670fee87c1767de1d200a661c1fee44a61fc37f",
        )),
        admin_secret_key: Some(String::from(
            "iotaprivkey1qpfc5nqsvs64p40347h0vcdxz3pgfn72uznw4pfvkak59fhpevxs73z6kwn",
        )),
        activation_key: None,
        iota_address: None,
        iota_key_pair: None,
        pre_secret_key: None,
        pre_public_key: None,
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
    let polling_state = PollingState {
        request_access: false,
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
        account_package,
        signin_state,
        signup_state,
        auth_state,
        polling_state,
        administrative_data: None,
    }));

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(setup)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            signin::is_signed_in,
            signin::signin,
            signup::generate_mnemonic,
            signup::signup,
            signout::signout,
            shared_cmds::validate_pin,
            shared_cmds::validate_confirm_pin,
            shared_cmds::is_session_pin_exist,
            shared_cmds::get_profile,
            shared_cmds::validate_seed_words,
            shared_cmds::get_pre_public_key_bytes,
            shared_cmds::update_profile,
            scan::process_qr,
            scan::stop_polling_request_access,
            home::get_medical_records,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
