mod access_delegation;
mod activation;
mod admin;
mod administrative_fetch;
mod administrative_personnel;
mod constants;
mod hospital_error;
mod hospital_pre;
mod macros;
mod medical_personnel;
mod move_call;
mod profile;
mod rme_admin_seed;
mod rme_metadata;
mod rme_segment;
mod shared_cmds;
mod signin;
mod signout;
mod signup;
mod types;
mod utils;

use constants::{
    DECMED_ADDRESS_ID_OBJECT_ID, DECMED_ADDRESS_ID_OBJECT_VERSION, DECMED_GLOBAL_ADMIN_CAP_ID,
    DECMED_HOSPITAL_ID_METADATA_OBJECT_ID, DECMED_HOSPITAL_ID_METADATA_OBJECT_VERSION,
    DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_ID,
    DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_VERSION, DECMED_MODULE_ADMIN,
    DECMED_MODULE_HOSPITAL_PERSONNEL, DECMED_PACKAGE_ID, DECMED_PATIENT_ID_ACCOUNT_OBJECT_ID,
    DECMED_PATIENT_ID_ACCOUNT_OBJECT_VERSION,
};
use iota_types::{base_types::ObjectID, Identifier};
use keyring::Entry;
use move_call::MoveCall;
use profile::{
    keyring_service_for_profile, migrate_legacy_default_profile_if_needed, resolve_profile_id,
    KEYRING_ACCOUNT,
};
use std::str::FromStr;
use tauri::{async_runtime::Mutex, Manager};
use types::{AppState, AuthState, DecmedPackage, KeysEntry, SignInState, SignUpState};

fn setup(app: &mut tauri::App) -> std::result::Result<(), Box<dyn std::error::Error>> {
    let profile_id = resolve_profile_id()?;
    let keyring_service = keyring_service_for_profile(&profile_id);
    let keys_entry = Entry::new(&keyring_service, KEYRING_ACCOUNT)?;
    let decmed_package = DecmedPackage {
        package_id: ObjectID::from_str(DECMED_PACKAGE_ID)?,
        module_hospital_personnel: Identifier::from_str(DECMED_MODULE_HOSPITAL_PERSONNEL)?,
        module_admin: Identifier::from_str(DECMED_MODULE_ADMIN)?,

        address_id_object_id: ObjectID::from_str(DECMED_ADDRESS_ID_OBJECT_ID)?,
        address_id_object_version: DECMED_ADDRESS_ID_OBJECT_VERSION,
        hospital_id_metadata_object_id: ObjectID::from_str(DECMED_HOSPITAL_ID_METADATA_OBJECT_ID)?,
        hospital_id_metadata_object_version: DECMED_HOSPITAL_ID_METADATA_OBJECT_VERSION,
        hospital_personnel_id_account_object_id: ObjectID::from_str(
            DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_ID,
        )?,
        hospital_personnel_id_account_object_version:
            DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_VERSION,
        patient_id_account_object_id: ObjectID::from_str(DECMED_PATIENT_ID_ACCOUNT_OBJECT_ID)?,
        patient_id_account_object_version: DECMED_PATIENT_ID_ACCOUNT_OBJECT_VERSION,

        global_admin_cap_id: ObjectID::from_str(DECMED_GLOBAL_ADMIN_CAP_ID)?,
    };
    let new_keys_entry = KeysEntry {
        id: None,
        admin_address: Some(String::from(
            "0x20d4b4309fab8b695bf6e2383e529b96f7eb60cb264abb358f40425c59836648",
        )),
        admin_secret_key: Some(String::from(
            "iotaprivkey1qq4e64j84c9hatlxywe32yftc27hhpjpgh2u3yu4l69q4me98g76jxtsgry",
        )),
        activation_key: None,
        hospital_pre_nonce: None,
        hospital_pre_public_key: None,
        hospital_pre_secret_key: None,
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
        is_signed_up: false,
        role: None,
        session_pin: None,
    };
    let move_call = MoveCall {
        decmed_package: decmed_package.clone(),
    };

    let migrated_legacy_default_profile =
        migrate_legacy_default_profile_if_needed(&keys_entry, &profile_id)?;

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

    if migrated_legacy_default_profile {
        println!("Migrated legacy keyring entry into default profile");
    }
    println!("Using DecMed hospital profile: {profile_id}");

    app.manage(Mutex::new(AppState {
        administrative_data: None,
        auth_state,
        keys_entry,
        move_call,
        profile_id,
        signin_state,
        signup_state,
    }));

    Ok(())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .plugin(tauri_plugin_fs::init())
        .setup(setup)
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            activation::global_admin_add_activation_key,
            activation::hospital_admin_add_activation_key,
            activation::update_personnel_activation_key,
            activation::activate_app,
            signup::generate_mnemonic,
            signup::signup,
            signup::is_signed_up,
            signout::signout,
            signout::reset,
            signin::signin,
            profile::get_profile_id,
            shared_cmds::validate_pin,
            shared_cmds::validate_confirm_pin,
            shared_cmds::get_profile,
            shared_cmds::update_profile,
            shared_cmds::auth_status,
            admin::get_hospital_personnels,
            admin::get_delegatee_candidates,
            medical_personnel::new_medical_record,
            rme_segment::new_medical_record_segment,
            medical_personnel::get_medical_record,
            medical_personnel::get_medical_record_payload,
            rme_metadata::get_accessible_medical_record_metadata,
            rme_metadata::get_accessible_medical_record_encounter_metadata,
            medical_personnel::get_medical_record_update,
            medical_personnel::get_read_access_medical_personnel,
            medical_personnel::get_update_access_medical_personnel,
            medical_personnel::update_medical_record,
            administrative_personnel::get_administrative_data,
            administrative_personnel::get_read_access_administrative_personnel,
            administrative_personnel::get_update_access_administrative_personnel,
            access_delegation::get_current_access_capabilities,
            access_delegation::create_delegated_access,
            access_delegation::create_admin_delegated_access,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
