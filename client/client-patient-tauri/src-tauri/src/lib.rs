// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use std::sync::Mutex;

use bip39::Mnemonic;
use tauri::Manager;

struct AppData {
    private_key: String,
    mnemonic: Option<Mnemonic>,
    pin: Option<Vec<u8>>,
    nik: Option<String>,
}

fn read_from_vault(app: &mut tauri::App) -> String {
    let app_dir = app
        .handle()
        .path()
        .app_data_dir()
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let passwords_file = format!("{}/vault.hold", app_dir);
    let passwords_file_path = std::path::Path::new(&passwords_file);
    let read_result = std::fs::read(passwords_file_path);

    let convert_bytes_to_string = |mut a: String, v: &u8| {
        let new_char = char::from(*v);
        a.push(new_char);
        return a;
    };

    if read_result.is_ok() {
        return format!(
            "{}",
            read_result
                .ok()
                .unwrap()
                .iter()
                .fold(String::from(""), convert_bytes_to_string)
        );
    }

    String::from("")
}

#[tauri::command]
fn is_session_exist(state: tauri::State<'_, Mutex<AppData>>) -> bool {
    if let Ok(data) = state.lock() {
        if !data.private_key.is_empty() {
            return true;
        }
    }

    false
}

#[tauri::command]
fn generate_mnemonic(state: tauri::State<'_, Mutex<AppData>>) -> String {
    let mnemonic = bip39::Mnemonic::generate(12).unwrap();
    let mnemonic_string = mnemonic.to_string();
    if let Ok(mut data) = state.lock() {
        data.mnemonic = Some(mnemonic);
    }
    mnemonic_string
}

#[tauri::command]
fn check_pin(state: tauri::State<'_, Mutex<AppData>>, pin: Vec<u8>) -> bool {
    if let Ok(mut data) = state.lock() {
        if pin.len() == 6 {
            data.pin = Some(pin);
            return true;
        }
    }

    false
}

#[tauri::command]
fn check_confirm_pin(state: tauri::State<'_, Mutex<AppData>>, confirm_pin: Vec<u8>) -> bool {
    if let Ok(data) = state.lock() {
        if let Some(pin) = &data.pin {
            if pin == &confirm_pin {
                return true;
            }
        }
    }

    false
}

#[tauri::command]
fn check_nik(state: tauri::State<'_, Mutex<AppData>>, nik: String) -> bool {
    if let Ok(mut data) = state.lock() {
        data.nik = Some(nik);
        return true;
    }

    false
}

#[tauri::command]
fn register_patient(state: tauri::State<'_, Mutex<AppData>>) -> bool {
    if let Ok(data) = state.lock() {
        return true;
    }

    false
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let res = read_from_vault(app);
            app.manage(Mutex::new(AppData {
                private_key: res,
                mnemonic: None,
                pin: None,
                nik: None,
            }));
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            is_session_exist,
            generate_mnemonic,
            register_patient,
            check_pin,
            check_confirm_pin,
            check_nik
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
