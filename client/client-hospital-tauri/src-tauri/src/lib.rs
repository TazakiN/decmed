// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use keyring::{Entry, Result};
use std::sync::Mutex;
use tauri::{Manager, State};

struct AppData {
    keyring_entry: Entry,
}

#[tauri::command]
fn greet(name: &str) -> String {
    println!("jiwoo");
    format!("Hello, {}! You've been greeted from Rust!", name)
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
        a
    };

    if read_result.is_ok() {
        return read_result
            .ok()
            .unwrap()
            .iter()
            .fold(String::from(""), convert_bytes_to_string)
            .to_string();
    }

    String::from("")
}

fn read_from_keyring() {}

#[tauri::command]
fn get_password_from_keyring(state: State<'_, Mutex<AppData>>) -> String {
    if let Ok(data) = state.lock() {
        let password = data.keyring_entry.get_password().unwrap();
        return format!("success: {}", password);
    }

    String::from("Failed to get password")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let entry = Entry::new_with_target("jiwoo_target", "jiwoo_service", "jiwoo_user")?;
            // entry.set_password("jiwoo very secret password");

            app.manage(Mutex::new(AppData {
                keyring_entry: entry,
            }));

            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![greet, get_password_from_keyring])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
