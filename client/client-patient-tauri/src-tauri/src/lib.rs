// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/

use std::sync::Mutex;

use tauri::Manager;

struct AppData {
    private_key: String,
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let res = read_from_vault(app);
            app.manage(Mutex::new(AppData { private_key: res }));
            Ok(())
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![is_session_exist])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
