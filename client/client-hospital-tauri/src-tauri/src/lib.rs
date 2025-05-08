use std::collections::HashMap;

use iota_sdk::IotaClientBuilder;
use iota_types::gas_coin::NANOS_PER_IOTA;
use keyring::Entry;

use serde::{Deserialize, Serialize};

const HOSPITAL_PACKAGE_ID: &str =
    "0x8b7abcd22d3d6aa4939c4b399c1d9141d0a66d611062058985dd94d14bb1d5e0";
const HOSPITAL_MODULE_NAME: &str = "hospital";
const HOSPITAL_TABLE_ID: &str =
    "0xd723bfa7273101ad50b1dc06fb56a9a343c90c62ade9ed9f338aa1f9e7c5fb1a";
const GAS_STATION_BASE_URL: &str = "http://localhost:9527/v1";

#[derive(Serialize, Deserialize, Debug)]
struct ReservationResponse {
    result: Option<ReservationResultData>,
    error: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ReservationResultData {
    sponsor_address: String,
    reservation_id: u64,
    gas_coins: Vec<ReservationGasCoin>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ReservationGasCoin {
    #[serde(rename = "objectId")]
    object_id: String,
    version: u64,
    digest: String,
}

#[tauri::command]
fn get_password_from_keyring() -> String {
    let entry = Entry::new_with_target("jiwoo_target", "jiwoo_service", "jiwoo_user").unwrap();
    let password = entry.get_password().unwrap();
    format!("success: {}", password)
}

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
async fn add_activation_key() {
    let iota_client = IotaClientBuilder::default().build_localnet().await.unwrap();

    let mut body = HashMap::new();
    body.insert("gas_budget", NANOS_PER_IOTA);
    body.insert("reserve_duration_secs", 10);

    let req_client = reqwest::Client::new();
    let res = req_client
        .post(format!("{GAS_STATION_BASE_URL}/reserve_gas"))
        .bearer_auth("token")
        .json(&body)
        .send()
        .await
        .unwrap();
    let res_body = res.json::<ReservationResponse>().await.unwrap();

    println!("{:#?}", res_body);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            is_app_activated,
            get_password_from_keyring,
            add_activation_key
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
