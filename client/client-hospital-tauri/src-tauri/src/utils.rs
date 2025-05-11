use iota_types::base_types::{IotaAddress, ObjectRef};
use serde_json::json;

use crate::constants::GAS_STATION_BASE_URL;
use crate::types::{ExecuteTxResponse, ReserveGasResponse};

pub async fn reserve_gas(
    gas_budget: u64,
    reserve_duration_secs: u64,
) -> (IotaAddress, u64, Vec<ObjectRef>) {
    let req_client = reqwest::Client::new();
    let res = req_client
        .post(format!("{GAS_STATION_BASE_URL}/reserve_gas"))
        .bearer_auth("token")
        .json(&json!({
          "gas_budget": gas_budget,
        "reserve_duration_secs": reserve_duration_secs
        }))
        .send()
        .await
        .unwrap();
    let res_body = res.json::<ReserveGasResponse>().await.unwrap();
    res_body
        .result
        .map(|result| {
            (
                result.sponsor_address,
                result.reservation_id,
                result
                    .gas_coins
                    .into_iter()
                    .map(|c| c.to_object_ref())
                    .collect(),
            )
        })
        .unwrap()
}

pub async fn execute_tx(
    reservation_id: u64,
    tx_base_64: String,
    signature_base_64: String,
) -> ExecuteTxResponse {
    let req_client = reqwest::Client::new();
    let res = req_client
        .post(format!("{GAS_STATION_BASE_URL}/execute_tx"))
        .bearer_auth("token")
        .json(&json!({
            "reservation_id": reservation_id,
            "tx_bytes": tx_base_64,
            "user_sig": signature_base_64
        }))
        .send()
        .await
        .unwrap();
    res.json::<ExecuteTxResponse>().await.unwrap()
}
