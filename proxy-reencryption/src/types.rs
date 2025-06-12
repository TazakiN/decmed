use iota_sdk::IotaClient;
use serde::{Deserialize, Serialize};

pub struct AppState {
    pub iota_client: IotaClient,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub status_code: u16,
    pub error: String,
}
