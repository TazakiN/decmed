use iota_json_rpc_types::{IotaObjectRef, IotaTransactionBlockEffects};
use iota_types::base_types::IotaAddress;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
pub struct ReserveGasResponse {
    pub result: Option<ReserveGasResult>,
    pub error: Option<String>,
}

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
pub struct ReserveGasResult {
    pub sponsor_address: IotaAddress,
    pub reservation_id: u64,
    pub gas_coins: Vec<IotaObjectRef>,
}

#[derive(Debug, JsonSchema, Serialize, Deserialize)]
pub struct ExecuteTxResponse {
    pub effects: Option<IotaTransactionBlockEffects>,
    pub error: Option<String>,
}
