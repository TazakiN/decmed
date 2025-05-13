use iota_json_rpc_types::{IotaObjectRef, IotaTransactionBlockEffects};
use iota_sdk::IotaClient;
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    Identifier,
};
use keyring::Entry;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysEntry {
    pub activation_key: Option<String>,
    pub iota_key_pair: Option<String>,
    pub iota_address: Option<String>,
    pub admin_address: Option<String>,
    pub admin_secret_key: Option<String>,
    pub pre_secret_key: Option<Vec<u8>>,
}

pub struct HospitalPackage {
    pub package_id: ObjectID,
    pub module: Identifier,
    pub activation_key_table_id: ObjectID,
    pub activation_key_table_version: u64,
    pub admin_cap_id: ObjectID,
}

pub struct AppState {
    pub keys_entry: Entry,
    pub iota_client: IotaClient,
    pub hospital_package: HospitalPackage,
}

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
