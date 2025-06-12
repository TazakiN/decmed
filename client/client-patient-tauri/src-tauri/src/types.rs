use iota_json_rpc_types::{IotaObjectRef, IotaTransactionBlockEffects};
use iota_sdk::IotaClient;
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    Identifier,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub enum AuthType {
    Signin,
    Signup,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ResponseStatus {
    Success,
    Error,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum HospitalPersonnelRole {
    Admin,
    MedicalPersonnel,
    AdministrativePersonnel,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum MedicalDataMainCategory {
    Category1,
    Category2,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
pub enum MedicalDataSubCategory {
    SubCategory1,
    SubCategory2,
}

///

#[derive(Debug, Serialize, Deserialize)]
pub struct HospitalPersonnelMetadataRaw {
    pub metadata: Vec<u8>,
    pub capsule: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HospitalPersonnelMetadata {
    pub id: String,
    pub activation_key: String,
    pub role: HospitalPersonnelRole,
}

pub struct SignUpState {
    pub seed_words: Option<String>,
    pub pin: Option<String>,
}

pub struct SignInState {
    pub pin: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthState {
    pub is_registered: bool,
    pub role: Option<HospitalPersonnelRole>,
    pub session_pin: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysEntry {
    pub activation_key: Option<String>,
    pub id: Option<String>,
    pub iota_key_pair: Option<Vec<u8>>,
    pub iota_address: Option<String>,
    pub admin_address: Option<String>,
    pub admin_secret_key: Option<String>,
    pub pre_secret_key: Option<Vec<u8>>,
    pub pre_nonce: Option<Vec<u8>>,
    pub iota_nonce: Option<Vec<u8>>,
}

pub struct AccountPackage {
    pub package_id: ObjectID,
    pub module: Identifier,
    pub id_activation_key_table_id: ObjectID,
    pub id_activation_key_table_version: u64,
    pub activation_key_table_id: ObjectID,
    pub activation_key_table_version: u64,
    pub address_id_table_id: ObjectID,
    pub address_id_table_version: u64,
    pub id_address_table_id: ObjectID,
    pub id_address_table_version: u64,
    pub administrative_table_id: ObjectID,
    pub administrative_table_version: u64,
    pub medical_table_id: ObjectID,
    pub medical_table_version: u64,
    pub id_hospital_personnel_metadata_table_id: ObjectID,
    pub id_hospital_personnel_metadata_table_version: u64,
    pub admin_cap_id: ObjectID,
    pub global_admin_add_key_cap_id: ObjectID,
}

pub struct AppState {
    // pub keys_entry: Entry,
    pub iota_client: IotaClient,
    pub account_package: AccountPackage,
    pub signin_state: SignInState,
    pub signup_state: SignUpState,
    pub auth_state: AuthState,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct AdministrativeData {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdministrativeMetadata {
    pub enc_data: Vec<u8>,
    pub enc_key_and_nonce: Vec<u8>,
    pub capsule: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AdministrativeKeyNonce {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SuccessResponse<T> {
    pub status: ResponseStatus,
    pub data: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MedicalData {
    pub main_category: MedicalDataMainCategory,
    pub sub_category: MedicalDataSubCategory,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MedicalMetadata {
    pub enc_data: Vec<u8>,
    pub enc_key_and_nonce: Vec<u8>,
    pub capsule: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MedicalKeyNonce {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}
