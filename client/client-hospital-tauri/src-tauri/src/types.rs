use iota_json_rpc_types::{IotaObjectRef, IotaTransactionBlockEffects};
use iota_sdk::IotaClient;
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    Identifier,
};
use keyring::Entry;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// Enum

pub enum AuthType {
    Signin,
    Signup,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum HospitalPersonnelRole {
    Admin,
    AdministrativePersonnel,
    MedicalPersonnel,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum MedicalDataMainCategory {
    Category1,
    Category2,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum MedicalDataSubCategory {
    SubCategory1,
    SubCategory2,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ResponseStatus {
    Error,
    Success,
}

// Struct

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountPackage {
    pub package_id: ObjectID,
    pub module: Identifier,

    pub activation_key_activation_key_metadata_table_id: ObjectID,
    pub activation_key_activation_key_metadata_table_version: u64,
    pub address_id_table_id: ObjectID,
    pub address_id_table_version: u64,
    pub hospital_id_registered_hospital_table_id: ObjectID,
    pub hospital_id_registered_hospital_table_version: u64,
    pub id_access_queue_table_id: ObjectID,
    pub id_access_queue_table_version: u64,
    pub id_activation_key_table_id: ObjectID,
    pub id_activation_key_table_version: u64,
    pub id_address_table_id: ObjectID,
    pub id_address_table_version: u64,
    pub id_administrative_table_id: ObjectID,
    pub id_administrative_table_version: u64,
    pub id_expected_hospital_personnel_table_id: ObjectID,
    pub id_expected_hospital_personnel_table_version: u64,
    pub id_hospital_personnel_access_table_id: ObjectID,
    pub id_hospital_personnel_access_table_version: u64,
    pub id_hospital_personnel_table_id: ObjectID,
    pub id_hospital_personnel_table_version: u64,
    pub id_medical_table_id: ObjectID,
    pub id_medical_table_version: u64,
    pub id_patient_access_log_table_id: ObjectID,
    pub id_patient_access_log_table_version: u64,
    pub proxy_address_table_id: ObjectID,
    pub proxy_address_table_version: u64,

    pub admin_cap_id: ObjectID,
    pub global_admin_add_key_cap_id: ObjectID,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdministrativeData {
    pub private: PrivateAdministrativeData,
    pub public: PublicAdministrativeData,
}

pub struct AppState {
    pub account_package: AccountPackage,
    pub administrative_data: Option<AdministrativeData>,
    pub auth_state: AuthState,
    pub iota_client: IotaClient,
    pub keys_entry: Entry,
    pub polling_state: PollingState,
    pub signin_state: SignInState,
    pub signup_state: SignUpState,
}

#[derive(Deserialize, Serialize)]
pub struct AuthState {
    pub is_signed_up: bool,
    pub role: Option<HospitalPersonnelRole>,
    pub session_pin: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandGetHospitalPersonnelsResponse {
    pub personnels: Vec<HospitalPersonnelMetadata>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandGetProfileResponse {
    pub hospital: Option<String>,
    pub id: String,
    #[serde(rename = "idHash")]
    pub id_hash: String,
    pub name: Option<String>,
    pub role: HospitalPersonnelRole,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandGlobalAdminAddActivationKeyResponse {
    #[serde(rename = "activationKey")]
    pub activation_key: String,
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandHospitalAdminAddActivationKeyResponse {
    #[serde(rename = "activationKey")]
    pub activation_key: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CommandUpdateProfileDataInput {
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ExecuteTxResponse {
    pub effects: Option<IotaTransactionBlockEffects>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HospitalPersonnelMetadata {
    pub activation_key: String,
    pub id: String,
    pub role: HospitalPersonnelRole,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeyNonce {
    pub key: Vec<u8>,
    pub nonce: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeysEntry {
    pub activation_key: Option<String>,
    pub admin_address: Option<String>,
    pub admin_secret_key: Option<String>,
    pub id: Option<String>,
    pub iota_address: Option<String>,
    pub iota_key_pair: Option<Vec<u8>>,
    pub iota_nonce: Option<Vec<u8>>,
    pub pre_nonce: Option<Vec<u8>>,
    pub pre_public_key: Option<Vec<u8>>,
    pub pre_secret_key: Option<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MedicalData {
    pub main_category: MedicalDataMainCategory,
    pub sub_category: MedicalDataSubCategory,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MedicalMetadata {
    pub capsule: Vec<u8>,
    pub cid: String,
    pub created_at: String,
    pub enc_key_and_nonce: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveGetAccessQueueResponse {
    pub data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveAdministrative {
    pub private_data: Vec<u8>,
    pub public_data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveGetHospitalPersonnelsResponse {
    pub data: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveHospitalAdminAddActivationKeyData {
    pub capsule: Vec<u8>,
    pub metadata: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveInitRequestInput {
    pub patient_id: String,
    pub patient_pre_public_key: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveRequestAccessInput {
    pub hospital_personnel_hospital: String,
    pub hospital_personnel_id: String,
    pub hospital_personnel_name: String,
    pub hospital_personnel_pre_public_key: Vec<u8>,
}

pub struct PollingState {
    pub is_polling_init_access: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateAdministrativeData {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrivateAdministrativeMetadata {
    pub capsule: Vec<u8>,
    pub enc_data: Vec<u8>,
    pub enc_key_nonce: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicAdministrativeData {
    pub hospital_name: Option<String>,
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ReserveGasResponse {
    pub error: Option<String>,
    pub result: Option<ReserveGasResult>,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ReserveGasResult {
    pub gas_coins: Vec<IotaObjectRef>,
    pub reservation_id: u64,
    pub sponsor_address: IotaAddress,
}

pub struct SignInState {
    pub pin: Option<String>,
}

pub struct SignUpState {
    pub pin: Option<String>,
    pub seed_words: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SuccessResponse<T> {
    pub data: T,
    pub status: ResponseStatus,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UtilIpfsAddResponse {
    pub allocations: Vec<String>,
    pub cid: String,
    pub name: String,
    pub size: u64,
}
