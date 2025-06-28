use iota_json_rpc_types::{IotaObjectRef, IotaTransactionBlockEffects};
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    Identifier,
};
use keyring::Entry;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::move_call::MoveCall;

// Enum

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MoveHospitalPersonnelAccessDataType {
    Administrative,
    Medical,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ResponseStatus {
    Error,
    Success,
}

// Struct

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessData {
    #[serde(rename = "accessDataTypes")]
    pub access_data_types: Vec<MoveHospitalPersonnelAccessDataType>,
    #[serde(rename = "accessToken")]
    pub access_token: String,
    pub exp: u64,
    #[serde(rename = "patientIotaAddress")]
    pub patient_iota_address: String,
    #[serde(rename = "patientName")]
    pub patient_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessMetadata {
    pub access_token: String,
    pub patient_iota_address: String,
    pub patient_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccessMetadataEncrypted {
    pub capsule: String,
    pub enc_data: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecmedPackage {
    pub package_id: ObjectID,
    pub module_admin: Identifier,
    pub module_hospital_personnel: Identifier,

    pub address_id_object_id: ObjectID,
    pub address_id_object_version: u64,
    pub hospital_id_metadata_object_id: ObjectID,
    pub hospital_id_metadata_object_version: u64,
    pub hospital_personnel_id_account_object_id: ObjectID,
    pub hospital_personnel_id_account_object_version: u64,
    pub patient_id_account_object_id: ObjectID,
    pub patient_id_account_object_version: u64,

    pub global_admin_cap_id: ObjectID,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdministrativeData {
    pub private: PrivateAdministrativeData,
    pub public: PublicAdministrativeData,
}

pub struct AppState {
    pub administrative_data: Option<AdministrativeData>,
    pub auth_state: AuthState,
    pub keys_entry: Entry,
    pub move_call: MoveCall,
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
pub struct CommandGetHospitalPersonnelsResponseData {
    pub personnels: Vec<HospitalPersonnelMetadata>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandGetProfileResponseData {
    pub hospital: String,
    pub id: String,
    #[serde(rename = "idHash")]
    pub id_hash: String,
    #[serde(rename = "iotaAddress")]
    pub iota_address: String,
    #[serde(rename = "iotaKeyPair")]
    pub iota_key_pair: String,
    pub name: Option<String>,
    #[serde(rename = "prePublicKey")]
    pub pre_public_key: String,
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
pub struct CommandUpdateProfileArgs {
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
    pub key: String,
    pub nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct KeysEntry {
    pub activation_key: Option<String>,
    pub admin_address: Option<String>,
    pub admin_secret_key: Option<String>,
    pub id: Option<String>,
    pub iota_address: Option<String>,
    pub iota_key_pair: Option<String>,
    pub iota_nonce: Option<String>,
    pub pre_nonce: Option<String>,
    pub pre_public_key: Option<String>,
    pub pre_secret_key: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MedicalData {
    pub main_category: MedicalDataMainCategory,
    pub sub_category: MedicalDataSubCategory,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MedicalMetadata {
    pub capsule: String,
    pub cid: String,
    pub created_at: String,
    pub enc_key_and_nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveHospitalMetadata {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveHospitalPersonnelAccessData {
    pub access_data_types: Vec<MoveHospitalPersonnelAccessDataType>,
    pub exp: u64,
    pub metadata: String,
    pub medical_metadata_index: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveHospitalPersonnelAdministrativeMetadata {
    pub private_metadata: String,
    pub public_metadata: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveCallHospitalAdminAddActivationKeyPayload {
    pub capsule: String,
    pub enc_metadata: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveHospitalPersonnelMetadata {
    pub metadata: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PrivateAdministrativeData {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrivateAdministrativeMetadata {
    pub capsule: String,
    pub enc_data: String,
    pub enc_key_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicAdministrativeData {
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
