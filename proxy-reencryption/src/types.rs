use std::fmt::Debug;

use iota_json_rpc_types::{IotaObjectRef, IotaTransactionBlockEffects};
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    Identifier,
};
use r2d2::Pool;
use redis::Client;
use schemars::JsonSchema;
use serde::{de, Deserialize, Deserializer, Serialize};

use crate::move_call::MoveCall;
use decmed_macaroon_auth::VerifiedDecmedToken;
use decmed_rme_segment::{DatasetCategory, FunctionCategory};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AuthRole {
    AdministrativePersonnel,
    MedicalPersonnel,
    Patient,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum MoveHospitalPersonnelRole {
    Admin,
    AdministrativePersonnel,
    MedicalPersonnel,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReencryptionPurposeType {
    Read,
    Update,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccessKeys {
    pub enc_data_pre_secret_key_seed: String,
    pub k_frag: String,
    pub data_pre_public_key: String,
    pub data_pre_secret_key_seed_capsule: String,
    pub patient_pre_public_key: String,
    pub signer_pre_public_key: String,
}

pub struct AppState {
    pub global_admin_iota_address: String,
    pub global_admin_iota_key_pair: String,
    pub macaroon_root_key: Vec<u8>,
    pub move_call: MoveCall,
    pub proxy_iota_address: String,
    pub proxy_iota_key_pair: String,
    pub redis_pool: Pool<Client>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ClientMedicalMetadata {
    pub capsule: String,
    pub enc_data: String,
    pub enc_key_and_nonce: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CurrentUser {
    pub iota_address: String,
    pub hospital_cid: Option<String>,
    pub purpose: ReencryptionPurposeType,
    pub role: AuthRole,
    #[serde(skip)]
    pub decmed_token: Option<VerifiedDecmedToken>,
    #[serde(skip)]
    pub bearer_token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecmedPackage {
    pub package_id: ObjectID,
    pub module_admin: Identifier,
    pub module_proxy: Identifier,

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

#[derive(Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub status_code: u16,
}

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ExecuteTxResponse {
    pub effects: Option<IotaTransactionBlockEffects>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenerateAndRegisterProxyAddress {
    pub iota_address: String,
    pub iota_keypair: String,
    pub seed_words: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PatientRevocationPayload {
    pub patient_address: String,
    pub purpose: String,
    pub root_subject: String,
    #[serde(default)]
    pub token_hash: Option<String>,
    #[serde(default)]
    pub expires_before: Option<String>,
    pub tx_digest: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct PatientRevocationSignedPayload {
    pub patient_address: String,
    pub purpose: String,
    pub root_subject: String,
    pub token_hash: Option<String>,
    pub expires_before: Option<String>,
    pub tx_digest: String,
}

impl From<&PatientRevocationPayload> for PatientRevocationSignedPayload {
    fn from(payload: &PatientRevocationPayload) -> Self {
        Self {
            patient_address: payload.patient_address.clone(),
            purpose: payload.purpose.clone(),
            root_subject: payload.root_subject.clone(),
            token_hash: payload.token_hash.clone(),
            expires_before: payload.expires_before.clone(),
            tx_digest: payload.tx_digest.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DelegationRevocationPayload {
    pub patient_address: String,
    pub purpose: String,
    pub delegated_by: String,
    pub delegated_to: String,
    #[serde(default)]
    pub related_rme_id: Option<String>,
    #[serde(default)]
    pub token_hash: Option<String>,
    #[serde(default)]
    pub expires_before: Option<String>,
    pub tx_digest: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenerateMacaroonKeyHandlerResponse {
    pub macaroon_root_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GetNonceHandlerPayload {
    pub iota_address: String, // hex string
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GenerateSignatureHandlerPayload {
    pub iota_keypair: String,
    pub nonce: String,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct HandlerCreateMedicalRecordPayload {
    pub medical_metadata: String,
    pub patient_iota_address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HandlerCreateMedicalRecordSegmentPayload {
    pub encrypted_segment: String,
    pub patient_iota_address: String,
}

#[derive(Debug, Deserialize)]
pub struct HandlerGetAdministrativeDataQueryParams {
    pub patient_iota_address: String,
}

#[derive(Debug, Deserialize)]
pub struct HandlerListMedicalRecordsQueryParams {
    pub patient_iota_address: String,
    #[serde(default)]
    pub cursor: Option<u64>,
    #[serde(default)]
    pub limit: Option<u64>,
    #[serde(default)]
    pub related_rme_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MedicalRecordMetadataItem {
    pub index: u64,
    pub list_index: u64,
    pub segment_id: String,
    pub related_rme_id: String,
    pub patient_address: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub ipfs_cid: String,
    pub created_at: String,
    pub author_address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ListMedicalRecordsResponse {
    pub items: Vec<MedicalRecordMetadataItem>,
    pub next_cursor: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct HandlerGetMedicalRecordQueryParams {
    #[serde(deserialize_with = "crate::utils::Utils::empty_string_as_none")]
    pub index: Option<u64>,
    pub patient_iota_address: String,
    #[serde(default)]
    pub include_administrative: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct HandlerGetMedicalRecordUpdateQueryParams {
    #[serde(deserialize_with = "crate::utils::Utils::empty_string_as_none")]
    pub index: Option<u64>,
    pub patient_iota_address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HandlerStoreKeysPayload {
    pub enc_data_pre_secret_key_seed: String,
    pub hospital_personnel_iota_address: String,
    pub k_frag: String,
    pub data_pre_public_key: String,
    pub data_pre_secret_key_seed_capsule: String,
    pub patient_iota_address: String,
    pub patient_pre_public_key: String,
    pub signature: String,
    pub signer_pre_public_key: String,
    #[serde(default)]
    pub related_rme_id: Option<String>,
    pub hospital_cid: String,
    #[serde(default)]
    pub root_subject: Option<String>,
    /// RAWAT_JALAN or RAWAT_INAP — required for AdministrativePersonnel DecMed dual issuance.
    #[serde(default)]
    pub encounter_dataset: Option<DatasetCategory>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HandlerUpdateMedicalRecordPayload {
    pub medical_metadata: String,
    pub patient_iota_address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MedicalMetadata {
    pub capsule: String,
    pub cid: String,
    pub created_at: String,
    pub enc_key_and_nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MovePatientAdministrativeMetadata {
    pub private_metadata: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MovePatientMedicalMetadata {
    pub index: u64,
    pub metadata: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PatientPrivateAdministrativeMetadata {
    pub capsule: String,
    pub enc_data: String,
    pub enc_key_nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SuccessResponse<T>
where
    T: Debug,
{
    pub data: T,
    pub status_code: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UtilIpfsAddResponse {
    #[serde(default)]
    pub allocations: Vec<String>,
    #[serde(alias = "Hash")]
    pub cid: String,
    #[serde(default, alias = "Name")]
    pub name: String,
    #[serde(default, alias = "Size", deserialize_with = "deserialize_ipfs_size")]
    pub size: u64,
}

fn deserialize_ipfs_size<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;

    match value {
        None | Some(serde_json::Value::Null) => Ok(0),
        Some(serde_json::Value::Number(number)) => number
            .as_u64()
            .ok_or_else(|| de::Error::custom("IPFS size must be an unsigned integer")),
        Some(serde_json::Value::String(value)) => value
            .parse::<u64>()
            .map_err(|err| de::Error::custom(format!("Invalid IPFS size: {err}"))),
        Some(_) => Err(de::Error::custom("IPFS size must be a number or string")),
    }
}

#[cfg(test)]
mod tests {
    use super::UtilIpfsAddResponse;

    #[test]
    fn ipfs_add_response_accepts_cluster_shape_without_allocations() {
        let response: UtilIpfsAddResponse =
            serde_json::from_str(r#"{"cid":"bafy123","name":"segment","size":126}"#).unwrap();

        assert_eq!(response.cid, "bafy123");
        assert!(response.allocations.is_empty());
        assert_eq!(response.size, 126);
    }

    #[test]
    fn ipfs_add_response_accepts_kubo_shape() {
        let response: UtilIpfsAddResponse =
            serde_json::from_str(r#"{"Name":"segment","Hash":"Qm123","Size":"126"}"#).unwrap();

        assert_eq!(response.cid, "Qm123");
        assert_eq!(response.name, "segment");
        assert_eq!(response.size, 126);
    }
}
