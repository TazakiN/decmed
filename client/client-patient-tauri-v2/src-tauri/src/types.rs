use std::fmt;

use iota_json_rpc_types::{IotaObjectRef, IotaTransactionBlockEffects};
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    Identifier,
};
use keyring::Entry;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::move_call::MoveCall;
pub use decmed_rme_segment::{
    DatasetCategory, FunctionCategory, RmeSegmentData, RmeSegmentMetadata,
};

// Enum.

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HospitalPersonnelRole {
    Admin,
    AdministrativePersonnel,
    MedicalPersonnel,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum HospitalPersonnelSubRole {
    Doctor,
    Nurse,
    LaboratoryStaff,
    Pharmacist,
}

pub type MedicalDataMainCategory = DatasetCategory;
pub type MedicalDataSubCategory = FunctionCategory;

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum MoveHospitalPersonnelAccessDataType {
    Administrative,
    Medical,
}

#[derive(Copy, Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub enum MoveHospitalPersonnelAccessType {
    Read,
    Update,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
pub enum MovePatientDelegationAuditEventType {
    Delegated,
    Revoked,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ResponseStatus {
    Error,
    Success,
}

// Struct

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AdministrativeData {
    pub private: PrivateAdministrativeData,
}

pub struct AppState {
    pub administrative_data: Option<AdministrativeData>,
    pub auth_state: AuthState,
    pub keys_entry: Entry,
    pub move_call: MoveCall,
    pub scan_state: ScanState,
    pub signin_state: SignInState,
    pub signup_state: SignUpState,
}

#[derive(Deserialize, Serialize)]
pub struct AuthState {
    pub is_registered: bool,
    pub role: Option<HospitalPersonnelRole>,
    pub session_pin: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandGetMedicalRecordsResponseData {
    #[serde(rename = "authorAddress")]
    pub author_address: String,
    pub cid: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "datasetCategory")]
    pub dataset_category: DatasetCategory,
    #[serde(rename = "functionCategory")]
    pub function_category: FunctionCategory,
    pub index: u64,
    #[serde(rename = "relatedRmeId")]
    pub related_rme_id: String,
    #[serde(rename = "correctionOfIndex")]
    pub correction_of_index: Option<u64>,
    #[serde(rename = "correctionReason")]
    pub correction_reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandGetProfileResponse {
    pub id: String,
    #[serde(rename = "idHash")]
    pub id_hash: String,
    #[serde(rename = "iotaAddress")]
    pub iota_address: String,
    pub name: Option<String>,
    #[serde(rename = "prePublicKey")]
    pub pre_public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandProcessQrResponse {
    #[serde(rename = "hospitalPersonnelHospitalName")]
    pub hospital_personnel_hospital_name: String,
    #[serde(rename = "hospitalPersonnelName")]
    pub hospital_personnel_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandUpdateProfileInput {
    pub name: String,
    #[serde(rename = "birthPlace")]
    pub birth_place: String,
    #[serde(rename = "dateOfBirth")]
    pub date_of_birth: String,
    pub gender: String,
    pub religion: String,
    pub education: String,
    pub occupation: String,
    #[serde(rename = "maritalStatus")]
    pub marital_status: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DecmedPackage {
    pub package_id: ObjectID,
    pub module_admin: Identifier,
    pub module_patient: Identifier,

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

#[derive(Debug, Deserialize, JsonSchema, Serialize)]
pub struct ExecuteTxResponse {
    pub effects: Option<IotaTransactionBlockEffects>,
    pub error: Option<String>,
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
    pub proxy_jwt: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HospitalPersonnelPublicAdministrativeData {
    pub name: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationAuditPersonnelSummary {
    pub address: String,
    pub name: Option<String>,
    pub hospital_name: Option<String>,
    pub role: Option<HospitalPersonnelRole>,
    pub sub_role: Option<HospitalPersonnelSubRole>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationAuditRootGrant {
    pub personnel: DelegationAuditPersonnelSummary,
    pub index: u64,
    pub token_hash: Option<String>,
    pub granted_at: Option<String>,
    pub expires_at: Option<String>,
    pub revoked: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationAuditEdge {
    pub delegated_by: DelegationAuditPersonnelSummary,
    pub delegated_to: DelegationAuditPersonnelSummary,
    pub depth: u8,
    pub token_hash: Option<String>,
    pub parent_token_hash: Option<String>,
    pub expires_at: Option<String>,
    pub revoked: bool,
    pub revoked_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvokeDelegationAuditChain {
    pub root_subject: String,
    pub access_type: MoveHospitalPersonnelAccessType,
    pub related_rme_id: Option<String>,
    pub root_grant: Option<DelegationAuditRootGrant>,
    pub edges: Vec<DelegationAuditEdge>,
    pub status: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CommandGetAccessLogResponse {
    pub access_data_type: Vec<MoveHospitalPersonnelAccessDataType>,
    pub access_type: MoveHospitalPersonnelAccessType,
    pub date: String,
    pub exp_dur: u64,
    pub hospital_metadata: MoveHospitalMetadata,
    pub hospital_personnel_address: String,
    pub hospital_personnel_metadata: HospitalPersonnelPublicAdministrativeData,
    pub index: u64,
    pub is_revoked: bool,
    pub is_delegated: bool,
    pub delegated_by_address: Option<String>,
    pub token_hash: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MovePatientAccessLog {
    pub access_data_type: Vec<MoveHospitalPersonnelAccessDataType>,
    pub access_type: MoveHospitalPersonnelAccessType,
    pub date: String,
    pub exp_dur: u64,
    pub hospital_metadata: MoveHospitalMetadata,
    pub hospital_personnel_address: IotaAddress,
    pub hospital_personnel_metadata: String,
    pub index: u64,
    pub is_revoked: bool,
    pub is_delegated: bool,
    pub delegated_by_address: Option<IotaAddress>,
    pub token_hash: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MovePatientDelegationAuditEntry {
    pub index: u64,
    pub event_type: MovePatientDelegationAuditEventType,
    pub timestamp_ms: u64,
    pub actor_address: IotaAddress,
    pub root_subject: IotaAddress,
    pub delegated_by: IotaAddress,
    pub delegated_to: IotaAddress,
    pub access_type: MoveHospitalPersonnelAccessType,
    pub related_rme_id: Option<String>,
    pub delegation_depth: u8,
    pub token_hash: Option<String>,
    pub parent_token_hash: Option<String>,
    pub expires_at_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveCreateAccessData {
    pub access_token: String,
    pub patient_iota_address: String,
    pub patient_name: String,
    pub patient_pre_public_key: Option<String>,
    pub enc_data_pre_secret_key_seed: Option<String>,
    pub data_pre_secret_key_seed_capsule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_rme_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveCreateAccessMetadata {
    pub capsule: String,
    pub enc_data: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveHospitalMetadata {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MoveHospitalPersonnelPublicAdministrativeData {
    pub hospital_name: Option<String>,
    pub name: Option<String>,
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct PrivateAdministrativeData {
    pub id: String,
    pub name: Option<String>,
    pub birth_place: Option<String>,
    pub date_of_birth: Option<String>,
    pub gender: Option<String>,
    pub religion: Option<String>,
    pub education: Option<String>,
    pub occupation: Option<String>,
    pub marital_status: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PrivateAdministrativeMetadata {
    pub capsule: String,
    pub enc_data: String,
    pub enc_key_nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyReencryptionPostKeysResponseData {
    pub access_token_read: Option<String>,
    pub access_token_update: Option<String>,
    pub access_token_read_hash: Option<String>,
    pub access_token_update_hash: Option<String>,
    #[serde(default)]
    pub related_rme_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyReencryptionErrorResponse {
    pub error: String,
    pub status_code: u16,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyReencryptionKeysPayload {
    pub enc_hospital_personnel_pre_secret_key_seed: String,
    pub hospital_personnel_iota_address: String,
    pub hospital_personnel_pre_public_key: String,
    pub hospital_personnel_pre_secret_key_seed_capsule: String,
    pub k_frag: String,
    pub patient_iota_address: String,
    pub patient_pre_public_key: String,
    pub signature: String,
    pub signer_pre_public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyReencryptionNoncePayload {
    pub iota_address: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyReencryptionPersonnelRoleResponseData {
    pub role: HospitalPersonnelRole,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProxyReencryptionSuccessResponse<T> {
    pub data: T,
    pub status_code: u16,
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

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ScanState {
    pub hospital_personnel_qr_content: Option<String>,
    pub encounter_dataset: Option<DatasetCategory>,
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

impl fmt::Display for ProxyReencryptionErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl std::error::Error for ProxyReencryptionErrorResponse {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[derive(Debug, Serialize)]
    struct WirePatientAccessLog {
        access_data_type: Vec<MoveHospitalPersonnelAccessDataType>,
        access_type: MoveHospitalPersonnelAccessType,
        date: String,
        exp_dur: u64,
        hospital_metadata: MoveHospitalMetadata,
        hospital_personnel_address: IotaAddress,
        hospital_personnel_metadata: String,
        index: u64,
        is_revoked: bool,
        is_delegated: bool,
        delegated_by_address: Option<IotaAddress>,
        token_hash: Option<String>,
    }

    #[derive(Debug, Serialize)]
    struct WirePatientDelegationAuditEntry {
        index: u64,
        event_type: MovePatientDelegationAuditEventType,
        timestamp_ms: u64,
        actor_address: IotaAddress,
        root_subject: IotaAddress,
        delegated_by: IotaAddress,
        delegated_to: IotaAddress,
        access_type: MoveHospitalPersonnelAccessType,
        related_rme_id: Option<String>,
        delegation_depth: u8,
        token_hash: Option<String>,
        parent_token_hash: Option<String>,
        expires_at_ms: Option<u64>,
    }

    #[test]
    fn move_patient_access_log_decodes_latest_bcs_layout() {
        let personnel_address = IotaAddress::from_str(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let delegated_by_address = IotaAddress::from_str(
            "0x2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();

        let wire = vec![WirePatientAccessLog {
            access_data_type: vec![
                MoveHospitalPersonnelAccessDataType::Medical,
                MoveHospitalPersonnelAccessDataType::Administrative,
            ],
            access_type: MoveHospitalPersonnelAccessType::Read,
            date: "2026-05-28T10:00:00Z".to_string(),
            exp_dur: 15,
            hospital_metadata: MoveHospitalMetadata {
                name: "RS DecMed".to_string(),
            },
            hospital_personnel_address: personnel_address,
            hospital_personnel_metadata: "eyJuYW1lIjoiRG9rdGVyIn0=".to_string(),
            index: 7,
            is_revoked: false,
            is_delegated: true,
            delegated_by_address: Some(delegated_by_address),
            token_hash: Some("hash-read".to_string()),
        }];

        let encoded = bcs::to_bytes(&wire).unwrap();
        let decoded: Vec<MovePatientAccessLog> = bcs::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.len(), 1);
        let entry = &decoded[0];
        assert_eq!(entry.access_data_type.len(), 2);
        assert!(matches!(
            entry.access_data_type[0],
            MoveHospitalPersonnelAccessDataType::Medical
        ));
        assert!(matches!(
            entry.access_type,
            MoveHospitalPersonnelAccessType::Read
        ));
        assert_eq!(entry.hospital_personnel_address, personnel_address);
        assert_eq!(entry.is_delegated, true);
        assert_eq!(entry.delegated_by_address, Some(delegated_by_address));
        assert_eq!(entry.token_hash.as_deref(), Some("hash-read"));
    }

    #[test]
    fn move_patient_delegation_audit_decodes_bcs_layout() {
        let admin = IotaAddress::from_str(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let doctor = IotaAddress::from_str(
            "0x2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let lab = IotaAddress::from_str(
            "0x3333333333333333333333333333333333333333333333333333333333333333",
        )
        .unwrap();

        let wire = vec![WirePatientDelegationAuditEntry {
            index: 3,
            event_type: MovePatientDelegationAuditEventType::Delegated,
            timestamp_ms: 1_780_000_000_000,
            actor_address: doctor,
            root_subject: admin,
            delegated_by: doctor,
            delegated_to: lab,
            access_type: MoveHospitalPersonnelAccessType::Read,
            related_rme_id: Some("RME-2026-demo".to_string()),
            delegation_depth: 2,
            token_hash: Some("child-hash".to_string()),
            parent_token_hash: Some("parent-hash".to_string()),
            expires_at_ms: Some(1_780_003_600_000),
        }];

        let encoded = bcs::to_bytes(&wire).unwrap();
        let decoded: Vec<MovePatientDelegationAuditEntry> = bcs::from_bytes(&encoded).unwrap();

        assert_eq!(decoded.len(), 1);
        let entry = &decoded[0];
        assert_eq!(entry.index, 3);
        assert_eq!(
            entry.event_type,
            MovePatientDelegationAuditEventType::Delegated
        );
        assert_eq!(entry.root_subject, admin);
        assert_eq!(entry.delegated_by, doctor);
        assert_eq!(entry.delegated_to, lab);
        assert_eq!(entry.related_rme_id.as_deref(), Some("RME-2026-demo"));
        assert_eq!(entry.delegation_depth, 2);
        assert_eq!(entry.token_hash.as_deref(), Some("child-hash"));
        assert_eq!(entry.parent_token_hash.as_deref(), Some("parent-hash"));
        assert_eq!(entry.expires_at_ms, Some(1_780_003_600_000));
    }
}
