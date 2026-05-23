use serde::{ Deserialize, Serialize };
use serde_json::Value;
use uuid::Uuid;

use crate::category::{ DatasetCategory, FunctionCategory };
use crate::crypto::{ ciphertext_integrity_hash_from_base64, payload_hash, EncryptionAlgorithm };
use crate::error::SegmentValidationError;
use crate::validation::{
    assert_no_plaintext_medical_fields,
    assert_valid_segment_category,
    is_empty_payload,
};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SegmentAttachment {
    pub cid: String,
    pub file_name: String,
    pub mime_type: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct CreateRmeSegmentRequest {
    pub related_rme_id: String,
    pub patient_address: String,
    pub patient_ref: String,
    pub fasyankes_id: String,
    pub encounter_id: String,
    pub service_date: String,
    pub author_address: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub payload: Value,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<SegmentAttachment>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct RmeSegmentData {
    pub segment_id: String,
    pub related_rme_id: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub patient_ref: String,
    pub encounter_id: String,
    pub service_date: String,
    pub author_address: String,
    pub payload: Value,
    pub payload_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachments: Option<Vec<SegmentAttachment>>,
}

impl RmeSegmentData {
    pub fn new(
        segment_id: Uuid,
        request: CreateRmeSegmentRequest
    ) -> Result<Self, SegmentValidationError> {
        assert_valid_segment_category(request.dataset_category, request.function_category)?;

        if is_empty_payload(&request.payload) {
            return Err(SegmentValidationError::EmptyPayload);
        }

        let attachments = if request.attachments.is_empty() {
            None
        } else {
            Some(request.attachments)
        };

        Ok(Self {
            segment_id: segment_id.to_string(),
            related_rme_id: request.related_rme_id,
            dataset_category: request.dataset_category,
            function_category: request.function_category,
            patient_ref: request.patient_ref,
            encounter_id: request.encounter_id,
            service_date: request.service_date,
            author_address: request.author_address,
            payload_hash: payload_hash(&request.payload),
            payload: request.payload,
            attachments,
        })
    }

    pub fn validate(&self) -> Result<(), SegmentValidationError> {
        assert_valid_segment_category(self.dataset_category, self.function_category)?;

        if self.payload_hash.is_empty() {
            return Err(SegmentValidationError::MissingField("payload_hash"));
        }

        if self.payload_hash != payload_hash(&self.payload) {
            return Err(SegmentValidationError::InvalidPayloadHash);
        }

        if is_empty_payload(&self.payload) {
            return Err(SegmentValidationError::EmptyPayload);
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ClientEncryptedRmeSegment {
    pub segment_id: String,
    pub related_rme_id: String,
    pub patient_address: String,
    pub fasyankes_id: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub integrity_hash: String,
    pub capsule: String,
    pub enc_data: String,
    pub enc_key_and_nonce: String,
    #[serde(default)]
    pub encryption_algo: EncryptionAlgorithm,
    pub author_address: String,
}

impl ClientEncryptedRmeSegment {
    pub fn validate(&self) -> Result<(), SegmentValidationError> {
        assert_valid_segment_category(self.dataset_category, self.function_category)?;

        for (field, value) in [
            ("segment_id", self.segment_id.as_str()),
            ("related_rme_id", self.related_rme_id.as_str()),
            ("patient_address", self.patient_address.as_str()),
            ("fasyankes_id", self.fasyankes_id.as_str()),
            ("integrity_hash", self.integrity_hash.as_str()),
            ("capsule", self.capsule.as_str()),
            ("enc_data", self.enc_data.as_str()),
            ("enc_key_and_nonce", self.enc_key_and_nonce.as_str()),
            ("author_address", self.author_address.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SegmentValidationError::MissingField(field));
            }
        }

        Uuid::parse_str(&self.segment_id).map_err(|_| SegmentValidationError::InvalidUuid)?;

        let computed_integrity_hash = ciphertext_integrity_hash_from_base64(&self.enc_data)?;
        if computed_integrity_hash != self.integrity_hash {
            return Err(SegmentValidationError::InvalidIntegrityHash);
        }

        Ok(())
    }

    pub fn into_metadata(self, ipfs_cid: String, created_at: String) -> RmeSegmentMetadata {
        RmeSegmentMetadata {
            segment_id: self.segment_id,
            related_rme_id: self.related_rme_id,
            patient_address: self.patient_address,
            fasyankes_id: self.fasyankes_id,
            dataset_category: self.dataset_category,
            function_category: self.function_category,
            ipfs_cid,
            integrity_hash: self.integrity_hash,
            capsule: self.capsule,
            enc_key_and_nonce: self.enc_key_and_nonce,
            encryption_algo: self.encryption_algo,
            created_at,
            author_address: self.author_address,
            updated_at: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RmeSegmentMetadata {
    pub segment_id: String,
    pub related_rme_id: String,
    pub patient_address: String,
    pub fasyankes_id: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub ipfs_cid: String,
    pub integrity_hash: String,
    pub capsule: String,
    pub enc_key_and_nonce: String,
    #[serde(default)]
    pub encryption_algo: EncryptionAlgorithm,
    pub created_at: String,
    pub author_address: String,
    pub updated_at: Option<String>,
}

impl RmeSegmentMetadata {
    pub fn validate(&self) -> Result<(), SegmentValidationError> {
        assert_valid_segment_category(self.dataset_category, self.function_category)?;

        for (field, value) in [
            ("segment_id", self.segment_id.as_str()),
            ("related_rme_id", self.related_rme_id.as_str()),
            ("patient_address", self.patient_address.as_str()),
            ("fasyankes_id", self.fasyankes_id.as_str()),
            ("ipfs_cid", self.ipfs_cid.as_str()),
            ("integrity_hash", self.integrity_hash.as_str()),
            ("capsule", self.capsule.as_str()),
            ("enc_key_and_nonce", self.enc_key_and_nonce.as_str()),
            ("created_at", self.created_at.as_str()),
            ("author_address", self.author_address.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(SegmentValidationError::MissingField(field));
            }
        }

        Uuid::parse_str(&self.segment_id).map_err(|_| SegmentValidationError::InvalidUuid)?;

        let value = serde_json
            ::to_value(self)
            .map_err(|_| SegmentValidationError::SerializationFailed)?;
        assert_no_plaintext_medical_fields(&value)?;

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreateRmeSegmentResponse {
    pub segment_id: String,
    pub related_rme_id: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub ipfs_cid: String,
    pub integrity_hash: String,
    pub created_at: String,
}

impl From<&RmeSegmentMetadata> for CreateRmeSegmentResponse {
    fn from(metadata: &RmeSegmentMetadata) -> Self {
        Self {
            segment_id: metadata.segment_id.clone(),
            related_rme_id: metadata.related_rme_id.clone(),
            dataset_category: metadata.dataset_category,
            function_category: metadata.function_category,
            ipfs_cid: metadata.ipfs_cid.clone(),
            integrity_hash: metadata.integrity_hash.clone(),
            created_at: metadata.created_at.clone(),
        }
    }
}
