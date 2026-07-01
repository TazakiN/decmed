use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use serde::{Deserialize, Serialize};

use crate::errors::CaveatVerificationError;

/// Canonical request signed by the delegator before PRE attenuates a token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationRequestProofContext {
    pub request_kind: String,
    pub mode: String,
    pub delegator_iota_address: String,
    pub delegatee_iota_address: String,
    pub patient_iota_address: String,
    pub parent_read_token_hash: Option<String>,
    pub parent_write_token_hash: Option<String>,
    pub expires_before: String,
    pub related_rme_id: Option<String>,
    pub preset: Option<String>,
    pub read_datasets: Vec<DatasetCategory>,
    pub write_datasets: Vec<DatasetCategory>,
    pub read_functions: Vec<FunctionCategory>,
    pub write_functions: Vec<FunctionCategory>,
}

impl DelegationRequestProofContext {
    pub fn canonical_message(&self) -> Result<String, CaveatVerificationError> {
        serde_json::to_string(self).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
    }
}
