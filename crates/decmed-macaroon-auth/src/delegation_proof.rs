use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::attenuation::DelegationAttenuationParams;
use crate::caveats::{format_dataset_list, format_function_list};
use crate::errors::CaveatVerificationError;

/// Canonical context signed by the delegator when creating a delegated token.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DelegationProofContext {
    pub token_hash: String,
    pub delegated_by: String,
    pub delegated_to: String,
    pub related_rme_id: String,
    pub expires_before: String,
    pub scope_fingerprint: String,
}

impl DelegationProofContext {
    pub fn from_delegation(
        macaroon_token: &str,
        related_rme_id: &str,
        params: &DelegationAttenuationParams,
    ) -> Self {
        Self {
            token_hash: hash_macaroon_token(macaroon_token),
            delegated_by: params.delegated_by.clone(),
            delegated_to: params.delegated_to.clone(),
            related_rme_id: related_rme_id.to_string(),
            expires_before: params.expires_before.format("%Y-%m-%dT%H:%M:%S").to_string(),
            scope_fingerprint: scope_fingerprint(params),
        }
    }

    pub fn canonical_message(&self) -> Result<String, CaveatVerificationError> {
        serde_json::to_string(self).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
    }
}

pub fn hash_macaroon_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn scope_fingerprint(params: &DelegationAttenuationParams) -> String {
    let payload = format!(
        "r:{}|w:{}|rf:{}|wf:{}",
        format_dataset_list(&params.read_datasets),
        format_dataset_list(&params.write_datasets),
        format_function_list(&params.read_functions),
        format_function_list(&params.write_functions),
    );
    hex::encode(Sha256::digest(payload.as_bytes()))
}
