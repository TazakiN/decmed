use axum::http::{HeaderMap, StatusCode};
use decmed_macaroon_auth::{
    verify_segment_access, AccessMode, CaveatVerificationError, SegmentAccessContext,
    TokenVerificationContext, VerifiedDecmedToken, WalletProofContext, WalletSignatureVerifier,
};
use decmed_rme_segment::{DatasetCategory, FunctionCategory, RmeSegmentMetadata};
use macaroon::Macaroon;
use serde_json::Value;

use crate::{
    macaroon_auth::{map_caveat_error, IotaWalletVerifier},
    middlewares::{WALLET_SIGNATURE_HEADER, WALLET_TIMESTAMP_HEADER},
    proxy_error::ProxyError,
    types::MedicalRecordMetadataItem,
    utils::Utils,
};

pub fn decode_rme_segment_metadata(raw: &str) -> Option<RmeSegmentMetadata> {
    let metadata_value: Value = Utils::serde_deserialize_from_base64(raw.to_string()).ok()?;
    if metadata_value.get("ipfs_cid").is_none() {
        return None;
    }
    let segment: RmeSegmentMetadata = serde_json::from_value(metadata_value).ok()?;
    segment.validate().ok()?;
    Some(segment)
}

pub fn segment_allowed_for_list(
    verified: &VerifiedDecmedToken,
    segment: &RmeSegmentMetadata,
    patient_iota_address: &str,
) -> bool {
    if segment.patient_address != patient_iota_address {
        return false;
    }
    if let Some(token_rme) = verified.effective.related_rme_id.as_deref() {
        if token_rme != segment.related_rme_id {
            return false;
        }
    }
    let ctx = TokenVerificationContext {
        operation: AccessMode::Read,
        segment: SegmentAccessContext {
            segment_id: segment.segment_id.clone(),
            patient_address: segment.patient_address.clone(),
            related_rme_id: segment.related_rme_id.clone(),
            dataset_category: segment.dataset_category,
            function_category: segment.function_category,
        },
        wallet_signature_b64: None,
        wallet_timestamp: None,
        now: chrono::Utc::now(),
    };
    verify_segment_access(&verified.effective, &ctx).is_ok()
}

pub fn verify_list_wallet_proof_if_required(
    verified: &VerifiedDecmedToken,
    mac: &Macaroon,
    patient_iota_address: &str,
    headers: &HeaderMap,
) -> Result<(), ProxyError> {
    if verified.effective.proof_required.is_none() {
        return Ok(());
    }

    let proof_timestamp = headers
        .get(WALLET_TIMESTAMP_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    let related_rme_id = verified
        .effective
        .related_rme_id
        .clone()
        .unwrap_or_default();

    let proof_ctx = WalletProofContext {
        token_id: verified.token_id.clone(),
        patient_address: patient_iota_address.to_string(),
        related_rme_id: related_rme_id.clone(),
        operation: AccessMode::Read,
        segment_id: String::new(),
        dataset_category: DatasetCategory::RAWAT_JALAN,
        function_category: FunctionCategory::ADMINISTRATIVE_GENERAL,
        timestamp: proof_timestamp,
    };

    let wallet_sig = match headers
        .get(WALLET_SIGNATURE_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        Some(sig) => sig,
        None => {
            return Err(ProxyError::WalletProofChallenge {
                code: StatusCode::UNAUTHORIZED.as_u16(),
                error: CaveatVerificationError::WalletSignatureRequired.to_string(),
                proof_context: proof_ctx,
            });
        }
    };

    IotaWalletVerifier
        .verify(&proof_ctx, wallet_sig, &verified.delegation.active_subject)
        .map_err(map_caveat_error)?;

    if let Some(token_patient) = verified.effective.patient_address.as_deref() {
        if token_patient != patient_iota_address {
            return Err(map_caveat_error(CaveatVerificationError::PatientMismatch));
        }
    }

    if verified.effective.is_expired(chrono::Utc::now()) {
        return Err(map_caveat_error(CaveatVerificationError::ExpiredToken));
    }

    let _ = mac;
    Ok(())
}

pub fn verify_decmed_token_patient_for_list(
    verified: &VerifiedDecmedToken,
    patient_iota_address: &str,
) -> Result<(), ProxyError> {
    if let Some(token_patient) = verified.effective.patient_address.as_deref() {
        if token_patient != patient_iota_address {
            return Err(map_caveat_error(CaveatVerificationError::PatientMismatch));
        }
    }
    if verified.effective.is_expired(chrono::Utc::now()) {
        return Err(map_caveat_error(CaveatVerificationError::ExpiredToken));
    }
    Ok(())
}

pub fn to_metadata_item(
    table_index: u64,
    list_index: u64,
    segment: &RmeSegmentMetadata,
) -> MedicalRecordMetadataItem {
    MedicalRecordMetadataItem {
        index: table_index,
        list_index,
        segment_id: segment.segment_id.clone(),
        related_rme_id: segment.related_rme_id.clone(),
        patient_address: segment.patient_address.clone(),
        dataset_category: segment.dataset_category,
        function_category: segment.function_category,
        ipfs_cid: segment.ipfs_cid.clone(),
        created_at: segment.created_at.clone(),
        author_address: segment.author_address.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decmed_macaroon_auth::{
        issue_initial_token, EffectiveCapability, InitialDoctorTokenParams,
    };
    use decmed_rme_segment::{DatasetCategory, FunctionCategory};
    use macaroon::MacaroonKey;

    fn sample_segment(
        patient: &str,
        dataset: DatasetCategory,
        function: FunctionCategory,
    ) -> RmeSegmentMetadata {
        RmeSegmentMetadata {
            segment_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
            related_rme_id: "rme-1".to_string(),
            patient_address: patient.to_string(),
            fasyankes_id: "f1".to_string(),
            dataset_category: dataset,
            function_category: function,
            ipfs_cid: "bafy".to_string(),
            integrity_hash: "abc".to_string(),
            capsule: "cap".to_string(),
            enc_key_and_nonce: "key".to_string(),
            encryption_algo: Default::default(),
            created_at: "2024-01-01T00:00:00Z".to_string(),
            author_address: "0xauthor".to_string(),
            updated_at: None,
        }
    }

    #[test]
    fn segment_allowed_respects_dataset_caveat() {
        let root_key = MacaroonKey::generate(b"decmed-test-root-key-64-bytes-padding!!");
        let mut params =
            InitialDoctorTokenParams::example_doctor_token("0xpatient", "rme-1", "0xdoc");
        params.read_datasets = vec![DatasetCategory::RAWAT_JALAN];
        params.read_functions = vec![FunctionCategory::ANAMNESIS];
        params.require_wallet_proof = false;
        let mac_str = issue_initial_token(&root_key, &params).unwrap();
        let mac = macaroon::Macaroon::deserialize(&mac_str).unwrap();
        let parsed = decmed_macaroon_auth::ParsedCaveats::from_macaroon(&mac).unwrap();
        let effective = EffectiveCapability::from_parsed(&parsed).unwrap();
        let delegation = decmed_macaroon_auth::DelegationChain::from_parsed(&parsed).unwrap();
        let verified = VerifiedDecmedToken {
            parsed,
            effective,
            delegation,
            token_id: "t".to_string(),
            is_legacy: false,
            legacy_subject: None,
            legacy_role: None,
            legacy_purpose: None,
        };

        let allowed = sample_segment(
            "0xpatient",
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ANAMNESIS,
        );
        let denied = sample_segment(
            "0xpatient",
            DatasetCategory::LABORATORIUM,
            FunctionCategory::ANAMNESIS,
        );

        assert!(segment_allowed_for_list(&verified, &allowed, "0xpatient"));
        assert!(!segment_allowed_for_list(&verified, &denied, "0xpatient"));
    }
}
