use axum::http::{HeaderMap, StatusCode};
use decmed_macaroon_auth::{
    verify_segment_access, AccessMode, CaveatVerificationError, SegmentAccessContext,
    TokenVerificationContext, VerifiedDecmedToken, WalletProofContext, WalletSignatureVerifier,
};
use decmed_rme_segment::{DatasetCategory, FunctionCategory, RmeSegmentMetadata};
use serde_json::Value;
use std::collections::HashMap;

use crate::{
    macaroon_auth::{map_caveat_error, IotaWalletVerifier},
    middlewares::{WALLET_SIGNATURE_HEADER, WALLET_TIMESTAMP_HEADER},
    proxy_error::ProxyError,
    types::{ListMedicalRecordsResponse, MedicalRecordMetadataItem},
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

pub fn verify_list_wallet_proof(
    verified: &VerifiedDecmedToken,
    patient_iota_address: &str,
    headers: &HeaderMap,
) -> Result<(), ProxyError> {
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

pub fn collapse_to_active_metadata_items(
    items: Vec<MedicalRecordMetadataItem>,
) -> Vec<MedicalRecordMetadataItem> {
    let mut active_items = HashMap::new();

    for item in items {
        let key = (
            item.related_rme_id.clone(),
            item.dataset_category,
            item.function_category,
        );

        let should_replace = active_items
            .get(&key)
            .map(|current: &MedicalRecordMetadataItem| {
                item.index > current.index
                    || (item.index == current.index && item.list_index < current.list_index)
            })
            .unwrap_or(true);

        if should_replace {
            active_items.insert(key, item);
        }
    }

    let mut items = active_items.into_values().collect::<Vec<_>>();
    items.sort_by(|left, right| {
        left.list_index
            .cmp(&right.list_index)
            .then_with(|| right.index.cmp(&left.index))
    });
    items
}

pub fn active_metadata_page(
    items: Vec<MedicalRecordMetadataItem>,
    cursor: u64,
    limit: u64,
) -> ListMedicalRecordsResponse {
    let items = collapse_to_active_metadata_items(items);
    let total = items.len() as u64;
    let start = cursor.min(total);
    let end = (cursor.saturating_add(limit)).min(total);
    let page_items = items[start as usize..end as usize].to_vec();
    let next_cursor = if end < total { Some(end) } else { None };

    ListMedicalRecordsResponse {
        items: page_items,
        next_cursor,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use decmed_macaroon_auth::{
        issue_initial_token, EffectiveCapability, InitialDoctorTokenParams, Macaroon, MacaroonKey,
    };
    use decmed_rme_segment::{DatasetCategory, FunctionCategory};

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

    fn metadata_item(
        related: &str,
        dataset: DatasetCategory,
        function: FunctionCategory,
        index: u64,
        list_index: u64,
        author: &str,
    ) -> MedicalRecordMetadataItem {
        MedicalRecordMetadataItem {
            index,
            list_index,
            segment_id: format!("seg-{index}"),
            related_rme_id: related.to_string(),
            patient_address: "0xpatient".to_string(),
            dataset_category: dataset,
            function_category: function,
            ipfs_cid: "bafy".to_string(),
            created_at: format!("2024-01-0{}T00:00:00Z", index + 1),
            author_address: author.to_string(),
        }
    }

    #[test]
    fn segment_allowed_respects_dataset_caveat() {
        let root_key = MacaroonKey::generate(b"decmed-test-root-key-64-bytes-padding!!");
        let mut params =
            InitialDoctorTokenParams::example_doctor_token("0xpatient", "rme-1", "0xdoc");
        params.read_datasets = vec![DatasetCategory::RAWAT_JALAN];
        params.read_functions = vec![FunctionCategory::ANAMNESIS];
        let mac_str = issue_initial_token(&root_key, &params).unwrap();
        let mac = Macaroon::deserialize(&mac_str).unwrap();
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

        let err = verify_list_wallet_proof(&verified, "0xpatient", &HeaderMap::new()).unwrap_err();
        assert!(matches!(err, ProxyError::WalletProofChallenge { .. }));

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

    #[test]
    fn active_metadata_page_collapses_duplicate_anamnesis_before_pagination() {
        let page = active_metadata_page(
            vec![
                metadata_item(
                    "rme-1",
                    DatasetCategory::RAWAT_JALAN,
                    FunctionCategory::ANAMNESIS,
                    5,
                    0,
                    "0xdoctor",
                ),
                metadata_item(
                    "rme-2",
                    DatasetCategory::RAWAT_JALAN,
                    FunctionCategory::DIAGNOSIS,
                    4,
                    1,
                    "0xdoctor",
                ),
                metadata_item(
                    "rme-1",
                    DatasetCategory::RAWAT_JALAN,
                    FunctionCategory::ANAMNESIS,
                    2,
                    3,
                    "0xnurse",
                ),
            ],
            0,
            1,
        );

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].index, 5);
        assert_eq!(page.items[0].author_address, "0xdoctor");
        assert_eq!(page.next_cursor, Some(1));

        let page = active_metadata_page(
            vec![
                metadata_item(
                    "rme-1",
                    DatasetCategory::RAWAT_JALAN,
                    FunctionCategory::ANAMNESIS,
                    5,
                    0,
                    "0xdoctor",
                ),
                metadata_item(
                    "rme-2",
                    DatasetCategory::RAWAT_JALAN,
                    FunctionCategory::DIAGNOSIS,
                    4,
                    1,
                    "0xdoctor",
                ),
                metadata_item(
                    "rme-1",
                    DatasetCategory::RAWAT_JALAN,
                    FunctionCategory::ANAMNESIS,
                    2,
                    3,
                    "0xnurse",
                ),
            ],
            1,
            1,
        );

        assert_eq!(page.items.len(), 1);
        assert_eq!(page.items[0].index, 4);
        assert_eq!(page.next_cursor, None);
    }

    #[test]
    fn collapse_keeps_distinct_rme_dataset_and_function_items() {
        let items = collapse_to_active_metadata_items(vec![
            metadata_item(
                "rme-1",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::ANAMNESIS,
                1,
                3,
                "0xnurse",
            ),
            metadata_item(
                "rme-2",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::ANAMNESIS,
                2,
                2,
                "0xdoctor",
            ),
            metadata_item(
                "rme-1",
                DatasetCategory::RAWAT_INAP,
                FunctionCategory::ANAMNESIS,
                3,
                1,
                "0xdoctor",
            ),
            metadata_item(
                "rme-1",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::DIAGNOSIS,
                4,
                0,
                "0xdoctor",
            ),
        ]);

        assert_eq!(items.len(), 4);
        assert_eq!(
            items.iter().map(|item| item.index).collect::<Vec<_>>(),
            vec![4, 3, 2, 1]
        );
    }
}
