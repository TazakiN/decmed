use serde_json::Value;

use crate::category::{
    DatasetCategory,
    FunctionCategory,
    APOTEK_FUNCTIONS,
    LABORATORIUM_FUNCTIONS,
    RAWAT_INAP_FUNCTIONS,
    RAWAT_JALAN_FUNCTIONS,
};
use crate::error::SegmentValidationError;
use crate::types::{ RmeSegmentData, RmeSegmentMetadata };

pub fn assert_valid_correction_request(
    correction_of_index: Option<u64>,
    correction_reason: Option<&str>
) -> Result<(), SegmentValidationError> {
    match (correction_of_index, correction_reason) {
        (None, None) => Ok(()),
        (Some(_), Some(reason)) if !reason.trim().is_empty() => Ok(()),
        (Some(_), _) => Err(SegmentValidationError::MissingField("correction_reason")),
        (None, Some(_)) =>
            Err(
                SegmentValidationError::InvalidCorrection(
                    "correction_reason requires correction_of_index"
                )
            ),
    }
}

pub fn assert_valid_correction_metadata(
    correction_of_index: Option<u64>,
    correction_reason: Option<&str>,
    updated_at: Option<u64>
) -> Result<(), SegmentValidationError> {
    assert_valid_correction_request(correction_of_index, correction_reason)?;

    match (correction_of_index, updated_at) {
        (None, None) | (Some(_), Some(_)) => Ok(()),
        (Some(_), None) => Err(SegmentValidationError::MissingField("updated_at")),
        (None, Some(_)) =>
            Err(
                SegmentValidationError::InvalidCorrection("updated_at requires correction_of_index")
            ),
    }
}

pub fn get_allowed_function_categories(dataset_category: DatasetCategory) -> Vec<FunctionCategory> {
    allowed_function_categories_slice(dataset_category).to_vec()
}

pub fn is_valid_segment_category(
    dataset_category: DatasetCategory,
    function_category: FunctionCategory
) -> bool {
    allowed_function_categories_slice(dataset_category).contains(&function_category)
}

pub fn assert_valid_segment_category(
    dataset_category: DatasetCategory,
    function_category: FunctionCategory
) -> Result<(), SegmentValidationError> {
    if is_valid_segment_category(dataset_category, function_category) {
        Ok(())
    } else {
        Err(SegmentValidationError::InvalidCategoryCombination {
            dataset_category,
            function_category,
        })
    }
}

pub fn assert_segment_pair_consistent(
    off_chain: &RmeSegmentData,
    on_chain: &RmeSegmentMetadata
) -> Result<(), SegmentValidationError> {
    if off_chain.segment_id != on_chain.segment_id {
        return Err(SegmentValidationError::InconsistentField("segment_id"));
    }
    if off_chain.related_rme_id != on_chain.related_rme_id {
        return Err(SegmentValidationError::InconsistentField("related_rme_id"));
    }
    if off_chain.dataset_category != on_chain.dataset_category {
        return Err(SegmentValidationError::InconsistentField("dataset_category"));
    }
    if off_chain.function_category != on_chain.function_category {
        return Err(SegmentValidationError::InconsistentField("function_category"));
    }
    if off_chain.correction_of_index != on_chain.correction_of_index {
        return Err(SegmentValidationError::InconsistentField("correction_of_index"));
    }
    if off_chain.correction_reason != on_chain.correction_reason {
        return Err(SegmentValidationError::InconsistentField("correction_reason"));
    }

    off_chain.validate()?;
    on_chain.validate()?;

    Ok(())
}

pub fn assert_no_plaintext_medical_fields(value: &Value) -> Result<(), SegmentValidationError> {
    const FORBIDDEN_FIELDS: [&str; 6] = [
        "payload",
        "service_date",
        "diagnose",
        "diagnosis",
        "hasil_lab",
        "resep",
    ];

    match value {
        Value::Object(map) => {
            for (key, nested) in map {
                if FORBIDDEN_FIELDS.contains(&key.as_str()) {
                    return Err(SegmentValidationError::ForbiddenOnChainField(key.clone()));
                }
                assert_no_plaintext_medical_fields(nested)?;
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_no_plaintext_medical_fields(nested)?;
            }
        }
        _ => {}
    }

    Ok(())
}

pub(crate) fn is_empty_payload(payload: &Value) -> bool {
    match payload {
        Value::Null => true,
        Value::String(value) => value.trim().is_empty(),
        Value::Array(values) => values.is_empty(),
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

fn allowed_function_categories_slice(
    dataset_category: DatasetCategory
) -> &'static [FunctionCategory] {
    match dataset_category {
        DatasetCategory::RAWAT_JALAN => &RAWAT_JALAN_FUNCTIONS,
        DatasetCategory::RAWAT_INAP => &RAWAT_INAP_FUNCTIONS,
        DatasetCategory::LABORATORIUM => &LABORATORIUM_FUNCTIONS,
        DatasetCategory::APOTEK => &APOTEK_FUNCTIONS,
    }
}
