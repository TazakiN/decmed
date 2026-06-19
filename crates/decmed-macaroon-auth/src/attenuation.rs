use chrono::{ DateTime, Utc };
use decmed_rme_segment::{ DatasetCategory, FunctionCategory };
use macaroon::{ Format, Macaroon };

use crate::caveats::{
    add_caveat_to_macaroon,
    format_dataset_list,
    format_function_list,
    CaveatKey,
    ParsedCaveats,
};
use crate::effective::EffectiveCapability;
use crate::errors::CaveatVerificationError;

/// Parameters appended when delegating a macaroon locally (no root key required).
#[derive(Clone, Debug)]
pub struct DelegationAttenuationParams {
    pub delegated_by: String,
    pub delegated_to: String,
    pub read_datasets: Vec<DatasetCategory>,
    pub write_datasets: Vec<DatasetCategory>,
    pub read_functions: Vec<FunctionCategory>,
    pub write_functions: Vec<FunctionCategory>,
    pub expires_before: DateTime<Utc>,
    pub max_delegation_depth: u32,
    /// When set, assigns a new related RME id (only allowed if parent has none).
    pub related_rme_id: Option<String>,
}

impl DelegationAttenuationParams {
    pub fn example_lab_delegation(delegator: &str, lab_address: &str) -> Self {
        use DatasetCategory::LABORATORIUM as LabDataset;
        use FunctionCategory::{
            ADMINISTRATIVE_GENERAL,
            LABORATORIUM as LabFunction,
            PEMERIKSAAN_PENUNJANG,
        };
        Self {
            delegated_by: delegator.to_string(),
            delegated_to: lab_address.to_string(),
            read_datasets: vec![LabDataset],
            write_datasets: vec![LabDataset],
            read_functions: vec![ADMINISTRATIVE_GENERAL, PEMERIKSAAN_PENUNJANG, LabFunction],
            write_functions: vec![LabFunction],
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T14:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 0,
            related_rme_id: None,
        }
    }

    pub fn example_nurse_delegation(delegator: &str, nurse_address: &str) -> Self {
        use DatasetCategory::RAWAT_JALAN;
        use FunctionCategory::{ ADMINISTRATIVE_GENERAL, ANAMNESIS, PEMERIKSAAN_FISIK };
        Self {
            delegated_by: delegator.to_string(),
            delegated_to: nurse_address.to_string(),
            read_datasets: vec![RAWAT_JALAN],
            write_datasets: vec![RAWAT_JALAN],
            read_functions: vec![ADMINISTRATIVE_GENERAL, ANAMNESIS, PEMERIKSAAN_FISIK],
            write_functions: vec![ADMINISTRATIVE_GENERAL, ANAMNESIS, PEMERIKSAAN_FISIK],
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T15:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 0,
            related_rme_id: None,
        }
    }

    pub fn example_apotek_delegation(delegator: &str, apotek_address: &str) -> Self {
        use DatasetCategory::APOTEK;
        use FunctionCategory::{ ADMINISTRATIVE_GENERAL, DISPENSING, PERESEPAN, TERAPI };
        Self {
            delegated_by: delegator.to_string(),
            delegated_to: apotek_address.to_string(),
            read_datasets: vec![APOTEK],
            write_datasets: vec![APOTEK],
            read_functions: vec![ADMINISTRATIVE_GENERAL, TERAPI, PERESEPAN, DISPENSING],
            write_functions: vec![PERESEPAN, DISPENSING],
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T16:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 0,
            related_rme_id: None,
        }
    }

    /// Delegation preset from an admin write parent (encounter + LAB + APOTEK).
    pub fn example_admin_delegate_to_doctor(
        delegated_by: &str,
        doctor_address: &str,
        related_rme_id: &str,
        encounter: DatasetCategory
    ) -> Self {
        let datasets = crate::issuance::admin_write_datasets(encounter);
        let functions = crate::issuance::admin_write_functions(encounter);
        Self {
            delegated_by: delegated_by.to_string(),
            delegated_to: doctor_address.to_string(),
            read_datasets: datasets.clone(),
            write_datasets: datasets,
            read_functions: functions.clone(),
            write_functions: functions,
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T17:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 1,
            related_rme_id: Some(related_rme_id.to_string()),
        }
    }
}

pub fn attenuate_macaroon(
    parent_serialized: &str,
    params: &DelegationAttenuationParams
) -> Result<String, CaveatVerificationError> {
    let mut mac = Macaroon::deserialize(parent_serialized).map_err(|e|
        CaveatVerificationError::ParseError(e.to_string())
    )?;

    let parsed = ParsedCaveats::from_macaroon(&mac)?;
    if !parsed.is_decmed_token() {
        return Err(
            CaveatVerificationError::ParseError("parent must be a DecMed caveat token".into())
        );
    }

    let parent_effective = EffectiveCapability::from_parsed(&parsed)?;
    validate_attenuation(&parent_effective, params)?;

    // Attach parent token hash for revocation cascade
    let parent_token_hash = crate::revocation::hash_token(parent_serialized);
    add_caveat_to_macaroon(&mut mac, CaveatKey::ParentTokenHash, &parent_token_hash);

    add_caveat_to_macaroon(&mut mac, CaveatKey::DelegatedBy, &params.delegated_by);
    add_caveat_to_macaroon(&mut mac, CaveatKey::DelegatedTo, &params.delegated_to);
    if !params.read_datasets.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::ReadDatasetIn,
            &format_dataset_list(&params.read_datasets)
        );
    }
    if !params.write_datasets.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::WriteDatasetIn,
            &format_dataset_list(&params.write_datasets)
        );
    }
    if !params.read_functions.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::ReadFunctionIn,
            &format_function_list(&params.read_functions)
        );
    }
    if !params.write_functions.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::WriteFunctionIn,
            &format_function_list(&params.write_functions)
        );
    }
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ExpiresBefore,
        &params.expires_before.format("%Y-%m-%dT%H:%M:%S").to_string()
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::MaxDelegationDepth,
        &params.max_delegation_depth.to_string()
    );
    if let Some(rme_id) = &params.related_rme_id {
        add_caveat_to_macaroon(&mut mac, CaveatKey::RelatedRmeId, rme_id);
    }

    mac.serialize(Format::V2).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
}

fn validate_attenuation(
    parent: &EffectiveCapability,
    params: &DelegationAttenuationParams
) -> Result<(), CaveatVerificationError> {
    if let Some(parent_remaining) = parent.remaining_max_delegation_depth {
        if parent_remaining == 0 {
            return Err(CaveatVerificationError::DelegationDepthExceeded);
        }
        if params.max_delegation_depth > parent_remaining.saturating_sub(1) {
            return Err(CaveatVerificationError::DelegationDepthNotMonotonic);
        }
    }

    if let Some(parent_exp) = parent.expires_before {
        if params.expires_before > parent_exp {
            return Err(CaveatVerificationError::ExpiryNotMonotonic);
        }
    }

    validate_scope_pair("read", params.read_datasets.is_empty(), params.read_functions.is_empty())?;
    validate_scope_pair(
        "write",
        params.write_datasets.is_empty(),
        params.write_functions.is_empty()
    )?;

    if !params.read_datasets.iter().all(|d| parent.read_datasets.contains(d)) {
        return Err(CaveatVerificationError::DelegationExpandsAccess("read_dataset_in".into()));
    }
    if !params.write_datasets.iter().all(|d| parent.write_datasets.contains(d)) {
        return Err(CaveatVerificationError::DelegationExpandsAccess("write_dataset_in".into()));
    }
    if !params.read_functions.iter().all(|f| parent.read_functions.contains(f)) {
        return Err(CaveatVerificationError::DelegationExpandsAccess("read_function_in".into()));
    }
    if !params.write_functions.iter().all(|f| parent.write_functions.contains(f)) {
        return Err(CaveatVerificationError::DelegationExpandsAccess("write_function_in".into()));
    }

    match (&parent.related_rme_id, &params.related_rme_id) {
        (None, Some(_)) => {}
        (None, None) => {}
        (Some(_), None) => {}
        (Some(_), Some(_)) => {
            return Err(CaveatVerificationError::RelatedRmeAlreadyAssigned);
        }
    }

    Ok(())
}

fn validate_scope_pair(
    mode: &str,
    datasets_empty: bool,
    functions_empty: bool
) -> Result<(), CaveatVerificationError> {
    if datasets_empty != functions_empty {
        return Err(
            CaveatVerificationError::ParseError(
                format!("{mode} datasets/functions must both be empty or both be present")
            )
        );
    }
    Ok(())
}
