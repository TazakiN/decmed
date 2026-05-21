use chrono::{DateTime, Utc};
use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use macaroon::{Format, Macaroon};

use crate::caveats::{
    add_caveat_to_macaroon, format_dataset_list, format_function_list, ParsedCaveats, CaveatKey,
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
    pub require_wallet_proof: bool,
}

impl DelegationAttenuationParams {
    pub fn example_lab_delegation(delegated_by: &str, lab_address: &str) -> Self {
        use DatasetCategory::LABORATORIUM;
        use FunctionCategory::{HASIL_PEMERIKSAAN, PERMINTAAN_PEMERIKSAAN};
        Self {
            delegated_by: delegated_by.to_string(),
            delegated_to: lab_address.to_string(),
            read_datasets: vec![LABORATORIUM],
            write_datasets: vec![LABORATORIUM],
            read_functions: vec![PERMINTAAN_PEMERIKSAAN],
            write_functions: vec![HASIL_PEMERIKSAAN],
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T14:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 0,
            require_wallet_proof: true,
        }
    }
}

pub fn attenuate_macaroon(
    parent_serialized: &str,
    params: &DelegationAttenuationParams,
) -> Result<String, CaveatVerificationError> {
    let mut mac = Macaroon::deserialize(parent_serialized)
        .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?;

    let parsed = ParsedCaveats::from_macaroon(&mac)?;
    if !parsed.is_decmed_token() {
        return Err(CaveatVerificationError::ParseError(
            "parent must be a DecMed caveat token".into(),
        ));
    }

    let parent_effective = EffectiveCapability::from_parsed(&parsed)?;
    validate_attenuation(&parent_effective, params)?;

    add_caveat_to_macaroon(&mut mac, CaveatKey::DelegatedBy, &params.delegated_by);
    add_caveat_to_macaroon(&mut mac, CaveatKey::DelegatedTo, &params.delegated_to);
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ReadDatasetIn,
        &format_dataset_list(&params.read_datasets),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::WriteDatasetIn,
        &format_dataset_list(&params.write_datasets),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ReadFunctionIn,
        &format_function_list(&params.read_functions),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::WriteFunctionIn,
        &format_function_list(&params.write_functions),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ExpiresBefore,
        &params.expires_before.format("%Y-%m-%dT%H:%M:%S").to_string(),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::MaxDelegationDepth,
        &params.max_delegation_depth.to_string(),
    );
    if params.require_wallet_proof {
        add_caveat_to_macaroon(&mut mac, CaveatKey::ProofRequired, "wallet_signature");
    }

    mac.serialize(Format::V2)
        .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
}

fn validate_attenuation(
    parent: &EffectiveCapability,
    params: &DelegationAttenuationParams,
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

    if !params.read_datasets.iter().all(|d| parent.read_datasets.contains(d)) {
        return Err(CaveatVerificationError::DelegationExpandsAccess(
            "read_dataset_in".into(),
        ));
    }
    if !params
        .write_datasets
        .iter()
        .all(|d| parent.write_datasets.contains(d))
    {
        return Err(CaveatVerificationError::DelegationExpandsAccess(
            "write_dataset_in".into(),
        ));
    }
    if !params
        .read_functions
        .iter()
        .all(|f| parent.read_functions.contains(f))
    {
        return Err(CaveatVerificationError::DelegationExpandsAccess(
            "read_function_in".into(),
        ));
    }
    let allowed_write_functions: std::collections::HashSet<_> = parent
        .write_functions
        .iter()
        .chain(parent.read_functions.iter())
        .copied()
        .collect();
    if !params
        .write_functions
        .iter()
        .all(|f| allowed_write_functions.contains(f))
    {
        return Err(CaveatVerificationError::DelegationExpandsAccess(
            "write_function_in".into(),
        ));
    }

    Ok(())
}
