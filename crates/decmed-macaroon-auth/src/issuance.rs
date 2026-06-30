use chrono::{ DateTime, Utc };
use decmed_rme_segment::{
    get_allowed_function_categories,
    DatasetCategory,
    FunctionCategory,
    ALL_DATASET_CATEGORIES,
    ALL_FUNCTION_CATEGORIES,
};
use macaroon::{ Format, Macaroon, MacaroonKey };
use std::collections::HashSet;

use crate::caveats::{
    add_caveat_to_macaroon,
    format_dataset_list,
    format_function_list,
    CaveatKey,
};
use crate::errors::CaveatVerificationError;

/// Read vs update macaroon for AdministrativePersonnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminTokenKind {
    Read,
    Update,
}

/// Parameters for issuing AdministrativePersonnel dual macaroons at patient grant.
#[derive(Clone, Debug, PartialEq)]
pub struct InitialAdminPersonnelTokenParams {
    pub patient_address: String,
    pub root_subject: String,
    /// Episode id assigned to the update token for this administrative grant.
    pub related_rme_id: Option<String>,
    /// Required for update token; ignored for read token.
    pub encounter_dataset: Option<DatasetCategory>,
    pub token_kind: AdminTokenKind,
    pub read_datasets: Vec<DatasetCategory>,
    pub write_datasets: Vec<DatasetCategory>,
    pub read_functions: Vec<FunctionCategory>,
    pub write_functions: Vec<FunctionCategory>,
    pub expires_before: DateTime<Utc>,
    pub max_delegation_depth: u32,
    pub hospital_cid: Option<String>,
    pub purpose: Option<String>,
}

impl InitialAdminPersonnelTokenParams {
    pub fn for_grant(
        patient_address: &str,
        admin_address: &str,
        encounter_dataset: DatasetCategory,
        token_kind: AdminTokenKind,
        expires_before: DateTime<Utc>
    ) -> Result<Self, CaveatVerificationError> {
        if !matches!(encounter_dataset, DatasetCategory::RAWAT_JALAN | DatasetCategory::RAWAT_INAP) {
            return Err(
                CaveatVerificationError::ParseError(
                    "encounter_dataset must be RAWAT_JALAN or RAWAT_INAP".into()
                )
            );
        }

        let (read_datasets, write_datasets, read_functions, write_functions) = match token_kind {
            AdminTokenKind::Read => {
                let datasets = admin_all_datasets();
                let functions = admin_all_functions();
                (datasets, Vec::new(), functions, Vec::new())
            }
            AdminTokenKind::Update => {
                let datasets = admin_write_datasets(encounter_dataset);
                let functions = admin_write_functions(encounter_dataset);
                (Vec::new(), datasets, Vec::new(), functions)
            }
        };

        let purpose = match token_kind {
            AdminTokenKind::Read => "Read",
            AdminTokenKind::Update => "Update",
        };

        Ok(Self {
            patient_address: patient_address.to_string(),
            root_subject: admin_address.to_string(),
            related_rme_id: None,
            encounter_dataset: Some(encounter_dataset),
            token_kind,
            read_datasets,
            write_datasets,
            read_functions,
            write_functions,
            expires_before,
            max_delegation_depth: 3,
            hospital_cid: None,
            purpose: Some(purpose.into()),
        })
    }
}

pub fn admin_all_datasets() -> Vec<DatasetCategory> {
    ALL_DATASET_CATEGORIES.to_vec()
}

pub fn admin_write_datasets(encounter: DatasetCategory) -> Vec<DatasetCategory> {
    use DatasetCategory::{ APOTEK, LABORATORIUM };
    vec![encounter, LABORATORIUM, APOTEK]
}

pub fn admin_all_functions() -> Vec<FunctionCategory> {
    ALL_FUNCTION_CATEGORIES.to_vec()
}

pub fn admin_write_functions(encounter: DatasetCategory) -> Vec<FunctionCategory> {
    functions_for_datasets(&admin_write_datasets(encounter))
}

pub fn functions_for_datasets(datasets: &[DatasetCategory]) -> Vec<FunctionCategory> {
    let mut set = HashSet::new();
    for ds in datasets {
        for f in get_allowed_function_categories(*ds) {
            set.insert(f);
        }
    }
    let mut functions: Vec<_> = set.into_iter().collect();
    functions.sort_by_key(|f| {
        ALL_FUNCTION_CATEGORIES.iter()
            .position(|c| c == f)
            .unwrap_or(usize::MAX)
    });
    functions
}

struct DecmedTokenFields<'a> {
    patient_address: &'a str,
    related_rme_id: Option<&'a str>,
    root_subject: &'a str,
    read_datasets: &'a [DatasetCategory],
    write_datasets: &'a [DatasetCategory],
    read_functions: &'a [FunctionCategory],
    write_functions: &'a [FunctionCategory],
    expires_before: DateTime<Utc>,
    max_delegation_depth: u32,
    hospital_cid: Option<&'a str>,
    purpose: Option<&'a str>,
}

fn issue_decmed_token(
    root_key: &MacaroonKey,
    fields: DecmedTokenFields<'_>
) -> Result<String, CaveatVerificationError> {
    validate_scope_pair("read", fields.read_datasets.is_empty(), fields.read_functions.is_empty())?;
    validate_scope_pair(
        "write",
        fields.write_datasets.is_empty(),
        fields.write_functions.is_empty()
    )?;

    let mut mac = Macaroon::create(
        Some("proxy-reencryption".into()),
        root_key,
        fields.root_subject.into()
    ).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?;

    add_caveat_to_macaroon(&mut mac, CaveatKey::PatientAddress, fields.patient_address);
    if let Some(rme_id) = fields.related_rme_id {
        add_caveat_to_macaroon(&mut mac, CaveatKey::RelatedRmeId, rme_id);
    }
    add_caveat_to_macaroon(&mut mac, CaveatKey::RootSubject, fields.root_subject);
    let include_read_scope = fields.purpose != Some("Update");
    let include_write_scope = fields.purpose != Some("Read");
    if include_read_scope && !fields.read_datasets.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::ReadDatasetIn,
            &format_dataset_list(fields.read_datasets)
        );
    }
    if include_write_scope && !fields.write_datasets.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::WriteDatasetIn,
            &format_dataset_list(fields.write_datasets)
        );
    }
    if include_read_scope && !fields.read_functions.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::ReadFunctionIn,
            &format_function_list(fields.read_functions)
        );
    }
    if include_write_scope && !fields.write_functions.is_empty() {
        add_caveat_to_macaroon(
            &mut mac,
            CaveatKey::WriteFunctionIn,
            &format_function_list(fields.write_functions)
        );
    }
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ExpiresBefore,
        &fields.expires_before.format("%Y-%m-%dT%H:%M:%S").to_string()
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::MaxDelegationDepth,
        &fields.max_delegation_depth.to_string()
    );
    if let Some(hospital_cid) = fields.hospital_cid {
        add_caveat_to_macaroon(&mut mac, CaveatKey::HospitalCid, hospital_cid);
    }
    if let Some(purpose) = fields.purpose {
        add_caveat_to_macaroon(&mut mac, CaveatKey::Purpose, purpose);
    }

    mac.serialize(Format::V2).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
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

pub fn issue_admin_personnel_token(
    root_key: &MacaroonKey,
    params: &InitialAdminPersonnelTokenParams
) -> Result<String, CaveatVerificationError> {
    issue_decmed_token(root_key, DecmedTokenFields {
        patient_address: &params.patient_address,
        related_rme_id: match params.token_kind {
            AdminTokenKind::Read => None,
            AdminTokenKind::Update => params.related_rme_id.as_deref(),
        },
        root_subject: &params.root_subject,
        read_datasets: &params.read_datasets,
        write_datasets: &params.write_datasets,
        read_functions: &params.read_functions,
        write_functions: &params.write_functions,
        expires_before: params.expires_before,
        max_delegation_depth: params.max_delegation_depth,
        hospital_cid: params.hospital_cid.as_deref(),
        purpose: params.purpose.as_deref(),
    })
}
