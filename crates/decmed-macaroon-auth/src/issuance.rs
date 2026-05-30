use chrono::{DateTime, Utc};
use decmed_rme_segment::{
    get_allowed_function_categories, DatasetCategory, FunctionCategory, ALL_DATASET_CATEGORIES,
    ALL_FUNCTION_CATEGORIES,
};
use macaroon::{Format, Macaroon, MacaroonKey};
use std::collections::HashSet;

use crate::caveats::{
    add_caveat_to_macaroon, format_dataset_list, format_function_list, CaveatKey,
};
use crate::errors::CaveatVerificationError;

/// Read vs write macaroon for AdministrativePersonnel.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdminTokenKind {
    Read,
    Write,
}

/// Parameters for issuing AdministrativePersonnel dual macaroons at patient grant.
#[derive(Clone, Debug, PartialEq)]
pub struct InitialAdminPersonnelTokenParams {
    pub patient_address: String,
    pub root_subject: String,
    /// Required for write token; ignored for read token.
    pub encounter_dataset: Option<DatasetCategory>,
    pub token_kind: AdminTokenKind,
    pub read_datasets: Vec<DatasetCategory>,
    pub write_datasets: Vec<DatasetCategory>,
    pub read_functions: Vec<FunctionCategory>,
    pub write_functions: Vec<FunctionCategory>,
    pub expires_before: DateTime<Utc>,
    pub max_delegation_depth: u32,
    pub require_wallet_proof: bool,
    pub hospital_id: Option<String>,
    pub role: Option<String>,
    pub purpose: Option<String>,
}

impl InitialAdminPersonnelTokenParams {
    pub fn for_grant(
        patient_address: &str,
        admin_address: &str,
        encounter_dataset: DatasetCategory,
        token_kind: AdminTokenKind,
        expires_before: DateTime<Utc>,
    ) -> Result<Self, CaveatVerificationError> {
        if !matches!(
            encounter_dataset,
            DatasetCategory::RAWAT_JALAN | DatasetCategory::RAWAT_INAP
        ) {
            return Err(CaveatVerificationError::ParseError(
                "encounter_dataset must be RAWAT_JALAN or RAWAT_INAP".into(),
            ));
        }

        let (read_datasets, write_datasets, read_functions, write_functions) = match token_kind {
            AdminTokenKind::Read => {
                let datasets = admin_all_datasets();
                let functions = admin_all_functions();
                (datasets.clone(), datasets, functions.clone(), functions)
            }
            AdminTokenKind::Write => {
                let datasets = admin_write_datasets(encounter_dataset);
                let functions = admin_write_functions(encounter_dataset);
                (datasets.clone(), datasets, functions.clone(), functions)
            }
        };

        let purpose = match token_kind {
            AdminTokenKind::Read => "Read",
            AdminTokenKind::Write => "Update",
        };

        Ok(Self {
            patient_address: patient_address.to_string(),
            root_subject: admin_address.to_string(),
            encounter_dataset: Some(encounter_dataset),
            token_kind,
            read_datasets,
            write_datasets,
            read_functions,
            write_functions,
            expires_before,
            max_delegation_depth: 2,
            require_wallet_proof: true,
            hospital_id: None,
            role: Some("AdministrativePersonnel".into()),
            purpose: Some(purpose.into()),
        })
    }
}

pub fn admin_all_datasets() -> Vec<DatasetCategory> {
    ALL_DATASET_CATEGORIES.to_vec()
}

pub fn admin_write_datasets(encounter: DatasetCategory) -> Vec<DatasetCategory> {
    use DatasetCategory::{APOTEK, LABORATORIUM};
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
        ALL_FUNCTION_CATEGORIES
            .iter()
            .position(|c| c == f)
            .unwrap_or(usize::MAX)
    });
    functions
}

/// Parameters for issuing an initial doctor token after patient approval.
#[derive(Clone, Debug, PartialEq)]
pub struct InitialDoctorTokenParams {
    pub patient_address: String,
    pub related_rme_id: String,
    pub root_subject: String,
    pub read_datasets: Vec<DatasetCategory>,
    pub write_datasets: Vec<DatasetCategory>,
    pub read_functions: Vec<FunctionCategory>,
    pub write_functions: Vec<FunctionCategory>,
    pub expires_before: DateTime<Utc>,
    pub max_delegation_depth: u32,
    pub require_wallet_proof: bool,
    pub hospital_id: Option<String>,
    pub role: Option<String>,
    pub purpose: Option<String>,
}

impl InitialDoctorTokenParams {
    pub fn example_doctor_token(
        patient_address: &str,
        related_rme_id: &str,
        doctor_address: &str,
    ) -> Self {
        Self {
            patient_address: patient_address.to_string(),
            related_rme_id: related_rme_id.to_string(),
            root_subject: doctor_address.to_string(),
            read_datasets: ALL_DATASET_CATEGORIES.to_vec(),
            write_datasets: ALL_DATASET_CATEGORIES.to_vec(),
            read_functions: ALL_FUNCTION_CATEGORIES.to_vec(),
            write_functions: ALL_FUNCTION_CATEGORIES.to_vec(),
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 1,
            require_wallet_proof: true,
            hospital_id: None,
            role: Some("MedicalPersonnel".into()),
            purpose: None,
        }
    }

    /// Initial token for Petugas Rekam Medis after patient approval.
    pub fn example_rm_initial_token(
        patient_address: &str,
        related_rme_id: &str,
        rm_address: &str,
    ) -> Self {
        use DatasetCategory::{APOTEK, LABORATORIUM as LabDataset, RAWAT_JALAN};
        use FunctionCategory::{
            ADMINISTRATIVE_GENERAL, ANAMNESIS, DIAGNOSIS, DISPENSING, LABORATORIUM as LabFunction,
            PEMERIKSAAN_FISIK, PEMERIKSAAN_PSIKOLOGIS, PERESEPAN, TERAPI,
        };
        Self {
            patient_address: patient_address.to_string(),
            related_rme_id: related_rme_id.to_string(),
            root_subject: rm_address.to_string(),
            read_datasets: vec![RAWAT_JALAN, LabDataset, APOTEK],
            write_datasets: vec![RAWAT_JALAN, LabDataset, APOTEK],
            read_functions: vec![
                ADMINISTRATIVE_GENERAL,
                ANAMNESIS,
                PEMERIKSAAN_FISIK,
                PEMERIKSAAN_PSIKOLOGIS,
                LabFunction,
                PERESEPAN,
                DIAGNOSIS,
                TERAPI,
            ],
            write_functions: vec![
                ADMINISTRATIVE_GENERAL,
                ANAMNESIS,
                PEMERIKSAAN_FISIK,
                PEMERIKSAAN_PSIKOLOGIS,
                DIAGNOSIS,
                TERAPI,
                LabFunction,
                PERESEPAN,
                DISPENSING,
            ],
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 2,
            require_wallet_proof: true,
            hospital_id: None,
            role: Some("MedicalPersonnel".into()),
            purpose: Some("Read".into()),
        }
    }
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
    require_wallet_proof: bool,
    hospital_id: Option<&'a str>,
    role: Option<&'a str>,
    purpose: Option<&'a str>,
}

fn issue_decmed_token(
    root_key: &MacaroonKey,
    fields: DecmedTokenFields<'_>,
) -> Result<String, CaveatVerificationError> {
    let mut mac = Macaroon::create(
        Some("proxy-reencryption".into()),
        root_key,
        fields.root_subject.into(),
    )
    .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?;

    add_caveat_to_macaroon(&mut mac, CaveatKey::PatientAddress, fields.patient_address);
    if let Some(rme_id) = fields.related_rme_id {
        add_caveat_to_macaroon(&mut mac, CaveatKey::RelatedRmeId, rme_id);
    }
    add_caveat_to_macaroon(&mut mac, CaveatKey::RootSubject, fields.root_subject);
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ReadDatasetIn,
        &format_dataset_list(fields.read_datasets),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::WriteDatasetIn,
        &format_dataset_list(fields.write_datasets),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ReadFunctionIn,
        &format_function_list(fields.read_functions),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::WriteFunctionIn,
        &format_function_list(fields.write_functions),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::ExpiresBefore,
        &fields
            .expires_before
            .format("%Y-%m-%dT%H:%M:%S")
            .to_string(),
    );
    add_caveat_to_macaroon(
        &mut mac,
        CaveatKey::MaxDelegationDepth,
        &fields.max_delegation_depth.to_string(),
    );
    if fields.require_wallet_proof {
        add_caveat_to_macaroon(&mut mac, CaveatKey::ProofRequired, "wallet_signature");
    }
    if let Some(hospital_id) = fields.hospital_id {
        add_caveat_to_macaroon(&mut mac, CaveatKey::HospitalId, hospital_id);
    }
    if let Some(role) = fields.role {
        add_caveat_to_macaroon(&mut mac, CaveatKey::Role, role);
    }
    if let Some(purpose) = fields.purpose {
        add_caveat_to_macaroon(&mut mac, CaveatKey::Purpose, purpose);
    }

    mac.serialize(Format::V2)
        .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
}

pub fn issue_admin_personnel_token(
    root_key: &MacaroonKey,
    params: &InitialAdminPersonnelTokenParams,
) -> Result<String, CaveatVerificationError> {
    issue_decmed_token(
        root_key,
        DecmedTokenFields {
            patient_address: &params.patient_address,
            related_rme_id: None,
            root_subject: &params.root_subject,
            read_datasets: &params.read_datasets,
            write_datasets: &params.write_datasets,
            read_functions: &params.read_functions,
            write_functions: &params.write_functions,
            expires_before: params.expires_before,
            max_delegation_depth: params.max_delegation_depth,
            require_wallet_proof: params.require_wallet_proof,
            hospital_id: params.hospital_id.as_deref(),
            role: params.role.as_deref(),
            purpose: params.purpose.as_deref(),
        },
    )
}

pub fn issue_initial_token(
    root_key: &MacaroonKey,
    params: &InitialDoctorTokenParams,
) -> Result<String, CaveatVerificationError> {
    issue_decmed_token(
        root_key,
        DecmedTokenFields {
            patient_address: &params.patient_address,
            related_rme_id: Some(&params.related_rme_id),
            root_subject: &params.root_subject,
            read_datasets: &params.read_datasets,
            write_datasets: &params.write_datasets,
            read_functions: &params.read_functions,
            write_functions: &params.write_functions,
            expires_before: params.expires_before,
            max_delegation_depth: params.max_delegation_depth,
            require_wallet_proof: params.require_wallet_proof,
            hospital_id: params.hospital_id.as_deref(),
            role: params.role.as_deref(),
            purpose: params.purpose.as_deref(),
        },
    )
}
