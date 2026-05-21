use chrono::{DateTime, Utc};
use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use macaroon::{Format, Macaroon, MacaroonKey};

use crate::caveats::{add_caveat_to_macaroon, format_dataset_list, format_function_list, CaveatKey};
use crate::errors::CaveatVerificationError;

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
    pub role: Option<String>,
    pub purpose: Option<String>,
}

impl InitialDoctorTokenParams {
    pub fn example_doctor_token(
        patient_address: &str,
        related_rme_id: &str,
        doctor_address: &str,
    ) -> Self {
        use DatasetCategory::*;
        use FunctionCategory::*;
        Self {
            patient_address: patient_address.to_string(),
            related_rme_id: related_rme_id.to_string(),
            root_subject: doctor_address.to_string(),
            read_datasets: vec![RAWAT_JALAN, RAWAT_INAP, LABORATORIUM, APOTEK],
            write_datasets: vec![RAWAT_JALAN, RAWAT_INAP, LABORATORIUM, APOTEK],
            read_functions: vec![
                ANAMNESIS,
                PEMERIKSAAN_FISIK,
                DIAGNOSIS,
                TERAPI,
                PERMINTAAN_PEMERIKSAAN,
                HASIL_PEMERIKSAAN,
                DATA_RESEP_DAN_OBAT,
            ],
            write_functions: vec![
                ANAMNESIS,
                PEMERIKSAAN_FISIK,
                DIAGNOSIS,
                TERAPI,
                PERMINTAAN_PEMERIKSAAN,
                HASIL_PEMERIKSAAN,
            ],
            expires_before: DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
                .unwrap()
                .with_timezone(&Utc),
            max_delegation_depth: 1,
            require_wallet_proof: true,
            role: Some("MedicalPersonnel".into()),
            purpose: None,
        }
    }
}

pub fn issue_initial_token(
    root_key: &MacaroonKey,
    params: &InitialDoctorTokenParams,
) -> Result<String, CaveatVerificationError> {
    let mut mac = Macaroon::create(
        Some("proxy-reencryption".into()),
        root_key,
        params.root_subject.clone().into(),
    )
    .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?;

    add_caveat_to_macaroon(&mut mac, CaveatKey::PatientAddress, &params.patient_address);
    add_caveat_to_macaroon(&mut mac, CaveatKey::RelatedRmeId, &params.related_rme_id);
    add_caveat_to_macaroon(&mut mac, CaveatKey::RootSubject, &params.root_subject);
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
    if let Some(role) = &params.role {
        add_caveat_to_macaroon(&mut mac, CaveatKey::Role, role);
    }
    if let Some(purpose) = &params.purpose {
        add_caveat_to_macaroon(&mut mac, CaveatKey::Purpose, purpose);
    }

    mac.serialize(Format::V2)
        .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))
}
