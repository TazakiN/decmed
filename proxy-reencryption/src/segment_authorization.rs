use anyhow::anyhow;
use axum::http::StatusCode;
use decmed_macaroon_auth::CaveatVerificationError;
use decmed_rme_segment::{DatasetCategory, FunctionCategory};

use crate::macaroon_auth::map_caveat_error;
use crate::proxy_error::ProxyError;
use crate::types::{AuthRole, HospitalPersonnelSubRole, ReencryptionPurposeType};

/// Role and function gate for `POST /medical-record-segment`.
///
/// - `MedicalPersonnel` + `Update`: dataset must match the on-chain personnel sub-role.
/// - `AdministrativePersonnel` + `Update`: only `ADMINISTRATIVE_GENERAL`.
pub fn authorize_create_rme_segment(
    role: AuthRole,
    sub_role: Option<HospitalPersonnelSubRole>,
    purpose: ReencryptionPurposeType,
    dataset_category: DatasetCategory,
    function_category: FunctionCategory,
) -> Result<(), ProxyError> {
    if purpose != ReencryptionPurposeType::Update {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Illegal action. Invalid purpose"),
            code: StatusCode::BAD_REQUEST,
        });
    }

    match role {
        AuthRole::MedicalPersonnel => {
            let sub_role = sub_role.ok_or_else(|| ProxyError::Anyhow {
                source: anyhow!("Medical personnel sub-role is required to write RME segments"),
                code: StatusCode::FORBIDDEN,
            })?;

            if sub_role_can_write_dataset(sub_role, dataset_category) {
                Ok(())
            } else {
                Err(ProxyError::Anyhow {
                    source: anyhow!(
                        "Medical personnel sub-role is not allowed to write {dataset_category:?} dataset"
                    ),
                    code: StatusCode::FORBIDDEN,
                })
            }
        }
        AuthRole::AdministrativePersonnel => {
            if function_category == FunctionCategory::ADMINISTRATIVE_GENERAL {
                Ok(())
            } else {
                Err(ProxyError::Anyhow {
                    source: anyhow!(
                        "Administrative personnel may only create ADMINISTRATIVE_GENERAL segments"
                    ),
                    code: StatusCode::FORBIDDEN,
                })
            }
        }
        _ => Err(ProxyError::Anyhow {
            source: anyhow!("Illegal action. Invalid role"),
            code: StatusCode::UNAUTHORIZED,
        }),
    }
}

fn sub_role_can_write_dataset(
    sub_role: HospitalPersonnelSubRole,
    dataset_category: DatasetCategory,
) -> bool {
    match sub_role {
        HospitalPersonnelSubRole::Doctor | HospitalPersonnelSubRole::Nurse => matches!(
            dataset_category,
            DatasetCategory::RAWAT_JALAN | DatasetCategory::RAWAT_INAP
        ),
        HospitalPersonnelSubRole::LaboratoryStaff => {
            dataset_category == DatasetCategory::LABORATORIUM
        }
        HospitalPersonnelSubRole::Pharmacist => dataset_category == DatasetCategory::APOTEK,
    }
}

pub fn authorize_segment_hospital(
    token_hospital_cid: Option<&str>,
    segment_hospital_cid: &str,
) -> Result<(), ProxyError> {
    let token_hospital_cid = token_hospital_cid.ok_or_else(|| {
        map_caveat_error(CaveatVerificationError::MissingRequiredCaveat(
            "hospital_cid",
        ))
    })?;

    if token_hospital_cid != segment_hospital_cid {
        return Err(map_caveat_error(
            CaveatVerificationError::HospitalCidMismatch,
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use decmed_rme_segment::{DatasetCategory, FunctionCategory};

    #[test]
    fn doctor_and_nurse_can_write_rawat_jalan_and_rawat_inap() {
        assert!(authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            Some(HospitalPersonnelSubRole::Doctor),
            ReencryptionPurposeType::Update,
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ANAMNESIS
        )
        .is_ok());
        assert!(authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            Some(HospitalPersonnelSubRole::Nurse),
            ReencryptionPurposeType::Update,
            DatasetCategory::RAWAT_INAP,
            FunctionCategory::PEMERIKSAAN_FISIK
        )
        .is_ok());
    }

    #[test]
    fn doctor_and_nurse_cannot_write_laboratorium_or_apotek() {
        for sub_role in [
            HospitalPersonnelSubRole::Doctor,
            HospitalPersonnelSubRole::Nurse,
        ] {
            for dataset in [DatasetCategory::LABORATORIUM, DatasetCategory::APOTEK] {
                let err = authorize_create_rme_segment(
                    AuthRole::MedicalPersonnel,
                    Some(sub_role),
                    ReencryptionPurposeType::Update,
                    dataset,
                    FunctionCategory::LABORATORIUM,
                )
                .unwrap_err();
                assert_proxy_status(err, StatusCode::FORBIDDEN);
            }
        }
    }

    #[test]
    fn laboratory_staff_can_only_write_laboratorium() {
        assert!(authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            Some(HospitalPersonnelSubRole::LaboratoryStaff),
            ReencryptionPurposeType::Update,
            DatasetCategory::LABORATORIUM,
            FunctionCategory::LABORATORIUM
        )
        .is_ok());

        let err = authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            Some(HospitalPersonnelSubRole::LaboratoryStaff),
            ReencryptionPurposeType::Update,
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ANAMNESIS,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::FORBIDDEN);
    }

    #[test]
    fn pharmacist_can_only_write_apotek() {
        assert!(authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            Some(HospitalPersonnelSubRole::Pharmacist),
            ReencryptionPurposeType::Update,
            DatasetCategory::APOTEK,
            FunctionCategory::DISPENSING
        )
        .is_ok());

        let err = authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            Some(HospitalPersonnelSubRole::Pharmacist),
            ReencryptionPurposeType::Update,
            DatasetCategory::LABORATORIUM,
            FunctionCategory::LABORATORIUM,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::FORBIDDEN);
    }

    #[test]
    fn medical_personnel_without_sub_role_is_denied() {
        let err = authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            None,
            ReencryptionPurposeType::Update,
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ANAMNESIS,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::FORBIDDEN);
    }

    #[test]
    fn administrative_personnel_update_administrative_general_allowed() {
        assert!(authorize_create_rme_segment(
            AuthRole::AdministrativePersonnel,
            None,
            ReencryptionPurposeType::Update,
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ADMINISTRATIVE_GENERAL
        )
        .is_ok());
    }

    fn assert_proxy_status(err: ProxyError, expected: StatusCode) {
        match err {
            ProxyError::Anyhow { code, .. } => assert_eq!(code, expected),
            ProxyError::Caveat { code, .. } => {
                assert_eq!(code, expected.as_u16())
            }
            other => panic!("expected Anyhow variant, got {other:?}"),
        }
    }

    #[test]
    fn administrative_personnel_denied_clinical_function() {
        let err = authorize_create_rme_segment(
            AuthRole::AdministrativePersonnel,
            None,
            ReencryptionPurposeType::Update,
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::DIAGNOSIS,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::FORBIDDEN);
    }

    #[test]
    fn read_purpose_denied_for_segment_create() {
        let err = authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            Some(HospitalPersonnelSubRole::Doctor),
            ReencryptionPurposeType::Read,
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ADMINISTRATIVE_GENERAL,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn patient_role_denied() {
        let err = authorize_create_rme_segment(
            AuthRole::Patient,
            None,
            ReencryptionPurposeType::Update,
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ADMINISTRATIVE_GENERAL,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn matching_hospital_is_allowed() {
        assert!(authorize_segment_hospital(Some("hospital-001"), "hospital-001").is_ok());
    }

    #[test]
    fn missing_hospital_caveat_is_unauthorized() {
        let err = authorize_segment_hospital(None, "hospital-001").unwrap_err();
        assert_proxy_status(err, StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn mismatched_hospital_is_forbidden() {
        let err = authorize_segment_hospital(Some("hospital-002"), "hospital-001").unwrap_err();
        assert_proxy_status(err, StatusCode::FORBIDDEN);
    }
}
