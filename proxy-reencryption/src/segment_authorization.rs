use anyhow::anyhow;
use axum::http::StatusCode;
use decmed_macaroon_auth::CaveatVerificationError;
use decmed_rme_segment::FunctionCategory;

use crate::macaroon_auth::map_caveat_error;
use crate::proxy_error::ProxyError;
use crate::types::{AuthRole, ReencryptionPurposeType};

/// Role and function gate for `POST /medical-record-segment`.
///
/// - `MedicalPersonnel` + `Update`: any function allowed by DecMed token verification.
/// - `AdministrativePersonnel` + `Update`: only `ADMINISTRATIVE_GENERAL`.
pub fn authorize_create_rme_segment(
    role: AuthRole,
    purpose: ReencryptionPurposeType,
    function_category: FunctionCategory,
) -> Result<(), ProxyError> {
    if purpose != ReencryptionPurposeType::Update {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Illegal action. Invalid purpose"),
            code: StatusCode::BAD_REQUEST,
        });
    }

    match role {
        AuthRole::MedicalPersonnel => Ok(()),
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
    use decmed_rme_segment::FunctionCategory;

    #[test]
    fn medical_personnel_update_any_function_allowed_at_role_gate() {
        assert!(authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            ReencryptionPurposeType::Update,
            FunctionCategory::ANAMNESIS,
        )
        .is_ok());
    }

    #[test]
    fn administrative_personnel_update_administrative_general_allowed() {
        assert!(authorize_create_rme_segment(
            AuthRole::AdministrativePersonnel,
            ReencryptionPurposeType::Update,
            FunctionCategory::ADMINISTRATIVE_GENERAL,
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
            ReencryptionPurposeType::Update,
            FunctionCategory::DIAGNOSIS,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::FORBIDDEN);
    }

    #[test]
    fn read_purpose_denied_for_segment_create() {
        let err = authorize_create_rme_segment(
            AuthRole::MedicalPersonnel,
            ReencryptionPurposeType::Read,
            FunctionCategory::ADMINISTRATIVE_GENERAL,
        )
        .unwrap_err();
        assert_proxy_status(err, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn patient_role_denied() {
        let err = authorize_create_rme_segment(
            AuthRole::Patient,
            ReencryptionPurposeType::Update,
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
