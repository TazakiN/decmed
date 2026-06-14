use std::str::FromStr;

use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use decmed_macaroon_auth::{
    attenuate_macaroon, CaveatKey, CaveatValue, DelegationAttenuationParams, EffectiveCapability,
    Macaroon, ParsedCaveats,
};
use decmed_rme_segment::{
    administrative_general_payload_from_fields, CreateRmeSegmentRequest, DatasetCategory,
    FunctionCategory,
};
use iota_types::{base_types::IotaAddress, crypto::IotaKeyPair};
use tauri_plugin_http::reqwest;
use umbral_pre::PublicKey;

use crate::{
    administrative_fetch::fetch_patient_administrative_data,
    current_fn,
    hospital_error::HospitalError,
    rme_segment::{build_encrypted_rme_segment, post_encrypted_rme_segment},
    types::{KeysEntry, PatientPrivateAdministrativeData},
};
#[derive(Debug, Default)]
pub struct SeedAdministrativeGeneralResult {
    pub seeded: u32,
    pub warnings: Vec<String>,
}

pub fn is_administrative_personnel_write_token(
    parent_write_token: &str,
) -> Result<bool, HospitalError> {
    let mac = Macaroon::deserialize(parent_write_token)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    let parsed = ParsedCaveats::from_macaroon(&mac)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    if !parsed.is_decmed_token() {
        return Ok(false);
    }
    let purpose = parsed
        .all(CaveatKey::Purpose)
        .first()
        .and_then(|entry| match &entry.value {
            CaveatValue::Text(value) => Some(value.as_str()),
            _ => None,
        })
        .unwrap_or_default();
    let effective = EffectiveCapability::from_parsed(&parsed)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    let has_encounter_write = effective.write_datasets.iter().any(|dataset| {
        matches!(
            dataset,
            DatasetCategory::RAWAT_JALAN | DatasetCategory::RAWAT_INAP
        )
    });
    Ok(purpose == "Update"
        && has_encounter_write
        && effective
            .write_functions
            .contains(&FunctionCategory::ADMINISTRATIVE_GENERAL))
}

fn effective_from_write_token(token: &str) -> Result<EffectiveCapability, HospitalError> {
    let mac = Macaroon::deserialize(token)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    let parsed = ParsedCaveats::from_macaroon(&mac)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))?;
    EffectiveCapability::from_parsed(&parsed)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))
}

fn seed_token_for_dataset(
    parent_write_token: &str,
    related_rme_id: &str,
    dataset: DatasetCategory,
    delegator: &str,
    expires_before: DateTime<Utc>,
) -> Result<String, HospitalError> {
    let parent = effective_from_write_token(parent_write_token)?;
    if let Some(parent_related_rme_id) = parent.related_rme_id.as_deref() {
        if parent_related_rme_id != related_rme_id {
            return Err(HospitalError::Anyhow(
                anyhow!("parent write token is bound to a different related_rme_id")
                    .context(current_fn!()),
            ));
        }
    }
    let params = DelegationAttenuationParams {
        delegated_by: delegator.to_string(),
        delegated_to: delegator.to_string(),
        read_datasets: Vec::new(),
        write_datasets: vec![dataset],
        read_functions: Vec::new(),
        write_functions: vec![FunctionCategory::ADMINISTRATIVE_GENERAL],
        expires_before,
        max_delegation_depth: 0,
        related_rme_id: parent
            .related_rme_id
            .is_none()
            .then(|| related_rme_id.to_string()),
    };
    attenuate_macaroon(parent_write_token, &params)
        .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))
}

fn admin_data_to_payload(
    admin: &PatientPrivateAdministrativeData,
) -> Result<serde_json::Value, HospitalError> {
    administrative_general_payload_from_fields(
        admin.id.clone(),
        admin.name.clone(),
        admin.birth_place.clone(),
        admin.date_of_birth.clone(),
        admin.gender.clone(),
        admin.religion.clone(),
        admin.education.clone(),
        admin.occupation.clone(),
        admin.marital_status.clone(),
    )
    .map_err(|e| HospitalError::Anyhow(anyhow!(e.to_string()).context(current_fn!())))
}

pub async fn seed_administrative_general_segments(
    parent_write_token: &str,
    parent_read_token: Option<&str>,
    related_rme_id: &str,
    patient_iota_address: &str,
    patient_pre_public_key: &str,
    author_address: &str,
    keys_entry: &KeysEntry,
    session_pin: &str,
    iota_key_pair: &IotaKeyPair,
    expires_before: DateTime<Utc>,
) -> Result<SeedAdministrativeGeneralResult, HospitalError> {
    let mut result = SeedAdministrativeGeneralResult::default();

    if !is_administrative_personnel_write_token(parent_write_token)? {
        return Ok(result);
    }

    let Some(read_token) = parent_read_token else {
        result.warnings.push(
            "Administrative segment seed skipped: parent read token required to fetch patient administrative data."
                .into(),
        );
        return Ok(result);
    };

    let parent_effective = effective_from_write_token(parent_write_token)?;
    if !parent_effective
        .write_functions
        .contains(&FunctionCategory::ADMINISTRATIVE_GENERAL)
    {
        result.warnings.push(
            "Administrative segment seed skipped: write token cannot write ADMINISTRATIVE_GENERAL."
                .into(),
        );
        return Ok(result);
    }

    let req_client = reqwest::Client::new();
    let admin_data = match fetch_patient_administrative_data(
        read_token,
        patient_iota_address,
        keys_entry,
        session_pin,
        &req_client,
    )
    .await
    {
        Ok(data) => data,
        Err(e) => {
            result.warnings.push(format!(
                "Administrative segment seed skipped: failed to fetch administrative data ({e})."
            ));
            return Ok(result);
        }
    };

    let payload = match admin_data_to_payload(&admin_data) {
        Ok(value) => value,
        Err(e) => {
            result.warnings.push(format!(
                "Administrative segment seed skipped: invalid administrative payload ({e})."
            ));
            return Ok(result);
        }
    };

    let patient_pre_public_key: PublicKey =
        crate::utils::serde_deserialize_from_base64(patient_pre_public_key.to_string())
            .context(current_fn!())?;
    let patient_address = patient_iota_address.to_string();
    let _patient_iota = IotaAddress::from_str(patient_iota_address).context(current_fn!())?;
    let service_date = Utc::now().to_rfc3339();

    let mut datasets: Vec<DatasetCategory> =
        parent_effective.write_datasets.iter().copied().collect();
    datasets.sort_by_key(|d| {
        decmed_rme_segment::ALL_DATASET_CATEGORIES
            .iter()
            .position(|c| c == d)
            .unwrap_or(usize::MAX)
    });

    for dataset in datasets {
        let segment_token = match seed_token_for_dataset(
            parent_write_token,
            related_rme_id,
            dataset,
            author_address,
            expires_before,
        ) {
            Ok(token) => token,
            Err(e) => {
                result.warnings.push(format!(
                    "Failed to prepare write token for {dataset:?} ADMINISTRATIVE_GENERAL: {e}"
                ));
                continue;
            }
        };

        let request = CreateRmeSegmentRequest {
            related_rme_id: related_rme_id.to_string(),
            patient_address: patient_address.clone(),
            patient_ref: patient_address.clone(),
            fasyankes_id: "decmed-hospital".to_string(),
            encounter_id: related_rme_id.to_string(),
            service_date: service_date.clone(),
            author_address: author_address.to_string(),
            dataset_category: dataset,
            function_category: FunctionCategory::ADMINISTRATIVE_GENERAL,
            payload: payload.clone(),
        };

        let encrypted = match build_encrypted_rme_segment(request, patient_pre_public_key.clone()) {
            Ok((_, enc)) => enc,
            Err(e) => {
                result.warnings.push(format!(
                    "Failed to encrypt ADMINISTRATIVE_GENERAL segment for {dataset:?}: {e}"
                ));
                continue;
            }
        };

        if let Err(e) = post_encrypted_rme_segment(
            &segment_token,
            &encrypted,
            patient_iota_address,
            iota_key_pair,
            None,
            &req_client,
        )
        .await
        {
            result.warnings.push(format!(
                "Failed to store ADMINISTRATIVE_GENERAL segment for {dataset:?}: {}",
                format_store_segment_error(&e)
            ));
            continue;
        }

        result.seeded += 1;
    }

    Ok(result)
}

/// Surface proxy HTTP errors in seed warnings (the `{{closure}}` suffix alone is not actionable).
fn format_store_segment_error(err: &HospitalError) -> String {
    match err {
        HospitalError::Anyhow(e) => format!("{:#}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use decmed_macaroon_auth::{
        issue_admin_personnel_token, AdminTokenKind, InitialAdminPersonnelTokenParams, MacaroonKey,
    };

    fn admin_write_token() -> String {
        let expires = chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let params = InitialAdminPersonnelTokenParams::for_grant(
            "0x1111111111111111111111111111111111111111111111111111111111111111",
            "0x7777777777777777777777777777777777777777777777777777777777777777",
            DatasetCategory::RAWAT_JALAN,
            AdminTokenKind::Write,
            expires,
        )
        .unwrap();
        let root_key = MacaroonKey::generate(b"decmed-hospital-admin-seed-test-key!!");
        issue_admin_personnel_token(&root_key, &params).unwrap()
    }

    #[test]
    fn recognizes_administrative_personnel_write_token() {
        let token = admin_write_token();
        assert!(is_administrative_personnel_write_token(&token).unwrap());
    }

    #[test]
    fn seed_token_for_dataset_is_write_only_administrative_general() {
        let parent = admin_write_token();
        let expires = chrono::DateTime::parse_from_rfc3339("2030-05-16T18:00:00+00:00")
            .unwrap()
            .with_timezone(&Utc);
        let seed = seed_token_for_dataset(
            &parent,
            "RME-2026-seed-test",
            DatasetCategory::LABORATORIUM,
            "0x7777777777777777777777777777777777777777777777777777777777777777",
            expires,
        )
        .unwrap();
        let mac = Macaroon::deserialize(&seed).unwrap();
        let parsed = ParsedCaveats::from_macaroon(&mac).unwrap();
        let effective = EffectiveCapability::from_parsed(&parsed).unwrap();
        assert!(effective.read_datasets.is_empty());
        assert!(effective.read_functions.is_empty());
        assert!(effective
            .write_datasets
            .contains(&DatasetCategory::LABORATORIUM));
        assert!(effective
            .write_functions
            .contains(&FunctionCategory::ADMINISTRATIVE_GENERAL));
        assert_eq!(
            effective.related_rme_id.as_deref(),
            Some("RME-2026-seed-test")
        );
    }
}
