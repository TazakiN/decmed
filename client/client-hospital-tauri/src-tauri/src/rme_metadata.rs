use std::collections::{BTreeMap, HashMap};

use anyhow::{anyhow, Context};
use chrono::{DateTime, Utc};
use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use serde::Deserialize;
use tauri::{async_runtime::Mutex, http::StatusCode, State};
use tauri_plugin_http::reqwest;

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    hospital_error::HospitalError,
    medical_personnel::{proxy_error_to_hospital, sign_wallet_proof_context},
    types::{
        ProxyReencryptionErrorResponse, ProxyReencryptionSuccessResponse, ResponseStatus,
        SuccessResponse,
    },
    utils::{get_iota_key_pair_from_keys_entry, parse_keys_entry},
};

#[derive(Clone, Debug, Deserialize, serde::Serialize)]
pub struct MedicalRecordMetadataFlatItem {
    pub index: u64,
    pub list_index: u64,
    pub segment_id: String,
    pub related_rme_id: String,
    pub patient_address: String,
    pub dataset_category: DatasetCategory,
    pub function_category: FunctionCategory,
    pub ipfs_cid: String,
    pub created_at: String,
    pub author_address: String,
    #[serde(default)]
    pub correction_of_index: Option<u64>,
    #[serde(default)]
    pub correction_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct ProxyListMedicalRecordsResponse {
    pub items: Vec<MedicalRecordMetadataFlatItem>,
    pub next_cursor: Option<u64>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RmeSegmentListItem {
    pub index: u64,
    pub segment_id: String,
    pub function_category: FunctionCategory,
    pub created_at: String,
    pub author_address: String,
    /// Offset from newest for `get_medical_record` query param.
    pub list_index: u64,
    pub correction_of_index: Option<u64>,
    pub correction_reason: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RmeDatasetGroup {
    pub dataset_category: DatasetCategory,
    pub segments: Vec<RmeSegmentListItem>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct RmeEncounterGroup {
    pub related_rme_id: String,
    pub created_at: String,
    pub datasets: Vec<RmeDatasetGroup>,
}

fn dataset_sort_key(category: DatasetCategory) -> u8 {
    match category {
        DatasetCategory::RAWAT_JALAN => 0,
        DatasetCategory::RAWAT_INAP => 1,
        DatasetCategory::LABORATORIUM => 2,
        DatasetCategory::APOTEK => 3,
    }
}

fn function_sort_key(category: FunctionCategory) -> String {
    format!("{category:?}")
}

fn parse_created_at(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
        .or_else(|| value.parse::<DateTime<Utc>>().ok())
}

pub fn compute_list_index(table_index: u64, max_table_index: u64) -> u64 {
    max_table_index.saturating_sub(table_index)
}

pub fn collapse_to_active_flat_items(
    items: Vec<MedicalRecordMetadataFlatItem>,
) -> Vec<MedicalRecordMetadataFlatItem> {
    let mut active_items = HashMap::new();

    for item in items {
        let key = (
            item.related_rme_id.clone(),
            item.dataset_category,
            item.function_category,
        );

        let should_replace = active_items
            .get(&key)
            .map(|current: &MedicalRecordMetadataFlatItem| {
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

pub fn group_medical_record_metadata(
    items: Vec<MedicalRecordMetadataFlatItem>,
) -> Vec<RmeEncounterGroup> {
    let items = collapse_to_active_flat_items(items);
    let mut by_rme: BTreeMap<String, Vec<MedicalRecordMetadataFlatItem>> = BTreeMap::new();
    for item in items {
        by_rme
            .entry(item.related_rme_id.clone())
            .or_default()
            .push(item);
    }

    let mut encounters: Vec<RmeEncounterGroup> = by_rme
        .into_iter()
        .map(|(related_rme_id, segments)| {
            let encounter_created_at = segments
                .iter()
                .filter_map(|s| parse_created_at(&s.created_at))
                .max()
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| {
                    segments
                        .first()
                        .map(|s| s.created_at.clone())
                        .unwrap_or_default()
                });

            let mut by_dataset: HashMap<DatasetCategory, Vec<RmeSegmentListItem>> = HashMap::new();
            for seg in segments {
                by_dataset
                    .entry(seg.dataset_category)
                    .or_default()
                    .push(RmeSegmentListItem {
                        index: seg.index,
                        segment_id: seg.segment_id.clone(),
                        function_category: seg.function_category,
                        created_at: seg.created_at.clone(),
                        author_address: seg.author_address.clone(),
                        list_index: seg.list_index,
                        correction_of_index: seg.correction_of_index,
                        correction_reason: seg.correction_reason.clone(),
                    });
            }

            let mut datasets: Vec<RmeDatasetGroup> = by_dataset
                .into_iter()
                .map(|(dataset_category, mut segments)| {
                    segments.sort_by(|a, b| {
                        let ta = parse_created_at(&a.created_at);
                        let tb = parse_created_at(&b.created_at);
                        match (ta, tb) {
                            (Some(ta), Some(tb)) => ta.cmp(&tb),
                            _ => a.created_at.cmp(&b.created_at),
                        }
                        .then_with(|| {
                            function_sort_key(a.function_category)
                                .cmp(&function_sort_key(b.function_category))
                        })
                    });
                    RmeDatasetGroup {
                        dataset_category,
                        segments,
                    }
                })
                .collect();
            datasets.sort_by_key(|d| dataset_sort_key(d.dataset_category));

            RmeEncounterGroup {
                related_rme_id,
                created_at: encounter_created_at,
                datasets,
            }
        })
        .collect();

    encounters.sort_by(|a, b| {
        let ta = parse_created_at(&a.created_at);
        let tb = parse_created_at(&b.created_at);
        match (ta, tb) {
            (Some(ta), Some(tb)) => tb.cmp(&ta),
            _ => b.created_at.cmp(&a.created_at),
        }
        .then_with(|| a.related_rme_id.cmp(&b.related_rme_id))
    });

    encounters
}

async fn request_medical_records_from_proxy(
    req_client: &reqwest::Client,
    access_token: &str,
    patient_iota_address: &str,
    cursor: u64,
    limit: u64,
    related_rme_id: Option<&str>,
    wallet_signature: Option<&str>,
    wallet_timestamp: Option<&str>,
    delegation_signature: Option<&str>,
) -> Result<
    Result<
        ProxyReencryptionSuccessResponse<ProxyListMedicalRecordsResponse>,
        ProxyReencryptionErrorResponse,
    >,
    HospitalError,
> {
    let mut url = format!(
        "{}/medical-records?patient_iota_address={}&cursor={}&limit={}",
        PROXY_BASE_URL, patient_iota_address, cursor, limit
    );
    if let Some(related_rme_id) = related_rme_id {
        url.push_str("&related_rme_id=");
        url.push_str(related_rme_id);
    }
    let mut request = req_client.get(&url).bearer_auth(access_token);
    if let Some(signature) = wallet_signature {
        request = request.header("x-decmed-wallet-signature", signature);
    }
    if let Some(timestamp) = wallet_timestamp {
        request = request.header("x-decmed-wallet-timestamp", timestamp);
    }
    if let Some(signature) = delegation_signature {
        request = request.header("x-decmed-delegation-signature", signature);
    }

    let response = request.send().await.context(current_fn!())?;
    let status = response.status();
    let body = response.bytes().await.context(current_fn!())?;

    if status != StatusCode::OK {
        let error = serde_json::from_slice::<ProxyReencryptionErrorResponse>(&body)
            .context(current_fn!())?;
        return Ok(Err(error));
    }

    let data = serde_json::from_slice::<
        ProxyReencryptionSuccessResponse<ProxyListMedicalRecordsResponse>,
    >(&body)
    .context(current_fn!())?;
    Ok(Ok(data))
}

async fn fetch_all_metadata_flat(
    req_client: &reqwest::Client,
    access_token: &str,
    patient_iota_address: &str,
    related_rme_id: Option<&str>,
    hospital_personnel_iota_key_pair: &iota_types::crypto::IotaKeyPair,
    delegation_signature: Option<&str>,
) -> Result<Vec<MedicalRecordMetadataFlatItem>, HospitalError> {
    let mut all = Vec::new();
    let mut cursor = 0u64;
    const PAGE_LIMIT: u64 = 100;

    loop {
        let res = match request_medical_records_from_proxy(
            req_client,
            access_token,
            patient_iota_address,
            cursor,
            PAGE_LIMIT,
            related_rme_id,
            None,
            None,
            delegation_signature,
        )
        .await
        .context(current_fn!())?
        {
            Ok(response) => response,
            Err(error_response) => {
                if error_response.status_code == StatusCode::UNAUTHORIZED.as_u16() {
                    if let Some(proof_context) = error_response.proof_context.clone() {
                        let wallet_signature = sign_wallet_proof_context(
                            &proof_context,
                            hospital_personnel_iota_key_pair,
                        )
                        .context(current_fn!())?;
                        match request_medical_records_from_proxy(
                            req_client,
                            access_token,
                            patient_iota_address,
                            cursor,
                            PAGE_LIMIT,
                            related_rme_id,
                            Some(&wallet_signature),
                            Some(&proof_context.timestamp),
                            delegation_signature,
                        )
                        .await
                        .context(current_fn!())?
                        {
                            Ok(response) => response,
                            Err(error_response) => {
                                return Err(proxy_error_to_hospital(error_response))
                            }
                        }
                    } else {
                        return Err(proxy_error_to_hospital(error_response));
                    }
                } else {
                    return Err(proxy_error_to_hospital(error_response));
                }
            }
        };

        let page = res.data;
        all.extend(page.items);
        match page.next_cursor {
            Some(next) => cursor = next,
            None => break,
        }
    }

    Ok(all)
}

#[tauri::command]
pub async fn get_accessible_medical_record_metadata(
    state: State<'_, Mutex<crate::types::AppState>>,
    access_token: String,
    patient_iota_address: String,
    delegation_signature: Option<String>,
) -> Result<SuccessResponse<Vec<RmeEncounterGroup>>, HospitalError> {
    let (keys_entry_secret, pin) = {
        let state = state.lock().await;
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found"))?;
        (state.keys_entry.get_secret().context(current_fn!())?, pin)
    };
    let keys_entry = parse_keys_entry(&keys_entry_secret).context(current_fn!())?;
    let req_client = reqwest::Client::new();

    let hospital_personnel_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

    let flat = fetch_all_metadata_flat(
        &req_client,
        &access_token,
        &patient_iota_address,
        None,
        &hospital_personnel_iota_key_pair,
        delegation_signature.as_deref(),
    )
    .await
    .context(current_fn!())?;

    let grouped = group_medical_record_metadata(flat);

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: grouped,
    })
}

#[tauri::command]
pub async fn get_accessible_medical_record_encounter_metadata(
    state: State<'_, Mutex<crate::types::AppState>>,
    access_token: String,
    patient_iota_address: String,
    related_rme_id: String,
    delegation_signature: Option<String>,
) -> Result<SuccessResponse<RmeEncounterGroup>, HospitalError> {
    let (keys_entry_secret, pin) = {
        let state = state.lock().await;
        let pin = state
            .auth_state
            .session_pin
            .clone()
            .ok_or(anyhow!("Session PIN not found"))?;
        (state.keys_entry.get_secret().context(current_fn!())?, pin)
    };
    let keys_entry = parse_keys_entry(&keys_entry_secret).context(current_fn!())?;
    let req_client = reqwest::Client::new();
    let hospital_personnel_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

    let flat = fetch_all_metadata_flat(
        &req_client,
        &access_token,
        &patient_iota_address,
        Some(&related_rme_id),
        &hospital_personnel_iota_key_pair,
        delegation_signature.as_deref(),
    )
    .await
    .context(current_fn!())?;

    let target_id = related_rme_id;
    let encounter = group_medical_record_metadata(flat)
        .into_iter()
        .find(|encounter| encounter.related_rme_id == target_id)
        .ok_or(anyhow!("RME tidak ditemukan atau tidak memiliki akses."))?;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: encounter,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(
        related: &str,
        dataset: DatasetCategory,
        function: FunctionCategory,
        index: u64,
        created_at: &str,
    ) -> MedicalRecordMetadataFlatItem {
        MedicalRecordMetadataFlatItem {
            index,
            list_index: compute_list_index(index, 2),
            segment_id: format!("seg-{index}"),
            related_rme_id: related.to_string(),
            patient_address: "0xpatient".to_string(),
            dataset_category: dataset,
            function_category: function,
            ipfs_cid: "bafy".to_string(),
            created_at: created_at.to_string(),
            author_address: "0xauthor".to_string(),
            correction_of_index: None,
            correction_reason: None,
        }
    }

    fn item_with_author(
        related: &str,
        dataset: DatasetCategory,
        function: FunctionCategory,
        index: u64,
        list_index: u64,
        author: &str,
    ) -> MedicalRecordMetadataFlatItem {
        MedicalRecordMetadataFlatItem {
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
            correction_of_index: None,
            correction_reason: None,
        }
    }

    #[test]
    fn group_medical_record_metadata_groups_and_sorts() {
        let items = vec![
            item(
                "rme-a",
                DatasetCategory::LABORATORIUM,
                FunctionCategory::LABORATORIUM,
                2,
                "2024-01-02T00:00:00Z",
            ),
            item(
                "rme-a",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::ANAMNESIS,
                1,
                "2024-01-01T00:00:00Z",
            ),
            item(
                "rme-b",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::DIAGNOSIS,
                0,
                "2024-02-01T00:00:00Z",
            ),
        ];

        let grouped = group_medical_record_metadata(items);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped[0].related_rme_id, "rme-b");
        assert_eq!(grouped[1].related_rme_id, "rme-a");
        assert_eq!(grouped[1].datasets.len(), 2);
        assert_eq!(
            grouped[1].datasets[0].dataset_category,
            DatasetCategory::RAWAT_JALAN
        );
        assert_eq!(grouped[1].datasets[0].segments.len(), 1);
        assert_eq!(grouped[1].datasets[0].segments[0].list_index, 1);
    }

    #[test]
    fn group_medical_record_metadata_keeps_latest_duplicate_function_slot() {
        let mut correction = item_with_author(
            "rme-a",
            DatasetCategory::RAWAT_JALAN,
            FunctionCategory::ANAMNESIS,
            5,
            0,
            "0xdoctor",
        );
        correction.correction_of_index = Some(2);
        correction.correction_reason = Some("Koreksi anamnesis".to_string());

        let grouped = group_medical_record_metadata(vec![
            correction,
            item_with_author(
                "rme-a",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::ANAMNESIS,
                2,
                3,
                "0xnurse",
            ),
        ]);

        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped[0].datasets.len(), 1);
        assert_eq!(grouped[0].datasets[0].segments.len(), 1);

        let segment = &grouped[0].datasets[0].segments[0];
        assert_eq!(segment.index, 5);
        assert_eq!(segment.list_index, 0);
        assert_eq!(segment.author_address, "0xdoctor");
        assert_eq!(segment.correction_of_index, Some(2));
        assert_eq!(
            segment.correction_reason.as_deref(),
            Some("Koreksi anamnesis")
        );
    }

    #[test]
    fn collapse_to_active_flat_items_keeps_distinct_slots() {
        let items = collapse_to_active_flat_items(vec![
            item_with_author(
                "rme-1",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::ANAMNESIS,
                1,
                3,
                "0xnurse",
            ),
            item_with_author(
                "rme-2",
                DatasetCategory::RAWAT_JALAN,
                FunctionCategory::ANAMNESIS,
                2,
                2,
                "0xdoctor",
            ),
            item_with_author(
                "rme-1",
                DatasetCategory::RAWAT_INAP,
                FunctionCategory::ANAMNESIS,
                3,
                1,
                "0xdoctor",
            ),
            item_with_author(
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
