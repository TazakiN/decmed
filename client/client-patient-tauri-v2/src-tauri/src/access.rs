use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};

use anyhow::{anyhow, Context};
use chrono::{DateTime, TimeZone, Utc};
use iota_types::{
    base_types::IotaAddress,
    crypto::{EncodeDecodeBase64, Signature},
};
use serde::Serialize;
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, State};
use tauri_plugin_http::reqwest;

use crate::{
    constants::PROXY_BASE_URL,
    current_fn,
    patient_error::PatientError,
    types::{
        AppState, CommandGetAccessLogResponse, DelegationAuditEdge,
        DelegationAuditPersonnelSummary, DelegationAuditRootGrant,
        HospitalPersonnelPublicAdministrativeData, InvokeDelegationAuditChain,
        MoveHospitalPersonnelAccessType, MovePatientAccessLog, MovePatientDelegationAuditEntry,
        MovePatientDelegationAuditEventType, ResponseStatus, SuccessResponse,
    },
    utils::{
        argon_hash, get_iota_address_from_keys_entry, get_iota_key_pair_from_keys_entry,
        parse_keys_entry, serde_deserialize_from_base64,
    },
};

#[derive(Serialize)]
struct PatientRevocationSignedPayload {
    patient_address: String,
    purpose: String,
    root_subject: String,
    delegated_by: Option<String>,
    delegated_to: Option<String>,
    related_rme_id: Option<String>,
    token_hash: Option<String>,
    parent_token_hash: Option<String>,
    expires_before: Option<String>,
    tx_digest: String,
}

const ACCESS_LOG_PAGE_SIZE: u64 = 10;
const DELEGATION_AUDIT_PAGE_SIZE: u64 = 10;

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ChainKey {
    root_subject: String,
    access_type: MoveHospitalPersonnelAccessType,
    related_rme_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct EdgeKey {
    root_subject: String,
    access_type: MoveHospitalPersonnelAccessType,
    related_rme_id: Option<String>,
    delegated_by: String,
    delegated_to: String,
    token_hash: Option<String>,
}

#[derive(Clone, Debug)]
struct EdgeState {
    delegated_by: String,
    delegated_to: String,
    depth: u8,
    token_hash: Option<String>,
    parent_token_hash: Option<String>,
    expires_at_ms: Option<u64>,
    revoked: bool,
    revoked_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct ChainState {
    edges: BTreeMap<EdgeKey, EdgeState>,
}

#[derive(Clone, Debug)]
struct RootGrantState {
    personnel: DelegationAuditPersonnelSummary,
    index: u64,
    token_hash: Option<String>,
    granted_at: Option<String>,
    expires_at: Option<String>,
    revoked: bool,
}

fn ms_to_rfc3339(ms: u64) -> Option<String> {
    Utc.timestamp_millis_opt(ms as i64)
        .single()
        .map(|dt| dt.to_rfc3339())
}

fn access_expires_at(date: &str, exp_dur_minutes: u64) -> Option<String> {
    let parsed = DateTime::parse_from_rfc3339(date).ok()?.with_timezone(&Utc);
    Some((parsed + chrono::Duration::minutes(exp_dur_minutes as i64)).to_rfc3339())
}

fn parse_expires_at_ms(value: Option<&str>) -> Result<Option<u64>, PatientError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(value)
        .map_err(|e| anyhow!(e))
        .context(current_fn!())?
        .with_timezone(&Utc);
    let millis = parsed.timestamp_millis();
    if millis < 0 {
        return Err(anyhow!("Delegation expiry is before Unix epoch")
            .context(current_fn!())
            .into());
    }
    Ok(Some(millis as u64))
}

async fn fetch_all_access_logs(
    move_call: &crate::move_call::MoveCall,
    patient_iota_address: IotaAddress,
) -> Result<Vec<MovePatientAccessLog>, PatientError> {
    let mut cursor = 0;
    let mut result = Vec::new();

    loop {
        let page = move_call
            .get_access_log(cursor, ACCESS_LOG_PAGE_SIZE, patient_iota_address)
            .await
            .context(current_fn!())?;
        if page.is_empty() {
            break;
        }
        cursor += page.len() as u64;
        result.extend(page);
    }

    Ok(result)
}

async fn fetch_all_delegation_audit_logs(
    move_call: &crate::move_call::MoveCall,
    patient_iota_address: IotaAddress,
) -> Result<Vec<MovePatientDelegationAuditEntry>, PatientError> {
    let mut cursor = 0;
    let mut result = Vec::new();

    loop {
        let page = move_call
            .get_delegation_audit_log(cursor, DELEGATION_AUDIT_PAGE_SIZE, patient_iota_address)
            .await
            .context(current_fn!())?;
        if page.is_empty() {
            break;
        }
        cursor += page.len() as u64;
        result.extend(page);
    }

    Ok(result)
}

fn fallback_personnel(address: &str) -> DelegationAuditPersonnelSummary {
    DelegationAuditPersonnelSummary {
        address: address.to_string(),
        name: None,
        hospital_name: None,
        role: None,
        sub_role: None,
    }
}

#[tauri::command]
pub async fn get_access_log(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<CommandGetAccessLogResponse>>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let patient_iota_address = {
        let patient_iota_address =
            get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;

        patient_iota_address
    };

    let access_log: Vec<MovePatientAccessLog> = fetch_all_access_logs(&state.move_call, patient_iota_address)
        .await
        .context(current_fn!())?;

    let access_log = access_log
        .into_iter()
        .map(|metadata| {
            let hospital_personnel_metadata: HospitalPersonnelPublicAdministrativeData =
                serde_deserialize_from_base64(metadata.hospital_personnel_metadata)
                    .context(current_fn!())?;

            Ok(CommandGetAccessLogResponse {
                access_data_type: metadata.access_data_type,
                access_type: metadata.access_type,
                date: metadata.date,
                exp_dur: metadata.exp_dur,
                hospital_metadata: metadata.hospital_metadata,
                hospital_personnel_address: metadata.hospital_personnel_address.to_string(),
                hospital_personnel_metadata,
                index: metadata.index,
                is_revoked: metadata.is_revoked,
                is_delegated: metadata.is_delegated,
                delegated_by_address: metadata
                    .delegated_by_address
                    .map(|address| address.to_string()),
                token_hash: metadata.token_hash,
            })
        })
        .collect::<Result<Vec<CommandGetAccessLogResponse>, PatientError>>()?;

    Ok(SuccessResponse {
        data: access_log,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn get_delegation_audit(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<Vec<InvokeDelegationAuditChain>>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;
    let patient_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;

    let access_logs = fetch_all_access_logs(&state.move_call, patient_iota_address)
        .await
        .context(current_fn!())?;
    let mut audit_entries = fetch_all_delegation_audit_logs(&state.move_call, patient_iota_address)
        .await
        .context(current_fn!())?;

    let mut personnel_cache: HashMap<String, DelegationAuditPersonnelSummary> = HashMap::new();
    let mut root_grants: HashMap<(String, MoveHospitalPersonnelAccessType), RootGrantState> =
        HashMap::new();

    for log in &access_logs {
        let address = log.hospital_personnel_address.to_string();
        let public_metadata: HospitalPersonnelPublicAdministrativeData =
            serde_deserialize_from_base64(log.hospital_personnel_metadata.clone())
                .unwrap_or(HospitalPersonnelPublicAdministrativeData { name: None });
        let summary = DelegationAuditPersonnelSummary {
            address: address.clone(),
            name: public_metadata.name,
            hospital_name: Some(log.hospital_metadata.name.clone()),
            role: None,
            sub_role: None,
        };
        personnel_cache
            .entry(address.clone())
            .or_insert_with(|| summary.clone());

        let key = (address, log.access_type);
        let should_replace = root_grants
            .get(&key)
            .map(|current| current.granted_at.as_deref().unwrap_or_default() < log.date.as_str())
            .unwrap_or(true);
        if should_replace {
            root_grants.insert(
                key,
                RootGrantState {
                    personnel: summary,
                    index: log.index,
                    token_hash: log.token_hash.clone(),
                    granted_at: Some(log.date.clone()),
                    expires_at: access_expires_at(&log.date, log.exp_dur),
                    revoked: log.is_revoked,
                },
            );
        }
    }

    for entry in &audit_entries {
        for address in [
            entry.actor_address,
            entry.root_subject,
            entry.delegated_by,
            entry.delegated_to,
        ] {
            personnel_cache
                .entry(address.to_string())
                .or_insert_with(|| fallback_personnel(&address.to_string()));
        }
    }

    let addresses = personnel_cache.keys().cloned().collect::<Vec<_>>();
    for address in addresses {
        let Ok(iota_address) = IotaAddress::from_str(&address) else {
            continue;
        };
        let Ok((public_metadata, hospital_name, role, sub_role)) = state
            .move_call
            .get_hospital_personnel_info(&iota_address, patient_iota_address)
            .await
        else {
            continue;
        };
        let public_metadata: HospitalPersonnelPublicAdministrativeData =
            serde_deserialize_from_base64(public_metadata)
                .unwrap_or(HospitalPersonnelPublicAdministrativeData { name: None });
        personnel_cache.insert(
            address.clone(),
            DelegationAuditPersonnelSummary {
                address,
                name: public_metadata.name,
                hospital_name: Some(hospital_name),
                role: Some(role),
                sub_role,
            },
        );
    }

    audit_entries.sort_by_key(|entry| entry.index);
    let mut chains: BTreeMap<ChainKey, ChainState> = BTreeMap::new();

    for entry in audit_entries {
        let root_subject = entry.root_subject.to_string();
        let delegated_by = entry.delegated_by.to_string();
        let delegated_to = entry.delegated_to.to_string();
        let chain_key = ChainKey {
            root_subject: root_subject.clone(),
            access_type: entry.access_type,
            related_rme_id: entry.related_rme_id.clone(),
        };

        match entry.event_type {
            MovePatientDelegationAuditEventType::Delegated => {
                let edge_key = EdgeKey {
                    root_subject,
                    access_type: entry.access_type,
                    related_rme_id: entry.related_rme_id,
                    delegated_by: delegated_by.clone(),
                    delegated_to: delegated_to.clone(),
                    token_hash: entry.token_hash.clone(),
                };
                chains.entry(chain_key).or_default().edges.insert(
                    edge_key,
                    EdgeState {
                        delegated_by,
                        delegated_to,
                        depth: entry.delegation_depth,
                        token_hash: entry.token_hash,
                        parent_token_hash: entry.parent_token_hash,
                        expires_at_ms: entry.expires_at_ms,
                        revoked: false,
                        revoked_at_ms: None,
                    },
                );
            }
            MovePatientDelegationAuditEventType::Revoked => {
                let matching_chain_keys = if entry.related_rme_id.is_some() {
                    vec![chain_key.clone()]
                } else {
                    let keys = chains
                        .keys()
                        .filter(|key| {
                            key.root_subject == root_subject && key.access_type == entry.access_type
                        })
                        .cloned()
                        .collect::<Vec<_>>();
                    if keys.is_empty() {
                        vec![chain_key.clone()]
                    } else {
                        keys
                    }
                };

                for revoke_chain_key in matching_chain_keys {
                    let chain = chains.entry(revoke_chain_key.clone()).or_default();
                    let mut matched = false;
                    for edge in chain.edges.values_mut() {
                        let token_matches = entry
                            .token_hash
                            .as_ref()
                            .map(|token_hash| edge.token_hash.as_ref() == Some(token_hash))
                            .unwrap_or(true);
                        if edge.delegated_by == delegated_by
                            && edge.delegated_to == delegated_to
                            && token_matches
                        {
                            edge.revoked = true;
                            edge.revoked_at_ms = Some(entry.timestamp_ms);
                            matched = true;
                        }
                    }

                    if !matched {
                        let edge_key = EdgeKey {
                            root_subject: revoke_chain_key.root_subject.clone(),
                            access_type: revoke_chain_key.access_type,
                            related_rme_id: revoke_chain_key.related_rme_id.clone(),
                            delegated_by: delegated_by.clone(),
                            delegated_to: delegated_to.clone(),
                            token_hash: entry.token_hash.clone(),
                        };
                        chain.edges.insert(
                            edge_key,
                            EdgeState {
                                delegated_by: delegated_by.clone(),
                                delegated_to: delegated_to.clone(),
                                depth: entry.delegation_depth,
                                token_hash: entry.token_hash.clone(),
                                parent_token_hash: entry.parent_token_hash.clone(),
                                expires_at_ms: entry.expires_at_ms,
                                revoked: true,
                                revoked_at_ms: Some(entry.timestamp_ms),
                            },
                        );
                    }
                }
            }
        }
    }

    for ((root_subject, access_type), _) in &root_grants {
        let has_chain = chains
            .keys()
            .any(|key| key.root_subject == *root_subject && key.access_type == *access_type);
        if !has_chain {
            chains.entry(ChainKey {
                root_subject: root_subject.clone(),
                access_type: *access_type,
                related_rme_id: None,
            })
            .or_default();
        }
    }

    let now_ms = Utc::now().timestamp_millis().max(0) as u64;
    let mut response = Vec::new();

    for (key, chain) in chains {
        let root_grant_state = root_grants
            .get(&(key.root_subject.clone(), key.access_type))
            .cloned();
        let mut edges = chain.edges.into_values().collect::<Vec<_>>();
        edges.sort_by_key(|edge| {
            (
                edge.depth,
                edge.delegated_by.clone(),
                edge.delegated_to.clone(),
            )
        });

        let rendered_edges = edges
            .iter()
            .map(|edge| DelegationAuditEdge {
                delegated_by: personnel_cache
                    .get(&edge.delegated_by)
                    .cloned()
                    .unwrap_or_else(|| fallback_personnel(&edge.delegated_by)),
                delegated_to: personnel_cache
                    .get(&edge.delegated_to)
                    .cloned()
                    .unwrap_or_else(|| fallback_personnel(&edge.delegated_to)),
                depth: edge.depth,
                token_hash: edge.token_hash.clone(),
                parent_token_hash: edge.parent_token_hash.clone(),
                expires_at: edge.expires_at_ms.and_then(ms_to_rfc3339),
                revoked: edge.revoked,
                revoked_at: edge.revoked_at_ms.and_then(ms_to_rfc3339),
            })
            .collect::<Vec<_>>();

        let root_revoked = root_grant_state
            .as_ref()
            .map(|grant| grant.revoked)
            .unwrap_or(false);
        let root_expired = root_grant_state
            .as_ref()
            .and_then(|grant| grant.expires_at.as_deref())
            .and_then(|expires_at| DateTime::parse_from_rfc3339(expires_at).ok())
            .map(|expires_at| expires_at.timestamp_millis().max(0) as u64 <= now_ms)
            .unwrap_or(false);
        let all_edges_revoked = !edges.is_empty() && edges.iter().all(|edge| edge.revoked);
        let active_edges = edges
            .iter()
            .filter(|edge| !edge.revoked)
            .collect::<Vec<_>>();
        let all_active_edges_expired = !active_edges.is_empty()
            && active_edges.iter().all(|edge| {
                edge.expires_at_ms
                    .map(|expires| expires <= now_ms)
                    .unwrap_or(false)
            });

        let status = if root_revoked || all_edges_revoked {
            "Revoked"
        } else if root_expired || all_active_edges_expired {
            "Expired"
        } else {
            "Active"
        }
        .to_string();

        response.push(InvokeDelegationAuditChain {
            root_subject: key.root_subject,
            access_type: key.access_type,
            related_rme_id: key.related_rme_id,
            root_grant: root_grant_state.map(|grant| DelegationAuditRootGrant {
                personnel: grant.personnel,
                index: grant.index,
                token_hash: grant.token_hash,
                granted_at: grant.granted_at,
                expires_at: grant.expires_at,
                revoked: grant.revoked,
            }),
            edges: rendered_edges,
            status,
        });
    }

    response.sort_by(|left, right| {
        let right_date = right
            .edges
            .first()
            .and_then(|edge| edge.expires_at.as_deref())
            .or(right.root_grant
                .as_ref()
                .and_then(|grant| grant.expires_at.as_deref()));
        let left_date = left
            .edges
            .first()
            .and_then(|edge| edge.expires_at.as_deref())
            .or(left
                .root_grant
                .as_ref()
                .and_then(|grant| grant.expires_at.as_deref()));

        right_date.cmp(&left_date)
    });

    Ok(SuccessResponse {
        data: response,
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn revoke_access(
    state: State<'_, Mutex<AppState>>,
    hospital_personnel_address: String,
    index: u64,
    purpose: String,
    root_subject: String,
    token_hash: Option<String>,
    expires_before: Option<String>,
) -> Result<SuccessResponse<()>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let pin = state
        .auth_state
        .session_pin
        .clone()
        .ok_or(anyhow!("Session PIN Not found"))
        .context(current_fn!())?;
    let patient_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
    let patient_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
    let hospital_personnel_address =
        IotaAddress::from_str(&hospital_personnel_address).context(current_fn!())?;
    let admin_personnel_id = argon_hash("admin".to_string()).context(current_fn!())?;

    // Execute the Move revoke
    let tx_digest = state
        .move_call
        .revoke_access(
            hospital_personnel_address,
            admin_personnel_id,
            index,
            patient_iota_address,
            patient_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    // Call proxy revocation endpoint after successful Move transaction
    let req_client = reqwest::Client::new();
    let proxy_url = format!("{}/revocations/patient", PROXY_BASE_URL);

    // Re-read key pair to sign the tx_digest for proxy
    let patient_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

    let signed_payload = PatientRevocationSignedPayload {
        patient_address: patient_iota_address.to_string(),
        purpose,
        root_subject,
        delegated_by: None,
        delegated_to: None,
        related_rme_id: None,
        token_hash,
        parent_token_hash: None,
        expires_before,
        tx_digest,
    };
    let canonical = serde_json::to_string(&signed_payload).context(current_fn!())?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let signature = Signature::new_secure(&intent_message, &patient_iota_key_pair);
    let signature_b64 = signature.encode_base64();

    let proxy_body = serde_json::json!({
        "patient_address": signed_payload.patient_address,
        "purpose": signed_payload.purpose,
        "root_subject": signed_payload.root_subject,
        "delegated_by": signed_payload.delegated_by,
        "delegated_to": signed_payload.delegated_to,
        "related_rme_id": signed_payload.related_rme_id,
        "token_hash": signed_payload.token_hash,
        "parent_token_hash": signed_payload.parent_token_hash,
        "expires_before": signed_payload.expires_before,
        "tx_digest": signed_payload.tx_digest,
        "signature": signature_b64,
    });

    let proxy_resp = req_client
        .post(&proxy_url)
        .json(&proxy_body)
        .send()
        .await
        .context(current_fn!())?;

    let proxy_status = proxy_resp.status();
    if !proxy_status.is_success() {
        let err_text = proxy_resp.text().await.unwrap_or_default();
        return Err(
            anyhow!("Proxy revocation failed: {proxy_status} {err_text}")
                .context(current_fn!())
                .into(),
        );
    }

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}

#[tauri::command]
pub async fn revoke_delegated_access(
    state: State<'_, Mutex<AppState>>,
    root_subject: String,
    delegated_by: String,
    delegated_to: String,
    access_type: String,
    related_rme_id: Option<String>,
    token_hash: Option<String>,
    parent_token_hash: Option<String>,
    delegation_depth: u8,
    expires_before: Option<String>,
) -> Result<SuccessResponse<()>, PatientError> {
    let state = state.lock().await;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)
        .context(current_fn!())?;

    let pin = state
        .auth_state
        .session_pin
        .clone()
        .ok_or(anyhow!("Session PIN Not found"))
        .context(current_fn!())?;
    let patient_iota_address =
        get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
    let patient_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin.clone()).context(current_fn!())?;
    let root_subject_address = IotaAddress::from_str(&root_subject).context(current_fn!())?;
    let delegated_by_address = IotaAddress::from_str(&delegated_by).context(current_fn!())?;
    let delegated_to_address = IotaAddress::from_str(&delegated_to).context(current_fn!())?;
    let admin_personnel_id = argon_hash("admin".to_string()).context(current_fn!())?;
    let expires_at_ms = parse_expires_at_ms(expires_before.as_deref())?;

    let tx_digest = state
        .move_call
        .revoke_delegated_access_by_patient(
            root_subject_address,
            delegated_by_address,
            delegated_to_address,
            admin_personnel_id,
            access_type.clone().into_bytes(),
            related_rme_id.clone(),
            token_hash.clone().unwrap_or_default(),
            parent_token_hash.clone().unwrap_or_default(),
            delegation_depth,
            expires_at_ms.unwrap_or_default(),
            patient_iota_address,
            patient_iota_key_pair,
        )
        .await
        .context(current_fn!())?;

    let req_client = reqwest::Client::new();
    let proxy_url = format!("{}/revocations/patient", PROXY_BASE_URL);

    let patient_iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, pin).context(current_fn!())?;

    let signed_payload = PatientRevocationSignedPayload {
        patient_address: patient_iota_address.to_string(),
        purpose: access_type,
        root_subject,
        delegated_by: Some(delegated_by),
        delegated_to: Some(delegated_to),
        related_rme_id,
        token_hash,
        parent_token_hash,
        expires_before,
        tx_digest,
    };
    let canonical = serde_json::to_string(&signed_payload).context(current_fn!())?;
    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let signature = Signature::new_secure(&intent_message, &patient_iota_key_pair);
    let signature_b64 = signature.encode_base64();

    let proxy_body = serde_json::json!({
        "patient_address": signed_payload.patient_address,
        "purpose": signed_payload.purpose,
        "root_subject": signed_payload.root_subject,
        "delegated_by": signed_payload.delegated_by,
        "delegated_to": signed_payload.delegated_to,
        "related_rme_id": signed_payload.related_rme_id,
        "token_hash": signed_payload.token_hash,
        "parent_token_hash": signed_payload.parent_token_hash,
        "expires_before": signed_payload.expires_before,
        "tx_digest": signed_payload.tx_digest,
        "signature": signature_b64,
    });

    let proxy_resp = req_client
        .post(&proxy_url)
        .json(&proxy_body)
        .send()
        .await
        .context(current_fn!())?;

    let proxy_status = proxy_resp.status();
    if !proxy_status.is_success() {
        let err_text = proxy_resp.text().await.unwrap_or_default();
        return Err(
            anyhow!("Proxy revocation failed: {proxy_status} {err_text}")
                .context(current_fn!())
                .into(),
        );
    }

    Ok(SuccessResponse {
        data: (),
        status: ResponseStatus::Success,
    })
}
