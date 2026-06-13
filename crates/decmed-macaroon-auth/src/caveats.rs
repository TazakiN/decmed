use std::collections::HashSet;

use chrono::{DateTime, Utc};
use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use macaroon::{Caveat, Macaroon};

use crate::errors::CaveatVerificationError;

/// Supported DecMed caveat keys (first-party predicates).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaveatKey {
    PatientAddress,
    RelatedRmeId,
    RootSubject,
    DelegatedBy,
    DelegatedTo,
    ReadDatasetIn,
    WriteDatasetIn,
    ReadFunctionIn,
    WriteFunctionIn,
    ExpiresBefore,
    MaxDelegationDepth,
    // Legacy compatibility only; wallet proof is mandatory for all DecMed tokens.
    ProofRequired,
    HospitalId,
    ParentTokenHash,
    // Legacy coarse-grained caveats (still parsed for migration)
    Role,
    Purpose,
    Subject,
    Time,
    HolderAddress,
}

impl CaveatKey {
    pub fn from_predicate_key(key: &str) -> Option<Self> {
        match key.trim() {
            "patient_address" => Some(Self::PatientAddress),
            "related_rme_id" => Some(Self::RelatedRmeId),
            "root_subject" => Some(Self::RootSubject),
            "delegated_by" => Some(Self::DelegatedBy),
            "delegated_to" => Some(Self::DelegatedTo),
            "read_dataset_in" => Some(Self::ReadDatasetIn),
            "write_dataset_in" => Some(Self::WriteDatasetIn),
            "read_function_in" => Some(Self::ReadFunctionIn),
            "write_function_in" => Some(Self::WriteFunctionIn),
            "expires_before" => Some(Self::ExpiresBefore),
            "max_delegation_depth" => Some(Self::MaxDelegationDepth),
            "proof_required" => Some(Self::ProofRequired),
            "hospital_id" => Some(Self::HospitalId),
            "parent_token_hash" => Some(Self::ParentTokenHash),
            "role" => Some(Self::Role),
            "purpose" => Some(Self::Purpose),
            "subject" => Some(Self::Subject),
            "time" => Some(Self::Time),
            "holder_address" => Some(Self::HolderAddress),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub enum CaveatValue {
    Text(String),
    DatasetList(HashSet<DatasetCategory>),
    FunctionList(HashSet<FunctionCategory>),
    Expiry(DateTime<Utc>),
    Depth(u32),
}

#[derive(Clone, Debug)]
pub struct DecmedCaveat {
    pub key: CaveatKey,
    pub value: CaveatValue,
    pub raw: String,
}

#[derive(Clone, Debug, Default)]
pub struct ParsedCaveats {
    pub entries: Vec<DecmedCaveat>,
}

impl ParsedCaveats {
    pub fn from_macaroon(mac: &Macaroon) -> Result<Self, CaveatVerificationError> {
        let mut entries = Vec::new();
        for caveat in mac.first_party_caveats() {
            if let Caveat::FirstParty(fp) = caveat {
                let raw = String::from_utf8(fp.predicate().0.clone())
                    .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?;
                entries.push(parse_caveat_line(&raw)?);
            }
        }
        Ok(Self { entries })
    }

    pub fn all(&self, key: CaveatKey) -> Vec<&DecmedCaveat> {
        self.entries.iter().filter(|c| c.key == key).collect()
    }

    pub fn is_decmed_token(&self) -> bool {
        self.all(CaveatKey::PatientAddress).len() == 1
    }
}

pub fn parse_caveat_line(raw: &str) -> Result<DecmedCaveat, CaveatVerificationError> {
    let raw = raw.trim();
    let (key_str, value_str) = raw
        .split_once('=')
        .ok_or_else(|| CaveatVerificationError::ParseError(format!("invalid caveat: {raw}")))?;
    let key = CaveatKey::from_predicate_key(key_str).ok_or_else(|| {
        CaveatVerificationError::ParseError(format!("unknown caveat key: {key_str}"))
    })?;

    if key == CaveatKey::HolderAddress {
        return Err(CaveatVerificationError::HolderAddressForbidden);
    }

    let value = parse_value(key, value_str.trim())?;
    Ok(DecmedCaveat {
        key,
        value,
        raw: raw.to_string(),
    })
}

fn parse_value(key: CaveatKey, value_str: &str) -> Result<CaveatValue, CaveatVerificationError> {
    match key {
        CaveatKey::ReadDatasetIn | CaveatKey::WriteDatasetIn => Ok(CaveatValue::DatasetList(
            parse_bracket_list(value_str, parse_dataset)?,
        )),
        CaveatKey::ReadFunctionIn | CaveatKey::WriteFunctionIn => Ok(CaveatValue::FunctionList(
            parse_bracket_list(value_str, parse_function)?,
        )),
        CaveatKey::ExpiresBefore => {
            let dt = DateTime::parse_from_rfc3339(value_str)
                .or_else(|_| {
                    chrono::NaiveDateTime::parse_from_str(value_str, "%Y-%m-%dT%H:%M:%S")
                        .map(|ndt| ndt.and_utc().fixed_offset())
                })
                .map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?
                .with_timezone(&Utc);
            Ok(CaveatValue::Expiry(dt))
        }
        CaveatKey::MaxDelegationDepth => {
            let depth: u32 = value_str.parse().map_err(|e| {
                CaveatVerificationError::ParseError(format!("max_delegation_depth: {e}"))
            })?;
            Ok(CaveatValue::Depth(depth))
        }
        CaveatKey::ProofRequired => {
            if value_str != "wallet_signature" {
                return Err(CaveatVerificationError::UnsupportedProofRequirement(
                    value_str.to_string(),
                ));
            }
            // Compatibility only: wallet proof is now mandatory for every DecMed token.
            Ok(CaveatValue::Text(value_str.to_string()))
        }
        CaveatKey::Time => Ok(CaveatValue::Text(value_str.to_string())),
        _ => Ok(CaveatValue::Text(value_str.to_string())),
    }
}

fn parse_bracket_list<T, E, F>(
    value_str: &str,
    mut parse_item: F,
) -> Result<HashSet<T>, CaveatVerificationError>
where
    T: Eq + std::hash::Hash,
    E: std::error::Error,
    F: FnMut(&str) -> Result<T, E>,
{
    let inner = value_str
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| {
            CaveatVerificationError::ParseError(format!("expected bracket list: {value_str}"))
        })?;
    let mut set = HashSet::new();
    for part in inner.split(',') {
        let item = part.trim();
        if item.is_empty() {
            continue;
        }
        set.insert(
            parse_item(item).map_err(|e| CaveatVerificationError::ParseError(e.to_string()))?,
        );
    }
    if set.is_empty() {
        return Err(CaveatVerificationError::ParseError(
            "empty category list".to_string(),
        ));
    }
    Ok(set)
}

fn parse_dataset(name: &str) -> Result<DatasetCategory, serde_json::Error> {
    let json = format!("\"{name}\"");
    serde_json::from_str(&json)
}

fn parse_function(name: &str) -> Result<FunctionCategory, serde_json::Error> {
    let json = format!("\"{name}\"");
    serde_json::from_str(&json)
}

pub fn format_dataset_list(categories: &[DatasetCategory]) -> String {
    let names: Vec<String> = categories
        .iter()
        .map(|c| {
            serde_json::to_string(c)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string()
        })
        .collect();
    format!("[{}]", names.join(", "))
}

pub fn format_function_list(categories: &[FunctionCategory]) -> String {
    let names: Vec<String> = categories
        .iter()
        .map(|c| {
            serde_json::to_string(c)
                .unwrap_or_default()
                .trim_matches('"')
                .to_string()
        })
        .collect();
    format!("[{}]", names.join(", "))
}

pub fn caveat_line(key: CaveatKey, value: &str) -> String {
    let key_name = match key {
        CaveatKey::PatientAddress => "patient_address",
        CaveatKey::RelatedRmeId => "related_rme_id",
        CaveatKey::RootSubject => "root_subject",
        CaveatKey::DelegatedBy => "delegated_by",
        CaveatKey::DelegatedTo => "delegated_to",
        CaveatKey::ReadDatasetIn => "read_dataset_in",
        CaveatKey::WriteDatasetIn => "write_dataset_in",
        CaveatKey::ReadFunctionIn => "read_function_in",
        CaveatKey::WriteFunctionIn => "write_function_in",
        CaveatKey::ExpiresBefore => "expires_before",
        CaveatKey::MaxDelegationDepth => "max_delegation_depth",
        CaveatKey::ProofRequired => "proof_required",
        CaveatKey::HospitalId => "hospital_id",
        CaveatKey::Role => "role",
        CaveatKey::Purpose => "purpose",
        CaveatKey::ParentTokenHash => "parent_token_hash",
        CaveatKey::Subject => "subject",
        CaveatKey::Time => "time",
        CaveatKey::HolderAddress => "holder_address",
    };
    if key == CaveatKey::Time {
        format!("{key_name} < {value}")
    } else {
        format!("{key_name} = {value}")
    }
}

pub fn add_caveat_to_macaroon(mac: &mut Macaroon, key: CaveatKey, value: &str) {
    mac.add_first_party_caveat(caveat_line(key, value).into());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_repeated_read_dataset_as_separate_entries() {
        let a = parse_caveat_line("read_dataset_in = [RAWAT_JALAN, LABORATORIUM]").unwrap();
        let b = parse_caveat_line("read_dataset_in = [LABORATORIUM]").unwrap();
        assert_eq!(a.key, CaveatKey::ReadDatasetIn);
        assert_eq!(b.key, CaveatKey::ReadDatasetIn);
    }

    #[test]
    fn rejects_holder_address() {
        assert!(matches!(
            parse_caveat_line("holder_address = 0xABC"),
            Err(CaveatVerificationError::HolderAddressForbidden)
        ));
    }
}
