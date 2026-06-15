use std::collections::HashSet;

use chrono::{DateTime, Utc};
use decmed_rme_segment::{DatasetCategory, FunctionCategory};
use serde::{Deserialize, Serialize};

use crate::caveats::{CaveatKey, CaveatValue, ParsedCaveats};
use crate::errors::CaveatVerificationError;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum AccessMode {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct EffectiveCapability {
    pub read_datasets: HashSet<DatasetCategory>,
    pub write_datasets: HashSet<DatasetCategory>,
    pub read_functions: HashSet<FunctionCategory>,
    pub write_functions: HashSet<FunctionCategory>,
    pub expires_before: Option<DateTime<Utc>>,
    /// First `max_delegation_depth` caveat (root delegation budget).
    pub root_max_delegation_depth: Option<u32>,
    /// Strictest / remaining `max_delegation_depth` after attenuation.
    pub remaining_max_delegation_depth: Option<u32>,
    pub patient_address: Option<String>,
    pub related_rme_id: Option<String>,
    pub hospital_cid: Option<String>,
}

impl EffectiveCapability {
    pub fn from_parsed(parsed: &ParsedCaveats) -> Result<Self, CaveatVerificationError> {
        let read_datasets = intersect_datasets(parsed, CaveatKey::ReadDatasetIn)?;
        let write_datasets = intersect_datasets(parsed, CaveatKey::WriteDatasetIn)?;
        let read_functions = intersect_functions(parsed, CaveatKey::ReadFunctionIn)?;
        let write_functions = intersect_functions(parsed, CaveatKey::WriteFunctionIn)?;

        let expires_before = earliest_expiry(parsed)?;
        let (root_max_delegation_depth, remaining_max_delegation_depth) =
            delegation_depth_limits(parsed)?;
        let patient_address = single_text(parsed, CaveatKey::PatientAddress)?;
        let related_rme_id = single_text(parsed, CaveatKey::RelatedRmeId)?;
        let hospital_cid = single_text(parsed, CaveatKey::HospitalCid)?;

        Ok(Self {
            read_datasets,
            write_datasets,
            read_functions,
            write_functions,
            expires_before,
            root_max_delegation_depth,
            remaining_max_delegation_depth,
            patient_address,
            related_rme_id,
            hospital_cid,
        })
    }

    pub fn allows_dataset(&self, mode: AccessMode, category: DatasetCategory) -> bool {
        let set = match mode {
            AccessMode::Read => &self.read_datasets,
            AccessMode::Write => &self.write_datasets,
        };
        !set.is_empty() && set.contains(&category)
    }

    pub fn allows_function(&self, mode: AccessMode, category: FunctionCategory) -> bool {
        let set = match mode {
            AccessMode::Read => &self.read_functions,
            AccessMode::Write => &self.write_functions,
        };
        !set.is_empty() && set.contains(&category)
    }

    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        self.expires_before.map(|exp| now >= exp).unwrap_or(false)
    }
}

fn intersect_datasets(
    parsed: &ParsedCaveats,
    key: CaveatKey,
) -> Result<HashSet<DatasetCategory>, CaveatVerificationError> {
    let entries = parsed.all(key);
    if entries.is_empty() {
        return Ok(HashSet::new());
    }
    let mut iter = entries.iter();
    let first = iter.next().unwrap();
    let mut acc = match &first.value {
        CaveatValue::DatasetList(s) => s.clone(),
        _ => {
            return Err(CaveatVerificationError::ParseError(
                "dataset list expected".into(),
            ))
        }
    };
    for entry in iter {
        let CaveatValue::DatasetList(set) = &entry.value else {
            return Err(CaveatVerificationError::ParseError(
                "dataset list expected".into(),
            ));
        };
        acc = acc.intersection(set).copied().collect();
    }
    Ok(acc)
}

fn intersect_functions(
    parsed: &ParsedCaveats,
    key: CaveatKey,
) -> Result<HashSet<FunctionCategory>, CaveatVerificationError> {
    let entries = parsed.all(key);
    if entries.is_empty() {
        return Ok(HashSet::new());
    }
    let mut iter = entries.iter();
    let first = iter.next().unwrap();
    let mut acc = match &first.value {
        CaveatValue::FunctionList(s) => s.clone(),
        _ => {
            return Err(CaveatVerificationError::ParseError(
                "function list expected".into(),
            ))
        }
    };
    for entry in iter {
        let CaveatValue::FunctionList(set) = &entry.value else {
            return Err(CaveatVerificationError::ParseError(
                "function list expected".into(),
            ));
        };
        acc = acc.intersection(set).copied().collect();
    }
    Ok(acc)
}

fn earliest_expiry(
    parsed: &ParsedCaveats,
) -> Result<Option<DateTime<Utc>>, CaveatVerificationError> {
    let entries = parsed.all(CaveatKey::ExpiresBefore);
    if entries.is_empty() {
        return Ok(None);
    }
    let mut earliest: Option<DateTime<Utc>> = None;
    for entry in entries {
        let CaveatValue::Expiry(dt) = &entry.value else {
            return Err(CaveatVerificationError::ParseError(
                "expiry expected".into(),
            ));
        };
        earliest = Some(match earliest {
            None => *dt,
            Some(prev) => prev.min(*dt),
        });
    }
    Ok(earliest)
}

fn delegation_depth_limits(
    parsed: &ParsedCaveats,
) -> Result<(Option<u32>, Option<u32>), CaveatVerificationError> {
    let entries = parsed.all(CaveatKey::MaxDelegationDepth);
    if entries.is_empty() {
        return Ok((None, None));
    }
    let mut root: Option<u32> = None;
    let mut remaining: Option<u32> = None;
    let mut last_seen: Option<u32> = None;
    for entry in entries {
        let CaveatValue::Depth(d) = &entry.value else {
            return Err(CaveatVerificationError::ParseError("depth expected".into()));
        };
        if root.is_none() {
            root = Some(*d);
        }
        if let Some(prev) = last_seen {
            if *d > prev {
                return Err(CaveatVerificationError::DelegationDepthNotMonotonic);
            }
        }
        last_seen = Some(*d);
        remaining = Some(match remaining {
            None => *d,
            Some(s) => s.min(*d),
        });
    }
    Ok((root, remaining))
}

fn single_text(
    parsed: &ParsedCaveats,
    key: CaveatKey,
) -> Result<Option<String>, CaveatVerificationError> {
    let entries = parsed.all(key);
    if entries.is_empty() {
        return Ok(None);
    }
    if entries.len() != 1 {
        return Err(CaveatVerificationError::ParseError(format!(
            "{key:?} must appear exactly once"
        )));
    }
    match &entries[0].value {
        CaveatValue::Text(s) => Ok(Some(s.clone())),
        _ => Err(CaveatVerificationError::ParseError("text expected".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caveats::parse_caveat_line;

    fn parsed(lines: &[&str]) -> ParsedCaveats {
        ParsedCaveats {
            entries: lines
                .iter()
                .map(|l| parse_caveat_line(l).unwrap())
                .collect(),
        }
    }

    #[test]
    fn intersects_repeated_read_dataset() {
        let p = parsed(&[
            "read_dataset_in = [RAWAT_JALAN, LABORATORIUM]",
            "read_dataset_in = [LABORATORIUM]",
        ]);
        let eff = EffectiveCapability::from_parsed(&p).unwrap();
        assert_eq!(eff.read_datasets.len(), 1);
        assert!(eff.read_datasets.contains(&DatasetCategory::LABORATORIUM));
    }

    #[test]
    fn earliest_expires_before_wins() {
        let p = parsed(&[
            "expires_before = 2026-05-16T18:00:00",
            "expires_before = 2026-05-16T14:00:00",
        ]);
        let eff = EffectiveCapability::from_parsed(&p).unwrap();
        let exp = eff.expires_before.unwrap();
        assert_eq!(exp.format("%H:%M:%S").to_string(), "14:00:00");
    }

    #[test]
    fn extracts_hospital_cid() {
        let p = parsed(&["hospital_cid = hospital-001"]);
        let eff = EffectiveCapability::from_parsed(&p).unwrap();

        assert_eq!(eff.hospital_cid.as_deref(), Some("hospital-001"));
    }

    #[test]
    fn rejects_multiple_hospital_cids() {
        let p = parsed(&[
            "hospital_cid = hospital-001",
            "hospital_cid = hospital-002",
        ]);

        assert!(EffectiveCapability::from_parsed(&p).is_err());
    }
}
