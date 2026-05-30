use crate::caveats::{CaveatKey, CaveatValue, ParsedCaveats};
use crate::errors::CaveatVerificationError;

#[derive(Clone, Debug, PartialEq)]
pub struct DelegationStep {
    pub delegated_by: String,
    pub delegated_to: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct DelegationChain {
    pub root_subject: String,
    pub steps: Vec<DelegationStep>,
    pub active_subject: String,
}

impl DelegationChain {
    pub fn from_parsed(parsed: &ParsedCaveats) -> Result<Self, CaveatVerificationError> {
        let root_entries = parsed.all(CaveatKey::RootSubject);
        if root_entries.len() != 1 {
            return Err(CaveatVerificationError::MissingRequiredCaveat(
                "root_subject",
            ));
        }
        let root_subject = match &root_entries[0].value {
            CaveatValue::Text(s) => s.clone(),
            _ => {
                return Err(CaveatVerificationError::ParseError(
                    "root_subject must be text".into(),
                ))
            }
        };

        let by_entries = parsed.all(CaveatKey::DelegatedBy);
        let to_entries = parsed.all(CaveatKey::DelegatedTo);

        if by_entries.len() != to_entries.len() {
            return Err(CaveatVerificationError::InvalidDelegationChain);
        }

        let mut steps = Vec::with_capacity(by_entries.len());
        for (by_c, to_c) in by_entries.iter().zip(to_entries.iter()) {
            let delegated_by = text_value(by_c)?;
            let delegated_to = text_value(to_c)?;
            steps.push(DelegationStep {
                delegated_by,
                delegated_to,
            });
        }

        if let Some(first) = steps.first() {
            if first.delegated_by != root_subject {
                return Err(CaveatVerificationError::InvalidDelegationChain);
            }
        }

        for window in steps.windows(2) {
            if window[0].delegated_to != window[1].delegated_by {
                return Err(CaveatVerificationError::InvalidDelegationChain);
            }
        }

        let active_subject = steps
            .last()
            .map(|s| s.delegated_to.clone())
            .unwrap_or_else(|| root_subject.clone());

        Ok(Self {
            root_subject,
            steps,
            active_subject,
        })
    }

    pub fn delegation_depth(&self) -> usize {
        self.steps.len()
    }
}

fn text_value(caveat: &crate::caveats::DecmedCaveat) -> Result<String, CaveatVerificationError> {
    match &caveat.value {
        CaveatValue::Text(s) => Ok(s.clone()),
        _ => Err(CaveatVerificationError::ParseError(format!(
            "expected text for {:?}",
            caveat.key
        ))),
    }
}
