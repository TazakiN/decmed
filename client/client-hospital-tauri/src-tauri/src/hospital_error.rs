use thiserror::Error;

#[derive(Debug, Error)]
pub enum HospitalError {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl serde::Serialize for HospitalError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            HospitalError::Anyhow(e) => {
                // Use compact display format which includes all context layers
                let full = format!("{:#}", e);
                // If the chain contains redirect codes ($<N>$), preserve them for
                // frontend auth routing in +layout.ts
                if full.contains("$<") {
                    serializer.serialize_str(&full)
                } else {
                    // For user-facing errors, show only the root cause message
                    serializer.serialize_str(&e.root_cause().to_string())
                }
            }
        }
    }
}
