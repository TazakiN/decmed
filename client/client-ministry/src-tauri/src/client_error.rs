use thiserror::Error;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl serde::Serialize for ClientError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match self {
            ClientError::Anyhow(e) => serializer.serialize_str(&e.root_cause().to_string()),
        }
    }
}
