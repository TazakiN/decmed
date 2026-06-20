use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum CaveatVerificationError {
    #[error("Invalid macaroon signature")]
    InvalidMacaroonSignature,
    #[error("Missing required caveat: {0}")] MissingRequiredCaveat(&'static str),
    #[error("Patient address mismatch")]
    PatientMismatch,
    #[error("Related RME id mismatch")]
    RmeMismatch,
    #[error("Hospital CID mismatch")]
    HospitalCidMismatch,
    #[error("Token expired")]
    ExpiredToken,
    #[error("Invalid delegation chain")]
    InvalidDelegationChain,
    #[error("Delegation depth exceeded")]
    DelegationDepthExceeded,
    #[error("Wallet signature required")]
    WalletSignatureRequired,
    #[error("Invalid wallet signature")]
    InvalidWalletSignature,
    #[error("Dataset category not allowed")]
    DatasetCategoryNotAllowed,
    #[error("Function category not allowed")]
    FunctionCategoryNotAllowed,
    #[error("Delegation would expand access: {0}")] DelegationExpandsAccess(String),
    #[error("Child max_delegation_depth exceeds parent")]
    DelegationDepthNotMonotonic,
    #[error("Child expires_after parent")]
    ExpiryNotMonotonic,
    #[error("Parse error: {0}")] ParseError(String),
    #[error("Related RME id already assigned on parent token")]
    RelatedRmeAlreadyAssigned,
    #[error("Related RME id assignment requires parent without RME id")]
    RelatedRmeAssignmentRequiresEmptyParent,
    #[error("Token has been revoked")]
    RevokedToken,
}
