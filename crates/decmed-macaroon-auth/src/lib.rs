//! DecMed Macaroon caveat parsing, effective access, delegation, and verification.
//!
//! See `README.md` in this crate for the TA-oriented design notes.

mod attenuation;
mod caveats;
mod delegation;
mod delegation_proof;
mod delegation_request;
mod effective;
mod errors;
mod issuance;
mod revocation;
mod rme_id;
mod verify;
mod wallet_proof;

/// Compatibility facade for consumers that need to deserialize or verify
/// DecMed macaroons without depending on the underlying macaroon crate.
pub use macaroon::{Macaroon, MacaroonKey};

pub use attenuation::{attenuate_macaroon, DelegationAttenuationParams};
pub use caveats::{CaveatKey, CaveatValue, DecmedCaveat, ParsedCaveats};
pub use delegation::{DelegationChain, DelegationStep};
pub use delegation_proof::{hash_macaroon_token, DelegationProofContext};
pub use delegation_request::DelegationRequestProofContext;
pub use effective::{AccessMode, EffectiveCapability};
pub use errors::CaveatVerificationError;
pub use issuance::{
    admin_all_datasets, admin_all_functions, admin_write_datasets, admin_write_functions,
    issue_admin_personnel_token, AdminTokenKind, InitialAdminPersonnelTokenParams,
};
pub use revocation::{compute_revocation_keys, hash_token, token_revocation_key};
pub use rme_id::format_related_rme_id;
pub use verify::{
    verify_decmed_token, verify_macaroon_signature, verify_segment_access, SegmentAccessContext,
    TokenVerificationContext, VerifiedDecmedToken,
};
pub use wallet_proof::{WalletProofContext, WalletSignatureVerifier};
