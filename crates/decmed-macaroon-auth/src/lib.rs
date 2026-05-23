//! DecMed Macaroon caveat parsing, effective access, delegation, and verification.
//!
//! See `README.md` in this crate for the TA-oriented design notes.

mod attenuation;
mod caveats;
mod delegation;
mod delegation_proof;
mod effective;
mod errors;
mod issuance;
mod rme_id;
mod verify;
mod wallet_proof;

pub use attenuation::{attenuate_macaroon, DelegationAttenuationParams};
pub use caveats::{
    add_caveat_to_macaroon, caveat_line, format_dataset_list, format_function_list, parse_caveat_line,
    CaveatKey, CaveatValue, DecmedCaveat, ParsedCaveats, ProofKind,
};
pub use delegation_proof::{hash_macaroon_token, DelegationProofContext, scope_fingerprint};
pub use delegation::{DelegationChain, DelegationStep};
pub use effective::{AccessMode, EffectiveCapability};
pub use errors::CaveatVerificationError;
pub use issuance::{
    admin_all_datasets, admin_all_functions, admin_write_datasets, admin_write_functions,
    issue_admin_personnel_token, issue_initial_token, AdminTokenKind,
    InitialAdminPersonnelTokenParams, InitialDoctorTokenParams,
};
pub use rme_id::generate_related_rme_id;
pub use verify::{
    decmed_caveat_satisfier, verify_decmed_token, verify_macaroon_signature, verify_segment_access,
    SegmentAccessContext, TokenVerificationContext, VerifiedDecmedToken,
};
pub use wallet_proof::{WalletProofContext, WalletSignatureVerifier};
