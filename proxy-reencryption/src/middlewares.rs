use std::sync::Arc;

use crate::{
    macaroon_auth::map_caveat_error,
    proxy_error::{ProxyError, ResultExt},
    types::{AppState, AuthRole, CurrentUser, ReencryptionPurposeType},
    utils::Utils,
};
use anyhow::anyhow;
use axum::{
    extract::{Request, State},
    http::{self, StatusCode},
    middleware::Next,
    response::Response,
};
use decmed_macaroon_auth::{
    verify_macaroon_signature, DelegationChain, EffectiveCapability, ParsedCaveats,
    VerifiedDecmedToken,
};

pub const WALLET_SIGNATURE_HEADER: &str = "x-decmed-wallet-signature";

pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ProxyError> {
    let authorization_header = request
        .headers()
        .get(http::header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok());

    let bearer_token = Utils::decode_authorization_header(authorization_header)?;

    let mac = macaroon::Macaroon::deserialize(&bearer_token)
        .map_err(|_| anyhow!("Invalid access token format"))
        .code(StatusCode::UNAUTHORIZED)?;

    let root_key = macaroon::MacaroonKey::generate(&state.macaroon_root_key);

    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(map_caveat_error)?;

    if parsed.is_decmed_token() {
        verify_macaroon_signature(&mac, &root_key).map_err(map_caveat_error)?;

        let effective = EffectiveCapability::from_parsed(&parsed).map_err(map_caveat_error)?;
        let delegation = DelegationChain::from_parsed(&parsed).map_err(map_caveat_error)?;

        let (role, purpose) = legacy_role_purpose_from_parsed(&parsed)?;

        let verified = VerifiedDecmedToken {
            parsed,
            effective,
            delegation: delegation.clone(),
            token_id: String::from_utf8(mac.identifier().0.clone()).unwrap_or_default(),
            is_legacy: false,
            legacy_subject: None,
            legacy_role: None,
            legacy_purpose: None,
        };

        let current_user = CurrentUser {
            iota_address: delegation.active_subject,
            purpose,
            role,
            decmed_token: Some(verified),
            bearer_token: bearer_token.clone(),
        };
        request.extensions_mut().insert(current_user);
        return Ok(next.run(request).await);
    }

    // Legacy coarse-grained macaroon flow
    let mut subject = String::new();
    let mut role_str = String::new();
    let mut purpose_str = String::new();

    for caveat in mac.first_party_caveats() {
        if let macaroon::Caveat::FirstParty(fp) = caveat {
            if let Ok(pred) = String::from_utf8(fp.predicate().0) {
                if let Some(s) = pred.strip_prefix("subject = ") {
                    subject = s.to_string();
                } else if let Some(r) = pred.strip_prefix("role = ") {
                    role_str = r.to_string();
                } else if let Some(p) = pred.strip_prefix("purpose = ") {
                    purpose_str = p.to_string();
                }
            }
        }
    }

    if subject.is_empty() || role_str.is_empty() || purpose_str.is_empty() {
        return Err(ProxyError::Anyhow {
            source: anyhow!("Missing required caveats in token"),
            code: StatusCode::UNAUTHORIZED,
        });
    }

    let mut verifier = macaroon::Verifier::default();
    verifier.satisfy_exact(format!("subject = {}", subject).into());
    verifier.satisfy_exact(format!("role = {}", role_str).into());
    verifier.satisfy_exact(format!("purpose = {}", purpose_str).into());

    verifier.satisfy_general(|pred| {
        if let Ok(pred_str) = String::from_utf8(pred.0.to_vec()) {
            if let Some(time_str) = pred_str.strip_prefix("time < ") {
                if let Ok(exp_time) = time_str.parse::<u64>() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::SystemTime::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    return now < exp_time;
                }
            }
        }
        false
    });

    verifier
        .verify(&mac, &root_key, Default::default())
        .map_err(|e| anyhow!("Token verification failed: {:?}", e))
        .code(StatusCode::UNAUTHORIZED)?;

    let role = match role_str.as_str() {
        "AdministrativePersonnel" => AuthRole::AdministrativePersonnel,
        "MedicalPersonnel" => AuthRole::MedicalPersonnel,
        "Patient" => AuthRole::Patient,
        _ => {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Invalid role in token"),
                code: StatusCode::UNAUTHORIZED,
            })
        }
    };

    let purpose = match purpose_str.as_str() {
        "Read" => ReencryptionPurposeType::Read,
        "Update" => ReencryptionPurposeType::Update,
        _ => {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Invalid purpose in token"),
                code: StatusCode::UNAUTHORIZED,
            })
        }
    };

    let current_user = CurrentUser {
        iota_address: subject,
        purpose,
        role,
        decmed_token: None,
        bearer_token: bearer_token.clone(),
    };
    request.extensions_mut().insert(current_user);

    Ok(next.run(request).await)
}

fn legacy_role_purpose_from_parsed(
    parsed: &ParsedCaveats,
) -> Result<(AuthRole, ReencryptionPurposeType), ProxyError> {
    use decmed_macaroon_auth::{CaveatKey, CaveatValue};

    let role_caveats = parsed.all(CaveatKey::Role);
    let purpose_caveats = parsed.all(CaveatKey::Purpose);
    let role_entry = role_caveats.first();
    let purpose_entry = purpose_caveats.first();

    let role_str = role_entry
        .and_then(|c| match &c.value {
            CaveatValue::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .unwrap_or("MedicalPersonnel");

    let purpose_str = purpose_entry
        .and_then(|c| match &c.value {
            CaveatValue::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .unwrap_or("Read");

    let role = match role_str {
        "AdministrativePersonnel" => AuthRole::AdministrativePersonnel,
        "MedicalPersonnel" => AuthRole::MedicalPersonnel,
        "Patient" => AuthRole::Patient,
        _ => {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Invalid role in token"),
                code: StatusCode::UNAUTHORIZED,
            })
        }
    };

    let purpose = match purpose_str {
        "Read" => ReencryptionPurposeType::Read,
        "Update" => ReencryptionPurposeType::Update,
        _ => {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Invalid purpose in token"),
                code: StatusCode::UNAUTHORIZED,
            })
        }
    };

    Ok((role, purpose))
}
