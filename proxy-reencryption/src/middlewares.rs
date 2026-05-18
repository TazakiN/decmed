use std::sync::Arc;

use crate::{
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
    };
    request.extensions_mut().insert(current_user);

    let response = next.run(request).await;

    Ok(response)
}
