use std::{str::FromStr, sync::Arc};

use crate::{
    macaroon_auth::map_caveat_error,
    proxy_error::{ProxyError, ResultExt},
    types::{AppState, AuthRole, CurrentUser, MoveHospitalPersonnelRole, ReencryptionPurposeType},
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
    compute_revocation_keys, hash_token, verify_macaroon_signature, DelegationChain,
    EffectiveCapability, Macaroon, MacaroonKey, ParsedCaveats, VerifiedDecmedToken,
};
use iota_types::base_types::IotaAddress;
use redis::Commands;

pub const WALLET_SIGNATURE_HEADER: &str = "x-decmed-wallet-signature";
pub const WALLET_TIMESTAMP_HEADER: &str = "x-decmed-wallet-timestamp";
pub const DELEGATION_SIGNATURE_HEADER: &str = "x-decmed-delegation-signature";

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

    let mac = Macaroon::deserialize(&bearer_token)
        .map_err(|_| anyhow!("Invalid access token format"))
        .code(StatusCode::UNAUTHORIZED)?;

    let root_key = MacaroonKey::generate(&state.macaroon_root_key);

    let parsed = ParsedCaveats::from_macaroon(&mac).map_err(map_caveat_error)?;

    if parsed.is_decmed_token() {
        verify_macaroon_signature(&mac, &root_key).map_err(map_caveat_error)?;

        let effective = EffectiveCapability::from_parsed(&parsed).map_err(map_caveat_error)?;
        let delegation = DelegationChain::from_parsed(&parsed).map_err(map_caveat_error)?;

        // Check revocation status in Redis
        {
            let token_str = &bearer_token;
            let token_hash = hash_token(token_str);
            let revocation_keys = compute_revocation_keys(&parsed, &delegation, &token_hash)
                .map_err(|e| anyhow!(e.to_string()))
                .code(StatusCode::UNAUTHORIZED)?;

            let mut conn = state.redis_pool.get().map_err(|e| ProxyError::Anyhow {
                source: anyhow!("Revocation store unavailable: {e}"),
                code: StatusCode::SERVICE_UNAVAILABLE,
            })?;
            for key in revocation_keys {
                let revoked: bool = conn.exists(&key).map_err(|e| ProxyError::Anyhow {
                    source: anyhow!("Revocation check failed: {e}"),
                    code: StatusCode::SERVICE_UNAVAILABLE,
                })?;
                if revoked {
                    return Err(ProxyError::Anyhow {
                        source: anyhow!("Token has been revoked"),
                        code: StatusCode::UNAUTHORIZED,
                    });
                }
            }
        }

        // Verify delegation proof for cross-person delegation only.
        // Self-delegation (delegated_by == delegated_to) is used internally
        // for scope narrowing (e.g., administrative segment seeding) and
        // does not carry a delegation signature.
        if let Some(last) = delegation.steps.last() {
            if last.delegated_by != last.delegated_to {
                let delegation_sig = request
                    .headers()
                    .get(DELEGATION_SIGNATURE_HEADER)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| ProxyError::Anyhow {
                        source: anyhow!(
                            "Delegated token requires {} header",
                            DELEGATION_SIGNATURE_HEADER
                        ),
                        code: StatusCode::UNAUTHORIZED,
                    })?;
                crate::macaroon_auth::verify_delegation_proof(&bearer_token, delegation_sig)?;
            }
        }

        let active_subject = delegation.active_subject.clone();
        let active_subject_address = IotaAddress::from_str(&active_subject)
            .map_err(|_| anyhow!("Invalid active subject address"))
            .code(StatusCode::UNAUTHORIZED)?;
        let proxy_iota_address = IotaAddress::from_str(&state.proxy_iota_address)
            .map_err(|_| anyhow!("Invalid proxy IOTA address"))
            .code(StatusCode::INTERNAL_SERVER_ERROR)?;

        // DecMed token caveat role is legacy/deprecated for delegated tokens.
        // Identity role/sub-role must come from on-chain registry for the active subject.
        let (move_role, sub_role) = state
            .move_call
            .get_hospital_personnel_auth_info(&active_subject_address, proxy_iota_address)
            .await?;
        let role = auth_role_from_move_role(move_role)?;
        let purpose = decmed_purpose_from_parsed(&parsed)?;
        let hospital_cid = effective.hospital_cid.clone();

        let verified = VerifiedDecmedToken {
            parsed,
            effective,
            delegation: delegation.clone(),
            token_id: String::from_utf8(mac.identifier().0.clone()).unwrap_or_default(),
        };

        let current_user = CurrentUser {
            iota_address: active_subject,
            hospital_cid,
            purpose,
            role,
            sub_role,
            decmed_token: Some(verified),
            bearer_token: bearer_token.clone(),
        };
        request.extensions_mut().insert(current_user);
        return Ok(next.run(request).await);
    }

    return Err(ProxyError::Anyhow {
        source: anyhow!("Token is not a valid DecMed token"),
        code: StatusCode::UNAUTHORIZED,
    });
}

fn decmed_purpose_from_parsed(
    parsed: &ParsedCaveats,
) -> Result<ReencryptionPurposeType, ProxyError> {
    use decmed_macaroon_auth::{CaveatKey, CaveatValue};

    let purpose_caveats = parsed.all(CaveatKey::Purpose);
    let purpose_entry = purpose_caveats.first();

    let purpose_str = purpose_entry
        .and_then(|c| match &c.value {
            CaveatValue::Text(s) => Some(s.as_str()),
            _ => None,
        })
        .unwrap_or("Read");

    let purpose = match purpose_str {
        "Read" => ReencryptionPurposeType::Read,
        "Update" => ReencryptionPurposeType::Update,
        _ => {
            return Err(ProxyError::Anyhow {
                source: anyhow!("Invalid purpose in token"),
                code: StatusCode::UNAUTHORIZED,
            });
        }
    };

    Ok(purpose)
}

fn auth_role_from_move_role(role: MoveHospitalPersonnelRole) -> Result<AuthRole, ProxyError> {
    match role {
        MoveHospitalPersonnelRole::AdministrativePersonnel => Ok(AuthRole::AdministrativePersonnel),
        MoveHospitalPersonnelRole::MedicalPersonnel => Ok(AuthRole::MedicalPersonnel),
        MoveHospitalPersonnelRole::Admin => Err(ProxyError::Anyhow {
            source: anyhow!("Invalid personnel account"),
            code: StatusCode::UNAUTHORIZED,
        }),
    }
}
