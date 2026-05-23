use decmed_macaroon_auth::WalletProofContext;
use iota_types::crypto::{EncodeDecodeBase64, Signature};
use serde::{Deserialize, Serialize};
use shared_crypto::intent::{Intent, IntentMessage};
use tauri::{async_runtime::Mutex, State};

use crate::{
    current_fn,
    hospital_error::HospitalError,
    types::{AppState, ResponseStatus, SuccessResponse},
    utils::{get_iota_address_from_keys_entry, get_iota_key_pair_from_keys_entry, parse_keys_entry},
};

use anyhow::Context;

#[derive(Debug, Deserialize, Serialize)]
pub struct SignWalletProofPayload {
    pub context: WalletProofContext,
    pub pin: String,
}

#[derive(Debug, Serialize)]
pub struct SignWalletProofResponse {
    pub signature: String,
}

#[tauri::command]
pub fn sign_wallet_proof(
    state: State<'_, Mutex<AppState>>,
    payload: SignWalletProofPayload,
) -> Result<SuccessResponse<SignWalletProofResponse>, HospitalError> {
    let state = state
        .try_lock()
        .map_err(|_| HospitalError::Anyhow(anyhow::anyhow!("State locked").context(current_fn!())))?;
    let keys_entry = parse_keys_entry(&state.keys_entry.get_secret().context(current_fn!())?)?;

    let iota_address = get_iota_address_from_keys_entry(&keys_entry).context(current_fn!())?;
    if payload.context.token_id.is_empty() {
        return Err(HospitalError::Anyhow(
            anyhow::anyhow!("token_id required").context(current_fn!()),
        ));
    }

    let iota_key_pair =
        get_iota_key_pair_from_keys_entry(&keys_entry, payload.pin).context(current_fn!())?;

    let canonical = payload
        .context
        .canonical_message()
        .map_err(|e| HospitalError::Anyhow(anyhow::anyhow!(e.to_string()).context(current_fn!())))?;

    let intent_message = IntentMessage::new(Intent::personal_message(), canonical);
    let signature = Signature::new_secure(&intent_message, &iota_key_pair);

    let _ = iota_address;

    Ok(SuccessResponse {
        status: ResponseStatus::Success,
        data: SignWalletProofResponse {
            signature: signature.encode_base64(),
        },
    })
}
