use anyhow::{anyhow, Context};
use tauri::{async_runtime::Mutex, State};

use crate::{
    current_fn,
    hospital_error::HospitalError,
    types::{AppState, ResponseStatus, SuccessResponse},
};

pub const DEFAULT_PROFILE_ID: &str = "default";
pub const KEYRING_ACCOUNT: &str = "decmed_user";
pub const KEYRING_SERVICE_LEGACY: &str = "decmed_service_keys";
pub const PROFILE_ENV_VAR: &str = "DEC_MED_PROFILE";

pub fn resolve_profile_id() -> anyhow::Result<String> {
    let cli_profile = profile_id_from_args(std::env::args().skip(1))?;
    let env_profile = std::env::var(PROFILE_ENV_VAR).ok();

    normalize_profile_id(
        cli_profile
            .as_deref()
            .or(env_profile.as_deref())
            .unwrap_or(DEFAULT_PROFILE_ID),
    )
}

pub fn keyring_service_for_profile(profile_id: &str) -> String {
    format!("{KEYRING_SERVICE_LEGACY}:{profile_id}")
}

pub fn normalize_profile_id(profile_id: &str) -> anyhow::Result<String> {
    let profile_id = profile_id.trim();

    if profile_id.is_empty() {
        return Ok(DEFAULT_PROFILE_ID.to_string());
    }

    if profile_id.len() > 64 {
        return Err(anyhow!("Profile id must be 64 characters or fewer"));
    }

    if !profile_id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return Err(anyhow!(
            "Profile id may only contain ASCII letters, numbers, dot, dash, and underscore"
        ));
    }

    Ok(profile_id.to_string())
}

fn profile_id_from_args<I>(args: I) -> anyhow::Result<Option<String>>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();

    while let Some(arg) = args.next() {
        if let Some(profile_id) = arg.strip_prefix("--profile=") {
            return Ok(Some(profile_id.to_string()));
        }

        if arg == "--profile" {
            return args
                .next()
                .map(Some)
                .ok_or_else(|| anyhow!("Missing value for --profile"));
        }
    }

    Ok(None)
}

#[tauri::command]
pub async fn get_profile_id(
    state: State<'_, Mutex<AppState>>,
) -> Result<SuccessResponse<String>, HospitalError> {
    let state = state.lock().await;

    Ok(SuccessResponse {
        data: state.profile_id.clone(),
        status: ResponseStatus::Success,
    })
}

pub fn migrate_legacy_default_profile_if_needed(
    keys_entry: &keyring::Entry,
    profile_id: &str,
) -> anyhow::Result<bool> {
    if profile_id != DEFAULT_PROFILE_ID {
        return Ok(false);
    }

    if keys_entry.get_secret().is_ok() {
        return Ok(false);
    }

    let legacy_entry =
        keyring::Entry::new(KEYRING_SERVICE_LEGACY, KEYRING_ACCOUNT).context(current_fn!())?;
    let legacy_secret = match legacy_entry.get_secret() {
        Ok(secret) => secret,
        Err(keyring::Error::NoEntry) => return Ok(false),
        Err(err) => return Err(err).context(current_fn!()),
    };

    keys_entry
        .set_secret(&legacy_secret)
        .context(current_fn!())?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::{
        keyring_service_for_profile, normalize_profile_id, profile_id_from_args, DEFAULT_PROFILE_ID,
    };

    #[test]
    fn normalize_profile_id_defaults_empty_values() {
        assert_eq!(normalize_profile_id("").unwrap(), DEFAULT_PROFILE_ID);
        assert_eq!(normalize_profile_id("   ").unwrap(), DEFAULT_PROFILE_ID);
    }

    #[test]
    fn normalize_profile_id_accepts_demo_profile_names() {
        assert_eq!(normalize_profile_id("admin").unwrap(), "admin");
        assert_eq!(normalize_profile_id("doctor_1").unwrap(), "doctor_1");
        assert_eq!(normalize_profile_id("lab-demo").unwrap(), "lab-demo");
        assert_eq!(
            normalize_profile_id("apoteker.demo").unwrap(),
            "apoteker.demo"
        );
    }

    #[test]
    fn normalize_profile_id_rejects_unsafe_names() {
        assert!(normalize_profile_id("doctor 1").is_err());
        assert!(normalize_profile_id("../doctor").is_err());
        assert!(normalize_profile_id("doctor:1").is_err());
    }

    #[test]
    fn profile_id_from_args_reads_separate_or_equals_syntax() {
        assert_eq!(
            profile_id_from_args(vec!["--profile".to_string(), "nurse".to_string()])
                .unwrap()
                .as_deref(),
            Some("nurse")
        );
        assert_eq!(
            profile_id_from_args(vec!["--profile=lab".to_string()])
                .unwrap()
                .as_deref(),
            Some("lab")
        );
    }

    #[test]
    fn keyring_service_is_scoped_by_profile() {
        assert_eq!(
            keyring_service_for_profile("admin"),
            "decmed_service_keys:admin"
        );
    }
}
