use std::env;
use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context};
use umbral_pre::PublicKey;

use crate::{
    current_fn,
    hospital_error::HospitalError,
    types::KeysEntry,
    utils::{
        aes_encrypt_custom_key, compute_pre_keys, generate_64_bytes_seed,
        serde_deserialize_from_base64, serde_serialize_to_base64, sha_hash,
    },
};

use base64::{engine::general_purpose::STANDARD, Engine as _};

const HOSPITAL_PRE_DIR: &str = "decmed-hospital";

/// Linux NAME_MAX is 255 bytes; argon hashes hex-encoded exceed that when used as filenames.
fn hospital_pre_public_key_filename(hospital_id_hash: &str) -> String {
    format!(
        "{}-pre-public.json",
        hex::encode(sha_hash(hospital_id_hash.as_bytes()))
    )
}

pub fn hospital_pre_public_key_path(hospital_id_hash: &str) -> Result<PathBuf, HospitalError> {
    let home = env::var("HOME")
        .or_else(|_| env::var("USERPROFILE"))
        .map_err(|_| HospitalError::Anyhow(anyhow!("Home dir not found")))?;
    Ok(PathBuf::from(home)
        .join(HOSPITAL_PRE_DIR)
        .join(hospital_pre_public_key_filename(hospital_id_hash)))
}

pub fn write_hospital_pre_public_key(
    hospital_id_hash: &str,
    pre_public_key: &PublicKey,
) -> Result<(), HospitalError> {
    let path = hospital_pre_public_key_path(hospital_id_hash)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context(current_fn!())?;
    }
    let payload = serde_json::json!({
        "hospital_id_hash": hospital_id_hash,
        "pre_public_key": serde_serialize_to_base64(pre_public_key).context(current_fn!())?,
    });
    fs::write(path, serde_json::to_vec_pretty(&payload).context(current_fn!())?)
        .context(current_fn!())?;
    Ok(())
}

pub fn read_hospital_pre_public_key(hospital_id_hash: &str) -> Result<PublicKey, HospitalError> {
    let path = hospital_pre_public_key_path(hospital_id_hash)?;
    let bytes = fs::read(path).context(current_fn!())?;
    let payload: serde_json::Value = serde_json::from_slice(&bytes).context(current_fn!())?;
    let pk = payload
        .get("pre_public_key")
        .and_then(|v| v.as_str())
        .ok_or_else(|| HospitalError::Anyhow(anyhow!("pre_public_key missing in hospital pre file")))?;
    crate::utils::serde_deserialize_from_base64(pk.to_string())
}

/// Generate hospital-level PRE keys for the admin account and persist public key for all personnel.
pub fn generate_hospital_pre_keys_for_admin(
    keys_entry: &mut KeysEntry,
    pin: &str,
    hospital_id_hash: &str,
) -> Result<PublicKey, HospitalError> {
    let hospital_pre_seed = generate_64_bytes_seed();
    let (_, hospital_pre_public_key) =
        compute_pre_keys(&hospital_pre_seed[0..32]).context(current_fn!())?;

    let (enc_hospital_pre_secret, hospital_pre_nonce) =
        aes_encrypt_custom_key(sha_hash(pin.as_bytes()).as_slice(), &hospital_pre_seed[0..32])
            .context(current_fn!())?;

    keys_entry.hospital_pre_secret_key = Some(STANDARD.encode(enc_hospital_pre_secret));
    keys_entry.hospital_pre_public_key =
        Some(serde_serialize_to_base64(&hospital_pre_public_key).context(current_fn!())?);
    keys_entry.hospital_pre_nonce = Some(STANDARD.encode(hospital_pre_nonce));

    write_hospital_pre_public_key(hospital_id_hash, &hospital_pre_public_key)?;
    Ok(hospital_pre_public_key)
}

pub fn hospital_pre_public_key_for_personnel(
    keys_entry: &KeysEntry,
    hospital_id_hash: &str,
) -> Result<PublicKey, HospitalError> {
    if let Some(pk) = keys_entry.hospital_pre_public_key.as_ref() {
        return serde_deserialize_from_base64(pk.clone());
    }
    read_hospital_pre_public_key(hospital_id_hash)
}
