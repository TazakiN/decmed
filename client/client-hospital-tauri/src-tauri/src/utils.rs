use std::{str::FromStr, time::SystemTime};

use aes_gcm::{aead::Aead, AeadCore, Aes256Gcm, KeyInit, Nonce};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordVerifier, Version,
};
use chrono::{DateTime, Utc};
use iota_json_rpc_types::{
    DevInspectResults, IotaObjectDataOptions, IotaTransactionBlockEffectsAPI,
};
use iota_keys::key_derive::derive_key_pair_from_path;
use iota_sdk::IotaClient;
use iota_types::base_types::{IotaAddress, ObjectID, ObjectRef};
use iota_types::crypto::{EmptySignInfo, IotaKeyPair, SignatureScheme};
use iota_types::message_envelope::Envelope;
use iota_types::programmable_transaction_builder::ProgrammableTransactionBuilder;
use iota_types::transaction::{
    CallArg, ObjectArg, ProgrammableTransaction, SenderSignedData, TransactionData,
    TransactionDataAPI,
};
use iota_types::{Identifier, TypeTag};
use rand::Rng;
use regex::Regex;
use serde::de::DeserializeOwned;
use serde_json::json;
use sha2::{Digest, Sha256};
use umbral_pre::{PublicKey, SecretKey, SecretKeyFactory};

use crate::types::{ExecuteTxResponse, KeysEntry, ReserveGasResponse};
use crate::{
    constants::{GAS_STATION_BASE_URL, HASH_SALT, IPFS_BASE_URL},
    types::UtilIpfsAddResponse,
};

pub async fn reserve_gas(
    gas_budget: u64,
    reserve_duration_secs: u64,
) -> (IotaAddress, u64, Vec<ObjectRef>) {
    let req_client = reqwest::Client::new();
    let res = req_client
        .post(format!("{GAS_STATION_BASE_URL}/reserve_gas"))
        .bearer_auth("token")
        .json(&json!({
          "gas_budget": gas_budget,
        "reserve_duration_secs": reserve_duration_secs
        }))
        .send()
        .await
        .unwrap();
    let res_body = res.json::<ReserveGasResponse>().await.unwrap();
    // println!("{:#?}", res_body);
    res_body
        .result
        .map(|result| {
            (
                result.sponsor_address,
                result.reservation_id,
                result
                    .gas_coins
                    .into_iter()
                    .map(|c| c.to_object_ref())
                    .collect(),
            )
        })
        .unwrap()
}

pub async fn execute_tx(
    tx: Envelope<SenderSignedData, EmptySignInfo>,
    reservation_id: u64,
) -> ExecuteTxResponse {
    let (tx_base_64, signature_base_64) = tx.to_tx_bytes_and_signatures();

    let req_client = reqwest::Client::new();
    let res = req_client
        .post(format!("{GAS_STATION_BASE_URL}/execute_tx"))
        .bearer_auth("token")
        .json(&json!({
            "reservation_id": reservation_id,
            "tx_bytes": tx_base_64.encoded(),
            "user_sig": signature_base_64[0].encoded()
        }))
        .send()
        .await
        .unwrap();

    res.json::<ExecuteTxResponse>().await.unwrap()
}

pub fn parse_keys_entry(keys_entry: &Vec<u8>) -> KeysEntry {
    serde_json::from_slice(keys_entry).unwrap()
}

pub fn generate_64_bytes_seed() -> [u8; 64] {
    let mut rng = rand::rng();
    let mut random_seed = [0u8; 64];
    rng.fill(&mut random_seed);

    random_seed
}

pub fn generate_iota_keys_ed(seed: &[u8]) -> (IotaAddress, IotaKeyPair) {
    derive_key_pair_from_path(
        &seed,
        Some(bip32::DerivationPath::from_str("m/44'/4218'/0'/0'/0'").unwrap()),
        &SignatureScheme::ED25519,
    )
    .unwrap()
}

pub fn construct_pt(
    function_name: String,
    package: ObjectID,
    module: Identifier,
    type_arguments: Vec<TypeTag>,
    call_args: Vec<CallArg>,
) -> ProgrammableTransaction {
    let mut builder = ProgrammableTransactionBuilder::new();
    let function = Identifier::from_str(function_name.as_str()).unwrap();

    builder
        .move_call(package, module, function, type_arguments, call_args)
        .unwrap();

    builder.finish()
}

pub fn construct_sponsored_tx_data(
    sender: IotaAddress,
    gas_payment: Vec<ObjectRef>,
    pt: ProgrammableTransaction,
    gas_budget: u64,
    gas_price: u64,
    sponsor_address: IotaAddress,
) -> TransactionData {
    let mut tx_data =
        TransactionData::new_programmable(sender, gas_payment.clone(), pt, gas_budget, gas_price);

    tx_data.gas_data_mut().payment = gas_payment;
    tx_data.gas_data_mut().owner = sponsor_address;

    tx_data
}

pub async fn get_ref_gas_price(iota_client: &IotaClient) -> u64 {
    (*iota_client)
        .governance_api()
        .get_reference_gas_price()
        .await
        .unwrap()
}

pub async fn construct_capability_call_arg(
    iota_client: &IotaClient,
    capability_id: ObjectID,
) -> CallArg {
    let cap_object = (*iota_client)
        .read_api()
        .get_object_with_options(
            capability_id,
            IotaObjectDataOptions {
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let cap_object_arg = ObjectArg::ImmOrOwnedObject((
        cap_object.data.clone().unwrap().object_id,
        cap_object.data.clone().unwrap().version,
        cap_object.data.unwrap().digest,
    ));

    CallArg::Object(cap_object_arg)
}

pub fn construct_shared_object_call_arg(id: ObjectID, version: u64, mutable: bool) -> CallArg {
    let activation_key_table_arg = ObjectArg::SharedObject {
        id,
        initial_shared_version: version.into(),
        mutable,
    };

    CallArg::Object(activation_key_table_arg)
}

pub async fn move_call_read_only(
    sender: IotaAddress,
    iota_client: &IotaClient,
    pt: ProgrammableTransaction,
) -> DevInspectResults {
    (*iota_client)
        .read_api()
        .dev_inspect_transaction_block(
            sender,
            iota_types::transaction::TransactionKind::ProgrammableTransaction(pt),
            None,
            None,
            None,
        )
        .await
        .unwrap()
}

pub fn argon_hash(password: String) -> String {
    let salt = SaltString::from_b64(HASH_SALT).unwrap();
    let argon2 = Argon2::new_with_secret(
        HASH_SALT.as_bytes(),
        Algorithm::Argon2id,
        Version::V0x13,
        Params::DEFAULT,
    )
    .unwrap();

    let hash = argon2
        .hash_password(password.as_str().as_bytes(), &salt)
        .unwrap()
        .to_string();

    hex::encode(hash)
}

pub fn _argon_verify(hash: String, password: String) -> bool {
    let argon2 = Argon2::new_with_secret(
        HASH_SALT.as_bytes(),
        Algorithm::Argon2id,
        Version::V0x13,
        Params::DEFAULT,
    )
    .unwrap();
    let hash = PasswordHash::new(hash.as_str()).unwrap();

    argon2.verify_password(password.as_bytes(), &hash).is_ok()
}

/**
* output:
* key: 32 bytes
* nonce: 12 bytes
*/
pub fn aes_encrypt(data: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let key = Aes256Gcm::generate_key(aes_gcm::aead::OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

    let ciphertext = cipher.encrypt(&nonce, data).unwrap();

    (ciphertext, key.to_vec(), nonce.to_vec())
}

pub fn aes_encrypt_custom_key(key: &[u8], data: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Aes256Gcm::generate_nonce(&mut aes_gcm::aead::OsRng);

    let ciphertext = cipher.encrypt(&nonce, data).unwrap();

    (ciphertext, nonce.to_vec())
}

pub fn aes_decrypt(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();
    let nonce = Nonce::from_slice(nonce);

    let original = match cipher.decrypt(nonce, ciphertext) {
        Ok(ori) => ori,
        Err(_) => return Err(String::from("Invalid decryption key.")),
    };

    Ok(original)
}

pub fn sha_hash(data: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(data);
    hash.to_vec()
}

pub fn sha_hash_to_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}

pub fn validate_pin_util(pin: String) -> bool {
    let re = Regex::new(r"^\d{6}$").unwrap();
    if !re.is_match(pin.as_str()) {
        return false;
    }

    true
}

pub fn validate_by_regex(value: &str, regex: &str) -> bool {
    let re = Regex::new(regex).unwrap();
    if !re.is_match(value) {
        return false;
    }

    true
}

pub fn compute_pre_keys(seed: &[u8]) -> (SecretKey, PublicKey) {
    let secret_key = SecretKeyFactory::from_secure_randomness(seed)
        .unwrap()
        .make_key(seed);
    let public_key = secret_key.public_key();

    (secret_key, public_key)
}

pub fn parse_move_read_only_result<T: DeserializeOwned>(
    val: DevInspectResults,
    index: usize,
) -> Result<T, String> {
    let res = val.results.unwrap()[0].return_values[index].0.to_vec();

    match bcs::from_bytes::<T>(res.as_slice()) {
        Ok(val) => Ok(val),
        Err(_) => Err("Failed to parse move read only result".to_string()),
    }
}

pub fn sys_time_to_iso(system_time: SystemTime) -> String {
    let iso: DateTime<Utc> = system_time.into();
    iso.to_rfc3339()
}

pub async fn add_and_pin_to_ipfs(data: Vec<u8>) -> String {
    let data = serde_json::to_string(&data).unwrap();
    let path_part = reqwest::multipart::Part::text(data);
    let form = reqwest::multipart::Form::new().part("path", path_part);
    let req_client = reqwest::Client::new();
    let res = req_client
        .post(format!("{}/add", IPFS_BASE_URL))
        .multipart(form)
        .send()
        .await
        .unwrap();

    let res = res.json::<UtilIpfsAddResponse>().await.unwrap();

    res.cid
}

/**
 * Double hash. First using argon and then sha256.
 * Ouput: Hex string
 */
pub fn _hash_argon_sha(val: String) -> String {
    let hash = argon_hash(val);
    let hash = sha_hash_to_hex(hash.as_bytes());

    hash
}

/**
 * Return: `(id_part, hospital_part)`
 */
pub fn decode_hospital_personnel_id(id: String) -> Result<(String, String), String> {
    let id: Vec<&str> = id.split("@").collect();

    if id.len() != 2 {
        return Err("Invalid id".to_string());
    }

    Ok((id[0].to_string(), id[1].to_string()))
}

/**
 * Return: `(id_part_hash, hospital_part_hash)`
 */
pub fn decode_hospital_personnel_id_to_argon(id: String) -> Result<(String, String), String> {
    let (id_part, hospital_part) = decode_hospital_personnel_id(id)?;

    let id_part_hash = argon_hash(id_part);
    let hospital_part_hash = argon_hash(hospital_part);

    Ok((id_part_hash, hospital_part_hash))
}

pub fn handle_error_move_call_read_only(
    func_name: String,
    response: DevInspectResults,
) -> Result<(), String> {
    if response.error.is_some() {
        // DEBUG:
        {
            println!("{}: Error {}", func_name, response.error.as_ref().unwrap());
        }
        return Err(format!("{}: Error {}", func_name, response.error.unwrap()));
    }

    if response.effects.status().is_err() {
        // DEBUG:
        {
            println!(
                "{}: Error {}",
                func_name,
                response.effects.status().to_string()
            );
        }
        return Err(format!(
            "{}: Error {}",
            func_name,
            response.effects.status().to_string()
        ));
    }

    Ok(())
}

pub fn handle_error_execute_tx(
    func_name: String,
    response: ExecuteTxResponse,
) -> Result<(), String> {
    if response.error.is_some() {
        // DEBUG:
        {
            println!("{}: Error {}", func_name, response.error.as_ref().unwrap());
        }
        return Err(format!("{}: Error {}", func_name, response.error.unwrap()));
    }

    if response.effects.as_ref().unwrap().status().is_err() {
        // DEBUG:
        {
            println!(
                "{}: Error {}",
                func_name,
                response.effects.as_ref().unwrap().status().to_string()
            );
        }
        return Err(format!(
            "{}: Error {}",
            func_name,
            response.effects.as_ref().unwrap().status().to_string()
        ));
    }

    Ok(())
}
