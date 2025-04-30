use alloy::network::{AnyNetwork, EthereumWallet, ReceiptResponse, TransactionBuilder};
use alloy::providers::fillers::WalletFiller;
use alloy::sol;
use alloy::{
    primitives::{address, FixedBytes},
    providers::{
        fillers::{BlobGasFiller, ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller},
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    signers::local::PrivateKeySigner,
};
use bip39::Mnemonic;
use ed25519_dalek::SigningKey;
use keyring::Entry;
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use Hospital::HospitalInstance;

type HospitalContract = HospitalInstance<
    FillProvider<
        JoinFill<
            JoinFill<
                Identity,
                JoinFill<GasFiller, JoinFill<BlobGasFiller, JoinFill<NonceFiller, ChainIdFiller>>>,
            >,
            WalletFiller<EthereumWallet>,
        >,
        RootProvider<AnyNetwork>,
        AnyNetwork,
    >,
    AnyNetwork,
>;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    Hospital,
    "../contracts/Hospital.json"
);

static RPC_URL: &str = "http://localhost:80/wasp/api/v1/chains/snd1pr2jn2dwx628nsz0ygzyd8ndhm45xldlmhwmwapqzyad9ns3tzwnv84f5g3/evm";

async fn construct_hospital_contract(signer: PrivateKeySigner) -> HospitalContract {
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .network::<AnyNetwork>()
        .connect(RPC_URL)
        .await
        .unwrap();

    Hospital::new(
        address!("0x3a1769fE25f148e988526B07c5A761Bc8fB398B2"),
        provider,
    )
}

#[tauri::command]
async fn deploy_hospital_contract() {
    let signer: PrivateKeySigner =
        "0xf15917df89ce4a6db98ad857007cfaa58485940c9583d8b5df62fb72a097174e"
            .parse()
            .unwrap();
    let provider = ProviderBuilder::new()
        .wallet(signer)
        .network::<AnyNetwork>()
        .connect(RPC_URL)
        .await
        .unwrap();

    let tx = Hospital::deploy_builder(&provider)
        .into_transaction_request()
        .with_gas_price(10_000_000_000)
        .with_gas_limit(10_000_000);

    let output = provider.call(tx.clone()).await;

    println!("Debug: {:#?}", output);

    let pending_tx = provider.send_transaction(tx).await.unwrap();

    println!("Pending transaction... {}", pending_tx.tx_hash());

    let receipt = pending_tx.get_receipt().await.unwrap();

    println!(
        "Transaction included in block {}. Status: {}. Address: {:#?}",
        receipt.block_number.expect("Failed to get block number"),
        receipt.status(),
        receipt.contract_address()
    );
}

#[tauri::command]
fn get_password_from_keyring() -> String {
    let entry = Entry::new_with_target("jiwoo_target", "jiwoo_service", "jiwoo_user").unwrap();
    let password = entry.get_password().unwrap();
    format!("success: {}", password)
}

#[tauri::command]
fn is_app_activated() -> bool {
    let activation_key_entry =
        Entry::new_with_target("activation_key", "decmed_service", "decmed_user").unwrap();
    if let Ok(activation_key) = activation_key_entry.get_password() {
        if !activation_key.is_empty() {
            return true;
        }
    }

    false
}

#[tauri::command]
async fn activate_app(
    activation_key: String,
    id: String,
) -> Result<serde_json::Value, serde_json::Value> {
    let signer = PrivateKeySigner::random();
    let contract = construct_hospital_contract(signer).await;

    let mut hasher = Sha256::new();
    let id_p_activation_key = format!("{}{}", activation_key, id);
    hasher.update(id_p_activation_key.as_bytes());
    let activation_key_bytes_n = hasher.finalize().into();
    println!("activate_app | activation_key: {}", id_p_activation_key);
    let activation_key = FixedBytes::new(activation_key_bytes_n);

    let builder = contract.useActivationKey(activation_key);
    let tx = builder
        .clone()
        .into_transaction_request()
        .with_gas_price(10_000_000_000)
        .with_gas_limit(100_000);

    let output = contract.provider().call(tx).await;

    let tx = builder
        .into_transaction_request()
        .with_gas_price(10_000_000_000)
        .with_gas_limit(100_000);

    match output {
        Ok(_) => {
            let pending_tx = contract.provider().send_transaction(tx).await.unwrap();
            println!("Pending transaction... {}", pending_tx.tx_hash());

            let receipt = pending_tx.get_receipt().await.unwrap();

            println!(
                "Transaction included in block {}. Status: {}",
                receipt.block_number.expect("Failed to get block number"),
                receipt.status()
            );

            return Ok(json!({
                "status": "success.",
            }));
        }
        Err(err) => {
            if let alloy::transports::RpcError::ErrorResp(err_payload) = &err {
                println!("{:#?}", err_payload);
                return Err(json!({
                    "status": "failed",
                    "message": err_payload.message.to_string()
                }));
            } else {
                println!("{:#?}", err);
            }
        }
    };

    Err(json!({
        "status": "failed",
        "message": "Something went wrong."
    }))
}

#[tauri::command]
async fn add_activation_key() -> Result<serde_json::Value, String> {
    let signer: PrivateKeySigner =
        "0xf15917df89ce4a6db98ad857007cfaa58485940c9583d8b5df62fb72a097174e"
            .parse()
            .unwrap();
    let contract = construct_hospital_contract(signer).await;

    let mut hasher = Sha256::new();
    let activation_key_raw = Uuid::new_v4();
    let id = String::from("HOS-12345678");
    let id_p_activation_key = format!("{}{}", activation_key_raw, id);
    println!(
        "add_activation_key | activation_key: {}",
        id_p_activation_key
    );
    hasher.update(id_p_activation_key.as_bytes());
    let activation_key_bytes_n = hasher.finalize().into();
    let activation_key = FixedBytes::new(activation_key_bytes_n);

    let builder = contract.addActivationKey(activation_key);
    let tx = builder
        .clone()
        .into_transaction_request()
        .with_gas_price(0)
        .with_gas_limit(100_000);

    let output = contract.provider().call(tx).await;

    let tx = builder
        .into_transaction_request()
        .with_gas_price(0)
        .with_gas_limit(100_000);

    match output {
        Ok(_) => {
            let pending_tx = contract.provider().send_transaction(tx).await.unwrap();
            println!("Pending transaction... {}", pending_tx.tx_hash());

            let receipt = pending_tx.get_receipt().await.unwrap();

            println!(
                "Transaction included in block {}. Status: {}",
                receipt.block_number.expect("Failed to get block number"),
                receipt.status()
            );

            return Ok(json!({
                "status": "success.",
                "activation_key": activation_key_raw.to_string(),
                "id": id.clone()
            }));
        }
        Err(err) => {
            if let alloy::transports::RpcError::ErrorResp(err_payload) = &err {
                println!("{:#?}", err_payload);
                return Err(err_payload.message.to_string());
            } else {
                println!("{:#?}", err);
            }
        }
    };

    Err(String::from("Something went wrong."))
}

#[tauri::command]
fn test_make_iota_address() {
    let mnemonic = Mnemonic::generate(12).unwrap();
    let seed_64 = mnemonic.to_seed_normalized("jiwoo_as_seed");
    let seed_32: [u8; 32] = seed_64[0..32].try_into().unwrap();
    let signing_key = SigningKey::from_bytes(&seed_32);
    let verifying_key = signing_key.verifying_key();
    println!("verifying_key: {:?}", verifying_key.as_bytes());
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            get_password_from_keyring,
            add_activation_key,
            is_app_activated,
            activate_app,
            deploy_hospital_contract,
            test_make_iota_address
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
