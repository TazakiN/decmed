use std::str::FromStr;

use iota_json_rpc_types::{DevInspectResults, IotaObjectDataOptions};
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
use serde_json::json;

use crate::constants::GAS_STATION_BASE_URL;
use crate::types::{ExecuteTxResponse, KeysEntry, ReserveGasResponse};

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

pub async fn construct_admin_cap_call_arg(
    iota_client: &IotaClient,
    admin_cap_id: ObjectID,
) -> CallArg {
    let admin_cap_object = (*iota_client)
        .read_api()
        .get_object_with_options(
            admin_cap_id,
            IotaObjectDataOptions {
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let admin_cap_object_arg = ObjectArg::ImmOrOwnedObject((
        admin_cap_object.data.clone().unwrap().object_id,
        admin_cap_object.data.clone().unwrap().version,
        admin_cap_object.data.unwrap().digest,
    ));

    CallArg::Object(admin_cap_object_arg)
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
