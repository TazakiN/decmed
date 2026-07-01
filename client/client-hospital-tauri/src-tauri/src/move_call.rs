use std::str::FromStr;

use anyhow::Context;
use iota_types::{
    base_types::{IotaAddress, ObjectID},
    crypto::IotaKeyPair,
    gas_coin::NANOS_PER_IOTA,
    programmable_transaction_builder::ProgrammableTransactionBuilder,
    transaction::{Argument, CallArg, Command, Transaction},
    Identifier, TypeTag,
};
use move_core_types::{account_address::AccountAddress, language_storage::StructTag};

use crate::{
    constants::GAS_BUDGET,
    current_fn,
    hospital_error::HospitalError,
    types::{
        DecmedPackage, HospitalPersonnelRole, HospitalPersonnelSubRole, MoveDelegateeCandidate,
        MoveHospitalMetadata, MoveHospitalPersonnelAccessData, MoveHospitalPersonnelAccessType,
        MoveHospitalPersonnelAdministrativeMetadata, MoveHospitalPersonnelMetadata,
        PatientDelegationAuditInput,
    },
    utils::{
        construct_capability_call_arg, construct_pt, construct_shared_object_call_arg,
        construct_sponsored_tx_data, execute_tx, get_iota_client, get_ref_gas_price,
        handle_error_execute_tx, handle_error_move_call_read_only, move_call_read_only,
        parse_move_read_only_result, reserve_gas,
    },
};

pub struct MoveCall {
    pub decmed_package: DecmedPackage,
}

const GAS_RESERVATION_DURATION_SECS: u64 = 60;
const CREATE_DELEGATED_ACCESS_GAS_BUDGET: u64 = 200_000_000;

fn move_string_type_tag() -> Result<TypeTag, HospitalError> {
    Ok(TypeTag::Struct(Box::new(StructTag {
        address: AccountAddress::ONE,
        module: Identifier::from_str("string").context(current_fn!())?,
        name: Identifier::from_str("String").context(current_fn!())?,
        type_params: vec![],
    })))
}

fn make_move_string_vector(
    builder: &mut ProgrammableTransactionBuilder,
    values: Vec<String>,
) -> Result<Argument, HospitalError> {
    let args = values
        .into_iter()
        .map(|item| builder.force_separate_pure(item).context(current_fn!()))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(builder.command(Command::MakeMoveVec(Some(move_string_type_tag()?), args)))
}

fn access_type_bytes(access_type: MoveHospitalPersonnelAccessType) -> Vec<u8> {
    match access_type {
        MoveHospitalPersonnelAccessType::Read => b"Read".to_vec(),
        MoveHospitalPersonnelAccessType::Update => b"Update".to_vec(),
    }
}

impl MoveCall {
    pub fn construct_address_id_object_call_arg(&self, mutable: bool) -> CallArg {
        construct_shared_object_call_arg(
            self.decmed_package.address_id_object_id,
            self.decmed_package.address_id_object_version,
            mutable,
        )
    }

    pub fn construct_clock_call_arg(&self) -> CallArg {
        construct_shared_object_call_arg(ObjectID::from_str("0x6").unwrap(), 1, false)
    }

    pub async fn construct_global_admin_cap(&self) -> Result<CallArg, HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        Ok(
            construct_capability_call_arg(&iota_client, self.decmed_package.global_admin_cap_id)
                .await
                .context(current_fn!())?,
        )
    }

    pub fn construct_hospital_id_metadata_object_call_arg(&self, mutable: bool) -> CallArg {
        construct_shared_object_call_arg(
            self.decmed_package.hospital_id_metadata_object_id,
            self.decmed_package.hospital_id_metadata_object_version,
            mutable,
        )
    }

    pub fn construct_hospital_personnel_id_account_object_call_arg(
        &self,
        mutable: bool,
    ) -> CallArg {
        construct_shared_object_call_arg(
            self.decmed_package.hospital_personnel_id_account_object_id,
            self.decmed_package
                .hospital_personnel_id_account_object_version,
            mutable,
        )
    }

    pub fn construct_patient_id_account_object_call_arg(&self, mutable: bool) -> CallArg {
        construct_shared_object_call_arg(
            self.decmed_package.patient_id_account_object_id,
            self.decmed_package.patient_id_account_object_version,
            mutable,
        )
    }

    pub async fn cleanup_read_access(
        &self,
        activation_key: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            "cleanup_read_access".to_string(),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_clock_call_arg(),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
            ],
        )
        .context(current_fn!())?;

        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA * 2, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn cleanup_update_access(
        &self,
        activation_key: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            "cleanup_update_access".to_string(),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_clock_call_arg(),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
            ],
        )
        .context(current_fn!())?;

        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA * 2, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn get_account_info(
        &self,
        activation_key: String,
        sender: IotaAddress,
    ) -> Result<
        (
            Option<MoveHospitalPersonnelAdministrativeMetadata>,
            HospitalPersonnelRole,
            MoveHospitalMetadata,
            Option<HospitalPersonnelSubRole>,
        ),
        HospitalError,
    > {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("get_account_info"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_id_metadata_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(false),
            ],
        )
        .context(current_fn!())?;

        let response = move_call_read_only(sender, &iota_client, pt)
            .await
            .context(current_fn!())?;
        handle_error_move_call_read_only(response.clone()).context(current_fn!())?;

        let hospital_personnel_administrative_metadata: Option<
            MoveHospitalPersonnelAdministrativeMetadata,
        > = parse_move_read_only_result(response.clone(), 0).context(current_fn!())?;
        let role: HospitalPersonnelRole =
            parse_move_read_only_result(response.clone(), 1).context(current_fn!())?;
        let hospital_metadata: MoveHospitalMetadata =
            parse_move_read_only_result(response.clone(), 2).context(current_fn!())?;
        let sub_role: Option<HospitalPersonnelSubRole> =
            parse_move_read_only_result(response.clone(), 3).context(current_fn!())?;

        Ok((
            hospital_personnel_administrative_metadata,
            role,
            hospital_metadata,
            sub_role,
        ))
    }

    /// ## Return:
    /// 0: status_code
    ///     - 0 means need activation
    ///     - 1 means need signup
    ///     - 2 means need signin
    ///     - 3 means ok
    pub async fn get_account_state(
        &self,
        activation_key: String,
        hospital_id: String,
        personnel_id: String,
        sender: IotaAddress,
    ) -> Result<(u64, Option<HospitalPersonnelRole>), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("get_account_state"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&hospital_id).context(current_fn!())?),
                self.construct_hospital_personnel_id_account_object_call_arg(false),
                CallArg::Pure(bcs::to_bytes(&personnel_id).context(current_fn!())?),
            ],
        )
        .context(current_fn!())?;

        let response = move_call_read_only(sender, &iota_client, pt)
            .await
            .context(current_fn!())?;
        handle_error_move_call_read_only(response.clone()).context(current_fn!())?;

        let state: u64 = parse_move_read_only_result(response.clone(), 0).context(current_fn!())?;
        let role: Option<HospitalPersonnelRole> =
            parse_move_read_only_result(response, 1).context(current_fn!())?;

        Ok((state, role))
    }

    pub async fn get_hospital_personnels(
        &self,
        activation_key: String,
        sender: IotaAddress,
    ) -> Result<Vec<MoveHospitalPersonnelMetadata>, HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("get_hospital_personnels"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(false),
            ],
        )
        .context(current_fn!())?;

        let response = move_call_read_only(sender, &iota_client, pt)
            .await
            .context(current_fn!())?;
        handle_error_move_call_read_only(response.clone()).context(current_fn!())?;

        let hospital_peersonnels_metadata: Vec<MoveHospitalPersonnelMetadata> =
            parse_move_read_only_result(response.clone(), 0).context(current_fn!())?;

        Ok(hospital_peersonnels_metadata)
    }

    pub async fn get_delegatee_candidates(
        &self,
        activation_key: String,
        admin_personnel_id: String,
        sender: IotaAddress,
    ) -> Result<Vec<MoveDelegateeCandidate>, HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("get_delegatee_candidates"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&admin_personnel_id).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(false),
            ],
        )
        .context(current_fn!())?;

        let response = move_call_read_only(sender, &iota_client, pt)
            .await
            .context(current_fn!())?;
        handle_error_move_call_read_only(response.clone()).context(current_fn!())?;

        let candidates: Vec<MoveDelegateeCandidate> =
            parse_move_read_only_result(response, 0).context(current_fn!())?;

        Ok(candidates)
    }

    pub async fn get_read_access(
        &self,
        activation_key: String,
        sender: IotaAddress,
    ) -> Result<Vec<MoveHospitalPersonnelAccessData>, HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("get_read_access"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(false),
            ],
        )
        .context(current_fn!())?;

        let response = move_call_read_only(sender, &iota_client, pt)
            .await
            .context(current_fn!())?;
        handle_error_move_call_read_only(response.clone()).context(current_fn!())?;

        let access: Vec<MoveHospitalPersonnelAccessData> =
            parse_move_read_only_result(response.clone(), 0).context(current_fn!())?;

        Ok(access)
    }

    pub async fn get_update_access(
        &self,
        activation_key: String,
        sender: IotaAddress,
    ) -> Result<Vec<MoveHospitalPersonnelAccessData>, HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("get_update_access"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(false),
            ],
        )
        .context(current_fn!())?;

        let response = move_call_read_only(sender, &iota_client, pt)
            .await
            .context(current_fn!())?;
        handle_error_move_call_read_only(response.clone()).context(current_fn!())?;

        let access: Vec<MoveHospitalPersonnelAccessData> =
            parse_move_read_only_result(response.clone(), 0).context(current_fn!())?;

        Ok(access)
    }

    pub async fn global_admin_create_activation_key(
        &self,
        activation_key: String,
        hospital_admin_id: String,
        hospital_id: String,
        hospital_name: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("create_activation_key"),
            self.decmed_package.package_id,
            self.decmed_package.module_admin.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&hospital_admin_id).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&hospital_id).context(current_fn!())?),
                self.construct_hospital_id_metadata_object_call_arg(true),
                CallArg::Pure(bcs::to_bytes(&hospital_name).context(current_fn!())?),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
                self.construct_global_admin_cap()
                    .await
                    .context(current_fn!())?,
            ],
        )
        .context(current_fn!())?;

        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn is_account_registered(
        &self,
        activation_key: String,
        sender: IotaAddress,
    ) -> Result<bool, HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("is_account_registered"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(false),
            ],
        )
        .context(current_fn!())?;

        let response = move_call_read_only(sender, &iota_client, pt)
            .await
            .context(current_fn!())?;
        if let Err(err) = handle_error_move_call_read_only(response) {
            let msg = err.to_string();
            if msg.contains("Account not found") || msg.contains("dynamic_field") {
                return Ok(false);
            }
            return Err(err);
        }

        Ok(true)
    }

    pub async fn hospital_admin_create_activation_key(
        &self,
        admin_activation_key: String,
        metadata: String,
        personnel_activation_key: String,
        personnel_id: String,
        role: &str,
        sub_role: Option<HospitalPersonnelSubRole>,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let sub_role_bytes: Vec<u8> = sub_role
            .map(|sr| sr.as_bytes().to_vec())
            .unwrap_or_default();
        let pt = construct_pt(
            String::from("create_activation_key"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                self.construct_address_id_object_call_arg(false),
                CallArg::Pure(bcs::to_bytes(&admin_activation_key).context(current_fn!())?),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
                CallArg::Pure(bcs::to_bytes(&metadata).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&personnel_activation_key).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&personnel_id).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(role.as_bytes()).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&sub_role_bytes).context(current_fn!())?),
            ],
        )
        .context(current_fn!())?;
        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA * 2, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn signup(
        &self,
        activation_key: String,
        hospital_id: String,
        personnel_id: String,
        private_metadata: String,
        public_metadata: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("signup"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(true),
                CallArg::Pure(bcs::to_bytes(&hospital_id).context(current_fn!())?),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
                CallArg::Pure(bcs::to_bytes(&personnel_id).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&private_metadata).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&public_metadata).context(current_fn!())?),
            ],
        )
        .context(current_fn!())?;

        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA * 2, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn update_administrative_metadata(
        &self,
        activation_key: String,
        private_metadata: String,
        public_metadata: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("update_administrative_metadata"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
                CallArg::Pure(bcs::to_bytes(&private_metadata).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&public_metadata).context(current_fn!())?),
            ],
        )
        .context(current_fn!())?;
        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA * 2, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn update_account_activation_key(
        &self,
        activation_key: String,
        metadata: String,
        personnel_id: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("update_account_activation_key"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                self.construct_address_id_object_call_arg(false),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
                CallArg::Pure(bcs::to_bytes(&metadata).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&personnel_id).context(current_fn!())?),
            ],
        )
        .context(current_fn!())?;

        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA * 2, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn use_activation_key(
        &self,
        activation_key: String,
        hospital_id: String,
        personnel_id: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("use_activation_key"),
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&activation_key).context(current_fn!())?),
                CallArg::Pure(bcs::to_bytes(&hospital_id).context(current_fn!())?),
                self.construct_hospital_personnel_id_account_object_call_arg(true),
                CallArg::Pure(bcs::to_bytes(&personnel_id).context(current_fn!())?),
            ],
        )
        .context(current_fn!())?;
        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let signer = sender_key_pair;
        let tx = Transaction::from_data_and_signer(tx_data, vec![&signer]);

        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;

        handle_error_execute_tx(response).context(current_fn!())?;

        Ok(())
    }

    pub async fn create_delegated_access(
        &self,
        activation_key: String,
        delegatee_address: IotaAddress,
        patient_address: IotaAddress,
        metadata: Vec<String>,
        audit_metadata: Vec<PatientDelegationAuditInput>,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), HospitalError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let mut builder = ProgrammableTransactionBuilder::new();
        let metadata_vector = make_move_string_vector(&mut builder, metadata)?;
        let audit_root_subjects: Vec<IotaAddress> = audit_metadata
            .iter()
            .map(|item| item.root_subject)
            .collect();
        let audit_single_access_type = audit_metadata
            .first()
            .map(|item| access_type_bytes(item.access_type))
            .unwrap_or_default();
        let audit_related_rme_ids = make_move_string_vector(
            &mut builder,
            audit_metadata
                .iter()
                .map(|item| item.related_rme_id.clone().unwrap_or_default())
                .collect(),
        )?;
        let audit_delegation_depths: Vec<u8> = audit_metadata
            .iter()
            .map(|item| item.delegation_depth)
            .collect();
        let audit_token_hashes = make_move_string_vector(
            &mut builder,
            audit_metadata
                .iter()
                .map(|item| item.token_hash.clone().unwrap_or_default())
                .collect(),
        )?;
        let audit_parent_token_hashes = make_move_string_vector(
            &mut builder,
            audit_metadata
                .iter()
                .map(|item| item.parent_token_hash.clone().unwrap_or_default())
                .collect(),
        )?;
        let audit_expires_at_ms: Vec<u64> = audit_metadata
            .iter()
            .map(|item| item.expires_at_ms.unwrap_or_default())
            .collect();
        let function = Identifier::from_str("create_delegated_access").context(current_fn!())?;
        let arguments = vec![
            builder.pure(activation_key).context(current_fn!())?,
            builder
                .input(self.construct_address_id_object_call_arg(false))
                .context(current_fn!())?,
            builder
                .input(self.construct_clock_call_arg())
                .context(current_fn!())?,
            builder.pure(delegatee_address).context(current_fn!())?,
            builder
                .input(self.construct_hospital_personnel_id_account_object_call_arg(true))
                .context(current_fn!())?,
            builder.pure(patient_address).context(current_fn!())?,
            metadata_vector,
            builder.pure(audit_root_subjects).context(current_fn!())?,
            builder
                .pure(audit_single_access_type)
                .context(current_fn!())?,
            audit_related_rme_ids,
            builder
                .pure(audit_delegation_depths)
                .context(current_fn!())?,
            audit_token_hashes,
            audit_parent_token_hashes,
            builder.pure(audit_expires_at_ms).context(current_fn!())?,
            builder
                .input(self.construct_patient_id_account_object_call_arg(true))
                .context(current_fn!())?,
        ];
        builder.programmable_move_call(
            self.decmed_package.package_id,
            self.decmed_package.module_hospital_personnel.clone(),
            function,
            vec![],
            arguments,
        );
        let pt = builder.finish();

        let (sponsor_account, reservation_id, gas_coins) =
            reserve_gas(NANOS_PER_IOTA, GAS_RESERVATION_DURATION_SECS)
                .await
                .context(current_fn!())?;
        let ref_gas_price = get_ref_gas_price(&iota_client)
            .await
            .context(current_fn!())?;

        let tx_data = construct_sponsored_tx_data(
            sender,
            gas_coins,
            pt,
            CREATE_DELEGATED_ACCESS_GAS_BUDGET,
            ref_gas_price,
            sponsor_account,
        );

        let tx = Transaction::from_data_and_signer(tx_data, vec![&sender_key_pair]);
        let response = execute_tx(tx, reservation_id)
            .await
            .context(current_fn!())?;
        handle_error_execute_tx(response).context(current_fn!())?;
        Ok(())
    }
}
