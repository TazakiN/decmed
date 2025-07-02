use anyhow::Context;
use iota_types::{
    base_types::IotaAddress,
    crypto::IotaKeyPair,
    gas_coin::NANOS_PER_IOTA,
    transaction::{CallArg, Transaction},
};

use crate::{
    client_error::ClientError,
    constants::GAS_BUDGET,
    current_fn,
    types::DecmedPackage,
    utils::{
        construct_capability_call_arg, construct_pt, construct_shared_object_call_arg,
        construct_sponsored_tx_data, execute_tx, get_iota_client, get_ref_gas_price,
        handle_error_execute_tx, reserve_gas,
    },
};

pub struct MoveCall {
    pub decmed_package: DecmedPackage,
}

impl MoveCall {
    pub fn construct_address_id_object_call_arg(&self, mutable: bool) -> CallArg {
        construct_shared_object_call_arg(
            self.decmed_package.address_id_object_id,
            self.decmed_package.address_id_object_version,
            mutable,
        )
    }

    pub async fn construct_global_admin_cap(&self) -> Result<CallArg, ClientError> {
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

    pub async fn create_activation_key(
        &self,
        compound_activation_key: String,
        hospital_admin_id: String,
        hospital_id: String,
        hospital_name: String,
        sender: IotaAddress,
        sender_key_pair: IotaKeyPair,
    ) -> Result<(), ClientError> {
        let iota_client = get_iota_client().await.context(current_fn!())?;
        let pt = construct_pt(
            String::from("create_activation_key"),
            self.decmed_package.package_id,
            self.decmed_package.module_admin.clone(),
            vec![],
            vec![
                CallArg::Pure(bcs::to_bytes(&compound_activation_key).context(current_fn!())?),
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

        let (sponsor_account, reservation_id, gas_coins) = reserve_gas(NANOS_PER_IOTA, 10)
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
}
