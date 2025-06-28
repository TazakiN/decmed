module decmed::admin;

use decmed::shared::{
    GlobalAdminCap,

    encode_hospital_id,
    encode_hospital_personnel_id,
};

use decmed::std_struct_hospital_id_metadata::HospitalIdMetadata;
use decmed::std_struct_hospital_metadata::{
    new as hospital_metadata_new
};
use decmed::std_struct_hospital_personnel_account::{
    new as hospital_personnel_account_new
};
use decmed::std_struct_hospital_personnel_id_account::HospitalPersonnelIdAccount;
use decmed::std_enum_hospital_personnel_role::{
    admin as hospital_personnel_role_admin,
};

use std::string::{String};

// Constants

#[error]
const EAccountAlreadyRegistered: vector<u8> = b"Account already registered";
#[error]
const EAccountNotFound: vector<u8> = b"Account not found";
#[error]
const EHospitalAlreadyRegistered: vector<u8> = b"Hospital already registered";

// Functions

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `hospital_id`: argon_hash(raw_hospital_id)
/// - `hospital_name`: raw_hospital_name
/// - `id`: argon_hash(raw_id)
entry fun create_activation_key(
    activation_key: String,
    hospital_admin_id: String,
    hospital_id: String,
    hospital_id_metadata: &mut HospitalIdMetadata,
    hospital_name: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    _: &GlobalAdminCap,
)
{
    let hospital_id = encode_hospital_id(hospital_id);
    let hospital_id_metadata_table = hospital_id_metadata.borrow_mut_table();

    assert!(!hospital_id_metadata_table.contains(hospital_id), EHospitalAlreadyRegistered);

    let hospital = hospital_metadata_new(hospital_name);

    hospital_id_metadata_table.add(hospital_id, hospital);

    let hospital_personnel_id = encode_hospital_personnel_id(hospital_id, hospital_admin_id);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();

    assert!(!hospital_personnel_id_account_table.contains(hospital_personnel_id), EAccountAlreadyRegistered);

    let account = hospital_personnel_account_new(
        option::none(),
        activation_key,
        option::none(),
        option::none(),
        hospital_id,
        false,
        false,
        option::none(),
        hospital_personnel_role_admin(),
    );

    hospital_personnel_id_account_table.add(hospital_personnel_id, account);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `hospital_id`: argon_hash(raw_hospital_id)
/// - `id`: argon_hash(raw_id)
entry fun update_activation_key(
    activation_key: String,
    hospital_id: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    personnel_id: String,
    _: &GlobalAdminCap,
    _ctx: &TxContext,
)
{
    let hospital_personnel_id = encode_hospital_personnel_id(hospital_id, personnel_id);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();

    assert!(hospital_personnel_id_account_table.contains(hospital_personnel_id), EAccountNotFound);

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    hospital_personnel_account.set_activation_key(activation_key);
    hospital_personnel_account.set_is_activation_key_used(false);
}
