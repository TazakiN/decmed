module decmed::proxy;

use decmed::std_enum_hospital_personnel_role::{
    HospitalPersonnelRole,
};
use decmed::shared::{
    GlobalAdminCap,
    ProxyCap,

    transfer_proxy_cap,
};
use decmed::std_struct_address_id::AddressId;
use decmed::std_struct_hospital_personnel_id_account::HospitalPersonnelIdAccount;
use decmed::std_struct_patient_id_account::PatientIdAccount;
use decmed::std_struct_patient_medical_metadata::{
    PatientMedicalMetadata,

    new as patient_medical_metadata_new,
};

use iota::clock::Clock;

use std::string::String;

const EAccessExpired: u64 = 3000;
#[error]
const EAccountNotFound: vector<u8> = b"Account not found";
#[error]
const EAddressNotFound: vector<u8> = b"Address not found";
const EMedicalRecordCreationLimit: u64 = 3001;
const EMedicalRecordNotFound: u64 = 3002;

entry fun create_capability(
    proxy_address: address,
    _: &GlobalAdminCap,
    ctx: &mut TxContext,
)
{
   transfer_proxy_cap(proxy_address, ctx);
}

entry fun create_medical_record(
    address_id: &AddressId,
    clock: &Clock,
    hospital_personnel_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    metadata: String,
    patient_address: address,
    patient_id_account: &mut PatientIdAccount,
    _: &ProxyCap,
)
{
    let address_id_table = address_id.borrow_table();

    let patient_id = address_id_table.borrow(patient_address);
    let hospital_personnel_id = address_id_table.borrow(hospital_personnel_address);

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(*hospital_personnel_id);
    let hospital_personnel_access = hospital_personnel_account.borrow_mut_access().borrow_mut();
    let hospital_personnel_update_access = hospital_personnel_access.borrow_mut_update();
    let update_access = hospital_personnel_update_access.get(patient_id);

    assert!(update_access.borrow_medical_metadata_index().is_none(), EMedicalRecordCreationLimit);

    if (update_access.borrow_exp() < clock.timestamp_ms()) {
        hospital_personnel_update_access.remove(patient_id);
        assert!(false, EAccessExpired);
    };

    let patient_id_account_table = patient_id_account.borrow_mut_table();
    let patient_account = patient_id_account_table.borrow_mut(*patient_id);
    let patient_medical_metadata = patient_account.borrow_mut_medical_metadata();

    let index = patient_medical_metadata.length();
    let medical_metadata = patient_medical_metadata_new(
        index,
        metadata,
    );

    patient_medical_metadata.push_back(medical_metadata);

    let update_access = hospital_personnel_update_access.get_mut(patient_id);
    update_access.set_medical_metadata_index(option::some(index));
}

entry fun get_hospital_personnel_role(
    address_id: &AddressId,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    hospital_personnel_address: address,
    _: &ProxyCap,
): HospitalPersonnelRole
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(hospital_personnel_address);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);
    let role = *hospital_personnel_account.borrow_role();

    role
}

/// ## Returns:
/// 1: prev_index
/// 2: next_index
entry fun get_medical_record(
    address_id: &AddressId,
    clock: &Clock,
    hospital_personnel_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    index: u64,
    patient_address: address,
    patient_id_account: &PatientIdAccount,
    _: &ProxyCap,
): (PatientMedicalMetadata, Option<u64>, Option<u64>)
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(hospital_personnel_address);
    let patient_id = *address_id_table.borrow(patient_address);

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    let patient_id_account_table = patient_id_account.borrow_table();
    let patient_account = patient_id_account_table.borrow(patient_id);

    // Check access
    let hospital_personnel_access = hospital_personnel_account.borrow_mut_access().borrow_mut();
    let hospital_personnel_read_access = hospital_personnel_access.borrow_mut_read();
    let read_access = hospital_personnel_read_access.get(&patient_id);

    if (read_access.borrow_exp() < clock.timestamp_ms()) {
        hospital_personnel_read_access.remove(&patient_id);
        assert!(false, EAccessExpired);
    };

    let patient_medical_metadata = patient_account.borrow_medical_metadata();
    let medical_metadata = patient_medical_metadata.borrow(index);

    let mut next_index = option::some(index + 1);
    let mut prev_index = option::none<u64>();

    if (patient_medical_metadata.length() == index + 1) {
        next_index = option::none()
    };
    if (index > 0) {
        prev_index = option::some(index - 1)
    };

    (*medical_metadata, prev_index, next_index)
}

entry fun is_patient_registered(
    address_id: &AddressId,
    patient_id_account: &PatientIdAccount,
    patient_address: address,
    _: &ProxyCap,
)
{
    let address_id_table = address_id.borrow_table();

    assert!(address_id_table.contains(patient_address), EAddressNotFound);

    let patient_id = *address_id_table.borrow(patient_address);
    let patient_id_account_table = patient_id_account.borrow_table();

    assert!(patient_id_account_table.contains(patient_id), EAccountNotFound);
}

entry fun update_medical_record(
    address_id: &AddressId,
    clock: &Clock,
    hospital_personnel_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    metadata: String,
    patient_address: address,
    patient_id_account: &mut PatientIdAccount,
    _: &ProxyCap,
)
{
    let address_id_table = address_id.borrow_table();

    let patient_id = address_id_table.borrow(patient_address);
    let hospital_personnel_id = address_id_table.borrow(hospital_personnel_address);

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(*hospital_personnel_id);
    let hospital_personnel_access = hospital_personnel_account.borrow_mut_access().borrow_mut();
    let hospital_personnel_update_access = hospital_personnel_access.borrow_mut_update();
    let update_access = hospital_personnel_update_access.get(patient_id);

    assert!(update_access.borrow_medical_metadata_index().is_some(), EMedicalRecordNotFound);

    let index = *update_access.borrow_medical_metadata_index().borrow();

    if (update_access.borrow_exp() < clock.timestamp_ms()) {
        hospital_personnel_update_access.remove(patient_id);
        assert!(false, EAccessExpired);
    };

    let patient_id_account_table = patient_id_account.borrow_mut_table();
    let patient_account = patient_id_account_table.borrow_mut(*patient_id);
    let patient_medical_metadata = patient_account.borrow_mut_medical_metadata();

    let medical_metadata = patient_medical_metadata_new(
        index,
        metadata,
    );

    patient_medical_metadata.push_back(medical_metadata);
    patient_medical_metadata.swap_remove(index);
}
