#[test_only]
module decmed::decmed_tests;

use decmed::patient::create_access_test;

use decmed::proxy::{
    get_administrative_data_test,
    get_medical_record_test,
};

use decmed::shared::{
    transfer_proxy_cap,
    ProxyCap,
};

use decmed::std_enum_hospital_personnel_role::{
    admin as hospital_personnel_role_admin,
    administrative_personnel as hospital_personnel_role_administrative_personnel,
    medical_personnel as hospital_personnel_role_medical_personnel,
};

use decmed::std_struct_address_id::{
    AddressId,
    default as address_id_default,
};
use decmed::std_struct_hospital::{
    new as hospital_new,
};
use decmed::std_struct_hospital_id_metadata::{
    HospitalIdMetadata,
    default as hospital_id_metadata_default,
};
use decmed::std_struct_hospital_metadata::{
    new as hospital_metadata_new,
};
use decmed::std_struct_hospital_personnel_account::{
    default as hospital_personnel_account_default,
};
use decmed::std_struct_hospital_personnel_id_account::{
    HospitalPersonnelIdAccount,
    default as hospital_personnel_id_account_default,
};
use decmed::std_struct_patient_account::{
    default as patient_account_default,
};
use decmed::std_struct_patient_id_account::{
    PatientIdAccount,
    default as patient_id_account_default,
};
use decmed::std_struct_patient_medical_metadata::{
    new as patient_medical_metadata_new,
};

use std::string::{Self, String};

use iota::clock::{Self, Clock};
use iota::test_scenario;

const PUBLISHER_ADDR: address = @0xA;
const PROXY_ADDR: address = @0xAAAA;
const PATIENT_ADDR: address = @0xAA;
const PATIENT_2_ADDR: address = @0xAA2;
const HOSPITAL_ADMIN_ADDR: address = @0x0A;
const ADMINISTRATIVE_PERSONNEL_ADDR: address = @0xBB;
const MEDICAL_PERSONNEL_ADDR: address = @0xCC;

#[test_only]
fun patient_id(): String
{
    string::utf8(b"Patient")
}

#[test_only]
fun patient_2_id(): String
{
    string::utf8(b"Patient2")
}

#[test_only]
fun hospital_admin_id(): String
{
    string::utf8(b"HospitalAdmin")
}

#[test_only]
fun administrative_personnel_id(): String
{
    string::utf8(b"AdministrativePersonnel")
}

#[test_only]
fun medical_personnel_id(): String
{
    string::utf8(b"MedicalPersonnel")
}

#[test_only]
fun setup(ctx: &mut TxContext)
{
    let mut address_id = address_id_default(ctx);
    let address_id_table = address_id.borrow_mut_table();
    let mut hospital_personnel_id_account = hospital_personnel_id_account_default(ctx);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let mut patient_id_account = patient_id_account_default(ctx);
    let patient_id_account_table = patient_id_account.borrow_mut_table();
    let mut hospital_id_metadata = hospital_id_metadata_default(ctx);

    address_id_table.add(PATIENT_ADDR, patient_id());
    address_id_table.add(PATIENT_2_ADDR, patient_2_id());
    address_id_table.add(HOSPITAL_ADMIN_ADDR, hospital_admin_id());
    address_id_table.add(ADMINISTRATIVE_PERSONNEL_ADDR, administrative_personnel_id());
    address_id_table.add(MEDICAL_PERSONNEL_ADDR, medical_personnel_id());

    let mut hospital_admin_account = hospital_personnel_account_default(hospital_personnel_role_admin());
    hospital_admin_account.set_address(option::some(HOSPITAL_ADMIN_ADDR));
    let mut administrative_personnel_account = hospital_personnel_account_default(hospital_personnel_role_administrative_personnel());
    administrative_personnel_account.set_address(option::some(ADMINISTRATIVE_PERSONNEL_ADDR));
    let mut medical_personnel_account = hospital_personnel_account_default(hospital_personnel_role_medical_personnel());
    medical_personnel_account.set_address(option::some(MEDICAL_PERSONNEL_ADDR));

    hospital_personnel_id_account_table.add(hospital_admin_id(), hospital_admin_account);
    hospital_personnel_id_account_table.add(administrative_personnel_id(), administrative_personnel_account);
    hospital_personnel_id_account_table.add(medical_personnel_id(), medical_personnel_account);

    let mut patient_account = patient_account_default(PATIENT_ADDR, ctx);
    let patient_medical_metadata = patient_account.borrow_mut_medical_metadata();
    patient_medical_metadata.push_back(patient_medical_metadata_new(0, string::utf8(b"MD_1")));
    patient_medical_metadata.push_back(patient_medical_metadata_new(1, string::utf8(b"MD_1")));

    let mut patient_2_account = patient_account_default(PATIENT_2_ADDR, ctx);
    let patient_2_medical_metadata = patient_2_account.borrow_mut_medical_metadata();
    patient_2_medical_metadata.push_back(patient_medical_metadata_new(0, string::utf8(b"MD2_1")));
    patient_2_medical_metadata.push_back(patient_medical_metadata_new(1, string::utf8(b"MD2_2")));

    patient_id_account_table.add(patient_id(), patient_account);
    patient_id_account_table.add(patient_2_id(), patient_2_account);

    let hospital_metadata = hospital_metadata_new(string::utf8(b"Hos1"));
    let hospital = hospital_new(string::utf8(b"HosAdminMetadata"), hospital_metadata);
    let hospital_id_metadata_table = hospital_id_metadata.borrow_mut_table();
    hospital_id_metadata_table.add(string::utf8(b"Hos1"), 0);
    let hospital_id_metadata_vec = hospital_id_metadata.borrow_mut_vec();
    hospital_id_metadata_vec.push_back(hospital);

    transfer_proxy_cap(PROXY_ADDR, ctx);
    transfer::public_share_object(address_id);
    transfer::public_share_object(hospital_personnel_id_account);
    transfer::public_share_object(patient_id_account);
    transfer::public_share_object(hospital_id_metadata);
}

#[test_only]
fun create_access(
    clock: &Clock,
    hospital_personnel_address: address,
    metadata: vector<String>,
    scenario: &mut test_scenario::Scenario,
)
{
    let address_id = test_scenario::take_shared<AddressId>(scenario);
    let mut hospital_personnel_id_account = test_scenario::take_shared<HospitalPersonnelIdAccount>(scenario);
    let mut patient_id_account = test_scenario::take_shared<PatientIdAccount>(scenario);
    let hospital_id_metadata = test_scenario::take_shared<HospitalIdMetadata>(scenario);

    create_access_test(
        &address_id,
        clock,
        string::utf8(b"2025-07-28T14:40:49+00:00"),
        &hospital_id_metadata,
        hospital_personnel_address,
        &mut hospital_personnel_id_account,
        metadata,
        &mut patient_id_account,
        test_scenario::ctx(scenario),
    );

    test_scenario::return_shared(address_id);
    test_scenario::return_shared(hospital_personnel_id_account);
    test_scenario::return_shared(patient_id_account);
    test_scenario::return_shared(hospital_id_metadata);
}

#[test, expected_failure(abort_code = ::decmed::proxy::EInvalidAccessType)]
// Read access medical part of medical record
// by administrative personnel
fun test_ill_01()
{
    let mut scenario_val = test_scenario::begin(PUBLISHER_ADDR);
    let scenario = &mut scenario_val;

    let mut clck = clock::create_for_testing(test_scenario::ctx(scenario));

    setup(test_scenario::ctx(scenario));

    test_scenario::next_tx(scenario, PATIENT_ADDR);

    {
        let mut metadata = vector::empty<String>();
        metadata.push_back(string::utf8(b"ReadAccessForAdmPersonnel"));

        create_access(
            &clck,
            ADMINISTRATIVE_PERSONNEL_ADDR,
            metadata,
            scenario
        );
    };

    test_scenario::next_tx(scenario, PROXY_ADDR);

    {
        let address_id = test_scenario::take_shared<AddressId>(scenario);
        let mut hospital_personnel_id_account = test_scenario::take_shared<HospitalPersonnelIdAccount>(scenario);
        let patient_id_account = test_scenario::take_shared<PatientIdAccount>(scenario);
        let hospital_id_metadata = test_scenario::take_shared<HospitalIdMetadata>(scenario);
        let proxy_cap = test_scenario::take_from_address<ProxyCap>(scenario, PROXY_ADDR);
        clck.increment_for_testing(3 * 60 * 1000);

        let (_, _, _) = get_medical_record_test(
            &address_id,
            &clck,
            ADMINISTRATIVE_PERSONNEL_ADDR,
            &mut hospital_personnel_id_account,
            0,
            PATIENT_ADDR,
            &patient_id_account,
            &proxy_cap
        );

        test_scenario::return_shared(address_id);
        test_scenario::return_shared(hospital_personnel_id_account);
        test_scenario::return_shared(patient_id_account);
        test_scenario::return_shared(hospital_id_metadata);
        test_scenario::return_to_address(PROXY_ADDR, proxy_cap);
    };

    clck.destroy_for_testing();
    test_scenario::end(scenario_val);
}

#[test, expected_failure(abort_code = ::decmed::proxy::EAccessExpired)]
// Read access administratif part of medical record
// by administrative personnel when access expired
fun test_ill_02()
{
    let mut scenario_val = test_scenario::begin(PUBLISHER_ADDR);
    let scenario = &mut scenario_val;

    let mut clck = clock::create_for_testing(test_scenario::ctx(scenario));

    setup(test_scenario::ctx(scenario));

    test_scenario::next_tx(scenario, PATIENT_ADDR);

    {
        let mut metadata = vector::empty<String>();
        metadata.push_back(string::utf8(b"ReadAccessForAdmPersonnel"));

        create_access(
            &clck,
            ADMINISTRATIVE_PERSONNEL_ADDR,
            metadata,
            scenario
        );
    };

    test_scenario::next_tx(scenario, PROXY_ADDR);

    {
        let address_id = test_scenario::take_shared<AddressId>(scenario);
        let mut hospital_personnel_id_account = test_scenario::take_shared<HospitalPersonnelIdAccount>(scenario);
        let patient_id_account = test_scenario::take_shared<PatientIdAccount>(scenario);
        let hospital_id_metadata = test_scenario::take_shared<HospitalIdMetadata>(scenario);
        let proxy_cap = test_scenario::take_from_address<ProxyCap>(scenario, PROXY_ADDR);
        clck.increment_for_testing(10 * 60 * 1000);

        let _ = get_administrative_data_test(
            &address_id,
            &clck,
            ADMINISTRATIVE_PERSONNEL_ADDR,
            &mut hospital_personnel_id_account,
            PATIENT_ADDR,
            &patient_id_account,
            &proxy_cap
        );

        test_scenario::return_shared(address_id);
        test_scenario::return_shared(hospital_personnel_id_account);
        test_scenario::return_shared(patient_id_account);
        test_scenario::return_shared(hospital_id_metadata);
        test_scenario::return_to_address(PROXY_ADDR, proxy_cap);
    };

    clck.destroy_for_testing();
    test_scenario::end(scenario_val);
}

#[test, expected_failure(abort_code = ::decmed::proxy::EAccessNotFound)]
// Read access administratif part of medical record owned by
// patient who didn't give access. By administrative personnel
fun test_ill_03()
{
    let mut scenario_val = test_scenario::begin(PUBLISHER_ADDR);
    let scenario = &mut scenario_val;

    let mut clck = clock::create_for_testing(test_scenario::ctx(scenario));

    setup(test_scenario::ctx(scenario));

    test_scenario::next_tx(scenario, PATIENT_ADDR);

    {
        let mut metadata = vector::empty<String>();
        metadata.push_back(string::utf8(b"ReadAccessForAdmPersonnel"));

        create_access(
            &clck,
            ADMINISTRATIVE_PERSONNEL_ADDR,
            metadata,
            scenario
        );
    };

    test_scenario::next_tx(scenario, PROXY_ADDR);

    {
        let address_id = test_scenario::take_shared<AddressId>(scenario);
        let mut hospital_personnel_id_account = test_scenario::take_shared<HospitalPersonnelIdAccount>(scenario);
        let patient_id_account = test_scenario::take_shared<PatientIdAccount>(scenario);
        let hospital_id_metadata = test_scenario::take_shared<HospitalIdMetadata>(scenario);
        let proxy_cap = test_scenario::take_from_address<ProxyCap>(scenario, PROXY_ADDR);
        clck.increment_for_testing(3 * 60 * 1000);

        let _ = get_administrative_data_test(
            &address_id,
            &clck,
            ADMINISTRATIVE_PERSONNEL_ADDR,
            &mut hospital_personnel_id_account,
            PATIENT_2_ADDR,
            &patient_id_account,
            &proxy_cap
        );

        test_scenario::return_shared(address_id);
        test_scenario::return_shared(hospital_personnel_id_account);
        test_scenario::return_shared(patient_id_account);
        test_scenario::return_shared(hospital_id_metadata);
        test_scenario::return_to_address(PROXY_ADDR, proxy_cap);
    };

    clck.destroy_for_testing();
    test_scenario::end(scenario_val);
}
