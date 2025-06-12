/// Module: account
module account::account;

// == Notes ==
//
// The final hash of `id` will be done on-chain.


// == Module import. ==

use 0x1::hash::{sha2_256};
use 0x1::string::{Self, String};
use 0x2::clock::{Clock};
use 0x2::hex::{encode};
use 0x2::table::{Self, Table};

// == Constants. ==

const EActivationKeyAlreadyUsed: u64 = 4;
const EDuplicateAccount: u64 = 0;
const EDuplicateActivationKey: u64 = 2;
const EIllegalAction: u64 = 5;
const EInvalidCount: u64 = 1;
const EInvalidRoleType: u64 = 3;

// == Enums. ==

public enum DataAccessType has copy, drop, store {
    Administrative,
    Medical
}

public enum HospitalRole has copy, drop, store {
   Admin,
   AdministrativePersonnel,
   MedicalPersonnel,
}

// == Structs ==

public struct Access has copy, drop, store {
    access_type: DataAccessType,
    exp: u64,
}

public struct AccessQueue has copy, drop, store {
    data: vector<u8>
}

public struct AccountAddress has copy, drop, store {
    address: address,
}

public struct ActivationKey has copy, drop, store {
    key: String,
}

public struct ActivationKeyMetadata has copy, drop, store {
    is_used: bool,
    role: HospitalRole,
    hospital_id: String,
}

public struct AdminCap has key {
    id: UID,
}

public struct Administrative has copy, drop, store {
    private_data: vector<u8>,
    public_data: vector<u8>,
}

public struct ExpectedHospitalPersonnel has copy, drop, store {
    id: String
}

public struct GetPatientAccessLogResponse has copy, drop, store {
    hospital_personnel_id: String,
    hospital_personnel_data: vector<u8>,
    date: String,
}

public struct GlobalAdminAddKeyCap has key {
    id: UID,
}

public struct HospitalPersonnel has store {
    index: Table<String, u64>,
    metadata: vector<HospitalPersonnelMetadata>,
}

/**
* Attributes:
* - data: `key: delegator id`
*/
public struct HospitalPersonnelAccess has store {
    data: Table<String, Access>
}

public struct HospitalPersonnelMetadata has copy, drop, store {
    data: vector<u8>
}

public struct Id has copy, drop, store {
    id: String,
}

public struct MedicalMetadata has copy, drop, store {
    data: vector<u8>,
    index: u64,
}

public struct PatientAccessLog has copy, drop, store {
    date: String,
    hospital_personnel_id: String,
}

public struct ProxyAddressExist has copy, drop, store {
    ok: bool,
}

public struct ProxyCap has key {
    id: UID,
}

public struct RegisteredHospital has copy, drop, store {
    admin_id: String,
    hospital_name: Option<String>,
}

// == Functions. ==

entry fun cleanup_access_queue(
    address_id_table: &Table<address, Id>,
    id_access_queue_table: &mut Table<String, vector<AccessQueue>>,
    ctx: &TxContext,
)
{
    let sender_id = table::borrow(address_id_table, ctx.sender());
    table::remove(id_access_queue_table, sender_id.id);
}

entry fun create_account(
    address_id_table: &mut Table<address, Id>,
    id_address_table: &mut Table<String, AccountAddress>,
    id: String,
    ctx: &TxContext,
)
{
    assert!(!table::contains(id_address_table, id), EDuplicateAccount);

    let account_address = AccountAddress {
        address: ctx.sender()
    };
    table::add(id_address_table, id, account_address);

    let id = Id {
        id
    };
    table::add(address_id_table, ctx.sender(), id);
}

// called by patient
entry fun create_new_access(
    activation_key_activation_key_metadata_table: &Table<String, ActivationKeyMetadata>,
    address_id_table: &Table<address, Id>,
    clock: &Clock,
    date: String,
    hospital_personnel_hospital_part: String,
    hospital_personnel_id_part: String,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_hospital_personnel_access_table: &mut Table<String, HospitalPersonnelAccess>,
    id_patient_access_log_table: &mut Table<String, vector<PatientAccessLog>>,
    ctx: &mut TxContext,
)
{
    let patient_id = table::borrow(address_id_table, ctx.sender());

    let hospital_personnel_id = util_encode_hospital_personnel_id(hospital_personnel_hospital_part, hospital_personnel_id_part);
    let hospital_personnel_activation_key = table::borrow(id_activation_key_table, hospital_personnel_id);
    let hospital_personnel_activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, hospital_personnel_activation_key.key);

    assert!(hospital_personnel_activation_key_metadata.role != HospitalRole::Admin, EIllegalAction);

    let mut access_type = DataAccessType::Medical;
    if (hospital_personnel_activation_key_metadata.role == HospitalRole::AdministrativePersonnel) {
        access_type = DataAccessType::Administrative;
    };

    let exp = clock.timestamp_ms() + 1000 * 60 * 60 * 2; // two hours
    let access = Access {
        exp,
        access_type
    };

    if (table::contains(id_hospital_personnel_access_table, hospital_personnel_id)) {
        let hospital_personnel_access = table::borrow_mut(id_hospital_personnel_access_table, hospital_personnel_id);
        let hospital_personnel_access_table = &mut hospital_personnel_access.data;

        if (table::contains(hospital_personnel_access_table, patient_id.id)) {
            table::remove(hospital_personnel_access_table, patient_id.id);
        };

        table::add(hospital_personnel_access_table, patient_id.id, access);
    } else {
        let mut hospital_personnel_access_table = table::new<String, Access>(ctx);
        table::add(&mut hospital_personnel_access_table, patient_id.id, access);

        let hospital_personnel_access = HospitalPersonnelAccess {
          data: hospital_personnel_access_table
        };

        table::add(id_hospital_personnel_access_table, hospital_personnel_id, hospital_personnel_access);
    };

    // Add to log
    let new_patient_access_log_entry = PatientAccessLog {
        hospital_personnel_id,
        date
    };
    let patient_access_log = table::borrow_mut(id_patient_access_log_table, patient_id.id);
    vector::push_back(patient_access_log, new_patient_access_log_entry);
}

// called by medical personnel
entry fun create_new_medical_record(
    activation_key_activation_key_metadata_table: &Table<String, ActivationKeyMetadata>,
    address_id_table: &Table<address, Id>,
    data: vector<u8>,
    patient_id: String,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_medical_table: &mut Table<String, vector<MedicalMetadata>>,
    ctx: &TxContext,
)
{
    let medical_personnel_id = table::borrow(address_id_table, ctx.sender());
    let medical_personnel_activation_key = table::borrow(id_activation_key_table, medical_personnel_id.id);
    let medical_personnel_activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, medical_personnel_activation_key.key);

    assert!(medical_personnel_activation_key_metadata.role == HospitalRole::MedicalPersonnel, EIllegalAction);

    let mut medical_metadata = MedicalMetadata {
        index: 0,
        data
    };

    let patient_id = util_sha2_256_to_hex(patient_id.into_bytes());

    if (table::contains(id_medical_table, patient_id)) {
        let medical_metadata_vec = table::borrow_mut(id_medical_table, patient_id);
        medical_metadata.index = vector::length(medical_metadata_vec);
        vector::push_back(medical_metadata_vec, medical_metadata);
    } else {
        let mut medical_metadata_vec = vector::empty<MedicalMetadata>();
        vector::push_back(&mut medical_metadata_vec, medical_metadata);
        table::add(id_medical_table, patient_id, medical_metadata_vec);
    };
}

entry fun create_new_proxy_capability(
    proxy_address: address,
    proxy_address_table: &mut Table<address, ProxyAddressExist>,
    _: &GlobalAdminAddKeyCap,
    ctx: &mut TxContext
)
{
    table::add(proxy_address_table, proxy_address, ProxyAddressExist{ ok: true });
    transfer::transfer(ProxyCap { id: object::new(ctx) }, proxy_address);
}

entry fun get_access_queue(
    address_id_table: &Table<address, Id>,
    id_access_queue_table: &Table<String, vector<AccessQueue>>,
    ctx: &TxContext
): vector<AccessQueue>
{
    let sender_id = table::borrow(address_id_table, ctx.sender());

    if (table::contains(id_access_queue_table, sender_id.id)) {
        return *table::borrow(id_access_queue_table, sender_id.id)
    };

    vector::empty<AccessQueue>()
}

// Return: (profile_data, role: ['Admin', 'MedicalPersonnel', 'AdministrativePersonnel', 'Patient'], hospital_name)
entry fun get_administrative_data_hospital_personnel(
    activation_key_activation_key_metadata_table: &Table<String, ActivationKeyMetadata>,
    address_id_table: &Table<address, Id>,
    hospital_id_registered_hospital_table: &Table<String, RegisteredHospital>,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_administrative_table: &Table<String, Administrative>,
    ctx: &TxContext
): (Administrative, String, Option<String>)
{
    let hospital_personnel_id = table::borrow(address_id_table, ctx.sender());

    let activation_key = table::borrow(id_activation_key_table, hospital_personnel_id.id);
    let activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, activation_key.key);

    let hospital_name = table::borrow(hospital_id_registered_hospital_table, activation_key_metadata.hospital_id).hospital_name;

    let role = match (activation_key_metadata.role) {
        HospitalRole::Admin => string::utf8(b"Admin"),
        HospitalRole::AdministrativePersonnel => string::utf8(b"AdministrativePersonnel"),
        HospitalRole::MedicalPersonnel => string::utf8(b"MedicalPersonnel"),
    };

    (*table::borrow(id_administrative_table, hospital_personnel_id.id), role, hospital_name)
}

entry fun get_administrative_data_patient(
    address_id_table: &Table<address, Id>,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_administrative_table: &Table<String, Administrative>,
    ctx: &TxContext
): Administrative
{
    let patient_id = table::borrow(address_id_table, ctx.sender());
    assert!(!table::contains(id_activation_key_table, patient_id.id), EIllegalAction);
    *table::borrow(id_administrative_table, patient_id.id)
}

entry fun get_hospital_personnel(
    address_id_table: &Table<address, Id>,
    id_hospital_personnel_table: &Table<String, HospitalPersonnel>,
    ctx: &TxContext
): vector<HospitalPersonnelMetadata>
{
    let id = table::borrow(address_id_table, ctx.sender());
    table::borrow(id_hospital_personnel_table, id.id).metadata
}

/**
* Called by patient
* Return: (public_data, hospital_name)
*/
entry fun get_hospital_personnel_public_data(
    activation_key_activation_key_metadata_table: &Table<String,ActivationKeyMetadata>,
    hospital_id_registered_hospital_table: &Table<String, RegisteredHospital>,
    hospital_personnel_hospital_part: String,
    hospital_personnel_id_part: String,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_administrative_table: &Table<String, Administrative>,
    _ctx: &TxContext
): (vector<u8>, String)
{
    let hospital_personnel_id = util_encode_hospital_personnel_id(hospital_personnel_hospital_part, hospital_personnel_id_part);
    let public_data = table::borrow(id_administrative_table, hospital_personnel_id).public_data;

    let activation_key = table::borrow(id_activation_key_table, hospital_personnel_id);
    let activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, activation_key.key);

    let hospital_name = table::borrow(hospital_id_registered_hospital_table, activation_key_metadata.hospital_id).hospital_name;
    (public_data, *option::borrow(&hospital_name))
}

entry fun get_hospital_personnel_role(
    activation_key_activation_key_metadata_table: &Table<String, ActivationKeyMetadata>,
    address_id_table: &Table<address, Id>,
    id_activation_key_table: &Table<String, ActivationKey>,
    ctx: &TxContext
): String
{
    let id = table::borrow(address_id_table, ctx.sender());
    let activation_key = table::borrow(id_activation_key_table, id.id);
    let activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, activation_key.key);

    match (activation_key_metadata.role) {
        HospitalRole::Admin => return string::utf8(b"Admin"),
        HospitalRole::MedicalPersonnel => return string::utf8(b"MedicalPersonnel"),
        HospitalRole::AdministrativePersonnel => return string::utf8(b"AdministrativePersonnel"),
    }
}

entry fun get_medical_records(
    address_id_table: &Table<address, Id>,
    id_medical_table: &Table<String, vector<MedicalMetadata>>,
    ctx: &TxContext
): vector<MedicalMetadata>
{
    let id = table::borrow(address_id_table, ctx.sender());
    *table::borrow(id_medical_table, id.id)
}

// Only proxy can invoke this method
entry fun get_medical_record_medical_personnel(
    address_id_table: &Table<address, Id>,
    clock: &Clock,
    id_hospital_personnel_access_table: &Table<String, HospitalPersonnelAccess>,
    id_medical_table: &Table<String, vector<MedicalMetadata>>,
    index: u64,
    patient_id: String,
    _: &ProxyCap,
    ctx: &TxContext
): MedicalMetadata
{
    let medical_personnel_id = *table::borrow(address_id_table, ctx.sender());
    let medical_personnel_access_table = &table::borrow(id_hospital_personnel_access_table, medical_personnel_id.id).data;

    let patient_id = util_sha2_256_to_hex(patient_id.into_bytes());

    let access = table::borrow(medical_personnel_access_table, patient_id);

    assert!(
        access.access_type == DataAccessType::Medical &&
        access.exp >= clock.timestamp_ms(),
        EIllegalAction
    );

    let medical_metadata_vec = table::borrow(id_medical_table, patient_id);
    *vector::borrow(medical_metadata_vec, index)
}

entry fun get_medical_record_patient(
    address_id_table: &Table<address, Id>,
    id_medical_table: &Table<String, vector<MedicalMetadata>>,
    index: u64,
    ctx: &TxContext
): MedicalMetadata
{
    let patient_id = table::borrow(address_id_table, ctx.sender());
    let medical_metadata_vec = table::borrow(id_medical_table, patient_id.id);

    *vector::borrow(medical_metadata_vec, index)
}

entry fun get_patient_access_log(
    address_id_table: &Table<address, Id>,
    cursor: u64,
    count: u64,
    id_administrative_table: &Table<String, Administrative>,
    id_patient_access_log_table: &Table<String, vector<PatientAccessLog>>,
    ctx: &TxContext,
): vector<GetPatientAccessLogResponse>
{
    let patient_id = table::borrow(address_id_table, ctx.sender());
    let patient_access_log_vec = table::borrow(id_patient_access_log_table, patient_id.id);
    let total_count = vector::length(patient_access_log_vec);

    assert!(count > 0 && count <= 10 && cursor < total_count, EInvalidCount);

    let cursor = total_count - cursor;

    assert!(count <= cursor, EInvalidCount);

    let min_index = cursor - count;
    let mut current_index = cursor - 1;

    let mut response = vector::empty<GetPatientAccessLogResponse>();

    loop {
        let access_log = vector::borrow(patient_access_log_vec, cursor);
        let hospital_personnel_data = table::borrow(id_administrative_table, access_log.hospital_personnel_id);
        let res_entry = GetPatientAccessLogResponse {
            hospital_personnel_id: access_log.hospital_personnel_id,
            hospital_personnel_data: hospital_personnel_data.public_data,
            date: access_log.date,
        };
        vector::push_back(&mut response, res_entry);

        if (current_index == min_index) {
            break
        };

        current_index = current_index - 1;
    };

    response
}

entry fun global_admin_add_activation_key(
    activation_key: String,
    activation_key_activation_key_metadata_table: &mut Table<String, ActivationKeyMetadata>,
    hospital_id_registered_hospital_table: &mut Table<String, RegisteredHospital>,
    hospital_part: String,
    id_activation_key_table: &mut Table<String, ActivationKey>,
    id_part: String,
    _: &GlobalAdminAddKeyCap,
    _: &mut TxContext
)
{
    assert!(!table::contains(activation_key_activation_key_metadata_table, activation_key), EDuplicateActivationKey);

    let admin_id = util_encode_hospital_personnel_id(hospital_part, id_part);

    if (table::contains(id_activation_key_table, admin_id)) {
        let prev_activation_key = *table::borrow(id_activation_key_table, admin_id);
        table::remove(activation_key_activation_key_metadata_table, prev_activation_key.key);
        table::remove(id_activation_key_table, admin_id);
    };

    let hospital_id = util_sha2_256_to_hex(hospital_part.into_bytes());

    if (!table::contains(hospital_id_registered_hospital_table, hospital_id)) {
        let registered_hospital = RegisteredHospital {
            admin_id,
            hospital_name: option::none<String>(),
        };

        table::add(hospital_id_registered_hospital_table, hospital_id, registered_hospital);
    };

    let activation_key_metadata = ActivationKeyMetadata {
        is_used: false,
        role: HospitalRole::Admin,
        hospital_id
    };
    table::add(activation_key_activation_key_metadata_table, activation_key, activation_key_metadata);

    let activation_key = ActivationKey {
        key: activation_key
    };
    table::add(id_activation_key_table, admin_id, activation_key);
}

// We need to make sure that hospital admin
// only able to add activation key under their corresponding hospital.
entry fun hospital_admin_add_activation_key (
    activation_key: String,
    activation_key_activation_key_metadata_table: &mut Table<String, ActivationKeyMetadata>,
    address_id_table: &Table<address, Id>,
    data: vector<u8>,
    hospital_id_registered_hospital_table: &Table<String, RegisteredHospital>,
    id_activation_key_table: &mut Table<String, ActivationKey>,
    id_hospital_personnel_table: &mut Table<String, HospitalPersonnel>,
    personnel_hospital_part: String,
    personnel_id_part: String,
    role: String,
    ctx: &mut TxContext,
)
{
    let admin_id = table::borrow(address_id_table, ctx.sender());
    let admin_activation_key = table::borrow(id_activation_key_table, admin_id.id);
    let admin_activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, admin_activation_key.key);

    assert!(admin_activation_key_metadata.role == HospitalRole::Admin, EIllegalAction);
    assert!(!table::contains(activation_key_activation_key_metadata_table, activation_key), EDuplicateActivationKey);

    let hospital_id = util_sha2_256_to_hex(personnel_hospital_part.into_bytes());

    let registered_hospital = table::borrow(hospital_id_registered_hospital_table, hospital_id);
    assert!(registered_hospital.admin_id == admin_id.id, EIllegalAction);

    let personnel_id = util_encode_hospital_personnel_id(personnel_hospital_part, personnel_id_part);

    let mut role_type = HospitalRole::MedicalPersonnel;
    if (role.as_bytes() == b"AdministrativePersonnel") {
        role_type = HospitalRole::AdministrativePersonnel;
    } else if (role.as_bytes() != b"MedicalPersonnel") {
        assert!(false, EInvalidRoleType);
    };

    if (table::contains(id_activation_key_table, personnel_id)) {
        let prev_activation_key = table::borrow(id_activation_key_table, personnel_id);
        table::remove(activation_key_activation_key_metadata_table, prev_activation_key.key);
        table::remove(id_activation_key_table, personnel_id);
    };

    let activation_key_metadata = ActivationKeyMetadata {
        is_used: false,
        role: role_type,
        hospital_id,
    };
    table::add(activation_key_activation_key_metadata_table, activation_key, activation_key_metadata);

    let activation_key = ActivationKey {
        key: activation_key
    };
    table::add(id_activation_key_table, personnel_id, activation_key);

    let hospital_personnel_metadata = HospitalPersonnelMetadata {
        data
    };

    if (table::contains(id_hospital_personnel_table, admin_id.id)) {
        let hospital_personnel = table::borrow_mut(id_hospital_personnel_table, admin_id.id);

        vector::push_back(&mut hospital_personnel.metadata, hospital_personnel_metadata);
        let len = vector::length(&hospital_personnel.metadata);

        if (table::contains(&hospital_personnel.index, personnel_id)) {
            let index = table::borrow(&hospital_personnel.index, personnel_id);
            vector::swap(&mut hospital_personnel.metadata, *index, len - 1);
            vector::pop_back(&mut hospital_personnel.metadata);
        } else {
            table::add(&mut hospital_personnel.index, personnel_id, len - 1);
        };
    } else {
        let mut index_table = table::new<String, u64>(ctx);
        let mut metadata_vec = vector::empty<HospitalPersonnelMetadata>();

        vector::push_back(&mut metadata_vec, hospital_personnel_metadata);
        table::add(&mut index_table, personnel_id, vector::length(&metadata_vec) - 1);

        let hospital_personnel = HospitalPersonnel {
            index: index_table,
            metadata: metadata_vec
        };

        table::add(id_hospital_personnel_table, admin_id.id, hospital_personnel);
    }
}

fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap {
        id: object::new(ctx)
    }, ctx.sender());
    transfer::transfer(GlobalAdminAddKeyCap{
        id: object::new(ctx)
    }, ctx.sender());

    let activation_key_activation_key_metadata_table = table::new<String, ActivationKeyMetadata>(ctx);
    let address_id_table = table::new<address, Id>(ctx);
    let hospital_id_registered_hospital_table = table::new<String, RegisteredHospital>(ctx);
    let id_access_queue_table = table::new<String, vector<AccessQueue>>(ctx);
    let id_activation_key_table = table::new<String, ActivationKey>(ctx);
    let id_address_table = table::new<String, AccountAddress>(ctx);
    let id_administrative_table = table::new<String, Administrative>(ctx);
    let id_expected_hospital_personnel_table = table::new<String, ExpectedHospitalPersonnel>(ctx); // only for patient
    let id_hospital_personnel_access_table = table::new<String, Access>(ctx);
    let id_hospital_personnel_table = table::new<String, HospitalPersonnel>(ctx);
    let id_medical_table = table::new<String, vector<MedicalMetadata>>(ctx);
    let id_patient_access_log_table = table::new<String, vector<PatientAccessLog>>(ctx);
    let proxy_address_table = table::new<address, ProxyAddressExist>(ctx);

    transfer::public_share_object(activation_key_activation_key_metadata_table);
    transfer::public_share_object(address_id_table);
    transfer::public_share_object(id_access_queue_table);
    transfer::public_share_object(id_activation_key_table);
    transfer::public_share_object(id_address_table);
    transfer::public_share_object(id_administrative_table);
    transfer::public_share_object(id_expected_hospital_personnel_table);
    transfer::public_share_object(id_hospital_personnel_access_table);
    transfer::public_share_object(id_hospital_personnel_table);
    transfer::public_share_object(id_medical_table);
    transfer::public_share_object(hospital_id_registered_hospital_table);
    transfer::public_share_object(id_patient_access_log_table);
    transfer::public_share_object(proxy_address_table);
}

// Called by patient
entry fun init_access(
    activation_key_activation_key_metadata_table: &Table<String, ActivationKeyMetadata>,
    address_id_table: &Table<address, Id>,
    data: vector<u8>,
    hospital_personnel_hospital_part: String,
    hospital_personnel_id_part: String,
    id_access_queue_table: &mut Table<String, vector<AccessQueue>>,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_expected_hospital_personnel_table: &mut Table<String, ExpectedHospitalPersonnel>,
    ctx: &TxContext,
)
{
    // Make sure only patient can use this method
    let patient_id = table::borrow(address_id_table, ctx.sender());
    assert!(!table::contains(id_activation_key_table, patient_id.id), EIllegalAction);

    let hospital_personnel_id = util_encode_hospital_personnel_id(hospital_personnel_hospital_part, hospital_personnel_id_part);

    let hospital_personnel_activation_key = table::borrow(id_activation_key_table, hospital_personnel_id);
    let hospital_personnel_activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, hospital_personnel_activation_key.key);

    assert!(
        hospital_personnel_activation_key_metadata.role == HospitalRole::MedicalPersonnel ||
        hospital_personnel_activation_key_metadata.role == HospitalRole::AdministrativePersonnel,
        EIllegalAction
    );

    let access_queue = AccessQueue {
        data
    };

    if (table::contains(id_access_queue_table, hospital_personnel_id)) {
        let access_queue_vec = table::borrow_mut(id_access_queue_table, hospital_personnel_id);
        vector::push_back(access_queue_vec, access_queue);
    } else {
        let mut access_queue_vec = vector::empty<AccessQueue>();
        vector::push_back(&mut access_queue_vec, access_queue);
        table::add(id_access_queue_table, hospital_personnel_id, access_queue_vec);
    };

    if (table::contains(id_expected_hospital_personnel_table, patient_id.id)) {
        table::remove(id_expected_hospital_personnel_table, patient_id.id);
    };

    let expected_delegatee_data = ExpectedHospitalPersonnel {
        id: hospital_personnel_id
    };
    table::add(id_expected_hospital_personnel_table, patient_id.id, expected_delegatee_data);
}

// called by proxy_reencryption
entry fun is_access_exist(
    access_type: String,
    clock: &Clock,
    hospital_personnel_hospital_part: String,
    hospital_personnel_id_part: String,
    id_hospital_personnel_access_table: &Table<String, HospitalPersonnelAccess>,
    patient_id: String,
    _: &ProxyCap,
    _ctx: &TxContext,
): bool
{
    let hospital_personnel_id = util_encode_hospital_personnel_id(hospital_personnel_hospital_part, hospital_personnel_id_part);
    let patient_id = util_sha2_256_to_hex(patient_id.into_bytes());

    let hospital_personnel_access_table = &table::borrow(id_hospital_personnel_access_table, hospital_personnel_id).data;
    let access = table::borrow(hospital_personnel_access_table, patient_id);

    let mut acc_type = DataAccessType::Medical;
    if (access_type.as_bytes() == b"Administrative") {
        acc_type = DataAccessType::Administrative;
    } else if (access_type.as_bytes() != b"Medical") {
        return false
    };

    access.exp > clock.timestamp_ms() && access.access_type == acc_type
}

// For signin
// Return: is_hospital_account
entry fun is_account_registered(
    address_id_table: &Table<address, Id>,
    ctx: &TxContext
): bool
{
    table::contains(address_id_table, ctx.sender())
}

// return type: (
//  is_activation_key_exist: bool,
//  is_id_registered: bool
// )
entry fun is_activation_key_id_registered(
    hospital_personnel_hospital_part: String,
    hospital_personnel_id_part: String,
    id_activation_key_table: &Table<String,ActivationKey>,
    id_address_table: &Table<String, AccountAddress>,
    _ctx: &TxContext,
): (bool, bool)
{
    let hospital_personnel_id = util_encode_hospital_personnel_id(hospital_personnel_hospital_part, hospital_personnel_id_part);

    (
        table::contains(id_activation_key_table, hospital_personnel_id),
        table::contains(id_address_table, hospital_personnel_id),
    )
}

// for signup patient
entry fun is_id_registered(
    id_address_table: &Table<String, AccountAddress>,
    patient_id: String,
    _: &TxContext,
): bool
{
    let patient_id = util_sha2_256_to_hex(patient_id.into_bytes());
    table::contains(id_address_table, patient_id)
}

entry fun register_hospital_personnel(
    address_id_table: &mut Table<address, Id>,
    hospital_personnel_hospital_part: String,
    hospital_personnel_id_part: String,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_address_table: &mut Table<String, AccountAddress>,
    id_administrative_table: &mut Table<String, Administrative>,
    private_data: vector<u8>,
    public_data: vector<u8>,
    ctx: &TxContext,
)
{
    let hospital_personnel_id = util_encode_hospital_personnel_id(hospital_personnel_hospital_part, hospital_personnel_id_part);

    assert!(table::contains(id_activation_key_table, hospital_personnel_id), EIllegalAction);

    create_account(
        address_id_table,
        id_address_table,
        hospital_personnel_id,
        ctx
    );
    update_administrative_data(
        address_id_table,
        id_administrative_table,
        private_data,
        public_data,
        ctx
    );
}

entry fun register_patient(
    address_id_table: &mut Table<address, Id>,
    patient_id: String,
    id_address_table: &mut Table<String, AccountAddress>,
    id_administrative_table: &mut Table<String, Administrative>,
    private_data: vector<u8>,
    public_data: vector<u8>,
    ctx: &TxContext,
)
{
    let patient_id = util_sha2_256_to_hex(patient_id.into_bytes());
    create_account(
        address_id_table,
        id_address_table,
        patient_id,
        ctx
    );
    update_administrative_data(
        address_id_table,
        id_administrative_table,
        private_data,
        public_data,
        ctx
    );
}

// Called by hospital personnels
entry fun request_access(
    address_id_table: &Table<address, Id>,
    data: vector<u8>,
    id_access_queue_table: &mut Table<String, vector<AccessQueue>>,
    id_activation_key_table: &Table<String, ActivationKey>,
    id_expected_hospital_personnel_table: &Table<String, ExpectedHospitalPersonnel>,
    patient_id: String,
    ctx: &TxContext
)
{
    // Make sure sender is the expected hospital personnel
    let patient_id = util_sha2_256_to_hex(patient_id.into_bytes());
    let hospital_personnel_id = table::borrow(address_id_table, ctx.sender());
    let expected_hospital_personnel = table::borrow(id_expected_hospital_personnel_table, patient_id);
    assert!(expected_hospital_personnel.id == hospital_personnel_id.id, EIllegalAction);

    // Make sure delegator is patient
    assert!(!table::contains(id_activation_key_table, patient_id), EIllegalAction);

    let access_queue = AccessQueue {
        data
    };

    if (table::contains(id_access_queue_table, patient_id)) {
        let access_queue_vec = table::borrow_mut(id_access_queue_table, patient_id);
        vector::push_back(access_queue_vec, access_queue);
    } else {
        let mut access_queue_vec = vector::empty<AccessQueue>();
        vector::push_back(&mut access_queue_vec, access_queue);
        table::add(id_access_queue_table, patient_id, access_queue_vec);
    };
}

entry fun update_administrative_data(
    address_id_table: &Table<address, Id>,
    id_administrative_table: &mut Table<String, Administrative>,
    private_data: vector<u8>,
    public_data: vector<u8>,
    ctx: &TxContext,
)
{
    let id = *table::borrow(address_id_table, ctx.sender());

    if (table::contains(id_administrative_table, id.id)) {
        table::remove(id_administrative_table, id.id);
    };

    let administrative_data = Administrative {
        private_data,
        public_data
    };
    table::add(id_administrative_table, id.id, administrative_data);
}

entry fun update_registered_hospital_data(
    activation_key_activation_key_metadata_table: &Table<String, ActivationKeyMetadata>,
    address_id_table: &Table<address, Id>,
    hospital_id_registered_hospital_table: &mut Table<String, RegisteredHospital>,
    hospital_name: String,
    id_activation_key_table: &Table<String, ActivationKey>,
    ctx: &TxContext,
)
{
    let admin_id = table::borrow(address_id_table, ctx.sender());
    let activation_key = table::borrow(id_activation_key_table, admin_id.id);
    let activation_key_metadata = table::borrow(activation_key_activation_key_metadata_table, activation_key.key);

    assert!(activation_key_metadata.role == HospitalRole::Admin, EIllegalAction);

    let hospital_id = activation_key_metadata.hospital_id;

    let registered_hospital = table::borrow_mut(hospital_id_registered_hospital_table, hospital_id);
    registered_hospital.hospital_name = option::some(hospital_name);
}

entry fun use_activation_key(
    activation_key: String,
    activation_key_activation_key_metadata_table: &mut Table<String, ActivationKeyMetadata>,
    _: &TxContext,
)
{
    let prev_activation_key_metadata = table::borrow_mut(activation_key_activation_key_metadata_table, activation_key);
    assert!(!prev_activation_key_metadata.is_used, EActivationKeyAlreadyUsed);
    prev_activation_key_metadata.is_used = true;
}

fun util_encode_hospital_personnel_id(
    hospital_part: String,
    id_part: String,
): String
{
    let mut id = string::utf8(b"");
    id.append(id_part);
    id.append(hospital_part);

    util_sha2_256_to_hex(id.into_bytes())
}

fun util_sha2_256_to_hex(
    data: vector<u8>
): String
{
    let res = sha2_256(data);
    let res = encode(res);

    string::utf8(res)
}
