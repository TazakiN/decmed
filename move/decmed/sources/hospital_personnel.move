module decmed::hospital_personnel;

use decmed::std_enum_hospital_personnel_role::{
    HospitalPersonnelRole,
    admin as hospital_personnel_role_admin,
    administrative_personnel as hospital_personnel_role_admin_administrative_personnel,
    medical_personnel as hospital_personnel_role_medical_personnel,
};

use decmed::std_enum_hospital_personnel_sub_role::{
    HospitalPersonnelSubRole,
    doctor as hospital_personnel_sub_role_doctor,
    nurse as hospital_personnel_sub_role_nurse,
    laboratory_staff as hospital_personnel_sub_role_laboratory_staff,
    pharmacist as hospital_personnel_sub_role_pharmacist,
};

use decmed::shared::{
    encode_hospital_id,
    encode_hospital_personnel_id,
};

use decmed::std_struct_address_id::AddressId;
use decmed::std_struct_hospital_id_metadata::HospitalIdMetadata;
use decmed::std_struct_hospital_metadata::HospitalMetadata;
use decmed::std_struct_hospital_personnel_access::{
    new as hospital_personnel_access_new,
};
use decmed::std_struct_hospital_personnel_access_data::{
    HospitalPersonnelAccessData,
    borrow_delegation_depth as hospital_personnel_access_data_borrow_delegation_depth,
    new_delegated as hospital_personnel_access_data_new_delegated,
};
use decmed::std_struct_hospital_personnel_account::{
    HospitalPersonnelAccount,
    new as hospital_personnel_account_new,
};
use decmed::std_struct_hospital_personnel_administrative_metadata::{
    HospitalPersonnelAdministrativeMetadata,
    new as hospital_personnel_administrative_metadata_new,
};
use decmed::std_struct_hospital_personnel_id_account::HospitalPersonnelIdAccount;
use decmed::std_struct_hospital_personnel_metadata::{
    HospitalPersonnelMetadata,
    new as hospital_personnel_metadata_new,
};
use decmed::std_struct_patient_id_account::PatientIdAccount;
use decmed::std_struct_patient_medical_metadata::{
    new as patient_medical_metadata_new,
};

use decmed::std_enum_hospital_personnel_access_data_type::{
    administrative as hospital_personnel_access_data_type_administrative,
    medical as hospital_personnel_access_data_type_medical,
};

use iota::clock::Clock;
use iota::event;
use iota::vec_map;

use std::string::{String};

// Constants

const EAccountAlreadyRegistered: u64 = 2000;
const EAccountNotActivated: u64 = 2001;
const EAccountNotFound: u64 = 2002;
const EActivationKeyAlreadyUsed: u64 = 2003;
const EAddressAlreadyRegistered: u64 = 2004;
const EIllegalActionAccessExpired: u64 = 2005;
const EIllegalActionInvalidRole: u64 = 2006;
const EIllegalActionNoUpdateAccess: u64 = 2007;
const EInvalidActivationKey: u64 = 2008;
const EInvalidHospitalPersonnelRole: u64 = 2009;
const EPatientNotFound: u64 = 2010;
const EDelegatorNoAccess: u64 = 2011;
const EDifferentHospital: u64 = 2012;
const EDelegateeNotFound: u64 = 2013;
const EInvalidMetadataLength: u64 = 2014;
const EAccessExpired: u64 = 2015;
const EInvalidHospitalPersonnelSubRole: u64 = 2016;
const ESubRoleRequiredForMedicalPersonnel: u64 = 2017;
const ESubRoleNotAllowedForNonMedicalPersonnel: u64 = 2018;
const EInvalidAccessType: u64 = 2019;

// Structs

/// Emitted when a delegator revokes delegated access for a patient.
public struct DelegationRevokedEvent has copy, drop, store {
    patient_address: address,
    revoker: address,
    delegatee_address: address,
    access_type: vector<u8>,
    related_rme_id: Option<String>,
    revoked_at_ms: u64,
}

public struct DelegateeCandidate has copy, drop, store {
    personnel_id_hash: String,
    address: address,
    role: HospitalPersonnelRole,
    sub_role: Option<HospitalPersonnelSubRole>,
    public_metadata: String,
}

// Functions

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
entry fun cleanup_read_access(
    activation_key: String,
    address_id: &AddressId,
    clock: &Clock,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);

    let hospital_personnel_access = hospital_personnel_account.borrow_mut_access().borrow_mut();
    let hospital_personnel_read_access = hospital_personnel_access.borrow_read();

    let mut cnt = 0;
    let len = hospital_personnel_read_access.size();
    let current_time = clock.timestamp_ms();

    let mut hospital_personnel_read_access_new = vec_map::empty<String, HospitalPersonnelAccessData>();

    while (cnt < len) {
        let (patient_id, access) = hospital_personnel_read_access.get_entry_by_idx(cnt);

        if (access.borrow_exp() < current_time) {
            cnt = cnt + 1;
            continue
        };

        hospital_personnel_read_access_new.insert(*patient_id, *access);
        cnt = cnt + 1;
    };

    hospital_personnel_access.set_read(hospital_personnel_read_access_new);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
entry fun cleanup_update_access(
    activation_key: String,
    address_id: &AddressId,
    clock: &Clock,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);

    let hospital_personnel_access = hospital_personnel_account.borrow_mut_access().borrow_mut();
    let hospital_personnel_update_access = hospital_personnel_access.borrow_update();

    let mut cnt = 0;
    let len = hospital_personnel_update_access.size();
    let current_time = clock.timestamp_ms();

    let mut hospital_personnel_update_access_new = vec_map::empty<String, HospitalPersonnelAccessData>();

    while (cnt < len) {
        let (patient_id, access) = hospital_personnel_update_access.get_entry_by_idx(cnt);

        if (access.borrow_exp() < current_time) {
            cnt = cnt + 1;
            continue
        };

        hospital_personnel_update_access_new.insert(*patient_id, *access);
        cnt = cnt + 1;
    };

    hospital_personnel_access.set_update(hospital_personnel_update_access_new);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `id`: argon_hash(raw_id)
/// - `metadata`: Base64
/// - `role`: raw_role ["Admin", "AdministrativePersonnel", "MedicalPersonnel"]
/// - `sub_role`: raw_sub_role bytes; required when `role` is "MedicalPersonnel"
///     - ["DOCTOR", "NURSE", "LABORATORY_STAFF", "PHARMACIST"]
///     - empty bytes (b"") when `role` is not "MedicalPersonnel"
entry fun create_activation_key(
    address_id: &AddressId,
    admin_activation_key: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    metadata: String,
    personnel_activation_key: String,
    personnel_id: String,
    role: vector<u8>,
    sub_role: vector<u8>,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let hospital_admin_id = *address_id_table.borrow(ctx.sender());
    let hopsital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_admin_account = hopsital_personnel_id_account_table.borrow(hospital_admin_id);

    require_account_activation(admin_activation_key, hospital_admin_account);

    assert!(hospital_admin_account.borrow_role() == hospital_personnel_role_admin(), EIllegalActionInvalidRole);

    let hospital_personnel_id = encode_hospital_personnel_id(*hospital_admin_account.borrow_hospital_id(), personnel_id);

    assert!(!hopsital_personnel_id_account_table.contains(hospital_personnel_id), EAccountAlreadyRegistered);

    let role = match (role) {
        b"AdministrativePersonnel" => hospital_personnel_role_admin_administrative_personnel(),
        b"MedicalPersonnel" => hospital_personnel_role_medical_personnel(),
        _ => return assert!(false, EInvalidHospitalPersonnelRole)
    };

    let sub_role_opt = resolve_sub_role(role, sub_role);

    let account = hospital_personnel_account_new(
        option::none(),
        personnel_activation_key,
        option::none(),
        option::none(),
        *hospital_admin_account.borrow_hospital_id(),
        false,
        false,
        option::none(),
        role,
        sub_role_opt,
    );

    hopsital_personnel_id_account_table.add(hospital_personnel_id, account);

    let hospital_admin_account = hopsital_personnel_id_account_table.borrow_mut(hospital_admin_id);

    let hospital_admin_account_personnels = hospital_admin_account.borrow_mut_personnels().borrow_mut();
    let personnel_metadata = hospital_personnel_metadata_new(metadata);

    hospital_admin_account_personnels.insert(hospital_personnel_id, personnel_metadata);
}

#[test_only]
public(package) fun create_activation_key_test(
    address_id: &AddressId,
    admin_activation_key: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    metadata: String,
    personnel_activation_key: String,
    personnel_id: String,
    role: vector<u8>,
    sub_role: vector<u8>,
    ctx: &TxContext,
)
{
    create_activation_key(
        address_id,
        admin_activation_key,
        hospital_personnel_id_account,
        metadata,
        personnel_activation_key,
        personnel_id,
        role,
        sub_role,
        ctx
    );
}

/// Validates and converts the raw `sub_role` bytes into an `Option<HospitalPersonnelSubRole>`.
/// - When `role` is `MedicalPersonnel`, `sub_role` MUST be one of the supported values.
/// - When `role` is not `MedicalPersonnel`, `sub_role` MUST be empty.
fun resolve_sub_role(
    role: HospitalPersonnelRole,
    sub_role: vector<u8>,
): Option<HospitalPersonnelSubRole>
{
    if (role == hospital_personnel_role_medical_personnel()) {
        assert!(!sub_role.is_empty(), ESubRoleRequiredForMedicalPersonnel);
        let sub_role_enum = match (sub_role) {
            b"DOCTOR" => hospital_personnel_sub_role_doctor(),
            b"NURSE" => hospital_personnel_sub_role_nurse(),
            b"LABORATORY_STAFF" => hospital_personnel_sub_role_laboratory_staff(),
            b"PHARMACIST" => hospital_personnel_sub_role_pharmacist(),
            _ => abort EInvalidHospitalPersonnelSubRole
        };
        option::some(sub_role_enum)
    } else {
        assert!(sub_role.is_empty(), ESubRoleNotAllowedForNonMedicalPersonnel);
        option::none<HospitalPersonnelSubRole>()
    }
}

/// ## Params:
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `metadata`: Base64 decoded string
entry fun create_medical_record(
    activation_key: String,
    address_id: &AddressId,
    clock: &Clock,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    metadata: String,
    patient_address: address,
    patient_id_account: &mut PatientIdAccount,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();

    assert!(address_id_table.contains(patient_address), EPatientNotFound);

    let patient_id = address_id_table.borrow(patient_address);

    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);

    let hospital_personnel_access = hospital_personnel_account.borrow_mut_access().borrow_mut();
    let hospital_personnel_update_access = hospital_personnel_access.borrow_mut_update();

    assert!(hospital_personnel_update_access.contains(patient_id), EIllegalActionNoUpdateAccess);

    let access = hospital_personnel_update_access.get(patient_id);

    if (access.borrow_exp() < clock.timestamp_ms()) {
        hospital_personnel_update_access.remove(patient_id);
        assert!(false, EIllegalActionAccessExpired);
    };

    let patient_id_account_table = patient_id_account.borrow_mut_table();
    let patient_account = patient_id_account_table.borrow_mut(*patient_id);
    let patient_medical_metadata = patient_account.borrow_mut_medical_metadata();

    let medical_metadata = patient_medical_metadata_new(patient_medical_metadata.length(), metadata);
    patient_medical_metadata.push_back(medical_metadata);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `hospital_id`: argon_hash(raw_hospital_id)
/// - `personel_id`: argon_hash(raw_id)
entry fun delete_hospital_personnel(
    activation_key: String,
    address_id: &mut AddressId,
    hospital_id: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    personnel_id: String,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_mut_table();

    let hospital_admin_id = *address_id_table.borrow(ctx.sender());

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_admin_account = hospital_personnel_id_account_table.borrow(hospital_admin_id);

    assert!(hospital_admin_account.borrow_role() == hospital_personnel_role_admin(), EIllegalActionInvalidRole);
    require_account_activation(activation_key, hospital_admin_account);

    let hospital_id = encode_hospital_id(hospital_id);
    let hospital_personnel_id = encode_hospital_personnel_id(hospital_id, personnel_id);
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);

    address_id_table.remove(*hospital_personnel_account.borrow_address().borrow());

    let hospital_admin_account = hospital_personnel_id_account_table.borrow_mut(hospital_admin_id);
    let hospital_admin_personnels = hospital_admin_account.borrow_mut_personnels().borrow_mut();
    assert!(hospital_admin_personnels.contains(&hospital_personnel_id), EAccountNotFound);

    hospital_admin_personnels.remove(&hospital_personnel_id);
    hospital_personnel_id_account_table.remove(hospital_personnel_id);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
entry fun get_account_info(
    activation_key: String,
    address_id: &AddressId,
    hospital_id_metadata: &HospitalIdMetadata,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    ctx: &TxContext,
): (Option<HospitalPersonnelAdministrativeMetadata>, HospitalPersonnelRole, HospitalMetadata, Option<HospitalPersonnelSubRole>)
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);

    let hospital_id_metadata_table = hospital_id_metadata.borrow_table();
    let hospital_id_metadata_vec = hospital_id_metadata.borrow_vec();
    let hospital_metadata_index = *hospital_id_metadata_table.borrow(*hospital_personnel_account.borrow_hospital_id());
    let hospital_metadata = hospital_id_metadata_vec.borrow(hospital_metadata_index).borrow_hospital_metadata();

    (
        *hospital_personnel_account.borrow_administrative_metadata(),
        *hospital_personnel_account.borrow_role(),
        *hospital_metadata,
        *hospital_personnel_account.borrow_sub_role(),
    )
}


/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `hospital_id`: argon_hash(raw_hospital_id)
/// - `personel_id`: argon_hash(raw_id)
///
/// ## Return:
/// 0: state_code
///     - 0 means need activation
///     - 1 means need signup
///     - 2 means need profile completion
///     - 3 means no action
entry fun get_account_state(
    activation_key: String,
    hospital_id: String,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    personnel_id: String,
): (u64, Option<HospitalPersonnelRole>)
{
    let hospital_id = encode_hospital_id(hospital_id);
    let hospital_personnel_id = encode_hospital_personnel_id(hospital_id, personnel_id);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();

    if (!hospital_personnel_id_account_table.contains(hospital_personnel_id)) {
        return (0, option::none())
    };

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);

    if (*hospital_personnel_account.borrow_activation_key() != activation_key || !hospital_personnel_account.borrow_is_activation_key_used()) {
        return (0, option::none())
    };

    if (hospital_personnel_account.borrow_address().is_none()) {
        return (1, option::none())
    };

    if (!hospital_personnel_account.borrow_is_profile_completed()) {
        return (2, option::none())
    };

    (3, option::some(*hospital_personnel_account.borrow_role()))
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
entry fun get_hospital_personnels(
    activation_key: String,
    address_id: &AddressId,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    ctx: &TxContext,
): vector<HospitalPersonnelMetadata>
{
    let address_id_table = address_id.borrow_table();
    let hospital_admin_id = *address_id_table.borrow(ctx.sender());

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    let hospital_admin_account = hospital_personnel_id_account_table.borrow(hospital_admin_id);

    require_account_activation(activation_key, hospital_admin_account);

    let hospital_admin_personnels = *hospital_admin_account.borrow_personnels().borrow();
    let (_, personnels) = hospital_admin_personnels.into_keys_values();

    personnels
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `admin_personnel_id`: argon_hash("admin")
entry fun get_delegatee_candidates(
    activation_key: String,
    admin_personnel_id: String,
    address_id: &AddressId,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    ctx: &TxContext,
): vector<DelegateeCandidate>
{
    let address_id_table = address_id.borrow_table();
    let caller_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    let caller_account = hospital_personnel_id_account_table.borrow(caller_personnel_id);

    require_account_activation(activation_key, caller_account);

    let caller_hospital_id = *caller_account.borrow_hospital_id();
    let hospital_admin_id = encode_hospital_personnel_id(caller_hospital_id, admin_personnel_id);

    assert!(hospital_personnel_id_account_table.contains(hospital_admin_id), EAccountNotFound);

    let hospital_admin_account = hospital_personnel_id_account_table.borrow(hospital_admin_id);
    let hospital_admin_personnels = hospital_admin_account.borrow_personnels().borrow();
    let mut candidates = vector::empty<DelegateeCandidate>();
    let mut cnt = 0;
    let len = hospital_admin_personnels.size();

    while (cnt < len) {
        let (candidate_personnel_id, _) = hospital_admin_personnels.get_entry_by_idx(cnt);
        let candidate_personnel_id = *candidate_personnel_id;

        if (
            candidate_personnel_id != caller_personnel_id &&
            hospital_personnel_id_account_table.contains(candidate_personnel_id)
        ) {
            let candidate_account = hospital_personnel_id_account_table.borrow(candidate_personnel_id);
            if (
                *candidate_account.borrow_hospital_id() == caller_hospital_id &&
                candidate_account.borrow_is_activation_key_used() &&
                candidate_account.borrow_is_profile_completed() &&
                candidate_account.borrow_address().is_some() &&
                candidate_account.borrow_administrative_metadata().is_some()
            ) {
                let administrative_metadata = candidate_account.borrow_administrative_metadata().borrow();
                candidates.push_back(DelegateeCandidate {
                    personnel_id_hash: candidate_personnel_id,
                    address: *candidate_account.borrow_address().borrow(),
                    role: *candidate_account.borrow_role(),
                    sub_role: *candidate_account.borrow_sub_role(),
                    public_metadata: *administrative_metadata.borrow_public_metadata(),
                });
            };
        };

        cnt = cnt + 1;
    };

    candidates
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
entry fun get_read_access(
    activation_key: String,
    address_id: &AddressId,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    ctx: &TxContext,
): vector<HospitalPersonnelAccessData>
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);

    let hospital_personnel_access = hospital_personnel_account.borrow_access().borrow();
    let hospital_personnel_read_access = *hospital_personnel_access.borrow_read();
    let (_, res) = hospital_personnel_read_access.into_keys_values();

    res
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
entry fun get_update_access(
    activation_key: String,
    address_id: &AddressId,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    ctx: &TxContext,
): vector<HospitalPersonnelAccessData>
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);

    let hospital_personnel_access = hospital_personnel_account.borrow_access().borrow();
    let hospital_personnel_update_access = *hospital_personnel_access.borrow_update();
    let (_, res) = hospital_personnel_update_access.into_keys_values();

    res
}

/// Delegator grants attenuated access to another personnel in the same hospital.
entry fun create_delegated_access(
    activation_key: String,
    address_id: &AddressId,
    clock: &Clock,
    delegatee_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    patient_address: address,
    metadata: vector<String>,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let delegator_address = ctx.sender();
    let delegator_personnel_id = *address_id_table.borrow(delegator_address);
    let delegatee_personnel_id = *address_id_table.borrow(delegatee_address);
    let patient_id = *address_id_table.borrow(patient_address);

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let current_time = clock.timestamp_ms();

    if (metadata.length() == 1) {
        let read_access_data_types;
        let read_exp;
        let delegation_depth;
        {
            let delegator_account = hospital_personnel_id_account_table.borrow(delegator_personnel_id);
            require_account_activation(activation_key, delegator_account);

            assert!(
                hospital_personnel_id_account_table.contains(delegatee_personnel_id),
                EDelegateeNotFound,
            );
            let delegatee_account = hospital_personnel_id_account_table.borrow(delegatee_personnel_id);
            assert!(delegatee_account.borrow_is_activation_key_used(), EAccountNotActivated);

            assert!(
                *delegator_account.borrow_hospital_id() == *delegatee_account.borrow_hospital_id(),
                EDifferentHospital,
            );

            let delegator_access = delegator_account.borrow_access().borrow();
            let delegator_read = delegator_access.borrow_read();
            assert!(delegator_read.contains(&patient_id), EDelegatorNoAccess);
            let source = delegator_read.get(&patient_id);
            assert!(source.borrow_exp() >= current_time, EAccessExpired);

            read_access_data_types = *source.borrow_access_data_types();
            read_exp = source.borrow_exp();
            delegation_depth = hospital_personnel_access_data_borrow_delegation_depth(source) + 1;
        };

        let delegatee_account = hospital_personnel_id_account_table.borrow_mut(delegatee_personnel_id);
        let delegatee_access = delegatee_account.borrow_mut_access().borrow_mut();
        let delegatee_read = delegatee_access.borrow_mut_read();
        if (delegatee_read.contains(&patient_id)) {
            delegatee_read.remove(&patient_id);
        };

        let delegated = hospital_personnel_access_data_new_delegated(
            read_access_data_types,
            read_exp,
            *metadata.borrow(0),
            option::none(),
            delegator_address,
            delegation_depth,
        );
        delegatee_read.insert(patient_id, delegated);
    } else if (metadata.length() == 2) {
        let mut read_access_data_types;
        let read_exp;
        let mut update_access_data_types;
        let update_exp;
        let delegation_depth;
        {
            let delegator_account = hospital_personnel_id_account_table.borrow(delegator_personnel_id);
            require_account_activation(activation_key, delegator_account);

            assert!(
                hospital_personnel_id_account_table.contains(delegatee_personnel_id),
                EDelegateeNotFound,
            );
            let delegatee_account = hospital_personnel_id_account_table.borrow(delegatee_personnel_id);
            assert!(delegatee_account.borrow_is_activation_key_used(), EAccountNotActivated);

            assert!(
                *delegator_account.borrow_hospital_id() == *delegatee_account.borrow_hospital_id(),
                EDifferentHospital,
            );

            let delegator_access = delegator_account.borrow_access().borrow();
            let delegator_read = delegator_access.borrow_read();
            let delegator_update = delegator_access.borrow_update();
            assert!(delegator_read.contains(&patient_id), EDelegatorNoAccess);
            assert!(delegator_update.contains(&patient_id), EDelegatorNoAccess);

            let source_read = delegator_read.get(&patient_id);
            let source_update = delegator_update.get(&patient_id);
            assert!(source_read.borrow_exp() >= current_time, EAccessExpired);
            assert!(source_update.borrow_exp() >= current_time, EAccessExpired);

            read_access_data_types = *source_read.borrow_access_data_types();
            read_exp = source_read.borrow_exp();
            update_access_data_types = *source_update.borrow_access_data_types();
            update_exp = source_update.borrow_exp();
            delegation_depth = hospital_personnel_access_data_borrow_delegation_depth(source_read) + 1;

            if (*delegator_account.borrow_role() == hospital_personnel_role_admin_administrative_personnel()) {
                read_access_data_types = vector::empty();
                read_access_data_types.push_back(hospital_personnel_access_data_type_medical());
                read_access_data_types.push_back(hospital_personnel_access_data_type_administrative());
                update_access_data_types = vector::empty();
                update_access_data_types.push_back(hospital_personnel_access_data_type_medical());
            };
        };

        let delegatee_account = hospital_personnel_id_account_table.borrow_mut(delegatee_personnel_id);
        let delegatee_access = delegatee_account.borrow_mut_access().borrow_mut();

        let delegatee_read = delegatee_access.borrow_mut_read();
        if (delegatee_read.contains(&patient_id)) {
            delegatee_read.remove(&patient_id);
        };
        let delegated_read = hospital_personnel_access_data_new_delegated(
            read_access_data_types,
            read_exp,
            *metadata.borrow(0),
            option::none(),
            delegator_address,
            delegation_depth,
        );
        delegatee_read.insert(patient_id, delegated_read);

        let delegatee_update = delegatee_access.borrow_mut_update();
        if (delegatee_update.contains(&patient_id)) {
            delegatee_update.remove(&patient_id);
        };
        let delegated_update = hospital_personnel_access_data_new_delegated(
            update_access_data_types,
            update_exp,
            *metadata.borrow(1),
            option::none(),
            delegator_address,
            delegation_depth,
        );
        delegatee_update.insert(patient_id, delegated_update);
    } else {
        abort EInvalidMetadataLength
    };
}

entry fun revoke_delegated_access(
    activation_key: String,
    address_id: &AddressId,
    clock: &Clock,
    delegatee_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    patient_address: address,
    access_type: vector<u8>,
    related_rme_id: Option<String>,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let delegator_address = ctx.sender();
    let delegator_personnel_id = *address_id_table.borrow(delegator_address);
    let delegatee_personnel_id = *address_id_table.borrow(delegatee_address);
    let patient_id = *address_id_table.borrow(patient_address);

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let delegator_account = hospital_personnel_id_account_table.borrow(delegator_personnel_id);
    require_account_activation(activation_key, delegator_account);

    assert!(hospital_personnel_id_account_table.contains(delegatee_personnel_id), EDelegateeNotFound);
    assert!(
        access_type == b"Read" || access_type == b"Update" || access_type == b"Read,Update",
        EInvalidAccessType,
    );
    let revoke_read = access_type == b"Read" || access_type == b"Read,Update";
    let revoke_update = access_type == b"Update" || access_type == b"Read,Update";

    let delegatee_account = hospital_personnel_id_account_table.borrow_mut(delegatee_personnel_id);
    let delegatee_access = delegatee_account.borrow_mut_access().borrow_mut();

    if (revoke_read) {
        let delegatee_read = delegatee_access.borrow_mut_read();
        if (delegatee_read.contains(&patient_id)) {
            delegatee_read.remove(&patient_id);
        };
    };

    if (revoke_update) {
        let delegatee_update = delegatee_access.borrow_mut_update();
        if (delegatee_update.contains(&patient_id)) {
            delegatee_update.remove(&patient_id);
        };
    };

    event::emit(
        DelegationRevokedEvent {
            patient_address,
            revoker: delegator_address,
            delegatee_address,
            access_type,
            related_rme_id,
            revoked_at_ms: clock.timestamp_ms(),
        }
    );
}

entry fun is_account_registered(
    activation_key: String,
    address_id: &AddressId,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    if (!address_id_table.contains(ctx.sender())) {
        abort EAccountNotFound
    };

    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    if (!hospital_personnel_id_account_table.contains(hospital_personnel_id)) {
        abort EAccountNotFound
    };

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
fun require_account_activation(
    activation_key: String,
    hospital_personnel_account: &HospitalPersonnelAccount,
)
{
    assert!(hospital_personnel_account.borrow_activation_key() == activation_key, EInvalidActivationKey);
    assert!(hospital_personnel_account.borrow_is_activation_key_used(), EAccountNotActivated);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `hospital_id`: argon_hash(raw_hospital_id)
/// - `id`: argon_hash(raw_id)
/// - `private_metadata`: Base64 encoded
/// - `public_metadata`: Base64 encoded
entry fun signup(
    activation_key: String,
    address_id: &mut AddressId,
    hospital_id: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    personnel_id: String,
    private_metadata: String,
    public_metadata: String,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_mut_table();
    assert!(!address_id_table.contains(ctx.sender()), EAddressAlreadyRegistered);

    let hospital_id = encode_hospital_id(hospital_id);
    let hospital_personnel_id = encode_hospital_personnel_id(hospital_id, personnel_id);

    address_id_table.add(ctx.sender(), hospital_personnel_id);

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();

    assert!(hospital_personnel_id_account_table.contains(hospital_personnel_id), EAccountNotFound);

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    assert!(hospital_personnel_account.borrow_address().is_none(), EAccountAlreadyRegistered);
    require_account_activation(activation_key, hospital_personnel_account);

    let administrative_metadata = hospital_personnel_administrative_metadata_new(
        private_metadata,
        public_metadata
    );
    hospital_personnel_account.set_administrative_metadata(option::some(administrative_metadata));
    hospital_personnel_account.set_address(option::some(ctx.sender()));

    if (hospital_personnel_account.borrow_role() != hospital_personnel_role_admin()) {
        let access = hospital_personnel_access_new(
            vec_map::empty<String, HospitalPersonnelAccessData>(),
            vec_map::empty<String, HospitalPersonnelAccessData>(),
        );
        hospital_personnel_account.set_access(option::some(access));
    };

    if (hospital_personnel_account.borrow_role() == hospital_personnel_role_admin()) {
        hospital_personnel_account.set_personnels(option::some(vec_map::empty<String, HospitalPersonnelMetadata>()));
    };
}

#[test_only]
public(package) fun signup_test(
    activation_key: String,
    address_id: &mut AddressId,
    hospital_id: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    personnel_id: String,
    private_metadata: String,
    public_metadata: String,
    ctx: &TxContext,
)
{
    signup(
        activation_key,
        address_id,
        hospital_id,
        hospital_personnel_id_account,
        personnel_id,
        private_metadata,
        public_metadata,
        ctx
    );
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `metadata`: Base64 encoded encrypted metadata
/// - `personnel_id`: argon_hash(raw_id)
entry fun update_account_activation_key(
    activation_key: String,
    address_id: &AddressId,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    metadata: String,
    personnel_id: String,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let hospital_admin_id = *address_id_table.borrow(ctx.sender());

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();

    let hospital_admin_account = hospital_personnel_id_account_table.borrow(hospital_admin_id);

    assert!(hospital_admin_account.borrow_role() == hospital_personnel_role_admin(), EIllegalActionInvalidRole);

    let hospital_personnel_id = encode_hospital_personnel_id(*hospital_admin_account.borrow_hospital_id(), personnel_id);

    assert!(hospital_personnel_id_account_table.contains(hospital_personnel_id), EAccountNotFound);

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);
    hospital_personnel_account.set_activation_key(activation_key);
    hospital_personnel_account.set_is_activation_key_used(false);

    let hospital_admin_account = hospital_personnel_id_account_table.borrow_mut(hospital_admin_id);
    let hospital_admin_account_personnels = hospital_admin_account.borrow_mut_personnels().borrow_mut();
    let personnel_metadata = hospital_admin_account_personnels.get_mut(&hospital_personnel_id);
    personnel_metadata.set_metadata(metadata);
}

/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `private_metadata`: Base64 encoded
/// - `public_metadata`: Base64 encoded
entry fun update_administrative_metadata(
    activation_key: String,
    address_id: &AddressId,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    private_metadata: String,
    public_metadata: String,
    ctx: &TxContext
)
{
    let address_id_table = address_id.borrow_table();
    let hospital_personnel_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    require_account_activation(activation_key, hospital_personnel_account);

    let hospital_personnel_administrative_metadata = hospital_personnel_account.borrow_mut_administrative_metadata().borrow_mut();
    hospital_personnel_administrative_metadata.set_public_metadata(public_metadata);
    hospital_personnel_administrative_metadata.set_private_metadata(private_metadata);
    hospital_personnel_account.set_is_profile_completed(true);
}


/// ## Params
/// - `activation_key`: argon_hash(<raw_uuid_v4>@<raw_id>)
/// - `hospital_id`: argon_hash(raw_hospital_id)
/// - `personnel_id`: argon_hash(raw_id)
entry fun use_activation_key(
    activation_key: String,
    hospital_id: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    personnel_id: String,
)
{
    let hospital_id = encode_hospital_id(hospital_id);
    let hospital_personnel_id = encode_hospital_personnel_id(hospital_id, personnel_id);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();

    assert!(hospital_personnel_id_account_table.contains(hospital_personnel_id), EAccountNotFound);

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);

    assert!((*hospital_personnel_account.borrow_activation_key()).into_bytes()  == activation_key.into_bytes(), EInvalidActivationKey);
    // assert!(!hospital_personnel_account.borrow_is_activation_key_used(), EActivationKeyAlreadyUsed);

    hospital_personnel_account.set_is_activation_key_used(true);
}

#[test_only]
public(package) fun use_activation_key_test(
    activation_key: String,
    hospital_id: String,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    personnel_id: String,
)
{
    use_activation_key(
        activation_key,
        hospital_id,
        hospital_personnel_id_account,
        personnel_id,
    );
}
