module decmed::patient;

use decmed::std_enum_hospital_personnel_role::{
    administrative_personnel as hospital_personnel_role_administrative_personnel,
    medical_personnel as hospital_personnel_role_medical_personnel,
    HospitalPersonnelRole,
};
use decmed::std_enum_hospital_personnel_sub_role::HospitalPersonnelSubRole;
use decmed::std_enum_hospital_personnel_access_type::{
    HospitalPersonnelAccessType,
    read as hospital_personnel_access_type_read,
    update as hospital_personnel_access_type_update,
};
use decmed::std_enum_patient_delegation_audit_event_type::{
    revoked as patient_delegation_audit_event_type_revoked,
};
use decmed::std_enum_hospital_personnel_access_data_type::{
    HospitalPersonnelAccessDataType,
    administrative as hospital_personnel_access_data_type_administrative,
    medical as  hospital_personnel_access_data_type_medical,
};
use decmed::shared::{
    encode_hospital_personnel_id,
    encode_patient_id,
};
use decmed::std_struct_address_id::AddressId;
use decmed::std_struct_hospital_personnel_access_data::{
    HospitalPersonnelAccessData,
    new as hospital_personnel_access_data_new,
};
use decmed::std_struct_hospital_id_metadata::HospitalIdMetadata;
use decmed::std_struct_hospital_personnel_id_account::HospitalPersonnelIdAccount;
use decmed::std_struct_patient_access_log::{
    PatientAccessLog,
    new as patient_access_log_new,
};
use decmed::std_struct_patient_account::{
    PatientAccount,
    new as patient_account_new,
};
use decmed::std_struct_patient_administrative_metadata::{
    PatientAdministrativeMetadata,
    new as patient_administrative_metadata_new,
};
use decmed::std_struct_patient_delegation_audit_entry::{
    PatientDelegationAuditEntry,
    new as patient_delegation_audit_entry_new,
};
use decmed::std_struct_patient_id_account::PatientIdAccount;
use decmed::std_struct_patient_medical_metadata::PatientMedicalMetadata;

use iota::clock::Clock;
use iota::event;
use iota::table_vec;

use std::string::String;

// Constants

const EAccountAlreadyRegistered: u64 = 3000;
const EAddressAlreadyRegistered: u64 = 3001;
const EAccountNotFound: u64 = 3002;
const EAddressNotFound: u64 = 3003;
const EHospitalPersonnelNotFound: u64 = 3004;
const EInvalidMetadataLength: u64 = 3005;
const EInvalidAccessType: u64 = 3006;
const EDuplicateAccessType: u64 = 3007;

// Enums

// Structs

public struct PatientCascadeRevokedEvent has copy, drop {
    patient_address: address,
    root_revoked_personnel_address: address,
    affected_delegatee_address: address,
    access_type: HospitalPersonnelAccessType,
    revoked_at_ms: u64,
}

// Functions

fun append_delegation_revoked_audit(
    patient_account: &mut PatientAccount,
    timestamp_ms: u64,
    actor_address: address,
    root_subject: address,
    delegated_by: address,
    delegated_to: address,
    access_type: HospitalPersonnelAccessType,
    delegation_depth: u8,
    expires_at_ms: Option<u64>,
) {
    let delegation_audit_log = patient_account.borrow_mut_delegation_audit_log();
    let entry = patient_delegation_audit_entry_new(
        delegation_audit_log.length(),
        patient_delegation_audit_event_type_revoked(),
        timestamp_ms,
        actor_address,
        root_subject,
        delegated_by,
        delegated_to,
        access_type,
        option::none(),
        delegation_depth,
        option::none(),
        option::none(),
        expires_at_ms,
    );
    delegation_audit_log.push_back(entry);
}

/// ## Params:
/// - `metadata`: vector<Base64 encoded>
/// - `access_types`: vector of b"Read" / b"Update"; parallel with metadata/token_hashes.
/// - `access_exp_dur_minutes`: expiry duration per access entry; parallel with metadata/token_hashes.
///     - length = 1 for read-only or update-only
///     - length = 2 for read + update
entry fun create_access(
    address_id: &AddressId,
    clock: &Clock,
    date: String,
    hospital_id_metadata: &HospitalIdMetadata,
    hospital_personnel_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    access_types: vector<vector<u8>>,
    access_exp_dur_minutes: vector<u64>,
    metadata: vector<String>,
    token_hashes: vector<String>,
    patient_id_account: &mut PatientIdAccount,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let patient_id_account_table = patient_id_account.borrow_mut_table();
    let patient_account = patient_id_account_table.borrow_mut(patient_id);
    let patient_access_log = patient_account.borrow_mut_access_log();

    assert!(address_id_table.contains(hospital_personnel_address), EHospitalPersonnelNotFound);

    let hospital_personnel_id = *address_id_table.borrow(hospital_personnel_address);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);
    let hospital_personnel_role = *hospital_personnel_account.borrow_role();
    let hospital_personnel_administrative_metadata = hospital_personnel_account.borrow_administrative_metadata().borrow();
    let hospital_personnel_administrative_metadata_public = *hospital_personnel_administrative_metadata.borrow_public_metadata();

    let hospital_id_metadata_table = hospital_id_metadata.borrow_table();
    let hospital_id_metadata_vec = hospital_id_metadata.borrow_vec();
    let hospital_index = *hospital_id_metadata_table.borrow(*hospital_personnel_account.borrow_hospital_id());
    let hospital = hospital_id_metadata_vec.borrow(hospital_index);
    let hospital_metadata = hospital.borrow_hospital_metadata();

    let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);
    let hospital_personnel_access = hospital_personnel_account.borrow_mut_access().borrow_mut();

    let metadata_length = metadata.length();
    assert!(metadata_length == 1 || metadata_length == 2, EInvalidMetadataLength);
    assert!(token_hashes.length() == metadata_length, EInvalidMetadataLength);
    assert!(access_types.length() == metadata_length, EInvalidMetadataLength);
    assert!(access_exp_dur_minutes.length() == metadata_length, EInvalidMetadataLength);

    let mut read_seen = false;
    let mut update_seen = false;
    let mut idx = 0;
    while (idx < metadata_length) {
        let access_type_bytes = access_types.borrow(idx);
        let access_type = if (*access_type_bytes == b"Read") {
            hospital_personnel_access_type_read()
        } else if (*access_type_bytes == b"Update") {
            hospital_personnel_access_type_update()
        } else {
            abort EInvalidAccessType
        };

        if (access_type == hospital_personnel_access_type_read()) {
            assert!(!read_seen, EDuplicateAccessType);
            read_seen = true;
        } else {
            assert!(!update_seen, EDuplicateAccessType);
            update_seen = true;
        };

        let access_data_types = create_access_data_types(hospital_personnel_role, access_type);
        let access_data_types_log = create_access_data_types(hospital_personnel_role, access_type);
        let exp_dur = *access_exp_dur_minutes.borrow(idx);
        let exp = clock.timestamp_ms() + (exp_dur * 60 * 1000);
        let hospital_personnel_access_data = hospital_personnel_access_data_new(
            access_data_types,
            exp,
            *metadata.borrow(idx),
            option::none(),
        );

        if (access_type == hospital_personnel_access_type_read()) {
            let hospital_personnel_read_access = hospital_personnel_access.borrow_mut_read();
            if (hospital_personnel_read_access.contains(&patient_id)) {
                hospital_personnel_read_access.remove(&patient_id);
            };
            hospital_personnel_read_access.insert(patient_id, hospital_personnel_access_data);
        } else {
            let hospital_personnel_update_access = hospital_personnel_access.borrow_mut_update();
            if (hospital_personnel_update_access.contains(&patient_id)) {
                hospital_personnel_update_access.remove(&patient_id);
            };
            hospital_personnel_update_access.insert(patient_id, hospital_personnel_access_data);
        };

        let patient_access_log_item = patient_access_log_new(
            access_data_types_log,
            access_type,
            date,
            exp_dur,
            *hospital_metadata,
            hospital_personnel_address,
            hospital_personnel_administrative_metadata_public,
            patient_access_log.length(),
            false,
            option::some(*token_hashes.borrow(idx)),
        );
        patient_access_log.push_back(patient_access_log_item);

        idx = idx + 1;
    };
}

#[test_only]
public(package) fun create_access_test(
    address_id: &AddressId,
    clock: &Clock,
    date: String,
    hospital_id_metadata: &HospitalIdMetadata,
    hospital_personnel_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    access_types: vector<vector<u8>>,
    access_exp_dur_minutes: vector<u64>,
    metadata: vector<String>,
    token_hashes: vector<String>,
    patient_id_account: &mut PatientIdAccount,
    ctx: &TxContext,
)
{
    create_access(
        address_id,
        clock, date,
        hospital_id_metadata,
        hospital_personnel_address,
        hospital_personnel_id_account,
        access_types,
        access_exp_dur_minutes,
        metadata,
        token_hashes,
        patient_id_account,
        ctx
    );
}

fun create_access_data_types(
    hospital_personnel_role: HospitalPersonnelRole,
    access_type: HospitalPersonnelAccessType,
): vector<HospitalPersonnelAccessDataType>
{
    let mut access_data_types = vector::empty<HospitalPersonnelAccessDataType>();
    if (hospital_personnel_role == hospital_personnel_role_administrative_personnel()) {
        access_data_types.push_back(hospital_personnel_access_data_type_administrative());
    } else if (hospital_personnel_role == hospital_personnel_role_medical_personnel()) {
        if (access_type == hospital_personnel_access_type_read()) {
            access_data_types.push_back(hospital_personnel_access_data_type_medical());
            access_data_types.push_back(hospital_personnel_access_data_type_administrative());
        } else if (access_type == hospital_personnel_access_type_update()) {
            access_data_types.push_back(hospital_personnel_access_data_type_medical());
        } else {
            abort EInvalidAccessType
        };
    } else {
        abort EInvalidAccessType
    };
    access_data_types
}

entry fun is_account_registered(
    address_id: &AddressId,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    assert!(address_id_table.contains(ctx.sender()), EAddressNotFound);
}

/// ## Params
/// - `patient_id`: argon_hash(raw_nik)
/// - `private_metadata`: Base64 encoded
entry fun signup(
    address_id: &mut AddressId,
    patient_id: String,
    patient_id_account: &mut PatientIdAccount,
    private_metadata: String,
    ctx: &mut TxContext,
)
{
    let address_id_table = address_id.borrow_mut_table();
    assert!(!address_id_table.contains(ctx.sender()), EAddressAlreadyRegistered);

    let patient_id = encode_patient_id(patient_id);

    address_id_table.add(ctx.sender(), patient_id);

    let patient_id_account_table = patient_id_account.borrow_mut_table();

    assert!(!patient_id_account_table.contains(patient_id), EAccountAlreadyRegistered);

    let access_log = table_vec::empty<PatientAccessLog>(ctx);
    let administrative_metadata = patient_administrative_metadata_new(private_metadata);
    let delegation_audit_log = table_vec::empty<PatientDelegationAuditEntry>(ctx);
    let medical_metadata = table_vec::empty<PatientMedicalMetadata>(ctx);

    let patient_account = patient_account_new(
        access_log,
        ctx.sender(),
        administrative_metadata,
        delegation_audit_log,
        false,
        medical_metadata,
    );
    patient_id_account_table.add(patient_id, patient_account);
}

#[test_only]
public(package) fun signup_test(
    address_id: &mut AddressId,
    patient_id: String,
    patient_id_account: &mut PatientIdAccount,
    private_metadata: String,
    ctx: &mut TxContext,
)
{
    signup(
        address_id,
        patient_id,
        patient_id_account,
        private_metadata,
        ctx
    );
}

entry fun get_account_info(
    address_id: &AddressId,
    patient_id_account: &PatientIdAccount,
    ctx: &TxContext,
): PatientAdministrativeMetadata
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let patient_id_account_table = patient_id_account.borrow_table();
    let patient_account = patient_id_account_table.borrow(patient_id);

    *patient_account.borrow_administrative_metadata()
}

/// ## Params
/// - `patient_id`: argon_hash(raw_id)
///
/// ## Return:
/// 0: state_code
///     - 0 means need auth
///     - 1 means need profile completion
///     - 2 means no action
entry fun get_account_state(
    patient_id: String,
    patient_id_account: &PatientIdAccount,
): u64
{
    let patient_id = encode_patient_id(patient_id);
    let patient_id_account_table = patient_id_account.borrow_table();

    if (!patient_id_account_table.contains(patient_id)) {
        return 0
    };

    let patient_account = patient_id_account_table.borrow(patient_id);

    if (!patient_account.borrow_is_profile_completed()) {
        return 1
    };

    2
}

/// ## Return:
/// 0: public administrative data
/// 1: hospital name
/// 2: hospital personnel role
/// 3: hospital personnel sub-role
entry fun get_hospital_personnel_info(
    address_id: &AddressId,
    hospital_id_metadata: &HospitalIdMetadata,
    hospital_personnel_address: address,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    ctx: &TxContext,
): (String, String, HospitalPersonnelRole, Option<HospitalPersonnelSubRole>)
{
    let address_id_table = address_id.borrow_table();

    assert!(address_id_table.contains(ctx.sender()), EAccountNotFound);

    let hospital_personnel_id = *address_id_table.borrow(hospital_personnel_address);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);
    let hospital_personnel_administrative_metadata = hospital_personnel_account.borrow_administrative_metadata().borrow();

    let hospital_id_metadata_table = hospital_id_metadata.borrow_table();
    let hospital_id_metadata_vec = hospital_id_metadata.borrow_vec();
    let hospital_metadata_index = hospital_id_metadata_table.borrow(*hospital_personnel_account.borrow_hospital_id());
    let hospital_metadata = hospital_id_metadata_vec.borrow(*hospital_metadata_index).borrow_hospital_metadata();

    let public_data = *hospital_personnel_administrative_metadata.borrow_public_metadata();
    let hospital_name = *hospital_metadata.borrow_name();
    let role = *hospital_personnel_account.borrow_role();
    let sub_role = *hospital_personnel_account.borrow_sub_role();

    (public_data, hospital_name, role, sub_role)
}

/// Role lookup for patient grant flow (no ProxyCap required).
entry fun get_hospital_personnel_role_for_grant(
    address_id: &AddressId,
    hospital_personnel_id_account: &HospitalPersonnelIdAccount,
    hospital_personnel_address: address,
    ctx: &TxContext,
): HospitalPersonnelRole {
    let address_id_table = address_id.borrow_table();

    assert!(address_id_table.contains(ctx.sender()), EAccountNotFound);

    let hospital_personnel_id = *address_id_table.borrow(hospital_personnel_address);
    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_table();
    let hospital_personnel_account = hospital_personnel_id_account_table.borrow(hospital_personnel_id);

    *hospital_personnel_account.borrow_role()
}

entry fun get_access_log(
    address_id: &AddressId,
    cursor: u64,
    patient_id_account: &PatientIdAccount,
    size: u64,
    ctx: &TxContext,
): vector<PatientAccessLog>
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let patient_id_account_table = patient_id_account.borrow_table();
    let patient_account = patient_id_account_table.borrow(patient_id);
    let patient_access_log = patient_account.borrow_access_log();

    let patient_access_log_length = patient_access_log.length();

    let mut result = vector::empty<PatientAccessLog>();

    if (cursor >= patient_access_log_length) {
        return result
    };

    let size = std::u64::min(size, 10);
    let end_idx = patient_access_log_length - cursor - 1;
    let mut start_idx = end_idx + 1 - std::u64::min(size, end_idx + 1);
    let mut curr_idx = end_idx;

    while (start_idx <= end_idx) {
        result.push_back(*patient_access_log.borrow(curr_idx));
        start_idx = start_idx + 1;

        if (curr_idx > 0) {
            curr_idx = curr_idx - 1;
        };
    };

    result
}

entry fun get_delegation_audit_log(
    address_id: &AddressId,
    cursor: u64,
    patient_id_account: &PatientIdAccount,
    size: u64,
    ctx: &TxContext,
): vector<PatientDelegationAuditEntry>
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let patient_id_account_table = patient_id_account.borrow_table();
    let patient_account = patient_id_account_table.borrow(patient_id);
    let delegation_audit_log = patient_account.borrow_delegation_audit_log();

    let delegation_audit_log_length = delegation_audit_log.length();

    let mut result = vector::empty<PatientDelegationAuditEntry>();

    if (cursor >= delegation_audit_log_length) {
        return result
    };

    let size = std::u64::min(size, 10);
    let end_idx = delegation_audit_log_length - cursor - 1;
    let mut start_idx = end_idx + 1 - std::u64::min(size, end_idx + 1);
    let mut curr_idx = end_idx;

    while (start_idx <= end_idx) {
        result.push_back(*delegation_audit_log.borrow(curr_idx));
        start_idx = start_idx + 1;

        if (curr_idx > 0) {
            curr_idx = curr_idx - 1;
        };
    };

    result
}

entry fun get_medical_record(
    address_id: &AddressId,
    index: u64,
    patient_id_account: &PatientIdAccount,
    ctx: &TxContext,
): PatientMedicalMetadata
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let patient_id_account_table = patient_id_account.borrow_table();
    let patient_account = patient_id_account_table.borrow(patient_id);
    let patient_medical_metadata = patient_account.borrow_medical_metadata();

    *patient_medical_metadata.borrow(index)
}

entry fun get_medical_records(
    address_id: &AddressId,
    cursor: u64,
    patient_id_account: &PatientIdAccount,
    size: u64,
    ctx: &TxContext,
): vector<PatientMedicalMetadata>
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let patient_id_account_table = patient_id_account.borrow_table();
    let patient_account = patient_id_account_table.borrow(patient_id);
    let patient_medical_metadata = patient_account.borrow_medical_metadata();

    let patient_medical_metadata_length = patient_medical_metadata.length();

    let mut result = vector::empty<PatientMedicalMetadata>();

    if (cursor >= patient_medical_metadata_length) {
        return result
    };

    let size = std::u64::min(size, 10);
    let end_idx = patient_medical_metadata_length - cursor - 1;
    let mut start_idx = end_idx + 1 - std::u64::min(size, end_idx + 1);
    let mut curr_idx = end_idx;

    while (start_idx <= end_idx) {
        result.push_back(*patient_medical_metadata.borrow(curr_idx));
        start_idx = start_idx + 1;

        if (curr_idx > 0) {
            curr_idx = curr_idx - 1;
        };
    };

    result
}

entry fun revoke_access(
    address_id: &AddressId,
    clock: &Clock,
    hospital_personnel_address: address,
    hospital_personnel_id_account: &mut HospitalPersonnelIdAccount,
    admin_personnel_id: String,
    index: u64,
    patient_id_account: &mut PatientIdAccount,
    ctx: &TxContext,
)
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let hospital_personnel_id = *address_id_table.borrow(hospital_personnel_address);

    let patient_id_account_table = patient_id_account.borrow_mut_table();

    assert!(patient_id_account_table.contains(patient_id), EAccountNotFound);

    let patient_account = patient_id_account_table.borrow_mut(patient_id);
    let patient_access_logs = patient_account.borrow_mut_access_log();
    let patient_access_log = patient_access_logs.borrow_mut(index);
    patient_access_log.set_is_revoked(true);

    let hospital_personnel_id_account_table = hospital_personnel_id_account.borrow_mut_table();
    let revoke_read = patient_access_log.borrow_access_type() == hospital_personnel_access_type_read();
    let revoke_update = patient_access_log.borrow_access_type() == hospital_personnel_access_type_update();
    let hospital_id = {
        let hospital_personnel_account = hospital_personnel_id_account_table.borrow_mut(hospital_personnel_id);
        let hospital_id = *hospital_personnel_account.borrow_hospital_id();
        let hospital_personnel_access_option = hospital_personnel_account.borrow_mut_access();
        let hospital_personnel_access = hospital_personnel_access_option.borrow_mut();

        let hospital_personnel_read_access = hospital_personnel_access.borrow_mut_read();
        if (hospital_personnel_read_access.contains(&patient_id) && revoke_read) {
            hospital_personnel_read_access.remove(&patient_id);
        };
        let hospital_personnel_update_access = hospital_personnel_access.borrow_mut_update();
        if (hospital_personnel_update_access.contains(&patient_id) && revoke_update) {
            hospital_personnel_update_access.remove(&patient_id);
        };

        hospital_id
    };

    let hospital_admin_id = encode_hospital_personnel_id(hospital_id, admin_personnel_id);
    if (!hospital_personnel_id_account_table.contains(hospital_admin_id)) {
        return
    };

    let mut personnel_ids = vector::empty<String>();
    {
        let hospital_admin_account = hospital_personnel_id_account_table.borrow(hospital_admin_id);
        if (hospital_admin_account.borrow_personnels().is_none()) {
            return
        };
        let hospital_admin_personnels = hospital_admin_account.borrow_personnels().borrow();
        let mut idx = 0;
        let personnel_len = hospital_admin_personnels.size();
        while (idx < personnel_len) {
            let (personnel_id, _) = hospital_admin_personnels.get_entry_by_idx(idx);
            personnel_ids.push_back(*personnel_id);
            idx = idx + 1;
        };
    };

    let mut revoked_addresses = vector::empty<address>();
    revoked_addresses.push_back(hospital_personnel_address);
    let mut changed = true;
    let mut idx = 0;
    while (changed) {
        changed = false;
        idx = 0;
        while (idx < personnel_ids.length()) {
            let personnel_id = *personnel_ids.borrow(idx);
            if (!hospital_personnel_id_account_table.contains(personnel_id)) {
                idx = idx + 1;
                continue
            };

            let candidate_account = hospital_personnel_id_account_table.borrow_mut(personnel_id);
            if (candidate_account.borrow_address().is_none()) {
                idx = idx + 1;
                continue
            };
            let candidate_address = *candidate_account.borrow_address().borrow();
            if (revoked_addresses.contains(&candidate_address)) {
                idx = idx + 1;
                continue
            };
            let candidate_access_option = candidate_account.borrow_mut_access();
            if (candidate_access_option.is_none()) {
                idx = idx + 1;
                continue
            };

            let mut candidate_revoked = false;
            let candidate_access = candidate_access_option.borrow_mut();

            if (revoke_read) {
                let candidate_read = candidate_access.borrow_mut_read();
                let mut should_revoke_read = false;
                let mut read_delegated_by = option::none<address>();
                let mut read_delegation_depth = 0;
                let mut read_exp = option::none<u64>();
                if (candidate_read.contains(&patient_id)) {
                    let source = candidate_read.get(&patient_id);
                    let delegated_by = source.borrow_delegated_by();
                    if (delegated_by.is_some() && revoked_addresses.contains(delegated_by.borrow())) {
                        should_revoke_read = true;
                        read_delegated_by = delegated_by;
                        read_delegation_depth = source.borrow_delegation_depth();
                        read_exp = option::some(source.borrow_exp());
                    };
                };
                if (should_revoke_read) {
                    candidate_read.remove(&patient_id);
                    candidate_revoked = true;
                    append_delegation_revoked_audit(
                        patient_account,
                        clock.timestamp_ms(),
                        ctx.sender(),
                        hospital_personnel_address,
                        *read_delegated_by.borrow(),
                        candidate_address,
                        hospital_personnel_access_type_read(),
                        read_delegation_depth,
                        read_exp,
                    );
                    event::emit(
                        PatientCascadeRevokedEvent {
                            patient_address: ctx.sender(),
                            root_revoked_personnel_address: hospital_personnel_address,
                            affected_delegatee_address: candidate_address,
                            access_type: hospital_personnel_access_type_read(),
                            revoked_at_ms: clock.timestamp_ms(),
                        }
                    );
                };
            };

            if (revoke_update) {
                let candidate_update = candidate_access.borrow_mut_update();
                let mut should_revoke_update = false;
                let mut update_delegated_by = option::none<address>();
                let mut update_delegation_depth = 0;
                let mut update_exp = option::none<u64>();
                if (candidate_update.contains(&patient_id)) {
                    let source = candidate_update.get(&patient_id);
                    let delegated_by = source.borrow_delegated_by();
                    if (delegated_by.is_some() && revoked_addresses.contains(delegated_by.borrow())) {
                        should_revoke_update = true;
                        update_delegated_by = delegated_by;
                        update_delegation_depth = source.borrow_delegation_depth();
                        update_exp = option::some(source.borrow_exp());
                    };
                };
                if (should_revoke_update) {
                    candidate_update.remove(&patient_id);
                    candidate_revoked = true;
                    append_delegation_revoked_audit(
                        patient_account,
                        clock.timestamp_ms(),
                        ctx.sender(),
                        hospital_personnel_address,
                        *update_delegated_by.borrow(),
                        candidate_address,
                        hospital_personnel_access_type_update(),
                        update_delegation_depth,
                        update_exp,
                    );
                    event::emit(
                        PatientCascadeRevokedEvent {
                            patient_address: ctx.sender(),
                            root_revoked_personnel_address: hospital_personnel_address,
                            affected_delegatee_address: candidate_address,
                            access_type: hospital_personnel_access_type_update(),
                            revoked_at_ms: clock.timestamp_ms(),
                        }
                    );
                };
            };

            if (candidate_revoked) {
                revoked_addresses.push_back(candidate_address);
                changed = true;
            };

            idx = idx + 1;
        };
    };
}

/// ## Params
/// - `private_metadata`: Base64 encoded
entry fun update_administrative_metadata(
    address_id: &AddressId,
    patient_id_account: &mut PatientIdAccount,
    private_metadata: String,
    ctx: &TxContext
)
{
    let address_id_table = address_id.borrow_table();
    let patient_id = *address_id_table.borrow(ctx.sender());
    let patient_id_account_table = patient_id_account.borrow_mut_table();
    let patient_account = patient_id_account_table.borrow_mut(patient_id);

    let patient_administrative_metadata = patient_account.borrow_mut_administrative_metadata();
    patient_administrative_metadata.set_private_metadata(private_metadata);
    patient_account.set_is_profile_completed(true);
}
