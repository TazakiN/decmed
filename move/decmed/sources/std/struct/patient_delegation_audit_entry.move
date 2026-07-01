module decmed::std_struct_patient_delegation_audit_entry;

use decmed::std_enum_hospital_personnel_access_type::HospitalPersonnelAccessType;
use decmed::std_enum_patient_delegation_audit_event_type::PatientDelegationAuditEventType;

use std::string::String;

public struct PatientDelegationAuditEntry has copy, drop, store {
    index: u64,
    event_type: PatientDelegationAuditEventType,
    timestamp_ms: u64,
    actor_address: address,
    root_subject: address,
    delegated_by: address,
    delegated_to: address,
    access_type: HospitalPersonnelAccessType,
    related_rme_id: Option<String>,
    delegation_depth: u8,
    token_hash: Option<String>,
    parent_token_hash: Option<String>,
    expires_at_ms: Option<u64>,
}

public(package) fun new(
    index: u64,
    event_type: PatientDelegationAuditEventType,
    timestamp_ms: u64,
    actor_address: address,
    root_subject: address,
    delegated_by: address,
    delegated_to: address,
    access_type: HospitalPersonnelAccessType,
    related_rme_id: Option<String>,
    delegation_depth: u8,
    token_hash: Option<String>,
    parent_token_hash: Option<String>,
    expires_at_ms: Option<u64>,
): PatientDelegationAuditEntry {
    PatientDelegationAuditEntry {
        index,
        event_type,
        timestamp_ms,
        actor_address,
        root_subject,
        delegated_by,
        delegated_to,
        access_type,
        related_rme_id,
        delegation_depth,
        token_hash,
        parent_token_hash,
        expires_at_ms,
    }
}

public(package) fun borrow_event_type(
    self: &PatientDelegationAuditEntry,
): &PatientDelegationAuditEventType {
    &self.event_type
}

public(package) fun borrow_delegated_to(
    self: &PatientDelegationAuditEntry,
): address {
    self.delegated_to
}

public(package) fun borrow_token_hash(
    self: &PatientDelegationAuditEntry,
): &Option<String> {
    &self.token_hash
}

public(package) fun borrow_parent_token_hash(
    self: &PatientDelegationAuditEntry,
): &Option<String> {
    &self.parent_token_hash
}

public(package) fun borrow_expires_at_ms(
    self: &PatientDelegationAuditEntry,
): &Option<u64> {
    &self.expires_at_ms
}
