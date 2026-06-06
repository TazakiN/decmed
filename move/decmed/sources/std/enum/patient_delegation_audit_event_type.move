module decmed::std_enum_patient_delegation_audit_event_type;

public enum PatientDelegationAuditEventType has copy, drop, store {
    Delegated,
    Revoked,
}

public(package) fun delegated(): PatientDelegationAuditEventType {
    PatientDelegationAuditEventType::Delegated
}

public(package) fun revoked(): PatientDelegationAuditEventType {
    PatientDelegationAuditEventType::Revoked
}
