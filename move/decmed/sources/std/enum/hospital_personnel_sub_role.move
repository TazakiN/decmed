module decmed::std_enum_hospital_personnel_sub_role;

public enum HospitalPersonnelSubRole has copy, drop, store {
    Doctor,
    Nurse,
    LaboratoryStaff,
    Pharmacist,
}

public(package) fun doctor(): HospitalPersonnelSubRole {
    HospitalPersonnelSubRole::Doctor
}

public(package) fun nurse(): HospitalPersonnelSubRole {
    HospitalPersonnelSubRole::Nurse
}

public(package) fun laboratory_staff(): HospitalPersonnelSubRole {
    HospitalPersonnelSubRole::LaboratoryStaff
}

public(package) fun pharmacist(): HospitalPersonnelSubRole {
    HospitalPersonnelSubRole::Pharmacist
}
