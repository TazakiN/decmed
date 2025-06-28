module decmed::std_struct_patient_access_log;

use decmed::std_enum_hospital_personnel_access_type::HospitalPersonnelAccessType;
use decmed::std_enum_hospital_personnel_access_data_type::HospitalPersonnelAccessDataType;

use std::string::String;

public struct PatientAccessLog has copy, drop, store {
    access_data_type: vector<HospitalPersonnelAccessDataType>,
    access_type: HospitalPersonnelAccessType,
    date: String,
    hospital_personnel_metadata: String,
    index: u64,
}

public(package) fun new(
    access_data_type: vector<HospitalPersonnelAccessDataType>,
    access_type: HospitalPersonnelAccessType,
    date: String,
    hospital_personnel_metadata: String,
    index: u64,
): PatientAccessLog
{
    PatientAccessLog {
        access_data_type,
        access_type,
        date,
        hospital_personnel_metadata,
        index,
    }
}

public(package) fun borrow_access_data_type(
    self: &PatientAccessLog,
): &vector<HospitalPersonnelAccessDataType>
{
    &self.access_data_type
}

public(package) fun borrow_mut_access_data_type(
    self: &mut PatientAccessLog,
): &mut vector<HospitalPersonnelAccessDataType>
{
    &mut self.access_data_type
}

public(package) fun set_access_data_type(
    self: &mut PatientAccessLog,
    access_data_type: vector<HospitalPersonnelAccessDataType>,
)
{
    self.access_data_type = access_data_type;
}

public(package) fun borrow_access_type(
    self: &PatientAccessLog,
): &HospitalPersonnelAccessType
{
    &self.access_type
}

public(package) fun borrow_mut_access_type(
    self: &mut PatientAccessLog,
): &mut HospitalPersonnelAccessType
{
    &mut self.access_type
}

public(package) fun set_access_type(
    self: &mut PatientAccessLog,
    access_type: HospitalPersonnelAccessType,
)
{
    self.access_type = access_type;
}

public(package) fun borrow_date(
    self: &PatientAccessLog,
): &String
{
    &self.date
}

public(package) fun borrow_mut_date(
    self: &mut PatientAccessLog,
): &mut String
{
    &mut self.date
}

public(package) fun set_date(
    self: &mut PatientAccessLog,
    date: String,
)
{
    self.date = date;
}

public(package) fun borrow_hospital_personnel_metadata(
    self: &PatientAccessLog,
): &String
{
    &self.hospital_personnel_metadata
}

public(package) fun borrow_mut_hospital_personnel_metadata(
    self: &mut PatientAccessLog,
): &mut String
{
    &mut self.hospital_personnel_metadata
}

public(package) fun set_hospital_personnel_metadata(
    self: &mut PatientAccessLog,
    hospital_personnel_metadata: String,
)
{
    self.hospital_personnel_metadata = hospital_personnel_metadata;
}

public(package) fun borrow_index(
    self: &PatientAccessLog,
): &u64
{
    &self.index
}

public(package) fun borrow_mut_index(
    self: &mut PatientAccessLog,
): &mut u64
{
    &mut self.index
}

public(package) fun set_index(
    self: &mut PatientAccessLog,
    index: u64,
)
{
    self.index = index;
}
