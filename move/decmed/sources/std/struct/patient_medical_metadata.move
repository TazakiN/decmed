module decmed::std_struct_patient_medical_metadata;

use std::string::String;

public struct PatientMedicalMetadata has copy, drop, store {
    index: u64,
    metadata: String,
}

public(package) fun new(
    index: u64,
    metadata: String,
): PatientMedicalMetadata
{
    PatientMedicalMetadata { index, metadata }
}

public(package) fun borrow_index(
    self: &PatientMedicalMetadata,
): &u64
{
    &self.index
}

public(package) fun borrow_mut_index(
    self: &mut PatientMedicalMetadata,
): &mut u64
{
    &mut self.index
}

public(package) fun set_index(
    self: &mut PatientMedicalMetadata,
    index: u64,
)
{
    self.index = index;
}

public(package) fun borrow_metadata(
    self: &PatientMedicalMetadata,
): &String
{
    &self.metadata
}

public(package) fun borrow_mut_metadata(
    self: &mut PatientMedicalMetadata,
): &mut String
{
    &mut self.metadata
}

public(package) fun set_metadata(
    self: &mut PatientMedicalMetadata,
    metadata: String,
)
{
    self.metadata = metadata;
}
