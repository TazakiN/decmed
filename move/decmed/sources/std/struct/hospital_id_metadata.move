module decmed::std_struct_hospital_id_metadata;

use decmed::std_struct_hospital_metadata::HospitalMetadata;

use iota::table::{Self, Table};

use std::string::String;

public struct HospitalIdMetadata has key, store {
    id: UID,
    table: Table<String, HospitalMetadata>,
}

public(package) fun borrow_id(
    self: &HospitalIdMetadata,
): &UID
{
    &self.id
}

public(package) fun borrow_table(
    self: &HospitalIdMetadata,
): &Table<String, HospitalMetadata>
{
    &self.table
}

public(package) fun borrow_mut_table(
    self: &mut HospitalIdMetadata,
): &mut Table<String, HospitalMetadata>
{
    &mut self.table
}


fun init(ctx: &mut TxContext) {
    let hospital_id_metadata = HospitalIdMetadata {
        id: object::new(ctx),
        table: table::new<String, HospitalMetadata>(ctx),
    };

    transfer::share_object(hospital_id_metadata);
}
