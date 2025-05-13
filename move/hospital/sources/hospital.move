/// Module: hospital
module hospital::hospital;

use 0x1::string::{Self, String};
use 0x2::table;

const EDuplicateActivationKey: u64 = 0;
const EActivationKeyNotFound: u64 = 1;
const EActivationKeyAlreadyUsed: u64 = 2;

public struct AdminCap has key {
    id: UID
}

fun init(ctx: &mut TxContext) {
    transfer::transfer(AdminCap {
        id: object::new(ctx),
    }, ctx.sender());

    let mut activation_key_table = table::new<String, bool>(ctx);
    table::add(&mut activation_key_table, string::utf8(b"act_key_1"), true);
    table::add(&mut activation_key_table, string::utf8(b"act_key_2"), false);

    transfer::public_share_object(activation_key_table);
}

entry fun add_activation_key(_: &AdminCap, activation_key_table: &mut table::Table<String, bool>, activation_key: String, _ctx: &mut TxContext) {
    assert!(!table::contains(activation_key_table, activation_key), EDuplicateActivationKey);

    table::add(activation_key_table, activation_key, false);
}

entry fun use_activation_key(activation_key_table: &mut table::Table<String, bool>, activation_key: String, _ctx: &mut TxContext) {
    assert!(table::contains(activation_key_table, activation_key), EActivationKeyNotFound);
    assert!(*table::borrow(activation_key_table, activation_key) == false, EActivationKeyAlreadyUsed);

    table::remove(activation_key_table, activation_key);
    table::add(activation_key_table, activation_key, true);
}

entry fun is_activation_key_used(activation_key_table: &table::Table<String, bool> ,activation_key: String, _ctx: &mut TxContext): bool {
    assert!(table::contains(activation_key_table, activation_key), EActivationKeyNotFound);

    *table::borrow(activation_key_table, activation_key)
}
