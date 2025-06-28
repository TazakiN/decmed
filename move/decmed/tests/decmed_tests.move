#[test_only]
module decmed::decmed_tests;
// uncomment this line to import the module
// use decmed::decmed;

use std::debug;
use iota::hash::blake2b256;

const ENotImplemented: u64 = 0;

#[test]
fun test_decmed() {
    let ctx = tx_context::dummy();

    debug::print(&ctx.sender());
    debug::print(&b"Jiwoo");
}

#[test, expected_failure(abort_code = ::decmed::decmed_tests::ENotImplemented)]
fun test_decmed_fail() {
    abort ENotImplemented
}

#[test]
fun test_create_activation_key(){
    let a = std::string::utf8(b"jiwoo");
    let b = std::string::utf8(b"jiwoo");

    let a = blake2b256(a.as_bytes());
    let b = blake2b256(b.as_bytes());

    let a = iota::hex::encode(a);
    let b = iota::hex::encode(b);

    let a = std::string::utf8(a);
    let b = std::string::utf8(b);


    debug::print(&a);
    debug::print(&b);
}
