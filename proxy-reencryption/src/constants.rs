pub const IOTA_URL: &str = "https://api.testnet.iota.cafe";
pub const GAS_STATION_BASE_URL: &str = "http://103.107.4.62:9527/v1";
pub const GAS_BUDGET: u64 = 200_000_000;
pub const _HASH_SALT: &str = "169224A2BE2B267684F93A9CE38080D359BD774741FD3AE738D09B657A1A8104";
pub const IPFS_BASE_URL: &str = "http://103.107.4.62:9094/api/v0";
pub const IPFS_GATEWAY_BASE_URL: &str = "http://103.107.4.62:8080";
/// Duration: 3 minutes
pub const NONCE_EXP_DUR: u64 = 3 * 60;
/// Duration: 1 day
pub const ADMINISTRATIVE_RAWAT_JALAN_KEYS_DUR: u64 = 24 * 60 * 60;
/// Duration: 3 days
pub const ADMINISTRATIVE_RAWAT_INAP_KEYS_DUR: u64 = 3 * 24 * 60 * 60;
/// Duration: 15 minutes
pub const MEDICAL_KEYS_READ_DUR: u64 = 15 * 60;
/// Duration: 2 hours
pub const MEDICAL_KEYS_UPDATE_DUR: u64 = 2 * 60 * 60;

pub const DECMED_MODULE_PROXY: &str = "proxy";
pub const DECMED_MODULE_SHARED: &str = "shared";

pub const DECMED_ORIGINAL_PACKAGE_ID: &str =
    "0xa9e7d6d9927c37fd31f3fde15f8bd3587f628f2fbadde35d04a685ef87587ca2";
pub const DECMED_PACKAGE_ID: &str =
    "0x728e2ae15c732ba68814ef7720b649b11a184a95aadb6b1a2ec93ade4590185e";
pub const DECMED_MODULE_ADMIN: &str = "admin";

pub const DECMED_ADDRESS_ID_OBJECT_ID: &str =
    "0x09bdfe9e42612ef553d535da2f76135fc79bc11d87bff169da72db7d681424ee";
/// `initial_shared_version` for shared objects (NOT the object's current on-chain version).
pub const DECMED_ADDRESS_ID_OBJECT_VERSION: u64 = 915244504;
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_ID: &str =
    "0x0dd480e7e07ba90c8b19c0e3fb4f4bb6a1bcff4dcdb925cab97ca11d4f89e23a";
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_VERSION: u64 = 915244504;
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_ID: &str =
    "0xffb88b9520a3f6e32bb70895e4ae908c20386741638c3ef06c9ac089f9bfea7f";
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_VERSION: u64 = 915244504;
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_ID: &str =
    "0xaf7e5415e55e625a95e5365ac1c3981372d273483ea492d6e4bb4d56b672e661";
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_VERSION: u64 = 915244504;

pub const DECMED_GLOBAL_ADMIN_CAP_ID: &str =
    "0x39e388aeb49bfcbcce38fa9c20f9ca224dabddcdc3cb17cb2a8425394e9fc120";
