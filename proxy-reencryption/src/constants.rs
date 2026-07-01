pub const IOTA_URL: &str = "http://103.107.4.64:9000";
pub const GAS_STATION_BASE_URL: &str = "http://103.107.4.68:9528/v1";
pub const GAS_BUDGET: u64 = 200_000_000;
pub const _HASH_SALT: &str = "169224A2BE2B267684F93A9CE38080D359BD774741FD3AE738D09B657A1A8104";
pub const IPFS_BASE_URL: &str = "http://103.107.4.68:5001/api/v0";
pub const IPFS_GATEWAY_BASE_URL: &str = "http://103.107.4.68:8080";
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
    "0x2a92c1a4bb03158c301da17c9a84cc416878ed75512aba73a2aa2862a2febf38";
pub const DECMED_PACKAGE_ID: &str =
    "0x8ae96079f85b91f260933e0181217f9ae062d50d372d7603d12e28728baa83f3";
pub const DECMED_MODULE_ADMIN: &str = "admin";

pub const DECMED_ADDRESS_ID_OBJECT_ID: &str =
    "0x5a5a7d876b82fab1c7dedc9a774f2ae37e97a811fcd0598f0b402b7538a4e202";
/// `initial_shared_version` for shared objects (NOT the object's current on-chain version).
pub const DECMED_ADDRESS_ID_OBJECT_VERSION: u64 = 3;
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_ID: &str =
    "0xa1b5400ef14ebb4303e68f044aeeaecdd47bd3989ec07c09f49262e9b6c55847";
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_VERSION: u64 = 3;
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_ID: &str =
    "0xbc5523e2b8b4d077ef46ac6d51e2c3e81706ee6c730ff2ad812ecb7490574eb9";
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_VERSION: u64 = 3;
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_ID: &str =
    "0x4a9188185e282d9376340ed12e06f3cd0db3be38f38c72932d9021ad0b328a8d";
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_VERSION: u64 = 3;

pub const DECMED_GLOBAL_ADMIN_CAP_ID: &str =
    "0xd0cffbe3d38ab8a99a9b35df1e9197293d97bf7b312204695ad338f8a6c101c4";
