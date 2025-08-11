// pub const IOTA_URL: &str = "https://live-sturgeon-needlessly.ngrok-free.app";
// pub const GAS_STATION_BASE_URL: &str = "https://ec7f-114-122-115-51.ngrok-free.app/v1";
pub const IOTA_URL: &str = "http://localhost:9000";
pub const GAS_STATION_BASE_URL: &str = "http://localhost:9527/v1";
pub const GAS_BUDGET: u64 = 10_000_000;
pub const _HASH_SALT: &str = "169224A2BE2B267684F93A9CE38080D359BD774741FD3AE738D09B657A1A8104";
pub const IPFS_BASE_URL: &str = "http://localhost:9094";
pub const IPFS_GATEWAY_BASE_URL: &str = "http://127.0.0.1:8080";
/// Duration: 3 minutes
pub const NONCE_EXP_DUR: u64 = 3 * 60;
/// Duration: 5 minutes
pub const ADMINISTRATIVE_KEYS_READ_DUR: u64 = 5 * 60;
/// Duration: 15 minutes
pub const MEDICAL_KEYS_READ_DUR: u64 = 15 * 60;
/// Duration: 2 hours
pub const MEDICAL_KEYS_UPDATE_DUR: u64 = 2 * 60 * 60;

pub const DECMED_MODULE_PROXY: &str = "proxy";
pub const DECMED_MODULE_SHARED: &str = "shared";

pub const DECMED_PACKAGE_ID: &str =
    "0x35e0df4af00704123e76f3e47cd96dce54fdaa9ad314d92abd137096b8690c7f";
pub const DECMED_MODULE_ADMIN: &str = "admin";

pub const DECMED_ADDRESS_ID_OBJECT_ID: &str =
    "0xde13cf7cb9e47f6220e839a19a6ce1c09e4a39f6efa1aded92602da73647bf47";
pub const DECMED_ADDRESS_ID_OBJECT_VERSION: u64 = 3;
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_ID: &str =
    "0xdce5fce4f06ec06a55682c1087b96e7f4ebca361a81d3a4e6400a6edbd7f6969";
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_VERSION: u64 = 3;
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_ID: &str =
    "0xe812895e71716f4dd03f55ce038f0734ef3865ae122aeafb8aac096931b2e854";
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_VERSION: u64 = 3;
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_ID: &str =
    "0xf698756a5f2a1725db8f4212dffa88712b6c4122ad3f1f18d51f9d067ccb0ede";
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_VERSION: u64 = 3;

pub const DECMED_GLOBAL_ADMIN_CAP_ID: &str =
    "0xd54642fce82288bf086992b98fb0428adc540be50f4e261f9d81e1b01889a4cb";
