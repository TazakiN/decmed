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
    "0xca55d746c11b087ff09592d08af22b67d61819c99f147bde5e1d6a5041816bb2";
pub const DECMED_MODULE_ADMIN: &str = "admin";

pub const DECMED_ADDRESS_ID_OBJECT_ID: &str =
    "0xc10dd46f15804f4f334d7fc0dfd768c2372b9fa94d6713efe98ce8bc059b664f";
pub const DECMED_ADDRESS_ID_OBJECT_VERSION: u64 = 5;
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_ID: &str =
    "0xf42a32f6abff12e0ac89334e6e5e45337ef07dddbe443bba79319e4d020148b8";
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_VERSION: u64 = 5;
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_ID: &str =
    "0x65e585d91bee1f188ae89225eabe3a5f9872f15b0e7366268390fbc8f0396316";
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_VERSION: u64 = 5;
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_ID: &str =
    "0x3ac2020c2474911cf3817127d2e10f8cd5d5fda7fc80d0538b99c74993c52fc1";
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_VERSION: u64 = 5;

pub const DECMED_GLOBAL_ADMIN_CAP_ID: &str =
    "0x8577cfc5fa66047a956532b31a4dd31421f25ed8c101b22e72b10fb0e2d836fe";
