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
    "0xa3c7f14e9d8db5153a3153722a0807dc5cfa1a3274461919a99af3d3aaf1b3fa";
pub const DECMED_MODULE_ADMIN: &str = "admin";

pub const DECMED_ADDRESS_ID_OBJECT_ID: &str =
    "0x8e07e5c4decdb68cb73c588c351b06955ad3544b464ad141d2ba132d81fc50e7";
pub const DECMED_ADDRESS_ID_OBJECT_VERSION: u64 = 4;
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_ID: &str =
    "0xa9347f20cdfd617a3ed1942b1a30cdd3620403bf23ecae6a305a7974c232e83b";
pub const DECMED_HOSPITAL_ID_METADATA_OBJECT_VERSION: u64 = 4;
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_ID: &str =
    "0x94546f27bc0627465fd1deb855438da02ace89f25124572a0ff9e2a48c498eed";
pub const DECMED_HOSPITAL_PERSONNEL_ID_ACCOUNT_OBJECT_VERSION: u64 = 4;
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_ID: &str =
    "0x5eb04124abc0019812b034535ae42d050add185dafe8e8b2c4c3944b41da9006";
pub const DECMED_PATIENT_ID_ACCOUNT_OBJECT_VERSION: u64 = 4;

pub const DECMED_GLOBAL_ADMIN_CAP_ID: &str =
    "0xd85009607eb86effc515ef11fd88b6243c40ace3ec8cd671854d4458815b3023";
