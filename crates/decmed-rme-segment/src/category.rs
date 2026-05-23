use serde::{ Deserialize, Serialize };

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum DatasetCategory {
    RAWAT_JALAN,
    RAWAT_INAP,
    LABORATORIUM,
    APOTEK,
}

pub const ALL_DATASET_CATEGORIES: [DatasetCategory; 4] = [
    DatasetCategory::RAWAT_JALAN,
    DatasetCategory::RAWAT_INAP,
    DatasetCategory::LABORATORIUM,
    DatasetCategory::APOTEK,
];

impl DatasetCategory {
    pub fn all() -> &'static [DatasetCategory] {
        &ALL_DATASET_CATEGORIES
    }
}

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum FunctionCategory {
    // ADMINISTRATIVE
    ADMINISTRATIVE_GENERAL,

    // RAWAT_JALAN & RAWAT_INAP
    ANAMNESIS,
    PEMERIKSAAN_FISIK,
    PEMERIKSAAN_PSIKOLOGIS,
    RIWAYAT_PENGGUNAAN_OBAT,
    RENCANA_RAWAT,
    INSTRUKSI_MEDIK_DAN_KEPERAWATAN,
    PEMERIKSAAN_PENUNJANG,
    DIAGNOSIS,
    INFORMED_CONSENT,
    TERAPI,

    // RAWAT_INAP
    PERENCANAAN_PEMULANGAN,

    // LABORATORIUM
    LABORATORIUM,

    // APOTEK
    PERESEPAN,
    DISPENSING,
}

pub const ALL_FUNCTION_CATEGORIES: [FunctionCategory; 15] = [
    FunctionCategory::ADMINISTRATIVE_GENERAL,
    FunctionCategory::ANAMNESIS,
    FunctionCategory::PEMERIKSAAN_FISIK,
    FunctionCategory::PEMERIKSAAN_PSIKOLOGIS,
    FunctionCategory::RIWAYAT_PENGGUNAAN_OBAT,
    FunctionCategory::RENCANA_RAWAT,
    FunctionCategory::PERENCANAAN_PEMULANGAN,
    FunctionCategory::INSTRUKSI_MEDIK_DAN_KEPERAWATAN,
    FunctionCategory::PEMERIKSAAN_PENUNJANG,
    FunctionCategory::DIAGNOSIS,
    FunctionCategory::INFORMED_CONSENT,
    FunctionCategory::TERAPI,
    FunctionCategory::LABORATORIUM,
    FunctionCategory::PERESEPAN,
    FunctionCategory::DISPENSING,
];

impl FunctionCategory {
    pub fn all() -> &'static [FunctionCategory] {
        &ALL_FUNCTION_CATEGORIES
    }
}

pub(crate) const RAWAT_JALAN_FUNCTIONS: [FunctionCategory; 11] = [
    FunctionCategory::ADMINISTRATIVE_GENERAL,
    FunctionCategory::ANAMNESIS,
    FunctionCategory::PEMERIKSAAN_FISIK,
    FunctionCategory::PEMERIKSAAN_PSIKOLOGIS,
    FunctionCategory::RIWAYAT_PENGGUNAAN_OBAT,
    FunctionCategory::RENCANA_RAWAT,
    FunctionCategory::INSTRUKSI_MEDIK_DAN_KEPERAWATAN,
    FunctionCategory::PEMERIKSAAN_PENUNJANG,
    FunctionCategory::DIAGNOSIS,
    FunctionCategory::INFORMED_CONSENT,
    FunctionCategory::TERAPI,
];

pub(crate) const RAWAT_INAP_FUNCTIONS: [FunctionCategory; 12] = [
    FunctionCategory::ADMINISTRATIVE_GENERAL,
    FunctionCategory::ANAMNESIS,
    FunctionCategory::PEMERIKSAAN_FISIK,
    FunctionCategory::PEMERIKSAAN_PSIKOLOGIS,
    FunctionCategory::RIWAYAT_PENGGUNAAN_OBAT,
    FunctionCategory::RENCANA_RAWAT,
    FunctionCategory::PERENCANAAN_PEMULANGAN,
    FunctionCategory::INSTRUKSI_MEDIK_DAN_KEPERAWATAN,
    FunctionCategory::PEMERIKSAAN_PENUNJANG,
    FunctionCategory::DIAGNOSIS,
    FunctionCategory::INFORMED_CONSENT,
    FunctionCategory::TERAPI,
];

pub(crate) const LABORATORIUM_FUNCTIONS: [FunctionCategory; 2] = [
    FunctionCategory::ADMINISTRATIVE_GENERAL,
    FunctionCategory::LABORATORIUM,
];

pub(crate) const APOTEK_FUNCTIONS: [FunctionCategory; 3] = [
    FunctionCategory::ADMINISTRATIVE_GENERAL,
    FunctionCategory::PERESEPAN,
    FunctionCategory::DISPENSING,
];
