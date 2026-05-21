use serde::{Deserialize, Serialize};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum DatasetCategory {
    ADMINISTRATIVE,
    RAWAT_JALAN,
    RAWAT_INAP,
    LABORATORIUM,
    APOTEK,
}

pub const ALL_DATASET_CATEGORIES: [DatasetCategory; 5] = [
    DatasetCategory::ADMINISTRATIVE,
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
    ADMINISTRATIVE_GENERAL,
    ANAMNESIS,
    PEMERIKSAAN_FISIK,
    PEMERIKSAAN_PSIKOLOGIS,
    RIWAYAT_PENGGUNAAN_OBAT,
    RENCANA_RAWAT,
    PERENCANAAN_PEMULANGAN,
    INSTRUKSI_MEDIK_DAN_KEPERAWATAN,
    PEMERIKSAAN_PENUNJANG,
    DIAGNOSIS,
    INFORMED_CONSENT,
    TERAPI,
    PERMINTAAN_PEMERIKSAAN,
    SPESIMEN_KLINIS,
    PENGOLAHAN_SPESIMEN,
    HASIL_PEMERIKSAAN,
    VALIDASI_HASIL,
    DISTRIBUSI_HASIL,
    DATA_RESEP_DAN_OBAT,
    RIWAYAT_ALERGI,
    ASAL_RESEP,
    DOKTER_PENULIS_RESEP,
    STATUS_DAN_PENGKAJIAN_RESEP,
    STATUS_RESEP,
    WAKTU_PENYIAPAN_OBAT,
    WAKTU_PENYERAHAN_OBAT,
    PETUGAS_DISPENSING,
    ETIKET,
}

pub const ALL_FUNCTION_CATEGORIES: [FunctionCategory; 28] = [
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
    FunctionCategory::PERMINTAAN_PEMERIKSAAN,
    FunctionCategory::SPESIMEN_KLINIS,
    FunctionCategory::PENGOLAHAN_SPESIMEN,
    FunctionCategory::HASIL_PEMERIKSAAN,
    FunctionCategory::VALIDASI_HASIL,
    FunctionCategory::DISTRIBUSI_HASIL,
    FunctionCategory::DATA_RESEP_DAN_OBAT,
    FunctionCategory::RIWAYAT_ALERGI,
    FunctionCategory::ASAL_RESEP,
    FunctionCategory::DOKTER_PENULIS_RESEP,
    FunctionCategory::STATUS_DAN_PENGKAJIAN_RESEP,
    FunctionCategory::STATUS_RESEP,
    FunctionCategory::WAKTU_PENYIAPAN_OBAT,
    FunctionCategory::WAKTU_PENYERAHAN_OBAT,
    FunctionCategory::PETUGAS_DISPENSING,
    FunctionCategory::ETIKET,
];

impl FunctionCategory {
    pub fn all() -> &'static [FunctionCategory] {
        &ALL_FUNCTION_CATEGORIES
    }
}

pub(crate) const ADMINISTRATIVE_FUNCTIONS: [FunctionCategory; 1] =
    [FunctionCategory::ADMINISTRATIVE_GENERAL];

pub(crate) const RAWAT_JALAN_FUNCTIONS: [FunctionCategory; 10] = [
    FunctionCategory::ANAMNESIS,
    FunctionCategory::PEMERIKSAAN_FISIK,
    FunctionCategory::PEMERIKSAAN_PSIKOLOGIS,
    FunctionCategory::RIWAYAT_PENGGUNAAN_OBAT,
    FunctionCategory::RENCANA_RAWAT,
    FunctionCategory::PEMERIKSAAN_PENUNJANG,
    FunctionCategory::DIAGNOSIS,
    FunctionCategory::INFORMED_CONSENT,
    FunctionCategory::TERAPI,
    FunctionCategory::PERMINTAAN_PEMERIKSAAN,
];

pub(crate) const RAWAT_INAP_FUNCTIONS: [FunctionCategory; 12] = [
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
    FunctionCategory::PERMINTAAN_PEMERIKSAAN,
];

pub(crate) const LABORATORIUM_FUNCTIONS: [FunctionCategory; 6] = [
    FunctionCategory::PERMINTAAN_PEMERIKSAAN,
    FunctionCategory::SPESIMEN_KLINIS,
    FunctionCategory::PENGOLAHAN_SPESIMEN,
    FunctionCategory::HASIL_PEMERIKSAAN,
    FunctionCategory::VALIDASI_HASIL,
    FunctionCategory::DISTRIBUSI_HASIL,
];

pub(crate) const APOTEK_FUNCTIONS: [FunctionCategory; 10] = [
    FunctionCategory::DATA_RESEP_DAN_OBAT,
    FunctionCategory::RIWAYAT_ALERGI,
    FunctionCategory::ASAL_RESEP,
    FunctionCategory::DOKTER_PENULIS_RESEP,
    FunctionCategory::STATUS_DAN_PENGKAJIAN_RESEP,
    FunctionCategory::STATUS_RESEP,
    FunctionCategory::WAKTU_PENYIAPAN_OBAT,
    FunctionCategory::WAKTU_PENYERAHAN_OBAT,
    FunctionCategory::PETUGAS_DISPENSING,
    FunctionCategory::ETIKET,
];
