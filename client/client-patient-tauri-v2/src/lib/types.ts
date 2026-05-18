import type { completeProfileSchema, signInSchemaStep3, signUpSchemaStep4 } from './schema';

export type Account = {
	id: string;
	name: string;
};

export type CompleteProfileSchema = typeof completeProfileSchema;

export type InvokeGetMedicalRecordsResponse = {
	cid: string;
	createdAt: string;
	index: string;
};

export type InvokeGetAccessLog = {
	access_data_type: ('Administrative' | 'Medical')[];
	access_type: 'Read' | 'Update';
	date: string;
	exp_dur: number;
	hospital_metadata: {
		name: string;
	};
	hospital_personnel_address: string;
	hospital_personnel_metadata: {
		name: string;
	};
	index: number;
	is_revoked: boolean;
};

export type InvokeProcessQrResponse = {
	hospitalPersonnelHospitalName: string;
	hospitalPersonnelName: string;
};

export type InvokeGetMedicalRecordResponse = {
	createdAt: string;
	medicalData: TauriMedicalData;
};

export type TauriAdministrativeData = {
	id: string;
	idHash: string;
	iotaAddress: string;
	prePublicKey: string;
	name: string | null;
	birthPlace: string | null;
	dateOfBirth: string | null;
	gender: string | null;
	religion: string | null;
	education: string | null;
	occupation: string | null;
	maritalStatus: string | null;
};

export type TauriMedicalData = {
	anamnesis: string;
	physical_check: string;
	psychological_check: string;
	diagnose: string;
	therapy: string;
};

export type DatasetCategory =
	| 'ADMINISTRATIVE'
	| 'RAWAT_JALAN'
	| 'RAWAT_INAP'
	| 'LABORATORIUM'
	| 'APOTEK';

export type FunctionCategory =
	| 'ADMINISTRATIVE_GENERAL'
	| 'ANAMNESIS'
	| 'PEMERIKSAAN_FISIK'
	| 'PEMERIKSAAN_PSIKOLOGIS'
	| 'RIWAYAT_PENGGUNAAN_OBAT'
	| 'RENCANA_RAWAT'
	| 'PERENCANAAN_PEMULANGAN'
	| 'INSTRUKSI_MEDIK_DAN_KEPERAWATAN'
	| 'PEMERIKSAAN_PENUNJANG'
	| 'DIAGNOSIS'
	| 'INFORMED_CONSENT'
	| 'TERAPI'
	| 'PERMINTAAN_PEMERIKSAAN'
	| 'SPESIMEN_KLINIS'
	| 'PENGOLAHAN_SPESIMEN'
	| 'HASIL_PEMERIKSAAN'
	| 'VALIDASI_HASIL'
	| 'DISTRIBUSI_HASIL'
	| 'DATA_RESEP_DAN_OBAT'
	| 'RIWAYAT_ALERGI'
	| 'ASAL_RESEP'
	| 'DOKTER_PENULIS_RESEP'
	| 'STATUS_DAN_PENGKAJIAN_RESEP'
	| 'STATUS_RESEP'
	| 'WAKTU_PENYIAPAN_OBAT'
	| 'WAKTU_PENYERAHAN_OBAT'
	| 'PETUGAS_DISPENSING'
	| 'ETIKET';

export type RmeSegmentAttachment = {
	cid: string;
	file_name: string;
	mime_type: string;
};

export type RmeSegmentData = {
	segment_id: string;
	related_rme_id: string;
	dataset_category: DatasetCategory;
	function_category: FunctionCategory;
	patient_ref: string;
	encounter_id: string;
	service_date: string;
	author_address: string;
	payload: Record<string, unknown>;
	payload_hash: string;
	attachments?: RmeSegmentAttachment[];
};

export type RmeSegmentMetadata = {
	segment_id: string;
	related_rme_id: string;
	patient_address: string;
	fasyankes_id: string;
	dataset_category: DatasetCategory;
	function_category: FunctionCategory;
	ipfs_cid: string;
	integrity_hash: string;
	capsule: string;
	enc_key_and_nonce: string;
	encryption_algo: 'AES-256-GCM';
	created_at: string;
	author_address: string;
	updated_at: string | null;
};

export type TauriMedicalDataMainCategory = DatasetCategory;

export type TauriMedicalDataSubCategory = FunctionCategory;

export type NavLink = {
	label: string;
	link: string;
	pageTitle: string;
};

export type SignUpSchemaStep4 = typeof signUpSchemaStep4;
export type SIgnInSchemaStep3 = typeof signInSchemaStep3;

export type SuccessResponse<T> = {
	data: T;
	status: string;
};

export type TryCatchAsValError = {
	error: string;
	success: false;
};
export type TryCatchAsValReturn<T> = TryCatchAsValSuccess<T> | TryCatchAsValError;
export type TryCatchAsValSuccess<T> = {
	success: true;
	data: T;
};
