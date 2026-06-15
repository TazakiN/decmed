import type {
	addPersonnelSchemaStep2,
	completeProfileAdminSchema,
	completeProfilePersonnelSchema,
	createMedicalRecordSchema,
	signInSchemaStep3,
	signUpSchemaStep4,
	updateMedicalRecordSchema
} from './schema';
import {
	ADMIN_ROLE,
	ADMINISTRATIVE_PERSONNEL_ROLE,
	MEDICAL_PERSONNEL_ROLE,
	MEDICAL_PERSONNEL_SUB_ROLES
} from './constants';
import type { z } from 'zod';

export type Role =
	| typeof ADMIN_ROLE
	| typeof MEDICAL_PERSONNEL_ROLE
	| typeof ADMINISTRATIVE_PERSONNEL_ROLE;

export type MedicalPersonnelSubRole = (typeof MEDICAL_PERSONNEL_SUB_ROLES)[number];

export type NavLink = {
	label: string;
	link: string;
	pageTitle: string;
};

export type Account = {
	role: Role;
	name: string;
	id: string;
};

export type HospitalPersonnel = {
	id: string;
	activation_key: string;
	role: Role;
	sub_role?: MedicalPersonnelSubRole;
};

export type DelegateeCandidate = {
	personnelIdHash: string;
	name?: string | null;
	role: Role;
	subRole?: MedicalPersonnelSubRole | null;
	iotaAddress: string;
	prePublicKey: string;
};

export type SuccessResponse<T> = {
	status: string;
	data: T;
};

export type TauriAccessData = {
	accessDataTypes: TauriAccessDataType[];
	accessToken: string;
	tokenHash?: string;
	dataPreSecretKeySeedCapsule?: string | null;
	encDataPreSecretKeySeed?: string | null;
	exp: number;
	medicalMetadataIndex: number | null;
	patientIotaAddress: string;
	patientName: string;
	patientPrePublicKey: string | null;
	relatedRmeId?: string | null;
	delegatedBy?: string | null;
	delegatedTo?: string | null;
	expiresBefore?: string | null;
	delegationSignature?: string | null;
	delegationDepth?: number | null;
};

export type TauriAccessDataType = 'Administrative' | 'Medical';

export type TauriMedicalData = {
	anamnesis: string;
	physical_check: string;
	psychological_check: string;
	diagnose: string;
	therapy: string;
};

export type DatasetCategory = 'RAWAT_JALAN' | 'RAWAT_INAP' | 'LABORATORIUM' | 'APOTEK';

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
	| 'LABORATORIUM'
	| 'PERESEPAN'
	| 'DISPENSING';

export type AccessCapabilityData = {
	access: TauriAccessData;
	purpose: 'Read' | 'Update' | string;
	readDatasets: DatasetCategory[];
	writeDatasets: DatasetCategory[];
	readFunctions: FunctionCategory[];
	writeFunctions: FunctionCategory[];
	expiresBefore?: string | null;
	relatedRmeId?: string | null;
	delegationDepth?: number | null;
};

export type AccessCapabilitiesResponse = {
	read: AccessCapabilityData[];
	write: AccessCapabilityData[];
};

export type RmeSegmentData = {
	segment_id: string;
	related_rme_id: string;
	dataset_category: DatasetCategory;
	function_category: FunctionCategory;
	patient_address: string;
	service_date: string;
	author_address: string;
	payload: Record<string, unknown>;
	payload_hash: string;
	correction_of_index: number | null;
	correction_reason: string | null;
};

export type RmeSegmentMetadata = {
	segment_id: string;
	related_rme_id: string;
	patient_address: string;
	hospital_cid: string;
	dataset_category: DatasetCategory;
	function_category: FunctionCategory;
	ipfs_cid: string;
	integrity_hash: string;
	capsule: string;
	enc_key_and_nonce: string;
	created_at: string;
	author_address: string;
	correction_of_index: number | null;
	correction_reason: string | null;
	updated_at: number | null;
};

export type CreateRmeSegmentResponse = {
	segment_id: string;
	related_rme_id: string;
	dataset_category: DatasetCategory;
	function_category: FunctionCategory;
	ipfs_cid: string;
	integrity_hash: string;
	created_at: string;
	correction_of_index: number | null;
	correction_reason: string | null;
	updated_at: number | null;
};

export type CreateRmeSegmentRequest = {
	related_rme_id: string;
	patient_address: string;
	service_date: string;
	author_address: string;
	dataset_category: DatasetCategory;
	function_category: FunctionCategory;
	payload: Record<string, unknown>;
	correction_of_index?: number | null;
	correction_reason?: string | null;
};

export type TauriPatientPrivateAdministrativeData = {
	id: string;
	name: string | null;
	birth_place: string | null;
	date_of_birth: string | null;
	gender: string | null;
	religion: string | null;
	education: string | null;
	occupation: string | null;
	marital_status: string | null;
};

export type AdministrativeData = {
	id: string;
	idHash: string;
	name?: string;
	hospital?: string;
};

export type GetProfileData = {
	hospital: string | null;
	hospitalCid: string;
	hospitalIdHash?: string | null;
	hospitalPrePublicKey?: string | null;
	id: string;
	idHash: string;
	iotaAddress: string;
	iotaKeyPair: string;
	name: string | null;
	prePublicKey: string;
	role: Role;
	subRole?: MedicalPersonnelSubRole;
};

export type RmeSegmentListItem = {
	index: number;
	segment_id: string;
	function_category: FunctionCategory;
	created_at: string;
	author_address: string;
	list_index: number;
	correction_of_index: number | null;
	correction_reason: string | null;
	updated_at: number | null;
};

export type RmeDatasetGroup = {
	dataset_category: DatasetCategory;
	segments: RmeSegmentListItem[];
};

export type RmeEncounterGroup = {
	related_rme_id: string;
	created_at: string;
	datasets: RmeDatasetGroup[];
};

export type InvokeGetMedicalRecordResponseData = {
	administrativeData: TauriPatientPrivateAdministrativeData;
	createdAt: string;
	medicalData: TauriMedicalData | null;
	recordKind?: 'legacy' | 'segment';
	segment?: RmeSegmentData | null;
	currentIndex: number;
	nextIndex?: number | null;
	prevIndex?: number | null;
};

export type InvokeGetMedicalRecordPayloadResponseData = Omit<
	InvokeGetMedicalRecordResponseData,
	'administrativeData'
> & {
	administrativeData?: TauriPatientPrivateAdministrativeData;
};

export type InvokeGetPatientAdministrativeDataResponseData = {
	administrativeData: TauriPatientPrivateAdministrativeData;
};

export type InvokeGlobalAdminAddActivationKeyData = {
	activationKey: string;
	id: string;
};

export type InvokeHospitalAdminAddActivationKeyResponse = {
	activationKey: string;
	id: string;
};

export type TryCatchAsValSuccess<T> = { success: true; data: T };
export type TryCatchAsValError = { success: false; error: string };
export type TryCatchAsValReturn<T> = TryCatchAsValSuccess<T> | TryCatchAsValError;

export type AddPersonnelSchemaStep2 = typeof addPersonnelSchemaStep2;
export type CompleteProfileAdminSchema = typeof completeProfileAdminSchema;
export type CompleteProfilePersonnelSchema = typeof completeProfilePersonnelSchema;
export type CreateMedicalRecordSchema = typeof createMedicalRecordSchema;
export type SignUpSchemaStep4 = typeof signUpSchemaStep4;
export type SignInSchemaStep3 = typeof signInSchemaStep3;
export type UpdateMedicalRecordSchema = typeof updateMedicalRecordSchema;

export type MedicalData = z.infer<typeof createMedicalRecordSchema>;
export type MedicalDataMainCategory = DatasetCategory;
export type MedicalDataSubCategory = FunctionCategory;
