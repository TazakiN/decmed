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

export type InvokeProcessQrResponse = {
	hospitalPersonnelHospitalName: string;
	hospitalPersonnelName: string;
};

export type TauriAdministrativeData = {
	id: string;
	idHash: string;
	iotaAddress: string;
	prePublicKey: string;
	name: string | undefined;
};

export type TauriMedicalData = {
	main_category: TauriMedicalDataMainCategory;
	sub_category: TauriMedicalDataSubCategory;
};

export type TauriMedicalDataMainCategory = 'Category1' | 'Category2';

export type TauriMedicalDataSubCategory = 'SubCategory1' | 'SubCategory2';

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
