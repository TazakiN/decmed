import type { completeProfileSchema, signInSchemaStep3, signUpSchemaStep4 } from './schema';

export type Account = {
	id: string;
	name: string;
};

export type AdministrativeData = {
	id: string;
	idHash: string;
	name: string | undefined;
};

export type CompleteProfileSchema = typeof completeProfileSchema;

export type InvokeGetMedicalRecordsResponse = {
	index: string;
	createdAt: string;
};

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
