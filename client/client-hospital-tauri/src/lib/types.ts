import type {
	addPersonnelSchemaStep2,
	completeProfileAdminSchema,
	completeProfilePersonnelSchema,
	signInSchemaStep3,
	signUpSchemaStep4
} from './schema';
import { ADMIN_ROLE, ADMINISTRATIVE_PERSONNEL_ROLE, MEDICAL_PERSONNEL_ROLE } from './constants';

export type Role =
	| typeof ADMIN_ROLE
	| typeof MEDICAL_PERSONNEL_ROLE
	| typeof ADMINISTRATIVE_PERSONNEL_ROLE;

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
};

export type SuccessResponse<T> = {
	status: string;
	data: T;
};

export type AdministrativeData = {
	id: string;
	idHash: string;
	name?: string;
	hospital?: string;
};

export type GetProfileData = {
	id: string;
	idHash: string;
	name: string | null;
	hospital: string | null;
	role: Role;
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

export type SignUpSchemaStep4 = typeof signUpSchemaStep4;
export type SIgnInSchemaStep3 = typeof signInSchemaStep3;
export type AddPersonnelSchemaStep2 = typeof addPersonnelSchemaStep2;
export type CompleteProfileAdminSchema = typeof completeProfileAdminSchema;
export type CompleteProfilePersonnelSchema = typeof completeProfilePersonnelSchema;
