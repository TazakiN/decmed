import { z } from 'zod';
import {
	ADMINISTRATIVE_PERSONNEL_ROLE,
	MEDICAL_PERSONNEL_ROLE,
	MEDICAL_PERSONNEL_SUB_ROLES
} from './constants';

export const datasetCategories = ['RAWAT_JALAN', 'RAWAT_INAP', 'LABORATORIUM', 'APOTEK'] as const;

export const functionCategories = [
	'ADMINISTRATIVE_GENERAL',
	'ANAMNESIS',
	'PEMERIKSAAN_FISIK',
	'PEMERIKSAAN_PSIKOLOGIS',
	'RIWAYAT_PENGGUNAAN_OBAT',
	'RENCANA_RAWAT',
	'PERENCANAAN_PEMULANGAN',
	'INSTRUKSI_MEDIK_DAN_KEPERAWATAN',
	'PEMERIKSAAN_PENUNJANG',
	'DIAGNOSIS',
	'INFORMED_CONSENT',
	'TERAPI',
	'LABORATORIUM',
	'PERESEPAN',
	'DISPENSING'
] as const;

export const allowedSegmentFunctionCategories = {
	RAWAT_JALAN: [
		'ADMINISTRATIVE_GENERAL',
		'ANAMNESIS',
		'PEMERIKSAAN_FISIK',
		'PEMERIKSAAN_PSIKOLOGIS',
		'RIWAYAT_PENGGUNAAN_OBAT',
		'RENCANA_RAWAT',
		'INSTRUKSI_MEDIK_DAN_KEPERAWATAN',
		'PEMERIKSAAN_PENUNJANG',
		'DIAGNOSIS',
		'INFORMED_CONSENT',
		'TERAPI'
	],
	RAWAT_INAP: [
		'ADMINISTRATIVE_GENERAL',
		'ANAMNESIS',
		'PEMERIKSAAN_FISIK',
		'PEMERIKSAAN_PSIKOLOGIS',
		'RIWAYAT_PENGGUNAAN_OBAT',
		'RENCANA_RAWAT',
		'PERENCANAAN_PEMULANGAN',
		'INSTRUKSI_MEDIK_DAN_KEPERAWATAN',
		'PEMERIKSAAN_PENUNJANG',
		'DIAGNOSIS',
		'INFORMED_CONSENT',
		'TERAPI'
	],
	LABORATORIUM: ['ADMINISTRATIVE_GENERAL', 'PEMERIKSAAN_PENUNJANG', 'LABORATORIUM'],
	APOTEK: ['ADMINISTRATIVE_GENERAL', 'RIWAYAT_PENGGUNAAN_OBAT', 'TERAPI', 'PERESEPAN', 'DISPENSING']
} as const satisfies Record<
	(typeof datasetCategories)[number],
	readonly (typeof functionCategories)[number][]
>;

export const datasetCategorySchema = z.enum(datasetCategories);
export const functionCategorySchema = z.enum(functionCategories);

export function isValidSegmentCategory(
	datasetCategory: (typeof datasetCategories)[number],
	functionCategory: (typeof functionCategories)[number]
) {
	return (allowedSegmentFunctionCategories[datasetCategory] as readonly string[]).includes(
		functionCategory
	);
}

const pinSchema = {
	pin: z
		.string({
			required_error: 'PIN is required.',
			invalid_type_error: 'PIN is invalid.'
		})
		.trim()
		.regex(/^\d{6}$/, { message: 'PIN is invalid.' })
		.min(1, { message: 'PIN is required.' })
		.max(6, { message: 'PIN maximum 6 digits.' })
};

const nameSchema = {
	name: z
		.string({ required_error: 'Name is required.', invalid_type_error: 'Name is invalid.' })
		.trim()
		.regex(/^[a-zA-Z0-9 ]{2,100}$/, {
			message: 'Name must consist of alphanumeric characters only of length 2 - 100.'
		})
};

export const medicalDataMainCategory = {
	mainCategory: datasetCategorySchema
};

export const medicalDataSubCategory = {
	subCategory: functionCategorySchema
};

const anamnesisSchema = {
	anamnesis: z
		.string({
			required_error: 'Anamnesis is required.',
			invalid_type_error: 'Anamnesis is invalid.'
		})
		.trim()
		.regex(/^[a-zA-Z0-9:,.\\ ]{2,1000}$/, {
			message: 'Anamnesis must consist of alphanumeric characters only of length 2 - 100.'
		})
};

const physicalCheckSchema = {
	physicalCheck: z
		.string({
			required_error: 'Physical check is required.',
			invalid_type_error: 'Physical check is invalid.'
		})
		.trim()
		.regex(/^[a-zA-Z0-9:,.\\ ]{2,1000}$/, {
			message: 'Physical check must consist of alphanumeric characters only of length 2 - 100.'
		})
};

const psychologicalCheckSchema = {
	psychologicalCheck: z
		.string({
			required_error: 'Psychological check is required.',
			invalid_type_error: 'Psychological check is invalid.'
		})
		.trim()
		.regex(/^[a-zA-Z0-9:,.\\ ]{2,1000}$/, {
			message: 'Psychological check must consist of alphanumeric characters only of length 2 - 100.'
		})
};

const diagnoseSchema = {
	diagnose: z
		.string({
			required_error: 'Diagnose is required.',
			invalid_type_error: 'Diagnose is invalid.'
		})
		.trim()
		.regex(/^[a-zA-Z0-9:,.\\ ]{2,1000}$/, {
			message: 'Diagnose must consist of alphanumeric characters only of length 2 - 100.'
		})
};

const therapySchema = {
	therapy: z
		.string({
			required_error: 'Therapy is required.',
			invalid_type_error: 'Therapy is invalid.'
		})
		.trim()
		.regex(/^[a-zA-Z0-9:,.\\ ]{2,1000}$/, {
			message: 'Therapy must consist of alphanumeric characters only of length 2 - 100.'
		})
};

// const _hospitalSchema = {
// 	hospital: z
// 		.string({ required_error: 'Hospital is required.', invalid_type_error: 'Hospital is invalid.' })
// 		.trim()
// 		.regex(/^[a-zA-Z0-9 ]{2,100}$/, {
// 			message: 'Hospital must consist of alphanumeric characters only of length 2 - 100.'
// 		})
//
// };

export const activationSchema = z.object({
	id: z
		.string({
			required_error: 'ID is required.',
			invalid_type_error: 'ID is invalid.'
		})
		.trim()
		.min(1, { message: 'ID is required.' }),
	activationKey: z
		.string({
			required_error: 'Activation Key is required.',
			invalid_type_error: 'Activation Key is invalid.'
		})
		.trim()
		.min(1, { message: 'Activation Key is required.' })
		.max(36, { message: 'Activation Key is invalid.' })
});

export const signInSchemaStep1 = z.object(pinSchema);

export const signInSchemaStep2 = signInSchemaStep1.extend({
	confirmPin: z
		.string({
			required_error: 'Confirm PIN is required.',
			invalid_type_error: 'Confirm PIN is invalid.'
		})
		.trim()
		.regex(/^\d{6}$/, { message: 'Confirm PIN is invalid.' })
		.min(1, { message: 'Confirm PIN is required.' })
		.max(6, { message: 'Confirm PIN maximum 6 digits.' })
});

export const signInSchemaStep3 = signInSchemaStep2
	.extend({
		seedWords: z
			.string({
				required_error: 'Seed Words is required.',
				invalid_type_error: 'Seed Words is invalid.'
			})
			.trim()
			.min(1, { message: 'Seed Words is required.' })

			.refine(
				(val) => {
					const words = val.split(' ');
					return words.length === 12;
				},
				{
					message: 'Seed Words is invalid.'
				}
			)
	})
	.superRefine((val, ctx) => {
		if (val.pin !== val.confirmPin) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ['confirmPin'],
				message: 'PIN and Confirm PIN must be same.'
			});
		}
	});

export const signUpSchemaStep1 = signInSchemaStep1;
export const signUpSchemaStep2 = signInSchemaStep2;
export const signUpSchemaStep3 = z.object({});
export const signUpSchemaStep4 = signInSchemaStep3;

export const medicalPersonnelSubRoleSchema = z.enum(MEDICAL_PERSONNEL_SUB_ROLES, {
	required_error: 'Sub role is required.',
	invalid_type_error: 'Sub role is invalid.'
});

export const addPersonnelSchemaStep1 = z.object({
	id: z
		.string({
			required_error: 'ID is required.',
			invalid_type_error: 'ID is invalid.'
		})
		.trim()
		.min(1, { message: 'ID is required.' }),
	role: z.enum([ADMINISTRATIVE_PERSONNEL_ROLE, MEDICAL_PERSONNEL_ROLE], {
		required_error: 'Role is required.',
		invalid_type_error: 'Role is invalid.'
	}),
	subRole: medicalPersonnelSubRoleSchema.optional()
});

export const addPersonnelSchemaStep2 = addPersonnelSchemaStep1.extend(pinSchema);
export const completeProfileAdminSchema = z.object(nameSchema);
export const completeProfilePersonnelSchema = z.object(nameSchema);
export const createRmeSegmentSchema = z
	.object({
		related_rme_id: z.string().trim().min(1),
		patient_address: z.string().trim().min(1),

		service_date: z.string().trim().min(1),
		author_address: z.string().trim().min(1),
		dataset_category: datasetCategorySchema,
		function_category: functionCategorySchema,
		payload: z.record(z.unknown()).refine((payload) => Object.keys(payload).length > 0, {
			message: 'Payload is required.'
		}),
		correction_of_index: z.number().int().nonnegative().nullable().optional(),
		correction_reason: z.string().trim().nullable().optional()
	})
	.superRefine((value, ctx) => {
		if (!isValidSegmentCategory(value.dataset_category, value.function_category)) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ['function_category'],
				message: 'Invalid dataset_category and function_category combination.'
			});
		}
		if (value.correction_of_index != null && !value.correction_reason?.trim()) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ['correction_reason'],
				message: 'Correction reason is required.'
			});
		}
		if (value.correction_of_index == null && value.correction_reason != null) {
			ctx.addIssue({
				code: z.ZodIssueCode.custom,
				path: ['correction_reason'],
				message: 'Correction reason requires correction_of_index.'
			});
		}
	});
export const createMedicalRecordSchema = z
	.object(anamnesisSchema)
	.extend(physicalCheckSchema)
	.extend(psychologicalCheckSchema)
	.extend(diagnoseSchema)
	.extend(therapySchema);
export const updateMedicalRecordSchema = z
	.object(anamnesisSchema)
	.extend(physicalCheckSchema)
	.extend(psychologicalCheckSchema)
	.extend(diagnoseSchema)
	.extend(therapySchema);

export const addPersonnelSchemas = [addPersonnelSchemaStep1, addPersonnelSchemaStep2];
export const signInSchemas = [signInSchemaStep1, signInSchemaStep2, signInSchemaStep3];
export const signUpSchemas = [
	signUpSchemaStep1,
	signUpSchemaStep2,
	signUpSchemaStep3,
	signUpSchemaStep4
];
