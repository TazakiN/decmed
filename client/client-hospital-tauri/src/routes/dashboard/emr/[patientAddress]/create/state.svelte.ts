import { goto } from '$app/navigation';
import { createMedicalRecordSchema } from '$lib/schema';
import type { CreateMedicalRecordSchema, SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { redirect } from '@sveltejs/kit';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';
import { superForm, type Infer, type SuperForm, type SuperValidated } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';

type Props = {
	accessToken: string;
	patientIotaAddress: string;
	patientPrePublicKey: string;
	createMedicalRecordForm: SuperValidated<Infer<CreateMedicalRecordSchema>>;
};

export class EmrCreateState {
	accessToken = $state<string>('');
	patientIotaAddress = $state('');
	patientPrePublicKey = $state<string>('');
	createMedicalRecordFormMeta: SuperForm<Infer<CreateMedicalRecordSchema>>;
	medicalDataMainCategory = [
		{
			value: 'Category1',
			label: 'Category 1'
		},
		{
			value: 'Category2',
			label: 'Category 2'
		}
	];
	medicalDataSubCategory = [
		{
			value: 'SubCategory1',
			label: 'Sub Category 1'
		},
		{
			value: 'SubCategory2',
			label: 'SubCategory 2'
		}
	];

	constructor({
		accessToken,
		createMedicalRecordForm,
		patientIotaAddress,
		patientPrePublicKey
	}: Props) {
		this.accessToken = accessToken;
		this.patientIotaAddress = patientIotaAddress;
		this.patientPrePublicKey = patientPrePublicKey;

		this.createMedicalRecordFormMeta = superForm(createMedicalRecordForm, {
			validators: zod(createMedicalRecordSchema),
			dataType: 'json',
			SPA: true,
			invalidateAll: false,
			onUpdate: async ({ form, result, cancel }) => {
				if (result.type === 'success') {
					const resInvokeCreateMedicalRecord = await tryCatchAsVal(async () => {
						return (await invoke('new_medical_record', {
							accessToken,
							data: { mainCategory: form.data.mainCategory, subCategory: form.data.subCategory },
							patientIotaAddress,
							patientPrePublicKey
						})) as SuccessResponse<null>;
					});

					if (!resInvokeCreateMedicalRecord.success) {
						toast.error(resInvokeCreateMedicalRecord.error);
						cancel();
						return;
					}

					toast.success('Medical record created sucessfully');
					await goto('/dashboard');
				}
			}
		});
	}
}
