import { updateMedicalRecordSchema } from '$lib/schema';
import type {
	InvokeGetMedicalRecordResponseData,
	MedicalDataMainCategory,
	MedicalDataSubCategory,
	SuccessResponse,
	UpdateMedicalRecordSchema
} from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';
import { superForm, type Infer, type SuperForm, type SuperValidated } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';

type Props = {
	accessToken: string;
	index: number | null;
	patientIotaAddress: string;
	patientPrePublicKey: string;
	updateMedicalRecordForm: SuperValidated<Infer<UpdateMedicalRecordSchema>>;
};

type SetFormDataProps = {
	mainCategory: MedicalDataMainCategory;
	subCategory: MedicalDataSubCategory;
};

export class EmrUpdateState {
	accessToken = $state<string>('');
	index = $state<number | null>(null);
	patientIotaAddress = $state('');
	patientPrePublicKey = $state<string>('');
	updateMedicalRecordFormMeta: SuperForm<Infer<UpdateMedicalRecordSchema>>;
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
		index,
		patientIotaAddress,
		patientPrePublicKey,
		updateMedicalRecordForm
	}: Props) {
		this.accessToken = accessToken;
		this.index = index;
		this.patientIotaAddress = patientIotaAddress;
		this.patientPrePublicKey = patientPrePublicKey;

		this.updateMedicalRecordFormMeta = superForm(updateMedicalRecordForm, {
			validators: zod(updateMedicalRecordSchema),
			dataType: 'json',
			SPA: true,
			invalidateAll: false,
			resetForm: false,
			onUpdate: async ({ form, result, cancel }) => {
				if (result.type === 'success') {
					const resInvokeUpdateMedicalRecord = await tryCatchAsVal(async () => {
						return (await invoke('update_medical_record', {
							accessToken,
							data: { mainCategory: form.data.mainCategory, subCategory: form.data.subCategory },
							patientIotaAddress,
							patientPrePublicKey
						})) as SuccessResponse<null>;
					});

					if (!resInvokeUpdateMedicalRecord.success) {
						toast.error(resInvokeUpdateMedicalRecord.error);
						cancel();
						return;
					}

					toast.success('Medical record updated sucessfully');
				}
			}
		});
	}

	getMedicalRecord = async (
		accessToken: string,
		index: number | null,
		patientIotaAddress: string
	) => {
		if (index === null) {
			throw '404';
		}

		const resInvokeGetMedicalRecord = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_record_update', {
				accessToken,
				index,
				patientIotaAddress
			})) as SuccessResponse<InvokeGetMedicalRecordResponseData>;
		});

		console.log(resInvokeGetMedicalRecord);

		if (!resInvokeGetMedicalRecord.success) {
			toast.error(resInvokeGetMedicalRecord.error);
			throw new Error(resInvokeGetMedicalRecord.error);
		}

		this.setFormData({
			mainCategory: resInvokeGetMedicalRecord.data.data.mainCategory as MedicalDataMainCategory,
			subCategory: resInvokeGetMedicalRecord.data.data.subCategory as MedicalDataSubCategory
		});

		return resInvokeGetMedicalRecord.data.data;
	};

	fetchMedicalRecord = $derived(
		this.getMedicalRecord(this.accessToken, this.index, this.patientIotaAddress)
	);

	setFormData = async ({ mainCategory, subCategory }: SetFormDataProps) => {
		this.updateMedicalRecordFormMeta.form.update((prev) => {
			prev.mainCategory = mainCategory;
			prev.subCategory = subCategory;
			return prev;
		});
	};
}
