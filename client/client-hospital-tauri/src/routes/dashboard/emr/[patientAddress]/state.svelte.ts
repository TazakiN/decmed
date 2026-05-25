import type { InvokeGetMedicalRecordResponseData, SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';

type Props = {
	accessToken: string;
	dataPreSecretKeySeedCapsule?: string | null;
	encDataPreSecretKeySeed?: string | null;
	index: number;
	patientIotaAddress: string;
};

export class EmrReadState {
	accessToken = $state<string>('');
	dataPreSecretKeySeedCapsule = $state<string | null>(null);
	encDataPreSecretKeySeed = $state<string | null>(null);
	index = $state<number>(0);
	patientIotaAddress = $state('');

	constructor({
		accessToken,
		dataPreSecretKeySeedCapsule,
		encDataPreSecretKeySeed,
		index,
		patientIotaAddress
	}: Props) {
		this.accessToken = accessToken;
		this.dataPreSecretKeySeedCapsule = dataPreSecretKeySeedCapsule || null;
		this.encDataPreSecretKeySeed = encDataPreSecretKeySeed || null;
		this.index = index;
		this.patientIotaAddress = patientIotaAddress;
	}

	getMedicalRecord = async (
		accessToken: string | null,
		encDataPreSecretKeySeed: string | null,
		dataPreSecretKeySeedCapsule: string | null,
		index: number | null,
		patientIotaAddress: string
	) => {
		const resInvokeGetMedicalRecord = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_record', {
				accessToken,
				encDataPreSecretKeySeed,
				dataPreSecretKeySeedCapsule,
				index,
				patientIotaAddress
			})) as SuccessResponse<InvokeGetMedicalRecordResponseData>;
		});

		if (!resInvokeGetMedicalRecord.success) {
			toast.error(resInvokeGetMedicalRecord.error);
			throw new Error(resInvokeGetMedicalRecord.error);
		}

		return resInvokeGetMedicalRecord.data.data;
	};

	fetchMedicalRecord = $derived(
		this.getMedicalRecord(
			this.accessToken,
			this.encDataPreSecretKeySeed,
			this.dataPreSecretKeySeedCapsule,
			this.index,
			this.patientIotaAddress
		)
	);
}
