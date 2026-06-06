import type { RmeEncounterGroup, SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';

type Props = {
	accessToken: string;
	patientIotaAddress: string;
};

export class EmrMetadataListState {
	accessToken = $state('');
	patientIotaAddress = $state('');

	constructor({ accessToken, patientIotaAddress }: Props) {
		this.accessToken = accessToken;
		this.patientIotaAddress = patientIotaAddress;
	}

	getMetadata = async (accessToken: string, patientIotaAddress: string) => {
		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_accessible_medical_record_metadata', {
				accessToken,
				patientIotaAddress
			})) as SuccessResponse<RmeEncounterGroup[]>;
		});

		if (!res.success) {
			toast.error(res.error);
			throw new Error(res.error);
		}

		return res.data.data;
	};

	fetchMetadata = $derived(this.getMetadata(this.accessToken, this.patientIotaAddress));
}

export function emrAccessQueryString(params: {
	accessToken: string;
	encDataPreSecretKeySeed?: string | null;
	dataPreSecretKeySeedCapsule?: string | null;
	patientName?: string | null;
}) {
	const search = new URLSearchParams();
	search.set('accessToken', params.accessToken);
	if (params.encDataPreSecretKeySeed) {
		search.set('encDataPreSecretKeySeed', params.encDataPreSecretKeySeed);
	}
	if (params.dataPreSecretKeySeedCapsule) {
		search.set('dataPreSecretKeySeedCapsule', params.dataPreSecretKeySeedCapsule);
	}
	if (params.patientName) {
		search.set('patientName', params.patientName);
	}
	return search.toString();
}
