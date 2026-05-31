import type {
	DatasetCategory,
	InvokeGetMedicalRecordResponseData,
	RmeEncounterGroup,
	RmeSegmentListItem,
	SuccessResponse
} from '$lib/types';
import { sortDatasets } from '$lib/capabilities';
import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';

type Props = {
	accessToken: string;
	patientIotaAddress: string;
	relatedRmeId: string;
	encDataPreSecretKeySeed?: string | null;
	dataPreSecretKeySeedCapsule?: string | null;
};

export class EmrDetailState {
	accessToken = $state('');
	patientIotaAddress = $state('');
	relatedRmeId = $state('');
	encDataPreSecretKeySeed = $state<string | null>(null);
	dataPreSecretKeySeedCapsule = $state<string | null>(null);

	encounter = $state<RmeEncounterGroup | null>(null);
	loadError = $state<string | null>(null);
	isLoading = $state(true);
	activeDatasetTab = $state<DatasetCategory | ''>('');

	payloadByListIndex = $state<Record<number, InvokeGetMedicalRecordResponseData>>({});
	loadingByListIndex = $state<Record<number, boolean>>({});
	errorByListIndex = $state<Record<number, string>>({});

	constructor(props: Props) {
		this.accessToken = props.accessToken;
		this.patientIotaAddress = props.patientIotaAddress;
		this.relatedRmeId = props.relatedRmeId;
		this.encDataPreSecretKeySeed = props.encDataPreSecretKeySeed ?? null;
		this.dataPreSecretKeySeedCapsule = props.dataPreSecretKeySeedCapsule ?? null;
		void this.load();
	}

	private async fetchEncounter(): Promise<RmeEncounterGroup> {
		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_accessible_medical_record_metadata', {
				accessToken: this.accessToken,
				patientIotaAddress: this.patientIotaAddress
			})) as SuccessResponse<RmeEncounterGroup[]>;
		});

		if (!res.success) {
			toast.error(res.error);
			throw new Error(res.error);
		}

		const targetId = decodeURIComponent(this.relatedRmeId);
		const encounter = res.data.data.find(
			(e) => e.related_rme_id === targetId || e.related_rme_id === this.relatedRmeId
		);
		if (!encounter) {
			throw new Error('RME tidak ditemukan atau tidak memiliki akses.');
		}
		return encounter;
	}

	load = async () => {
		this.isLoading = true;
		this.loadError = null;
		this.encounter = null;
		this.payloadByListIndex = {};
		this.errorByListIndex = {};
		this.loadingByListIndex = {};

		try {
			const encounter = await this.fetchEncounter();
			this.encounter = encounter;
			const categories = encounter.datasets.map((d) => d.dataset_category);
			const ordered = sortDatasets(categories);
			this.activeDatasetTab = ordered[0] ?? '';
			void this.loadAllPayloads(encounter);
		} catch (err) {
			this.loadError = err instanceof Error ? err.message : String(err);
		} finally {
			this.isLoading = false;
		}
	};

	private allSegments(encounter: RmeEncounterGroup): RmeSegmentListItem[] {
		return encounter.datasets.flatMap((dataset) => dataset.segments);
	}

	private setPayloadLoading(listIndex: number, isLoading: boolean) {
		if (isLoading) {
			this.loadingByListIndex = { ...this.loadingByListIndex, [listIndex]: true };
			return;
		}

		const { [listIndex]: _removed, ...rest } = this.loadingByListIndex;
		this.loadingByListIndex = rest;
	}

	loadAllPayloads = async (encounter = this.encounter) => {
		if (!encounter) return;

		const listIndexes = this.allSegments(encounter)
			.map((segment) => segment.list_index)
			.filter(
				(listIndex) => !this.payloadByListIndex[listIndex] && !this.loadingByListIndex[listIndex]
			);

		await Promise.all(listIndexes.map((listIndex) => this.loadPayload(listIndex, false)));
	};

	loadPayload = async (listIndex: number, showToast = true) => {
		if (this.payloadByListIndex[listIndex] || this.loadingByListIndex[listIndex]) return;

		this.setPayloadLoading(listIndex, true);
		const { [listIndex]: _removed, ...restErrors } = this.errorByListIndex;
		this.errorByListIndex = restErrors;

		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_record', {
				accessToken: this.accessToken,
				index: listIndex,
				patientIotaAddress: this.patientIotaAddress,
				encDataPreSecretKeySeed: this.encDataPreSecretKeySeed,
				dataPreSecretKeySeedCapsule: this.dataPreSecretKeySeedCapsule
			})) as SuccessResponse<InvokeGetMedicalRecordResponseData>;
		});

		this.setPayloadLoading(listIndex, false);

		if (!res.success) {
			const message =
				res.error.includes('401') || res.error.toLowerCase().includes('unauthorized')
					? 'Akses ditolak atau token kedaluwarsa. Silakan kembali ke daftar pasien.'
					: res.error;
			this.errorByListIndex = { ...this.errorByListIndex, [listIndex]: message };
			if (showToast) toast.error(message);
			return;
		}

		this.payloadByListIndex = {
			...this.payloadByListIndex,
			[listIndex]: res.data.data
		};
	};
}
