import type {
	DatasetCategory,
	InvokeGetMedicalRecordPayloadResponseData,
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
	delegationSignature?: string | null;
	patientIotaAddress: string;
	relatedRmeId: string;
	encDataPreSecretKeySeed?: string | null;
	dataPreSecretKeySeedCapsule?: string | null;
};

export class EmrDetailState {
	accessToken = $state('');
	delegationSignature = $state<string | null>(null);
	patientIotaAddress = $state('');
	relatedRmeId = $state('');
	encDataPreSecretKeySeed = $state<string | null>(null);
	dataPreSecretKeySeedCapsule = $state<string | null>(null);

	encounter = $state<RmeEncounterGroup | null>(null);
	loadError = $state<string | null>(null);
	isLoading = $state(true);
	activeDatasetTab = $state<DatasetCategory | ''>('');

	payloadByListIndex = $state<Record<number, InvokeGetMedicalRecordPayloadResponseData>>({});
	loadingByListIndex = $state<Record<number, boolean>>({});
	errorByListIndex = $state<Record<number, string>>({});
	authorNameMap = $state<Record<string, string>>({});

	constructor(props: Props) {
		this.accessToken = props.accessToken;
		this.delegationSignature = props.delegationSignature ?? null;
		this.patientIotaAddress = props.patientIotaAddress;
		this.relatedRmeId = props.relatedRmeId;
		this.encDataPreSecretKeySeed = props.encDataPreSecretKeySeed ?? null;
		this.dataPreSecretKeySeedCapsule = props.dataPreSecretKeySeedCapsule ?? null;
		void this.load();
	}

	private async fetchEncounter(): Promise<RmeEncounterGroup> {
		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_accessible_medical_record_encounter_metadata', {
				accessToken: this.accessToken,
				delegationSignature: this.delegationSignature,
				patientIotaAddress: this.patientIotaAddress,
				relatedRmeId: decodeURIComponent(this.relatedRmeId)
			})) as SuccessResponse<RmeEncounterGroup>;
		});

		if (!res.success) {
			toast.error(res.error);
			throw new Error(res.error);
		}

		return res.data.data;
	}

	load = async () => {
		this.isLoading = true;
		this.loadError = null;
		this.encounter = null;
		this.payloadByListIndex = {};
		this.errorByListIndex = {};
		this.loadingByListIndex = {};

		try {
			void this.loadAuthorNames();

			const encounter = await this.fetchEncounter();
			this.encounter = encounter;
			const categories = encounter.datasets.map((d) => d.dataset_category);
			const ordered = sortDatasets(categories);
			this.activeDatasetTab = ordered[0] ?? '';
			void this.loadDatasetPayloads(this.activeDatasetTab, encounter);
		} catch (err) {
			this.loadError = err instanceof Error ? err.message : String(err);
		} finally {
			this.isLoading = false;
		}
	};

	loadAuthorNames = async () => {
		const profileRes = await tryCatchAsVal(async () => {
			return (await invoke('get_profile')) as SuccessResponse<any>;
		});
		if (profileRes.success && profileRes.data.data) {
			const profile = profileRes.data.data;
			if (profile.iotaAddress && profile.name) {
				this.authorNameMap[profile.iotaAddress] = `${profile.name} (Saya)`;
			}
		}

		const candidatesRes = await tryCatchAsVal(async () => {
			return (await invoke('get_delegatee_candidates')) as SuccessResponse<any>;
		});
		if (candidatesRes.success && candidatesRes.data.data?.candidates) {
			for (const candidate of candidatesRes.data.data.candidates) {
				if (candidate.iotaAddress && candidate.name) {
					this.authorNameMap[candidate.iotaAddress] = candidate.name;
				}
			}
		}
	};

	private allSegments(encounter: RmeEncounterGroup): RmeSegmentListItem[] {
		return encounter.datasets.flatMap((dataset) => dataset.segments);
	}

	private segmentsForDataset(
		datasetCategory: DatasetCategory | '',
		encounter = this.encounter
	): RmeSegmentListItem[] {
		if (!encounter || !datasetCategory) return [];
		return (
			encounter.datasets.find((dataset) => dataset.dataset_category === datasetCategory)?.segments ?? []
		);
	}

	private setPayloadLoading(listIndex: number, isLoading: boolean) {
		if (isLoading) {
			this.loadingByListIndex = { ...this.loadingByListIndex, [listIndex]: true };
			return;
		}

		const { [listIndex]: _removed, ...rest } = this.loadingByListIndex;
		this.loadingByListIndex = rest;
	}

	loadDatasetPayloads = async (
		datasetCategory: DatasetCategory | '',
		encounter = this.encounter
	) => {
		const listIndexes = this.segmentsForDataset(datasetCategory, encounter)
			.map((segment) => segment.list_index)
			.filter(
				(listIndex) => !this.payloadByListIndex[listIndex] && !this.loadingByListIndex[listIndex]
			);

		await Promise.all(listIndexes.map((listIndex) => this.loadPayload(listIndex, false)));
	};

	loadAllPayloads = async (encounter = this.encounter) => {
		if (!encounter) return;

		const listIndexes = this.allSegments(encounter)
			.map((segment) => segment.list_index)
			.filter(
				(listIndex) => !this.payloadByListIndex[listIndex] && !this.loadingByListIndex[listIndex]
			);

		await Promise.all(listIndexes.map((listIndex) => this.loadPayload(listIndex, false)));
	};

	activateDatasetTab = (datasetCategory: DatasetCategory) => {
		this.activeDatasetTab = datasetCategory;
		void this.loadDatasetPayloads(datasetCategory);
	};

	loadPayload = async (listIndex: number, showToast = true) => {
		if (this.payloadByListIndex[listIndex] || this.loadingByListIndex[listIndex]) return;

		this.setPayloadLoading(listIndex, true);
		const { [listIndex]: _removed, ...restErrors } = this.errorByListIndex;
		this.errorByListIndex = restErrors;

		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_record_payload', {
				accessToken: this.accessToken,
				delegationSignature: this.delegationSignature,
				index: listIndex,
				patientIotaAddress: this.patientIotaAddress,
				encDataPreSecretKeySeed: this.encDataPreSecretKeySeed,
				dataPreSecretKeySeedCapsule: this.dataPreSecretKeySeedCapsule
			})) as SuccessResponse<InvokeGetMedicalRecordPayloadResponseData>;
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
