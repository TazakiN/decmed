<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { datasetLabels, functionLabels } from '$lib/capabilities';
	import AdministrativeDataGrid from '$lib/components/administrative-data-grid.svelte';
	import { parseAdministrativeGeneralPayload } from '$lib/administrative-payload';
	import type {
		AccessCapabilitiesResponse,
		AccessCapabilityData,
		DatasetCategory,
		RmeSegmentListItem,
		SuccessResponse
	} from '$lib/types';
	import { tryCatchAsVal } from '$lib/utils';
	import { EmrDetailState } from './detail-state.svelte.js';
	import { emrAccessQueryString } from '../metadata-state.svelte.js';
	import { Loader2, LucideInfo } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';

	let { data } = $props();
	let visibleSegmentInfo = $state<Record<string, boolean>>({});
	let writeCapabilities = $state<AccessCapabilityData[]>([]);
	let correctingSegmentId = $state<string | null>(null);
	let correctionReason = $state('');
	let correctionPayload = $state('');
	let correctionPayloadMode = $state<'text' | 'json'>('text');
	let correctionOriginalPayload = $state<Record<string, unknown>>({});
	let isSubmittingCorrection = $state(false);

	const detailState = new EmrDetailState({
		accessToken: data.accessToken,
		delegationSignature: data.delegationSignature,
		patientIotaAddress: data.patientIotaAddress,
		relatedRmeId: data.relatedRmeId,
		encDataPreSecretKeySeed: data.encDataPreSecretKeySeed,
		dataPreSecretKeySeedCapsule: data.dataPreSecretKeySeedCapsule
	});

	const backQuery = emrAccessQueryString({
		accessToken: data.accessToken,
		delegationSignature: data.delegationSignature,
		encDataPreSecretKeySeed: data.encDataPreSecretKeySeed,
		dataPreSecretKeySeedCapsule: data.dataPreSecretKeySeedCapsule
	});

	const formatDate = (value: string | number) => {
		const parsed = new Date(value);
		if (Number.isNaN(parsed.getTime())) return value;
		return parsed.toLocaleDateString('id-ID', {
			year: 'numeric',
			month: 'short',
			day: 'numeric',
			hour: '2-digit',
			minute: '2-digit',
			hourCycle: 'h24'
		});
	};

	const segmentPayloadText = (payload: Record<string, unknown> | undefined) => {
		if (!payload) return '';
		return typeof payload.text === 'string' ? payload.text : JSON.stringify(payload, null, 2);
	};

	const toggleSegmentInfo = (segmentId: string) => {
		visibleSegmentInfo = {
			...visibleSegmentInfo,
			[segmentId]: !visibleSegmentInfo[segmentId]
		};
	};

	const loadWriteCapabilities = async () => {
		const res = await tryCatchAsVal(async () => {
			return (await invoke(
				'get_current_access_capabilities'
			)) as SuccessResponse<AccessCapabilitiesResponse>;
		});
		if (res.success) writeCapabilities = res.data.data.write;
	};

	const correctionCapability = (
		datasetCategory: DatasetCategory,
		segment: RmeSegmentListItem
	) => {
		const relatedRmeId = decodeURIComponent(data.relatedRmeId);
		return (
			writeCapabilities.find((capability) => {
				const capabilityRmeId =
					capability.relatedRmeId ?? capability.access.relatedRmeId ?? null;
				return (
					capability.access.patientIotaAddress === data.patientIotaAddress &&
					(!capabilityRmeId || capabilityRmeId === relatedRmeId) &&
					capability.writeDatasets.includes(datasetCategory) &&
					capability.writeFunctions.includes(segment.function_category) &&
					Boolean(capability.access.patientPrePublicKey)
				);
			}) ?? null
		);
	};

	const openCorrection = async (segment: RmeSegmentListItem) => {
		await detailState.loadPayload(segment.list_index);
		const record = detailState.payloadByListIndex[segment.list_index];
		if (record?.recordKind !== 'segment' || !record.segment) {
			toast.error('Payload segmen tidak tersedia untuk diperbaiki');
			return;
		}

		correctionOriginalPayload = record.segment.payload;
		if (typeof record.segment.payload.text === 'string') {
			correctionPayloadMode = 'text';
			correctionPayload = record.segment.payload.text;
		} else {
			correctionPayloadMode = 'json';
			correctionPayload = JSON.stringify(record.segment.payload, null, 2);
		}
		correctionReason = '';
		correctingSegmentId = segment.segment_id;
	};

	const closeCorrection = () => {
		correctingSegmentId = null;
		correctionReason = '';
		correctionPayload = '';
		correctionOriginalPayload = {};
	};

	const submitCorrection = async (
		datasetCategory: DatasetCategory,
		segment: RmeSegmentListItem
	) => {
		const capability = correctionCapability(datasetCategory, segment);
		const record = detailState.payloadByListIndex[segment.list_index];
		const reason = correctionReason.trim();
		if (
			!capability?.access.patientPrePublicKey ||
			record?.recordKind !== 'segment' ||
			!record.segment
		) {
			toast.error('Write capability atau payload segmen tidak tersedia');
			return;
		}
		if (!reason) {
			toast.error('Alasan perbaikan wajib diisi');
			return;
		}

		let payload: Record<string, unknown>;
		if (correctionPayloadMode === 'text') {
			if (!correctionPayload.trim()) {
				toast.error('Payload perbaikan wajib diisi');
				return;
			}
			payload = { ...correctionOriginalPayload, text: correctionPayload };
		} else {
			try {
				const parsed = JSON.parse(correctionPayload) as unknown;
				if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
					throw new Error('Payload harus berupa object JSON');
				}
				payload = parsed as Record<string, unknown>;
				if (Object.keys(payload).length === 0) {
					throw new Error('Payload tidak boleh kosong');
				}
			} catch (error) {
				toast.error(error instanceof Error ? error.message : 'Payload JSON tidak valid');
				return;
			}
		}

		isSubmittingCorrection = true;
		const res = await tryCatchAsVal(async () => {
			return (await invoke('new_medical_record_segment', {
				accessToken: capability.access.accessToken,
				data: {
					related_rme_id: decodeURIComponent(data.relatedRmeId),
					patient_address: data.patientIotaAddress,
					service_date: record.segment.service_date,
					author_address: 'self',
					dataset_category: datasetCategory,
					function_category: segment.function_category,
					payload,
					correction_of_index: segment.index,
					correction_reason: reason
				},
				patientPrePublicKey: capability.access.patientPrePublicKey,
				pin: null,
				delegationSignature: capability.access.delegationSignature ?? null
			})) as SuccessResponse<unknown>;
		});
		isSubmittingCorrection = false;

		if (!res.success) {
			toast.error(res.error);
			return;
		}

		closeCorrection();
		await detailState.load();
		detailState.activateDatasetTab(datasetCategory);
		toast.success('Perbaikan segmen berhasil disimpan');
	};

	onMount(() => {
		void loadWriteCapabilities();
	});
</script>

<a
	href={`/dashboard/emr/${data.patientIotaAddress}?${backQuery}`}
	class="text-sm text-zinc-600 hover:text-zinc-900 mb-4 inline-block"
>
	← Back
</a>

<h2 class="text-lg font-montserrat font-semibold">Detail RME</h2>
<p class="text-sm text-zinc-500 my-1 break-all">{data.relatedRmeId}</p>

{#if detailState.isLoading}
	<div class="p-4 mt-4">
		<div
			class="animate-pulse bg-zinc-100 w-full shadow h-20 flex items-center justify-center rounded-md"
		>
			<Loader2 class="animate-spin" />
		</div>
	</div>
{:else if detailState.loadError}
	<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500 mt-4">
		<p>Gagal memuat detail RME.</p>
		<p class="text-sm mt-1">{detailState.loadError}</p>
	</div>
{:else if detailState.encounter}
	<Tabs.Root bind:value={detailState.activeDatasetTab} class="w-full mt-4">
		<Tabs.List class="w-full flex flex-wrap gap-2 mb-4">
			{#each detailState.encounter.datasets as dataset (dataset.dataset_category)}
				<Tabs.Trigger
					value={dataset.dataset_category}
					onclick={() => detailState.activateDatasetTab(dataset.dataset_category)}
					class="data-[state=active]:bg-zinc-100 hover:bg-zinc-100 cursor-pointer px-3 py-1 rounded-md border border-zinc-200 bg-white text-sm"
				>
					{datasetLabels[dataset.dataset_category]}
				</Tabs.Trigger>
			{/each}
		</Tabs.List>

		{#each detailState.encounter.datasets as dataset (dataset.dataset_category)}
			<Tabs.Content value={dataset.dataset_category} class="space-y-4">
				{#each dataset.segments as segment (segment.segment_id)}
					<div class="bg-white border border-zinc-200 rounded-md p-4">
						<div class="flex items-start justify-between gap-3">
								<div class="grid grid-cols-[80px_1fr] gap-2 text-sm">
									<span class="text-zinc-500">Fungsi</span>
									<span class="font-medium">
										{functionLabels[segment.function_category]}
										{#if segment.correction_of_index !== null}
											<span class="ml-2 rounded bg-amber-100 px-2 py-0.5 text-xs text-amber-800">
												Correction
											</span>
										{/if}
									</span>
							</div>
							<button
								type="button"
								class="rounded-full p-1 text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-700"
								onclick={() => toggleSegmentInfo(segment.segment_id)}
								aria-label={`Toggle info for ${functionLabels[segment.function_category]}`}
								aria-expanded={Boolean(visibleSegmentInfo[segment.segment_id])}
							>
								<LucideInfo size={16} />
							</button>
						</div>

						{#if visibleSegmentInfo[segment.segment_id]}
							<div class="mt-3 grid grid-cols-[80px_1fr] gap-2 text-sm">
								<span class="text-zinc-500">Waktu</span>
								<span>{formatDate(segment.created_at)}</span>
								<span class="text-zinc-500">Author</span>
									<span class="break-all"
										>{detailState.authorNameMap[segment.author_address] ||
											segment.author_address}</span
									>
									{#if segment.correction_of_index !== null}
										<span class="text-zinc-500">Correction</span>
										<span>Index #{segment.correction_of_index}</span>
										<span class="text-zinc-500">Alasan</span>
										<span>{segment.correction_reason}</span>
										{#if segment.updated_at !== null}
											<span class="text-zinc-500">Diperbarui</span>
											<span>{formatDate(segment.updated_at)}</span>
										{/if}
									{/if}
								</div>
						{/if}

						{#if detailState.errorByListIndex[segment.list_index]}
							<p class="text-sm text-red-600 mt-2">
								{detailState.errorByListIndex[segment.list_index]}
							</p>
						{/if}

						{#if detailState.loadingByListIndex[segment.list_index]}
							<div class="mt-4 flex items-center gap-2 text-sm text-zinc-500">
								<Loader2 class="animate-spin" size={16} />
								<span>Memuat payload...</span>
							</div>
						{:else if detailState.payloadByListIndex[segment.list_index]}
							{@const record = detailState.payloadByListIndex[segment.list_index]}
							<div class="mt-4">
								{#if record.recordKind === 'segment' && record.segment}
									{@const adminPayload =
										segment.function_category === 'ADMINISTRATIVE_GENERAL'
											? parseAdministrativeGeneralPayload(record.segment.payload)
											: null}
									{#if adminPayload}
										<AdministrativeDataGrid data={adminPayload} />
									{:else}
										<label for="payload-{segment.segment_id}" class="font-medium text-sm py-2 block"
											>Payload</label
										>
										<textarea
											id="payload-{segment.segment_id}"
											disabled
											value={segmentPayloadText(record.segment.payload)}
											class="border border-zinc-300 p-2 w-full focus:outline-none focus:ring-3 ring-zinc-500 rounded-md min-h-28"
											></textarea>
										{/if}

										{#if correctionCapability(dataset.dataset_category, segment)}
											{#if correctingSegmentId === segment.segment_id}
												<div
													class="mt-4 space-y-3 rounded-md border border-amber-200 bg-amber-50 p-3"
												>
													<p class="text-sm font-medium">Perbaikan Segmen</p>
													<label class="block text-sm">
														<span class="mb-1 block font-medium">Alasan perbaikan</span>
														<input
															class="input-text w-full"
															bind:value={correctionReason}
															placeholder="Alasan singkat, tanpa data klinis sensitif"
														/>
													</label>
													<label class="block text-sm">
														<span class="mb-1 block font-medium">Payload perbaikan</span>
														<textarea
															class="input-text min-h-32 w-full font-mono text-sm"
															bind:value={correctionPayload}
														></textarea>
													</label>
													<div class="flex gap-2">
														<button
															type="button"
															class="button-dark px-3 py-1.5 text-sm disabled:opacity-50"
															disabled={isSubmittingCorrection}
															onclick={() => submitCorrection(dataset.dataset_category, segment)}
														>
															{isSubmittingCorrection ? 'Menyimpan...' : 'Simpan correction'}
														</button>
														<button
															type="button"
															class="rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm"
															disabled={isSubmittingCorrection}
															onclick={closeCorrection}
														>
															Batal
														</button>
													</div>
												</div>
											{:else}
												<button
													type="button"
													class="mt-4 rounded-md border border-zinc-300 bg-white px-3 py-1.5 text-sm hover:bg-zinc-50"
													onclick={() => openCorrection(segment)}
												>
													Buat correction
												</button>
											{/if}
										{/if}
									{:else if record.medicalData}
									<p class="text-sm text-zinc-600">Data legacy (bukan segment RME).</p>
									<pre
										class="text-xs mt-2 p-2 bg-zinc-50 border rounded-md overflow-auto">{JSON.stringify(
											record.medicalData,
											null,
											2
										)}</pre>
								{:else}
									<p class="text-sm text-zinc-500">Payload tidak tersedia.</p>
								{/if}
							</div>
						{/if}
					</div>
				{/each}
			</Tabs.Content>
		{/each}
	</Tabs.Root>
{/if}
