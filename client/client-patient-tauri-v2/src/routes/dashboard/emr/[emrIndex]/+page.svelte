<script lang="ts">
	import { Tabs } from 'bits-ui';
	import {
		compareDatasets,
		compareFunctions,
		datasetLabels,
		formatDateTime,
		functionLabels,
		payloadToText,
		timeValue
	} from '$lib/rme.js';
	import type {
		DatasetCategory,
		InvokeGetMedicalRecordResponse,
		InvokeGetMedicalRecordsResponse,
		SuccessResponse
	} from '$lib/types.js';
	import { tryCatchAsVal } from '$lib/utils.js';
	import { Loader2, LucideArrowLeft, LucideInfo } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { onMount } from 'svelte';
	import { toast } from 'svelte-sonner';

	type DatasetRecord = {
		datasetCategory: DatasetCategory;
		segments: InvokeGetMedicalRecordsResponse[];
	};

	let { data } = $props();

	let isLoading = $state(true);
	let loadError = $state<string | null>(null);
	let datasets = $state<DatasetRecord[]>([]);
	let activeDatasetTab = $state<DatasetCategory | ''>('');
	let payloadByIndex = $state<Record<number, InvokeGetMedicalRecordResponse>>({});
	let loadingByIndex = $state<Record<number, boolean>>({});
	let errorByIndex = $state<Record<number, string>>({});
	let visibleRecordInfo = $state<Record<string, boolean>>({});

	async function getMedicalRecords() {
		const resInvokeGetMedicalRecords = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_records')) as SuccessResponse<
				InvokeGetMedicalRecordsResponse[]
			>;
		});

		if (!resInvokeGetMedicalRecords.success) {
			toast.error(resInvokeGetMedicalRecords.error);
			throw new Error(resInvokeGetMedicalRecords.error);
		}

		return resInvokeGetMedicalRecords.data.data;
	}

	function groupDatasets(records: InvokeGetMedicalRecordsResponse[], relatedRmeId: string) {
		const grouped = new Map<DatasetCategory, DatasetRecord>();

		for (const record of records) {
			if (record.relatedRmeId !== relatedRmeId) {
				continue;
			}

			const current = grouped.get(record.datasetCategory);

			if (!current) {
				grouped.set(record.datasetCategory, {
					datasetCategory: record.datasetCategory,
					segments: [record]
				});
				continue;
			}

			current.segments = [...current.segments, record].sort(compareSegments);
		}

		return [...grouped.values()].sort((left, right) => {
			return compareDatasets(left.datasetCategory, right.datasetCategory);
		});
	}

	function compareSegments(
		left: InvokeGetMedicalRecordsResponse,
		right: InvokeGetMedicalRecordsResponse
	) {
		const functionSort = compareFunctions(left.functionCategory, right.functionCategory);
		return functionSort || timeValue(left.createdAt) - timeValue(right.createdAt);
	}

	function segmentsForDataset(datasetCategory: DatasetCategory | '') {
		if (!datasetCategory) return [];
		return datasets.find((dataset) => dataset.datasetCategory === datasetCategory)?.segments ?? [];
	}

	function setPayloadLoading(index: number, loading: boolean) {
		if (loading) {
			loadingByIndex = { ...loadingByIndex, [index]: true };
			return;
		}

		const { [index]: _removed, ...rest } = loadingByIndex;
		loadingByIndex = rest;
	}

	async function loadPayload(index: number) {
		if (payloadByIndex[index] || loadingByIndex[index]) return;

		setPayloadLoading(index, true);
		const { [index]: _removed, ...restErrors } = errorByIndex;
		errorByIndex = restErrors;

		const resInvokeGetMedicalRecord = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_record', {
				index
			})) as SuccessResponse<InvokeGetMedicalRecordResponse>;
		});

		setPayloadLoading(index, false);

		if (!resInvokeGetMedicalRecord.success) {
			errorByIndex = { ...errorByIndex, [index]: resInvokeGetMedicalRecord.error };
			toast.error(resInvokeGetMedicalRecord.error);
			return;
		}

		payloadByIndex = {
			...payloadByIndex,
			[index]: resInvokeGetMedicalRecord.data.data
		};
	}

	async function loadDatasetPayloads(datasetCategory: DatasetCategory | '') {
		const indexes = segmentsForDataset(datasetCategory).map((segment) => segment.index);
		await Promise.all(indexes.map((index) => loadPayload(index)));
	}

	function activateDatasetTab(datasetCategory: DatasetCategory) {
		activeDatasetTab = datasetCategory;
		void loadDatasetPayloads(datasetCategory);
	}

	function toggleRecordInfo(index: number) {
		const key = String(index);
		visibleRecordInfo = {
			...visibleRecordInfo,
			[key]: !visibleRecordInfo[key]
		};
	}

	async function loadDetail() {
		isLoading = true;
		loadError = null;

		try {
			const records = await getMedicalRecords();
			datasets = groupDatasets(records, data.relatedRmeId);
			activeDatasetTab = datasets[0]?.datasetCategory ?? '';
			await loadDatasetPayloads(activeDatasetTab);
		} catch (err) {
			loadError = err instanceof Error ? err.message : String(err);
		} finally {
			isLoading = false;
		}
	}

	onMount(() => {
		void loadDetail();
	});
</script>

<div class="mb-4 mt-2">
	<a href="/dashboard" class="flex max-w-max items-center gap-1"
		><LucideArrowLeft size={18} />Back</a
	>
</div>

<div class="mb-4 rounded-md border border-zinc-200 bg-zinc-50 p-3">
	<p class="text-xs font-medium text-zinc-600">RME ID</p>
	<h2 class="break-all font-montserrat text-lg font-semibold">{data.relatedRmeId}</h2>
</div>

{#if isLoading}
	<div class="h-20 animate-pulse bg-zinc-100 w-full flex items-center justify-center">
		<Loader2 class="animate-spin" />
	</div>
{:else if loadError}
	<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
		<p>Something went wrong.</p>
		<p class="mt-1 text-sm">{loadError}</p>
	</div>
{:else if datasets.length > 0}
	<Tabs.Root bind:value={activeDatasetTab} class="w-full">
		<Tabs.List class="w-full flex flex-wrap gap-2 mb-4">
			{#each datasets as dataset (dataset.datasetCategory)}
				<Tabs.Trigger
					value={dataset.datasetCategory}
					onclick={() => activateDatasetTab(dataset.datasetCategory)}
					class="data-[state=active]:bg-zinc-100 hover:bg-zinc-100 cursor-pointer px-3 py-1 rounded-md border border-zinc-200 bg-white text-sm"
				>
					{datasetLabels[dataset.datasetCategory]}
				</Tabs.Trigger>
			{/each}
		</Tabs.List>

		{#each datasets as dataset (dataset.datasetCategory)}
			<Tabs.Content value={dataset.datasetCategory} class="space-y-3">
				{#each dataset.segments as segment (segment.index)}
					<section class="rounded-md border border-zinc-200 bg-white p-4">
						<div class="flex flex-col gap-1 border-b border-zinc-100 pb-3">
							<div class="flex items-center justify-between gap-2">
								<p class="font-medium">{functionLabels[segment.functionCategory]}</p>
								<button
									type="button"
									class="rounded-full p-1 text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-700"
									onclick={() => toggleRecordInfo(segment.index)}
									aria-label={`Toggle info for ${functionLabels[segment.functionCategory]}`}
									aria-expanded={Boolean(visibleRecordInfo[String(segment.index)])}
								>
									<LucideInfo size={16} />
								</button>
							</div>
							{#if visibleRecordInfo[String(segment.index)]}
								<div class="flex flex-col gap-0.5 text-xs text-zinc-500">
									<p>
										{formatDateTime(payloadByIndex[segment.index]?.createdAt ?? segment.createdAt)}
									</p>
								</div>
							{/if}
						</div>

						<div class="pt-3">
							{#if errorByIndex[segment.index]}
								<p class="text-sm text-red-600">{errorByIndex[segment.index]}</p>
							{:else if loadingByIndex[segment.index]}
								<div class="flex items-center gap-2 text-sm text-zinc-500">
									<Loader2 class="animate-spin" size={16} />
									<span>Memuat payload...</span>
								</div>
							{:else if payloadByIndex[segment.index]}
								<p class="mt-1 whitespace-pre-wrap wrap-break-word text-sm">
									{payloadToText(payloadByIndex[segment.index].segmentData.payload)}
								</p>
							{/if}
						</div>
					</section>
				{/each}
			</Tabs.Content>
		{/each}
	</Tabs.Root>
{:else}
	<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
		<p>No dataset found for this RME</p>
	</div>
{/if}
