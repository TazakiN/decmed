<script lang="ts">
	import {
		compareFunctions,
		datasetLabels,
		formatDateTime,
		functionLabels,
		payloadToText,
		timeValue
	} from '$lib/rme.js';
	import type {
		InvokeGetMedicalRecordResponse,
		InvokeGetMedicalRecordsResponse,
		SuccessResponse
	} from '$lib/types.js';
	import { tryCatchAsVal } from '$lib/utils.js';
	import { Loader2, LucideArrowLeft, LucideInfo } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { toast } from 'svelte-sonner';

	type DatasetFunctionRecord = InvokeGetMedicalRecordResponse & {
		index: number;
	};

	let { data } = $props();

	let visibleRecordInfo = $state<Record<string, boolean>>({});
	let fetchDatasetRecords = $state(getDatasetRecords());

	async function getDatasetRecords() {
		const resInvokeGetMedicalRecords = await tryCatchAsVal(async () => {
			return (await invoke('get_medical_records')) as SuccessResponse<
				InvokeGetMedicalRecordsResponse[]
			>;
		});

		if (!resInvokeGetMedicalRecords.success) {
			toast.error(resInvokeGetMedicalRecords.error);
			throw new Error(resInvokeGetMedicalRecords.error);
		}

		const matchingSegments = resInvokeGetMedicalRecords.data.data
			.filter((record) => {
				return (
					record.relatedRmeId === data.relatedRmeId &&
					record.datasetCategory === data.datasetCategory
				);
			})
			.sort((left, right) => {
				const functionSort = compareFunctions(left.functionCategory, right.functionCategory);
				return functionSort || timeValue(left.createdAt) - timeValue(right.createdAt);
			});

		const records: DatasetFunctionRecord[] = await Promise.all(
			matchingSegments.map(async (segment) => {
				const resInvokeGetMedicalRecord = await tryCatchAsVal(async () => {
					return (await invoke('get_medical_record', {
						index: segment.index
					})) as SuccessResponse<InvokeGetMedicalRecordResponse>;
				});

				if (!resInvokeGetMedicalRecord.success) {
					toast.error(resInvokeGetMedicalRecord.error);
					throw new Error(resInvokeGetMedicalRecord.error);
				}

				return {
					...resInvokeGetMedicalRecord.data.data,
					index: segment.index
				};
			})
		);

		return records.sort((left, right) => {
			const functionSort = compareFunctions(
				left.segmentData.function_category,
				right.segmentData.function_category
			);
			return functionSort || timeValue(left.createdAt) - timeValue(right.createdAt);
		});
	}

	function toggleRecordInfo(segmentId: string) {
		visibleRecordInfo = {
			...visibleRecordInfo,
			[segmentId]: !visibleRecordInfo[segmentId]
		};
	}
</script>

<div class="mb-4 mt-2">
	<a
		href={`/dashboard/emr/${encodeURIComponent(data.relatedRmeId)}`}
		class="flex max-w-max items-center gap-1"><LucideArrowLeft size={18} />Back</a
	>
</div>

<div class="mb-4 rounded-md border border-zinc-200 bg-zinc-50 p-3">
	<h2 class="font-montserrat text-lg font-semibold">{datasetLabels[data.datasetCategory]}</h2>
	<p class="mt-1 break-all text-xs text-zinc-500">{data.relatedRmeId}</p>
</div>

{#await fetchDatasetRecords}
	<div class="h-20 animate-pulse bg-zinc-100 w-full flex items-center justify-center">
		<Loader2 class="animate-spin" />
	</div>
{:then records}
	{#if records.length > 0}
		<div class="flex flex-col gap-3">
			{#each records as record (record.segmentData.segment_id)}
				<section class="rounded-md border border-zinc-200 bg-white p-4">
					<div class="flex flex-col gap-1 border-b border-zinc-100 pb-3">
						<div class="flex items-center justify-between gap-2">
							<p class="font-medium">{functionLabels[record.segmentData.function_category]}</p>
							<button
								type="button"
								class="rounded-full p-1 text-zinc-500 transition hover:bg-zinc-100 hover:text-zinc-700"
								onclick={() => toggleRecordInfo(record.segmentData.segment_id)}
								aria-label={`Toggle info for ${functionLabels[record.segmentData.function_category]}`}
								aria-expanded={Boolean(visibleRecordInfo[record.segmentData.segment_id])}
							>
								<LucideInfo size={16} />
							</button>
						</div>
						{#if visibleRecordInfo[record.segmentData.segment_id]}
							<div class="flex flex-col gap-0.5 text-xs text-zinc-500">
								<p>{formatDateTime(record.createdAt)}</p>
							</div>
						{/if}
					</div>
					<div class="pt-3">
						<p class="mt-1 whitespace-pre-wrap break-words text-sm">
							{payloadToText(record.segmentData.payload)}
						</p>
					</div>
				</section>
			{/each}
		</div>
	{:else}
		<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
			<p>No function data found for this dataset</p>
		</div>
	{/if}
{:catch e}
	<p>Something went wrong.</p>
	{JSON.stringify(e)}
{/await}
