<script lang="ts">
	import {
		compareDatasets,
		compareFunctions,
		datasetLabels,
		formatDateTime,
		functionLabels,
		timeValue
	} from '$lib/rme.js';
	import type {
		DatasetCategory,
		FunctionCategory,
		InvokeGetMedicalRecordsResponse,
		SuccessResponse
	} from '$lib/types.js';
	import { tryCatchAsVal } from '$lib/utils.js';
	import { ChevronRight, Loader2, LucideArrowLeft } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { toast } from 'svelte-sonner';

	type DatasetRecord = {
		createdAt: string;
		datasetCategory: DatasetCategory;
		functions: FunctionCategory[];
	};

	let { data } = $props();

	let fetchMedicalRecords = $state(getMedicalRecords());

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
					createdAt: record.createdAt,
					datasetCategory: record.datasetCategory,
					functions: [record.functionCategory]
				});
				continue;
			}

			if (timeValue(record.createdAt) > timeValue(current.createdAt)) {
				current.createdAt = record.createdAt;
			}

			if (!current.functions.includes(record.functionCategory)) {
				current.functions = [...current.functions, record.functionCategory].sort(compareFunctions);
			}
		}

		return [...grouped.values()].sort((left, right) => {
			return compareDatasets(left.datasetCategory, right.datasetCategory);
		});
	}
</script>

<div class="mb-4 mt-2">
	<a href="/dashboard" class="flex max-w-max items-center gap-1"
		><LucideArrowLeft size={18} />Back</a
	>
</div>

{#await fetchMedicalRecords}
	<div class="h-20 animate-pulse bg-zinc-100 w-full flex items-center justify-center">
		<Loader2 class="animate-spin" />
	</div>
{:then records}
	{@const datasets = groupDatasets(records, data.relatedRmeId)}
	<div class="flex flex-col gap-4">
		<div class="rounded-md border border-zinc-200 bg-zinc-50 p-3">
			<p class="text-xs font-medium text-zinc-600">Related RME ID</p>
			<h2 class="break-all font-montserrat text-lg font-semibold">{data.relatedRmeId}</h2>
		</div>

		{#if datasets.length > 0}
			<div class="flex flex-col border border-zinc-200 rounded-md">
				{#each datasets as dataset (dataset.datasetCategory)}
					<a
						class="flex items-center gap-3 p-4 [&:not(:last-child)]:border-b border-zinc-200 justify-between"
						href={`/dashboard/emr/${encodeURIComponent(data.relatedRmeId)}/dataset/${dataset.datasetCategory}`}
					>
						<div class="min-w-0 flex flex-col gap-2">
							<div>
								<p class="font-medium">{datasetLabels[dataset.datasetCategory]}</p>
							</div>
						</div>
						<div class="flex shrink-0 items-center gap-2 text-right">
							<p class="text-sm">{formatDateTime(dataset.createdAt)}</p>
							<ChevronRight size={16} />
						</div>
					</a>
				{/each}
			</div>
		{:else}
			<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
				<p>No dataset found for this RME</p>
			</div>
		{/if}
	</div>
{:catch e}
	<p>Something went wrong.</p>
	{JSON.stringify(e)}
{/await}
