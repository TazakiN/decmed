<script lang="ts">
	import { compareDatasets, datasetLabels, formatDateTime, timeValue } from '$lib/rme.js';
	import type {
		DatasetCategory,
		FunctionCategory,
		InvokeGetMedicalRecordsResponse,
		SuccessResponse
	} from '$lib/types.js';
	import { tryCatchAsVal } from '$lib/utils.js';
	import { ChevronRight, Loader2 } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';
	import { toast } from 'svelte-sonner';

	type RmeRecord = {
		createdAt: string;
		datasets: DatasetCategory[];
		functions: FunctionCategory[];
		relatedRmeId: string;
	};

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

	function groupRecordsByRme(records: InvokeGetMedicalRecordsResponse[]) {
		const grouped = new Map<string, RmeRecord>();

		for (const record of records) {
			const current = grouped.get(record.relatedRmeId);

			if (!current) {
				grouped.set(record.relatedRmeId, {
					createdAt: record.createdAt,
					datasets: [record.datasetCategory],
					functions: [record.functionCategory],
					relatedRmeId: record.relatedRmeId
				});
				continue;
			}

			if (timeValue(record.createdAt) > timeValue(current.createdAt)) {
				current.createdAt = record.createdAt;
			}

			if (!current.datasets.includes(record.datasetCategory)) {
				current.datasets = [...current.datasets, record.datasetCategory].sort(compareDatasets);
			}

			if (!current.functions.includes(record.functionCategory)) {
				current.functions = [...current.functions, record.functionCategory];
			}
		}

		return [...grouped.values()].sort((left, right) => {
			return timeValue(right.createdAt) - timeValue(left.createdAt);
		});
	}
</script>

<h2 class="font-montserrat font-medium text-xl my-2">My Records</h2>
{#await fetchMedicalRecords}
	<div class="h-20 animate-pulse bg-zinc-100 w-full flex items-center justify-center">
		<Loader2 class="animate-spin" />
	</div>
{:then records}
	{@const rmeRecords = groupRecordsByRme(records)}
	{#if rmeRecords.length > 0}
		<div class="flex flex-col border border-zinc-200 rounded-md">
			{#each rmeRecords as record, i (record.relatedRmeId)}
				<a
					class="flex items-center gap-3 p-4 [&:not(:last-child)]:border-b border-zinc-200 justify-between"
					href={`/dashboard/emr/${encodeURIComponent(record.relatedRmeId)}`}
				>
					<div class="min-w-0 flex flex-col gap-2">
						<div class="min-w-0">
							<span class="font-medium">RME {i + 1}</span>
							<p class="break-all text-xs text-zinc-500">{record.relatedRmeId}</p>
						</div>
					</div>
					<div class="flex shrink-0 items-center gap-2 text-right">
						<div>
							<p class="text-sm">{formatDateTime(record.createdAt)}</p>
						</div>
						<ChevronRight size={16} />
					</div>
				</a>
			{/each}
		</div>
	{:else}
		<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
			<p>No EMR found</p>
		</div>
	{/if}
{:catch e}
	<p>Something went wrong.</p>
	{JSON.stringify(e)}
{/await}
