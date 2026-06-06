<script lang="ts">
	import { Tabs } from 'bits-ui';
	import { datasetLabels, functionLabels } from '$lib/capabilities';
	import AdministrativeDataGrid from '$lib/components/administrative-data-grid.svelte';
	import { parseAdministrativeGeneralPayload } from '$lib/administrative-payload';
	import { EmrDetailState } from './detail-state.svelte.js';
	import { emrAccessQueryString } from '../metadata-state.svelte.js';
	import { Loader2, LucideInfo } from '@lucide/svelte';

	let { data } = $props();
	let visibleSegmentInfo = $state<Record<string, boolean>>({});

	const detailState = new EmrDetailState({
		accessToken: data.accessToken,
		patientIotaAddress: data.patientIotaAddress,
		relatedRmeId: data.relatedRmeId,
		encDataPreSecretKeySeed: data.encDataPreSecretKeySeed,
		dataPreSecretKeySeedCapsule: data.dataPreSecretKeySeedCapsule
	});

	const backQuery = emrAccessQueryString({
		accessToken: data.accessToken,
		encDataPreSecretKeySeed: data.encDataPreSecretKeySeed,
		dataPreSecretKeySeedCapsule: data.dataPreSecretKeySeedCapsule
	});

	const formatDate = (value: string) => {
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
								<span class="font-medium">{functionLabels[segment.function_category]}</span>
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
