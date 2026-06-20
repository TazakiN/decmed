<script lang="ts">
	import { datasetLabels } from '$lib/capabilities';
	import { EmrMetadataListState, emrAccessQueryString } from './metadata-state.svelte.js';
	import { ChevronRight, Loader2 } from '@lucide/svelte';

	let { data } = $props();

	const metadataState = $derived(new EmrMetadataListState({
		accessToken: data.accessToken,
		delegationSignature: data.delegationSignature,
		patientIotaAddress: data.patientIotaAddress
	}));

	const accessQuery = $derived(emrAccessQueryString({
		accessToken: data.accessToken,
		delegationSignature: data.delegationSignature,
		encDataPreSecretKeySeed: data.encDataPreSecretKeySeed,
		dataPreSecretKeySeedCapsule: data.dataPreSecretKeySeedCapsule
	}));

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
</script>

<h2 class="text-lg font-montserrat font-semibold">Rekam Medis</h2>
<p class="text-sm text-zinc-500 my-2 break-all">{data.patientIotaAddress}</p>

{#if data.accessToken}
	{#await metadataState.fetchMetadata}
		<div class="p-4">
			<div
				class="animate-pulse bg-zinc-100 w-full shadow h-20 flex items-center justify-center rounded-md"
			>
				<Loader2 class="animate-spin" />
			</div>
		</div>
	{:then encounters}
		{#if encounters.length > 0}
			<div class="bg-white border border-zinc-200 rounded-md mt-4">
				{#each encounters as encounter (encounter.related_rme_id)}
					<a
						href={`/dashboard/emr/${data.patientIotaAddress}/${encodeURIComponent(encounter.related_rme_id)}?${accessQuery}`}
						class="p-4 [&:not(:last-child)]:border-b border-zinc-200 flex flex-col gap-2 hover:bg-zinc-50"
					>
						<div class="flex items-center gap-2">
							<div class="flex-1 min-w-0">
								<p class="font-medium truncate">{encounter.related_rme_id}</p>
								<p class="text-sm text-zinc-500">{formatDate(encounter.created_at)}</p>
							</div>
							<ChevronRight class="shrink-0" />
						</div>
						<div class="flex flex-wrap gap-2">
							{#each encounter.datasets as dataset (dataset.dataset_category)}
								<span class="text-xs px-2 py-1 rounded-md bg-zinc-100 border border-zinc-200">
									{datasetLabels[dataset.dataset_category]}
								</span>
							{/each}
						</div>
					</a>
				{/each}
			</div>
		{:else}
			<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500 mt-4">
				<p>Tidak ada RME yang dapat diakses.</p>
			</div>
		{/if}
	{:catch err}
		<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500 mt-4">
			<p>Gagal memuat daftar RME.</p>
			{#if err instanceof Error}
				<p class="text-sm mt-1">{err.message}</p>
			{/if}
		</div>
	{/await}
{/if}
