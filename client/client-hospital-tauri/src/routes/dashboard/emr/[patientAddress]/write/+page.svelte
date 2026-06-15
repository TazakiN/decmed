<script lang="ts">
	import {
		datasetLabels,
		functionLabels,
		functionsForDataset,
		intersect,
		sortDatasets,
		sortFunctions
	} from '$lib/capabilities';
	import type {
		AccessCapabilitiesResponse,
		AccessCapabilityData,
		DatasetCategory,
		FunctionCategory,
		SuccessResponse
	} from '$lib/types';
	import { tryCatchAsVal } from '$lib/utils';
	import { invoke } from '@tauri-apps/api/core';
	import { Loader2 } from '@lucide/svelte';
	import { toast } from 'svelte-sonner';

	let { data } = $props();

	let capability = $state<AccessCapabilityData | null>(null);
	let selectedDataset = $state<DatasetCategory | ''>('');
	let payloadByFunction = $state<Record<string, string>>({});
	let isSubmitting = $state(false);

	const allowedDatasets = $derived(
		sortDatasets(
			(capability?.writeDatasets ?? []).filter((dataset) =>
				functionsForDataset(dataset).some((fn) => (capability?.writeFunctions ?? []).includes(fn))
			)
		)
	);
	const allowedFunctions = $derived(
		selectedDataset
			? sortFunctions(
					intersect(functionsForDataset(selectedDataset), capability?.writeFunctions ?? []).filter(
						(fn) => fn !== 'ADMINISTRATIVE_GENERAL'
					)
				)
			: []
	);

	const loadCapability = async () => {
		const res = await tryCatchAsVal(async () => {
			return (await invoke('get_current_access_capabilities')) as SuccessResponse<AccessCapabilitiesResponse>;
		});
		if (!res.success) {
			toast.error(res.error);
			return null;
		}

		const found =
			res.data.data.write.find((item) => item.access.accessToken === data.accessToken) ?? null;
		capability = found;
		selectedDataset = found
			? sortDatasets(
					found.writeDatasets.filter((dataset) =>
						functionsForDataset(dataset).some((fn) => found.writeFunctions.includes(fn))
					)
				)[0] ?? ''
			: '';
		return found;
	};

	const submitSegments = async () => {
		if (!capability || !selectedDataset || !data.relatedRmeId) {
			toast.error('Write capability tidak lengkap');
			return;
		}

		const entries = allowedFunctions
			.map((functionCategory) => ({
				functionCategory,
				text: payloadByFunction[functionCategory]?.trim() ?? ''
			}))
			.filter((entry) => entry.text.length > 0);

		if (entries.length === 0) {
			toast.error('Isi minimal satu function category');
			return;
		}

		isSubmitting = true;
		for (const entry of entries) {
			const res = await tryCatchAsVal(async () => {
				return (await invoke('new_medical_record_segment', {
					accessToken: data.accessToken,
					data: {
						related_rme_id: data.relatedRmeId,
						patient_address: data.patientIotaAddress,
						patient_ref: data.patientIotaAddress,
						fasyankes_id: 'decmed-hospital',
						service_date: new Date().toISOString(),
						author_address: 'self',
						dataset_category: selectedDataset,
						function_category: entry.functionCategory,
						payload: { text: entry.text }
					},
					patientPrePublicKey: data.patientPrePublicKey,
					pin: null,
					delegationSignature: data.delegationSignature || capability.access.delegationSignature || null
				})) as SuccessResponse<unknown>;
			});

			if (!res.success) {
				toast.error(res.error);
				isSubmitting = false;
				return;
			}
		}

		isSubmitting = false;
		toast.success('RME berhasil ditulis');
	};
</script>

<h2 class="font-montserrat text-lg font-semibold">Write RME</h2>

{#await loadCapability()}
	<div class="p-4 mt-4 bg-white border border-zinc-200 rounded-md flex items-center gap-2">
		<Loader2 class="animate-spin" size={18} />
		<span>Loading...</span>
	</div>
{:then loadedCapability}
	{#if !loadedCapability || allowedDatasets.length === 0}
		<div class="p-4 mt-4 bg-white border border-zinc-200 rounded-md">
			<p>No write capability found.</p>
		</div>
	{:else}
		<div class="flex flex-col gap-4 mt-4">
			<div class="bg-white border border-zinc-200 rounded-md p-4">
				<p class="font-medium">{loadedCapability.access.patientName}</p>
				<p class="text-xs text-zinc-500 break-all">{loadedCapability.access.patientIotaAddress}</p>
			</div>

			<label class="flex flex-col gap-1 max-w-sm">
				<span class="text-sm font-medium">Dataset</span>
				<select class="input-text" bind:value={selectedDataset}>
					{#each allowedDatasets as dataset (dataset)}
						<option value={dataset}>{datasetLabels[dataset]}</option>
					{/each}
				</select>
			</label>

			<div class="flex flex-col gap-3">
				{#each allowedFunctions as functionCategory (functionCategory)}
					<label class="flex flex-col gap-1 bg-white border border-zinc-200 rounded-md p-3">
						<span class="text-sm font-medium">{functionLabels[functionCategory]}</span>
						<textarea
							class="input-text min-h-24"
							value={payloadByFunction[functionCategory] ?? ''}
							oninput={(event) =>
								(payloadByFunction = {
									...payloadByFunction,
									[functionCategory]: (event.currentTarget as HTMLTextAreaElement).value
								})}
						></textarea>
					</label>
				{/each}
			</div>

			<button
				type="button"
				class="button-dark max-w-max px-4 disabled:opacity-50"
				disabled={isSubmitting}
				onclick={submitSegments}
			>
				{isSubmitting ? 'Writing...' : 'Write'}
			</button>
		</div>
	{/if}
{/await}
