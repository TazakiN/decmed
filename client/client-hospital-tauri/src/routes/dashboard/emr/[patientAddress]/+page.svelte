<script lang="ts">
	import Error from '$lib/components/error.svelte';
	import { EmrReadState } from './state.svelte.js';

	let { data } = $props();

	let emrReadState = new EmrReadState({
		accessToken: data.accessToken,
		index: data.index,
		patientIotaAddress: data.patientIotaAddress
	});
</script>

{#if data.accessToken}
	Read EMR of {data.patientIotaAddress}

	{#await emrReadState.fetchMedicalRecord}
		Loading...
	{:then record}
		<div class="grid grid-cols-[150px_1fr] items-center my-4">
			<div class="p-2 bg-white border border-b-0 border-zinc-200">
				<span>Index</span>
			</div>
			<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
				<span>{data.index}</span>
			</div>
			<div class="p-2 bg-white border border-zinc-200">
				<span>Created at</span>
			</div>
			<div class="p-2 border border-zinc-200 border-l-0">
				<span
					>{new Date(record.createdAt).toLocaleDateString('id-ID', {
						year: 'numeric',
						month: 'short',
						day: 'numeric',
						hour: '2-digit',
						minute: '2-digit',
						hourCycle: 'h24'
					})}</span
				>
			</div>
		</div>

		<div class="flex items-center">
			{#if record.prevIndex !== null}
				<div class="flex-1 justify-start flex items-center">
					<a
						href={`/dashboard/emr/${data.patientIotaAddress}?accessToken=${data.accessToken}&index=${record.prevIndex}`}
						class="max-w-max"
						onclick={() => {
							emrReadState.index = parseInt(record.prevIndex);
						}}>Prev</a
					>
				</div>
			{/if}
			{#if record.nextIndex}
				<div class="flex-1 justify-end flex items-center">
					<a
						href={`/dashboard/emr/${data.patientIotaAddress}?accessToken=${data.accessToken}&index=${record.nextIndex}`}
						class="max-w-max"
						onclick={() => {
							emrReadState.index = parseInt(record.nextIndex);
						}}>Next</a
					>
				</div>
			{/if}
		</div>
	{:catch e}
		<Error error={e} />
	{/await}
{:else}
	nothing
{/if}
