<script lang="ts">
	import Error from '$lib/components/error.svelte';
	import { AdmReadState } from './state.svelte.js';

	let { data } = $props();

	let admReadState = new AdmReadState({
		accessToken: data.accessToken,
		patientIotaAddress: data.patientIotaAddress
	});
</script>

{#if data.accessToken}
	Read EMR of {data.patientIotaAddress}

	{#await admReadState.fetchPatientAdministrativeData}
		Loading...
	{:then record}
		<div class="grid grid-cols-[150px_1fr] items-center my-4">
			<div class="p-2 bg-white border border-b-0 border-zinc-200">
				<span>NIK</span>
			</div>
			<div class="p-2 border border-zinc-200 border-b-0 border-l-0">
				<span>{record.id}</span>
			</div>
			<div class="p-2 bg-white border border-b border-zinc-200">
				<span>Name</span>
			</div>
			<div class="p-2 border border-zinc-200 border-b border-l-0">
				<span>{record.name}</span>
			</div>
		</div>
	{:catch e}
		<Error error={e} />
	{/await}
{:else}
	nothing
{/if}
