<script lang="ts">
	import AdministrativeDataGrid from '$lib/components/administrative-data-grid.svelte';
	import Error from '$lib/components/error.svelte';
	import { AdmReadState } from './state.svelte.js';

	let { data } = $props();

	let admReadState = new AdmReadState({
		accessToken: data.accessToken,
		patientIotaAddress: data.patientIotaAddress
	});
</script>

{#if data.accessToken}
	{#await admReadState.fetchPatientAdministrativeData}
		Loading...
	{:then record}
		<AdministrativeDataGrid data={record.administrativeData} />
	{:catch e}
		<Error error={e} />
	{/await}
{:else}
	nothing
{/if}
