<script lang="ts">
	import { getAuthContext } from '../(context)/auth-context.svelte';
	import HomeAdmin from './home-admin.svelte';
	import HomeAdministrative from './home-administrative.svelte';
	import HomeMedical from './home-medical.svelte';

	const authContext = getAuthContext();
</script>

{#if authContext.role === 'admin'}
	<HomeAdmin />
{:else if authContext.role === 'medical'}
	<HomeMedical />
{:else if authContext.role === 'administrative'}
	<HomeAdministrative />
{/if}
