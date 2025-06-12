<script lang="ts">
	import Admin from './admin.svelte';
	import Personnel from './personnel.svelte';

	let { data } = $props();
</script>

<div class="flex flex-col max-w-md w-full">
	<h2 class="font-montserrat text-xl font-medium my-4">Complete Your Profile</h2>
	{#if data.role === 'Admin'}
		<Admin completeProfileAdminFormData={data.completeProfileAdminFrom} />
	{:else}
		<Personnel completeProfilePersonnelFormData={data.completeProfilePersonnelFrom} />
	{/if}
</div>
