<script lang="ts">
	import { ChevronRight } from '@lucide/svelte';

	let { data } = $props();
</script>

<h2 class="font-montserrat font-medium text-xl my-2">My Records</h2>
<div class="flex flex-col border border-zinc-200 rounded-md">
	{#each data.medicalRecordsMetadata || [] as metadata, i (i)}
		<a
			class="flex items-center p-4 [&:not(:last-child)]:border-b border-zinc-200 justify-between"
			href="/dashboard"
		>
			<span class="font-medium">Record {i + 1}</span>
			<div class="flex items-center gap-2">
				<p>
					{new Date(metadata.createdAt).toLocaleDateString('en-US', {
						year: 'numeric',
						month: 'short',
						day: '2-digit'
					})}
				</p>
				<ChevronRight size={16} />
			</div>
		</a>
	{/each}
</div>
