<script lang="ts">
	import { ChevronRight, Loader2 } from '@lucide/svelte';
	import { AdministrativeHomeState } from './administrative-state.svelte';

	const administrativeHomeState = new AdministrativeHomeState();
</script>

<div class="bg-white border border-zinc-200 rounded-md">
	{#await administrativeHomeState.get_read_access()}
		<div class="p-4">
			<div
				class="animate-pulse bg-zinc-100 w-full shadow h-20 flex items-center justify-center rounded-md"
			>
				<Loader2 class="animate-spin" />
			</div>
		</div>
	{:then readAccess}
		{#if readAccess && readAccess.length > 0}
			{#each readAccess as access, i (i)}
				<a
					href={`/dashboard/adm/${access.patientIotaAddress}?accessToken=${encodeURIComponent(access.accessToken)}`}
					class="p-2 [&:not(:last-child)]:border-b border-zinc-200 flex items-center gap-2"
				>
					<div
						class="size-8 rounded-full flex items-center justify-center bg-zinc-50 border border-zinc-200 shrink-0"
					>
						<p class="text-xs font-medium">{i + 1}</p>
					</div>
					<p class="flex-1 flex">{access.patientName}</p>
					<span class="flex items-center justify-center">
						<ChevronRight />
					</span>
				</a>
			{/each}
		{:else}
			<div class="p-2">
				<p>No access found.</p>
			</div>
		{/if}
	{/await}
</div>
