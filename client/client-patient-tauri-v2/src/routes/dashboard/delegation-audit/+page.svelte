<script lang="ts">
	import { formatDateTime } from '$lib/rme';
	import type { DelegationAuditPersonnelSummary } from '$lib/types';

	let { data } = $props();

	const personLabel = (person: DelegationAuditPersonnelSummary) => {
		const role = person.subRole ?? person.role;
		const name = person.name ?? '-';
		return role ? `${name} (${role})` : name;
	};

	const statusClass = (status: string) => {
		if (status === 'Active') return 'bg-emerald-100 text-emerald-700';
		if (status === 'Expired') return 'bg-amber-100 text-amber-700';
		return 'bg-red-100 text-red-700';
	};
</script>

<div class="flex flex-col gap-3">
	<h2 class="font-montserrat font-medium text-xl my-2">Delegation Audit</h2>

	{#await data.delegationAudit}
		<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
			<p>Loading...</p>
		</div>
	{:then delegationAudit}
		{#if delegationAudit.data.length > 0}
			<div class="flex flex-col gap-3">
				{#each delegationAudit.data as chain}
					<div class="bg-zinc-100 border border-zinc-300 p-3 rounded-md flex flex-col gap-3">
						<div class="flex items-start justify-between gap-3">
							<div>
								<p class="font-medium">
									{chain.rootGrant
										? personLabel(chain.rootGrant.personnel)
										: '-'}
								</p>
							</div>
							<span class={`px-2 py-1 rounded text-xs font-medium ${statusClass(chain.status)}`}>
								{chain.status}
							</span>
						</div>

						<div class="flex flex-wrap gap-2 text-xs">
							<span class="bg-white px-2 py-1 rounded">Access: {chain.accessType}</span>
							{#if chain.relatedRmeId}
								<span class="bg-white px-2 py-1 rounded break-all">RME: {chain.relatedRmeId}</span>
							{/if}
							{#if chain.rootGrant}
								<span class="bg-white px-2 py-1 rounded">
									Root expires: {formatDateTime(chain.rootGrant.expiresAt)}
								</span>
							{/if}
						</div>

						<div class="flex flex-col gap-2">
							{#each chain.edges as edge}
								<div class="bg-white border border-zinc-200 rounded-md p-3">
									<div class="flex flex-col gap-1">
										<p class="font-medium">
											{personLabel(edge.delegatedBy)} -> {personLabel(edge.delegatedTo)}
										</p>
									</div>
									<div class="mt-2 flex flex-wrap gap-2 text-xs">
										<span class="bg-zinc-100 px-2 py-1 rounded">Depth: {edge.depth}</span>
										<span class="bg-zinc-100 px-2 py-1 rounded">
											Expires: {formatDateTime(edge.expiresAt)}
										</span>
										{#if edge.revoked}
											<span class="bg-red-100 text-red-700 px-2 py-1 rounded">
												Revoked: {formatDateTime(edge.revokedAt)}
											</span>
										{:else}
											<span class="bg-emerald-100 text-emerald-700 px-2 py-1 rounded">
												Active
											</span>
										{/if}
									</div>
								</div>
							{/each}
						</div>
					</div>
				{/each}
			</div>
		{:else}
			<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
				<p>No delegation audit found</p>
			</div>
		{/if}
	{:catch e}
		<div class="bg-red-50 border border-red-200 text-red-700 p-3 rounded-md">{e}</div>
	{/await}
</div>
