<script lang="ts">
	import { formatDateTime } from '$lib/rme';
	import type {
		DelegationAuditEdge,
		DelegationAuditPersonnelSummary,
		InvokeDelegationAuditChain
	} from '$lib/types';

	let { data } = $props();

	type DelegationStatus = InvokeDelegationAuditChain['status'];

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

	const dateValue = (value: string | null | undefined) => {
		if (!value) return null;
		const time = new Date(value).getTime();
		return Number.isNaN(time) ? null : time;
	};

	const isExpired = (value: string | null | undefined) => {
		const time = dateValue(value);
		return time !== null && time <= Date.now();
	};

	const effectiveExpiresAt = (chain: InvokeDelegationAuditChain, edge: DelegationAuditEdge) => {
		return [chain.rootGrant?.expiresAt, edge.expiresAt]
			.filter((value): value is string => Boolean(value))
			.sort((left, right) => (dateValue(left) ?? 0) - (dateValue(right) ?? 0))[0];
	};

	const edgeStatus = (
		chain: InvokeDelegationAuditChain,
		edge: DelegationAuditEdge
	): DelegationStatus => {
		if (edge.revoked || chain.rootGrant?.revoked || chain.status === 'Revoked') {
			return 'Revoked';
		}

		if (
			chain.status === 'Expired' ||
			isExpired(chain.rootGrant?.expiresAt) ||
			isExpired(edge.expiresAt)
		) {
			return 'Expired';
		}

		return 'Active';
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
									{chain.rootGrant ? personLabel(chain.rootGrant.personnel) : '-'}
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
								{#if chain.rootGrant.expiresAt}
									<span class="bg-white px-2 py-1 rounded">
										Root expires: {formatDateTime(chain.rootGrant.expiresAt)}
									</span>
								{/if}
							{/if}
						</div>

						<div class="flex flex-col gap-2">
							{#each chain.edges as edge}
								{@const status = edgeStatus(chain, edge)}
								{@const expiresAt = effectiveExpiresAt(chain, edge)}
								<div class="bg-white border border-zinc-200 rounded-md p-3">
									<div class="flex flex-col gap-1">
										<p class="font-medium">
											{personLabel(edge.delegatedBy)} -> {personLabel(edge.delegatedTo)}
										</p>
									</div>
									<div class="mt-2 flex flex-wrap gap-2 text-xs">
										<span class="bg-zinc-100 px-2 py-1 rounded">Depth: {edge.depth}</span>
										{#if edge.expiresAt}
											<span class="bg-zinc-100 px-2 py-1 rounded">
												Expires: {formatDateTime(edge.expiresAt)}
											</span>
										{/if}
										{#if status === 'Revoked'}
											<span class="bg-red-100 text-red-700 px-2 py-1 rounded">
												{edge.revokedAt ? `Revoked: ${formatDateTime(edge.revokedAt)}` : 'Revoked'}
											</span>
										{:else if status === 'Expired'}
											<span class="bg-amber-100 text-amber-700 px-2 py-1 rounded">
												{expiresAt ? `Expired: ${formatDateTime(expiresAt)}` : 'Expired'}
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
