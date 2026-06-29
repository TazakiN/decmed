<script lang="ts">
	import { invalidateAll } from '$app/navigation';
	import { formatDateTime } from '$lib/rme';
	import { waitMs } from '$lib/utils';
	import type {
		DelegationAuditEdge,
		DelegationAuditPersonnelSummary,
		InvokeDelegationAuditChain
	} from '$lib/types';
	import { Loader2 } from '@lucide/svelte';
	import { invoke } from '@tauri-apps/api/core';

	let { data } = $props();
	let revokingKey = $state<string | null>(null);
	let revokeError = $state<string | null>(null);

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
		const expiresAt = effectiveExpiresAt(chain, edge);
		const expiresAtMs = dateValue(expiresAt);
		const revokedAtMs = dateValue(edge.revokedAt);

		if (edge.revoked) {
			if (expiresAtMs !== null && revokedAtMs !== null && expiresAtMs <= revokedAtMs) {
				return 'Expired';
			}

			return 'Revoked';
		}

		if (chain.rootGrant?.revoked) {
			return 'Revoked';
		}

		if (chain.status === 'Expired' || isExpired(expiresAt)) {
			return 'Expired';
		}

		return 'Active';
	};

	const chainDisplayStatus = (chain: InvokeDelegationAuditChain): DelegationStatus => {
		if (!chain.rootGrant) return chain.status;
		if (chain.rootGrant.revoked) return 'Revoked';
		if (isExpired(chain.rootGrant.expiresAt)) return 'Expired';

		return 'Active';
	};

	const revokeKeyRoot = (chain: InvokeDelegationAuditChain) => {
		return `root:${chain.rootSubject}:${chain.accessType}:${chain.relatedRmeId ?? ''}:${chain.rootGrant?.tokenHash ?? ''}`;
	};

	const revokeKeyEdge = (chain: InvokeDelegationAuditChain, edge: DelegationAuditEdge) => {
		return [
			'edge',
			chain.rootSubject,
			chain.accessType,
			chain.relatedRmeId ?? '',
			edge.delegatedBy.address,
			edge.delegatedTo.address,
			edge.tokenHash ?? ''
		].join(':');
	};

	const rootCanRevoke = (chain: InvokeDelegationAuditChain) => {
		return Boolean(
			chainDisplayStatus(chain) === 'Active' &&
			chain.rootGrant &&
			!chain.rootGrant.revoked &&
			!isExpired(chain.rootGrant.expiresAt)
		);
	};

	const revokeRootAccess = async (chain: InvokeDelegationAuditChain) => {
		if (!chain.rootGrant) return;

		const key = revokeKeyRoot(chain);
		try {
			revokeError = null;
			revokingKey = key;
			await invoke('revoke_access', {
				hospitalPersonnelAddress: chain.rootSubject,
				index: chain.rootGrant.index,
				purpose: chain.accessType,
				rootSubject: chain.rootSubject,
				tokenHash: chain.rootGrant.tokenHash ?? null,
				expiresBefore: chain.rootGrant.expiresAt ?? null
			});
			await waitMs(2000);
			await invalidateAll();
		} catch (e) {
			revokeError = e instanceof Error ? e.message : String(e);
		} finally {
			revokingKey = null;
		}
	};

	const revokeDelegation = async (chain: InvokeDelegationAuditChain, edge: DelegationAuditEdge) => {
		const expiresAt = effectiveExpiresAt(chain, edge);
		const key = revokeKeyEdge(chain, edge);

		try {
			revokeError = null;
			revokingKey = key;
			await invoke('revoke_delegated_access', {
				rootSubject: chain.rootSubject,
				delegatedBy: edge.delegatedBy.address,
				delegatedTo: edge.delegatedTo.address,
				accessType: chain.accessType,
				relatedRmeId: chain.relatedRmeId,
				tokenHash: edge.tokenHash,
				parentTokenHash: edge.parentTokenHash,
				delegationDepth: edge.depth,
				expiresBefore: expiresAt ?? null
			});
			await waitMs(2000);
			await invalidateAll();
		} catch (e) {
			revokeError = e instanceof Error ? e.message : String(e);
		} finally {
			revokingKey = null;
		}
	};
</script>

<div class="flex flex-col gap-3">
	<h2 class="font-montserrat font-medium text-xl my-2">Delegation Audit</h2>

	{#if revokeError}
		<div class="bg-red-50 border border-red-200 text-red-700 p-3 rounded-md">{revokeError}</div>
	{/if}

	{#await data.delegationAudit}
		<div class="bg-zinc-100 p-4 border border-zinc-200 rounded-md text-zinc-500">
			<p>Loading...</p>
		</div>
	{:then delegationAudit}
		{#if delegationAudit.data.length > 0}
			<div class="flex flex-col gap-3">
				{#each delegationAudit.data as chain}
					{@const displayStatus = chainDisplayStatus(chain)}
					<div class="bg-zinc-100 border border-zinc-300 p-3 rounded-md flex flex-col gap-3">
						<div class="flex items-start justify-between gap-3">
							<div>
								<p class="font-medium">
									{chain.rootGrant ? personLabel(chain.rootGrant.personnel) : '-'}
								</p>
							</div>
							<div class="flex items-center gap-2">
								{#if rootCanRevoke(chain)}
									{@const rootKey = revokeKeyRoot(chain)}
									<button
										class="bg-zinc-800 text-zinc-100 px-3 py-2 rounded text-xs font-medium disabled:cursor-not-allowed disabled:bg-zinc-300 disabled:text-zinc-500"
										disabled={revokingKey !== null}
										onclick={() => revokeRootAccess(chain)}
									>
										{#if revokingKey === rootKey}
											<Loader2 class="size-4 animate-spin" />
										{:else}
											Revoke
										{/if}
									</button>
								{/if}
								<span class={`px-2 py-1 rounded text-xs font-medium ${statusClass(displayStatus)}`}>
									{displayStatus}
								</span>
							</div>
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
								{@const edgeKey = revokeKeyEdge(chain, edge)}
								<div class="bg-white border border-zinc-200 rounded-md p-3">
									<div class="flex items-start justify-between gap-3">
										<div class="flex flex-col gap-1">
											<p class="font-medium">
												{personLabel(edge.delegatedBy)} -> {personLabel(edge.delegatedTo)}
											</p>
										</div>
										{#if status === 'Active'}
											<button
												class="bg-zinc-800 text-zinc-100 px-3 py-2 rounded text-xs font-medium disabled:cursor-not-allowed disabled:bg-zinc-300 disabled:text-zinc-500"
												disabled={revokingKey !== null}
												onclick={() => revokeDelegation(chain, edge)}
											>
												{#if revokingKey === edgeKey}
													<Loader2 class="size-4 animate-spin" />
												{:else}
													Revoke
												{/if}
											</button>
										{/if}
									</div>
									<div class="mt-2 flex flex-wrap gap-2 text-xs">
										<span class="bg-zinc-100 px-2 py-1 rounded">Depth: {edge.depth}</span>
										{#if edge.delegatedAt}
											<span class="bg-zinc-100 px-2 py-1 rounded">
												Delegated: {formatDateTime(edge.delegatedAt)}
											</span>
										{/if}
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
