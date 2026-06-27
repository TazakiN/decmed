import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import type { InvokeDelegationAuditChain, InvokeGetAccessLog, SuccessResponse } from '$lib/types';

const addMinutes = (value: string, minutes: number) => {
	const time = new Date(value).getTime();
	if (Number.isNaN(time)) return null;
	return new Date(time + minutes * 60 * 1000).toISOString();
};

const accessStatus = (access: InvokeGetAccessLog): InvokeDelegationAuditChain['status'] => {
	if (access.is_revoked) return 'Revoked';

	const expiresAt = addMinutes(access.date, access.exp_dur);
	if (expiresAt && new Date(expiresAt).getTime() <= Date.now()) return 'Expired';

	return 'Active';
};

const withRootGrantFallback = async (): Promise<SuccessResponse<InvokeDelegationAuditChain[]>> => {
	const [delegationAudit, accessLog] = await Promise.all([
		invoke('get_delegation_audit') as Promise<SuccessResponse<InvokeDelegationAuditChain[]>>,
		invoke('get_access_log') as Promise<SuccessResponse<InvokeGetAccessLog[]>>
	]);

	const chains = [...delegationAudit.data];
	const existingRootKeys = new Set(
		chains
			.filter((chain) => chain.rootGrant)
			.map((chain) => `${chain.rootSubject}:${chain.accessType}:${chain.relatedRmeId ?? ''}`)
	);

	for (const access of accessLog.data) {
		const key = `${access.hospital_personnel_address}:${access.access_type}:`;
		if (existingRootKeys.has(key)) continue;

		chains.push({
			rootSubject: access.hospital_personnel_address,
			accessType: access.access_type,
			relatedRmeId: null,
			rootGrant: {
				personnel: {
					address: access.hospital_personnel_address,
					name: access.hospital_personnel_metadata.name,
					hospitalName: access.hospital_metadata.name,
					role: null,
					subRole: null
				},
				index: access.index,
				tokenHash: access.token_hash ?? null,
				grantedAt: access.date,
				expiresAt: addMinutes(access.date, access.exp_dur),
				revoked: access.is_revoked
			},
			edges: [],
			status: accessStatus(access)
		});
		existingRootKeys.add(key);
	}

	chains.sort((left, right) => {
		const rightDate = right.edges[0]?.expiresAt ?? right.rootGrant?.expiresAt ?? '';
		const leftDate = left.edges[0]?.expiresAt ?? left.rootGrant?.expiresAt ?? '';
		return rightDate.localeCompare(leftDate);
	});

	return {
		...delegationAudit,
		data: chains
	};
};

export const load: PageLoad = async () => {
	return {
		delegationAudit: withRootGrantFallback()
	};
};
