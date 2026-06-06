import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import type { InvokeDelegationAuditChain, SuccessResponse } from '$lib/types';

export const load: PageLoad = async () => {
	const delegationAudit = invoke('get_delegation_audit') as Promise<
		SuccessResponse<InvokeDelegationAuditChain[]>
	>;

	return {
		delegationAudit
	};
};
