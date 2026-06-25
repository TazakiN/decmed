import { isReadableCapability, isWritableCapability } from '$lib/capabilities';
import type { AccessCapabilitiesResponse, AccessCapabilityData, SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';

const readScopeScore = (capability: AccessCapabilityData) =>
	capability.readDatasets.length * 100 + capability.readFunctions.length;

const readScopeSort = (left: AccessCapabilityData, right: AccessCapabilityData) => {
	const scoreDiff = readScopeScore(right) - readScopeScore(left);
	if (scoreDiff !== 0) return scoreDiff;

	const leftRme = left.relatedRmeId ?? left.access.relatedRmeId ?? null;
	const rightRme = right.relatedRmeId ?? right.access.relatedRmeId ?? null;
	if (!leftRme && rightRme) return -1;
	if (leftRme && !rightRme) return 1;

	return left.access.patientName.localeCompare(right.access.patientName);
};

export class MedicalHomeState {
	tabs = ['read', 'write'];
	currentTab = $state(this.tabs[0]);

	constructor() {}

	get_read_access = async () => {
		const resInvokeGetReadAccess = await tryCatchAsVal(async () => {
			return (await invoke('get_current_access_capabilities')) as SuccessResponse<AccessCapabilitiesResponse>;
		});

		if (!resInvokeGetReadAccess.success) {
			toast.error(resInvokeGetReadAccess.error);
			return [];
		}

		return resInvokeGetReadAccess.data.data.read.filter(isReadableCapability).sort(readScopeSort);
	};

	get_update_access = async () => {
		const resInvokeGetUpdateAccess = await tryCatchAsVal(async () => {
			return (await invoke('get_current_access_capabilities')) as SuccessResponse<AccessCapabilitiesResponse>;
		});

		if (!resInvokeGetUpdateAccess.success) {
			toast.error(resInvokeGetUpdateAccess.error);

			return [];
		}

		return resInvokeGetUpdateAccess.data.data.write.filter(isWritableCapability);
	};
}
