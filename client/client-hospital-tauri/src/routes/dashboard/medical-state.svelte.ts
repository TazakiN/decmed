import { isReadableCapability, isWritableCapability } from '$lib/capabilities';
import type { AccessCapabilitiesResponse, SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import { toast } from 'svelte-sonner';

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

		return resInvokeGetReadAccess.data.data.read.filter(isReadableCapability);
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
