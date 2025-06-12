import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { tryCatchAsVal } from '$lib/utils';
import type { AdministrativeData, SuccessResponse } from '$lib/types';

type PageLoadData = {
	profile?: AdministrativeData;
};

export const load: PageLoad = async () => {
	const resInvokeIsSignedIn = await tryCatchAsVal(async () => {
		return (await invoke('is_signed_in')) as SuccessResponse<null>;
	});
	if (!resInvokeIsSignedIn.success) {
		return redirect(301, '/signin');
	}

	const resInvokeGetProfile = await tryCatchAsVal(async () => {
		return (await invoke('get_profile')) as SuccessResponse<AdministrativeData>;
	});
	if (!resInvokeGetProfile.success || !resInvokeGetProfile.data.data.name) {
		return redirect(301, '/complete-profile');
	}

	const defaultData: PageLoadData = {};

	if (!resInvokeGetProfile.success) {
		return defaultData;
	}

	defaultData.profile = resInvokeGetProfile.data.data;

	return defaultData;
};
