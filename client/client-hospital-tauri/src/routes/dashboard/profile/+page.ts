import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import type { GetProfileData, SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';
import { toast } from 'svelte-sonner';

type PageLoadData = {
	admData?: GetProfileData;
};

export const load: PageLoad = async () => {
	const resInvokeIsAppActivated = await tryCatchAsVal(async () => {
		return (await invoke('is_app_activated')) as SuccessResponse<null>;
	});
	if (!resInvokeIsAppActivated.success) {
		return redirect(301, '/activation');
	}

	const resInvokeIsSignedUp = await tryCatchAsVal(async () => {
		return (await invoke('is_signed_up')) as SuccessResponse<null>;
	});
	if (!resInvokeIsSignedUp.success) {
		return redirect(301, '/signup');
	}

	const resInvokeIsSignedIn = await tryCatchAsVal(async () => {
		return (await invoke('is_signed_in')) as SuccessResponse<null>;
	});
	if (!resInvokeIsSignedIn.success) {
		return redirect(301, '/signin');
	}

	const defaultData: PageLoadData = {};

	const resInvokeGetProfile = await tryCatchAsVal(async () => {
		return (await invoke('get_profile')) as SuccessResponse<GetProfileData>;
	});
	if (!resInvokeGetProfile.success) {
		toast.error(resInvokeGetProfile.error);
		return defaultData;
	}

	defaultData.admData = resInvokeGetProfile.data.data;

	return defaultData;
};
