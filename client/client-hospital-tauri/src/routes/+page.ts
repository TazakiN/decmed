import { redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';

import { invoke } from '@tauri-apps/api/core';
import { tryCatchAsVal } from '$lib/utils';
import type { SuccessResponse } from '$lib/types';

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

	return redirect(301, '/dashboard');
};
