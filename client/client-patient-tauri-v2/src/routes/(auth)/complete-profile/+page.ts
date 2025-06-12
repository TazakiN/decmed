import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import type { AdministrativeData, SuccessResponse } from '$lib/types';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { completeProfileSchema } from '$lib/schema';

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
	console.log(resInvokeGetProfile);
	if (resInvokeGetProfile.success && resInvokeGetProfile.data.data.name) {
		return redirect(301, '/dashboard');
	}

	const completeProfileForm = await superValidate(zod(completeProfileSchema));

	return {
		completeProfileForm
	};
};
