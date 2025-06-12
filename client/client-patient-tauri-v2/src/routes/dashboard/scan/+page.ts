import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { hospitalQrSchema } from '$lib/schema';
import type { AdministrativeData, SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';

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

	const hospitalQrForm = await superValidate(zod(hospitalQrSchema));

	return {
		hospitalQrForm
	};
};
