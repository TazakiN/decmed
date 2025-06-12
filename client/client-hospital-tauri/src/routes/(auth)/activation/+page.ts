import type { PageLoad } from './$types';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { activationSchema } from '$lib/schema';
import { invoke } from '@tauri-apps/api/core';
import { redirect } from '@sveltejs/kit';
import type { SuccessResponse } from '$lib/types';
import { tryCatchAsVal } from '$lib/utils';

export const load: PageLoad = async () => {
	const resInvokeIsAppActivated = await tryCatchAsVal(async () => {
		return (await invoke('is_app_activated')) as SuccessResponse<null>;
	});
	if (resInvokeIsAppActivated.success) {
		return redirect(301, '/dashboard');
	}

	const activationForm = await superValidate(zod(activationSchema));

	return {
		activationForm
	};
};
