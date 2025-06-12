import { superValidate } from 'sveltekit-superforms';
import type { PageLoad } from './$types';
import { zod } from 'sveltekit-superforms/adapters';
import { signUpSchemaStep4 } from '$lib/schema';
import { invoke } from '@tauri-apps/api/core';
import { redirect } from '@sveltejs/kit';
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
	if (resInvokeIsSignedUp.success) {
		return redirect(301, '/signin');
	}

	const signUpForm = await superValidate(zod(signUpSchemaStep4));

	return {
		signUpForm
	};
};
