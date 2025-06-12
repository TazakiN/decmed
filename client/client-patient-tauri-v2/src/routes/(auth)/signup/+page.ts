import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { signUpSchemaStep5 } from '$lib/schema';
import { tryCatchAsVal } from '$lib/utils';
import type { SuccessResponse } from '$lib/types';

export const load: PageLoad = async () => {
	const resInvokeIsSignedIn = await tryCatchAsVal(async () => {
		return (await invoke('is_signed_in')) as SuccessResponse<null>;
	});
	if (resInvokeIsSignedIn.success) {
		return redirect(301, '/dashboard');
	}

	const signUpForm = await superValidate(zod(signUpSchemaStep5));

	return {
		signUpForm
	};
};
