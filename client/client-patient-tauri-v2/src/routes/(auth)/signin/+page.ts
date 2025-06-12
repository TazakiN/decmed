import { redirect } from '@sveltejs/kit';
import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { superValidate } from 'sveltekit-superforms';
import { signInSchemaStep3 } from '$lib/schema';
import { zod } from 'sveltekit-superforms/adapters';
import { tryCatchAsVal } from '$lib/utils';
import type { SuccessResponse } from '$lib/types';

export const load: PageLoad = async () => {
	const resInvokeIsSignedIn = await tryCatchAsVal(async () => {
		return (await invoke('is_signed_in')) as SuccessResponse<null>;
	});
	if (resInvokeIsSignedIn.success) {
		return redirect(301, '/dashboard');
	}

	const signInForm = await superValidate(zod(signInSchemaStep3));

	return {
		signInForm
	};
};
