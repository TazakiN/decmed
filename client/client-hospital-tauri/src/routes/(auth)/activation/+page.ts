import type { PageLoad } from './$types';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { ActivationSchema } from './schema';
import { invoke } from '@tauri-apps/api/core';
import { redirect } from '@sveltejs/kit';

export const load: PageLoad = async () => {
	const isAppActivated = (await invoke('is_app_activated')) as boolean;

	if (isAppActivated) {
		return redirect(301, '/dashboard');
	}

	const activationForm = await superValidate(zod(ActivationSchema));

	return {
		activationForm
	};
};
