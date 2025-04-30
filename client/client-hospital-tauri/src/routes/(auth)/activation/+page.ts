import type { PageLoad } from './$types';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { ActivationSchema } from './schema';

export const load: PageLoad = async () => {
	const activationForm = await superValidate(zod(ActivationSchema));

	return {
		activationForm
	};
};
