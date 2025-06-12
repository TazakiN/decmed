import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import type { SuccessResponse, GetProfileData, Role } from '$lib/types';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { completeProfileAdminSchema, completeProfilePersonnelSchema } from '$lib/schema';
import { tryCatchAsVal } from '$lib/utils';

type PageLoadData = {
	role?: Role;
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
	if (resInvokeGetProfile.success) {
		defaultData.role = resInvokeGetProfile.data.data.role;

		if (resInvokeGetProfile.data.data.name) {
			return redirect(301, '/dashboard');
		}
	}

	const resInvokeIsSessionPinExist = await tryCatchAsVal(async () => {
		return (await invoke('is_session_pin_exist')) as SuccessResponse<null>;
	});
	if (!resInvokeIsSessionPinExist.success) {
		return redirect(301, '/pin');
	}

	const completeProfileAdminFrom = await superValidate(zod(completeProfileAdminSchema));
	const completeProfilePersonnelFrom = await superValidate(zod(completeProfilePersonnelSchema));

	return {
		completeProfileAdminFrom,
		completeProfilePersonnelFrom,
		...defaultData
	};
};
