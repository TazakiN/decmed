import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import { redirect } from '@sveltejs/kit';
import { superValidate } from 'sveltekit-superforms';
import { zod } from 'sveltekit-superforms/adapters';
import { addPersonnelSchemaStep2 } from '$lib/schema';
import type { HospitalPersonnel, SuccessResponse, GetProfileData } from '$lib/types';
import { ADMIN_ROLE } from '$lib/constants';
import { tryCatchAsVal } from '$lib/utils';
import { toast } from 'svelte-sonner';

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

	const resInvokeGetProfile = await tryCatchAsVal(async () => {
		return (await invoke('get_profile')) as SuccessResponse<GetProfileData>;
	});
	if (!resInvokeGetProfile.success || !resInvokeGetProfile.data.data.name) {
		return redirect(301, '/complete-profile');
	}

	const resInvokeIsSessionPinExist = await tryCatchAsVal(async () => {
		return (await invoke('is_session_pin_exist')) as SuccessResponse<null>;
	});
	if (!resInvokeIsSessionPinExist.success) {
		return redirect(301, '/pin');
	}

	const role = resInvokeGetProfile.data.data.role;

	const defaultData = {
		role
	};

	if (role === ADMIN_ROLE) {
		let personnels: HospitalPersonnel[] = [];
		const resInvokeGetHospitalPersonnels = await tryCatchAsVal(async () => {
			return (await invoke('get_hospital_personnels')) as SuccessResponse<{
				personnels: HospitalPersonnel[];
			}>;
		});

		if (!resInvokeGetHospitalPersonnels.success) {
			toast.error(resInvokeGetHospitalPersonnels.error);
		} else {
			personnels = resInvokeGetHospitalPersonnels.data.data.personnels;
		}

		const addPersonnelForm = await superValidate(zod(addPersonnelSchemaStep2));

		return {
			...defaultData,
			addPersonnelForm,
			personnels
		};
	}

	return defaultData;
};
