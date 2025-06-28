import { tryCatchAsVal } from '$lib/utils';
import { invoke } from '@tauri-apps/api/core';
import type { PageLoad } from './$types';
import type { SuccessResponse, TauriMedicalData } from '$lib/types';
import { error, redirect } from '@sveltejs/kit';
import { toast } from 'svelte-sonner';

type PageLoadData = {
	emrIndex: number;
	medicalData?: TauriMedicalData;
};

export const load: PageLoad = async ({ parent, params }) => {
	await parent();

	const emrIndex = parseInt(params.emrIndex);

	return { emrIndex };
};
