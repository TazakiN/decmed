import { redirect } from '@sveltejs/kit';
import type { PageLoad } from './$types';

import { invoke } from '@tauri-apps/api/core';

export const load: PageLoad = async () => {
	const isAppActivated = (await invoke('is_app_activated')) as boolean;

	if (!isAppActivated) {
		return redirect(301, '/activation');
	}
};
