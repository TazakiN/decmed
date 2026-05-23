import type { PageLoad } from './$types';

export const load: PageLoad = async ({ parent }) => {
	const { role } = await parent();
	return { role };
};
